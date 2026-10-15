// Copyright (c) 2019-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include <chainparams.h>
#include <consensus/validation.h>
#include <interfaces/chain.h>
#include <kernel/disconnected_transactions.h>
#include <node/block_template_manager.h>
#include <node/chainstatemanager_args.h>
#include <node/kernel_notifications.h>
#include <node/utxo_snapshot.h>
#include <random.h>
#include <rpc/blockchain.h>
#include <sync.h>
#include <test/util/chainstate.h>
#include <test/util/common.h>
#include <test/util/logging.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <uint256.h>
#include <util/byte_units.h>
#include <util/result.h>
#include <util/vector.h>
#include <validation.h>
#include <validationinterface.h>

#include <tinyformat.h>

#include <vector>

#include <boost/test/unit_test.hpp>

using node::BlockManager;
using node::KernelNotifications;
using node::SnapshotMetadata;

BOOST_FIXTURE_TEST_SUITE(validation_chainstatemanager_tests, TestingSetup)

//! Basic tests for ChainstateManager.
//!
//! Activating a snapshot replaces the coins of the only chainstate. Its
//! previous coins are kept to validate the snapshot.
BOOST_FIXTURE_TEST_CASE(chainstatemanager, TestChain100Setup)
{
    ChainstateManager& manager = *m_node.chainman;
    Chainstate& c1 = manager.ActiveChainstate();

    BOOST_CHECK(WITH_LOCK(::cs_main, return !manager.CurrentChainstate().m_from_snapshot_blockhash));
    BOOST_CHECK(!WITH_LOCK(::cs_main, return manager.AssumedValidBase()));
    BOOST_CHECK(!WITH_LOCK(::cs_main, return manager.GetHistoricalBlockRange()));
    {
        LOCK(manager.GetMutex());
        BOOST_CHECK_EQUAL(manager.m_chainstates.size(), 1);
        BOOST_CHECK_EQUAL(manager.m_chainstates[0].get(), &c1);
    }

    // Get to a valid assumeutxo tip (per chainparams);
    mineBlocks(10);
    BOOST_CHECK_EQUAL(WITH_LOCK(manager.GetMutex(), return manager.ActiveHeight()), 110);
    const CBlockIndex* snapshot_base{WITH_LOCK(manager.GetMutex(), return manager.ActiveTip())};

    BOOST_REQUIRE(CreateAndActivateUTXOSnapshot(this));
    {
        LOCK(manager.GetMutex());
        BOOST_CHECK_EQUAL(*manager.CurrentChainstate().m_from_snapshot_blockhash, snapshot_base->GetBlockHash());
        BOOST_CHECK(manager.CurrentChainstate().m_assumeutxo == Assumeutxo::UNVALIDATED);
        BOOST_CHECK_EQUAL(manager.AssumedValidBase(), snapshot_base);
        BOOST_CHECK_EQUAL(manager.m_chainstates.size(), 1);
        BOOST_CHECK_EQUAL(&manager.ActiveChainstate(), &c1);
        BOOST_CHECK_EQUAL(manager.ActiveTip(), snapshot_base);

        // The previous coins are at the snapshot base already.
        const auto historical_blocks{manager.GetHistoricalBlockRange()};
        BOOST_REQUIRE(historical_blocks);
        BOOST_CHECK_EQUAL(historical_blocks->first, snapshot_base);
        BOOST_CHECK_EQUAL(historical_blocks->second, snapshot_base);
    }

    mineBlocks(1);
    BOOST_CHECK_EQUAL(WITH_LOCK(manager.GetMutex(), return manager.ActiveHeight()), 111);
    BOOST_CHECK_EQUAL(WITH_LOCK(manager.GetMutex(), return manager.GetHistoricalBlockRange()->first), snapshot_base);

    // Let scheduler events finish running to avoid accessing memory that is going to be unloaded
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
}

//! Test rebalancing the caches of the chainstate and of the coins validating a snapshot.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_rebalance_caches, TestChain100Setup)
{
    ChainstateManager& manager = *m_node.chainman;
    auto& test_manager{static_cast<TestChainstateManager&>(manager)};

    size_t max_cache = 10000;
    manager.m_total_coinsdb_cache = max_cache;
    manager.m_total_coinstip_cache = max_cache;

    Chainstate& c1 = manager.ActiveChainstate();
    WITH_LOCK(::cs_main, manager.MaybeRebalanceCaches());
    BOOST_CHECK_EQUAL(c1.m_coinstip_cache_size_bytes, max_cache);
    BOOST_CHECK_EQUAL(c1.m_coinsdb_cache_size_bytes, max_cache);

    mineBlocks(10);
    BOOST_REQUIRE(CreateAndActivateUTXOSnapshot(this));

    // Reset IBD state so IsInitialBlockDownload() returns true and causes
    // MaybeRebalanceCaches() to prioritize the snapshot chainstate, giving it
    // more cache space than the coins validating the snapshot. Calling
    // ResetIbd() is necessary because m_cached_is_ibd is already latched to
    // false before the test starts due to the test setup.
    test_manager.ResetIbd();
    {
        LOCK(::cs_main);
        manager.MaybeRebalanceCaches();
        BOOST_CHECK_EQUAL(c1.m_coinstip_cache_size_bytes, size_t(max_cache * 0.95));
        BOOST_CHECK_EQUAL(c1.m_coinsdb_cache_size_bytes, size_t(max_cache * 0.95));
        BOOST_CHECK(manager.HistoricalCoinsCacheSizes() == std::make_pair(size_t(max_cache * 0.05), size_t(max_cache * 0.05)));
    }

    // Once the chainstate is at the tip, validating the snapshot is prioritized.
    test_manager.JumpOutOfIbd();
    {
        LOCK(::cs_main);
        manager.MaybeRebalanceCaches();
        BOOST_CHECK_EQUAL(c1.m_coinstip_cache_size_bytes, size_t(max_cache * 0.05));
        BOOST_CHECK_EQUAL(c1.m_coinsdb_cache_size_bytes, size_t(max_cache * 0.05));
        BOOST_CHECK(manager.HistoricalCoinsCacheSizes() == std::make_pair(size_t(max_cache * 0.95), size_t(max_cache * 0.95)));
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_ibd_exit_after_loading_blocks, ChainTestingSetup)
{
    CBlockIndex tip;
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    auto apply{[&](bool cached_is_ibd, bool loading_blocks, bool tip_exists, bool enough_work, bool tip_recent) {
        LOCK(::cs_main);
        chainman.ResetChainstates();
        chainman.InitializeChainstate(m_node.mempool.get());

        const auto recent_time{Now<NodeSeconds>() - chainman.m_options.max_tip_age};

        chainman.m_cached_is_ibd.store(cached_is_ibd, std::memory_order_relaxed);
        chainman.m_blockman.m_importing = loading_blocks;
        if (tip_exists) {
            tip.nChainWork = chainman.MinimumChainWork() - (enough_work ? 0 : 1);
            tip.nTime = (recent_time - (tip_recent ? 0h : 100h)).time_since_epoch().count();
            chainman.ActiveChain().SetTip(tip);
        } else {
            assert(!chainman.ActiveChain().Tip());
        }
        chainman.UpdateIBDStatus();
    }};

    for (const bool cached_is_ibd : {false, true}) {
        for (const bool loading_blocks : {false, true}) {
            for (const bool tip_exists : {false, true}) {
                for (const bool enough_work : {false, true}) {
                    for (const bool tip_recent : {false, true}) {
                        apply(cached_is_ibd, loading_blocks, tip_exists, enough_work, tip_recent);
                        const bool expected_ibd = cached_is_ibd && (loading_blocks || !tip_exists || !enough_work || !tip_recent);
                        BOOST_CHECK_EQUAL(chainman.IsInitialBlockDownload(), expected_ibd);
                    }
                }
            }
        }
    }
}

struct SnapshotTestSetup : TestChain100Setup {
    // Run with coinsdb on the filesystem to support, e.g., moving invalidated
    // chainstate dirs to "*_invalid".
    //
    // Note that this means the tests run considerably slower than in-memory DB
    // tests, but we can't otherwise test this functionality since it relies on
    // destructive filesystem operations.
    SnapshotTestSetup() : TestChain100Setup{
                              {},
                              {
                                  .coins_db_in_memory = false,
                                  .block_tree_db_in_memory = false,
                              },
                          }
    {
    }

    void SetupSnapshot()
    {
        ChainstateManager& chainman = *Assert(m_node.chainman);
        auto& test_chainman{static_cast<TestChainstateManager&>(chainman)};
        const fs::path snapshot_dir{chainman.m_options.datadir / "chainstate_snapshot"};
        const fs::path historical_dir{chainman.m_options.datadir / "chainstate_verify"};

        {
            LOCK(::cs_main);
            BOOST_CHECK(!chainman.CurrentChainstate().m_from_snapshot_blockhash);
            BOOST_CHECK(!fs::exists(snapshot_dir));
        }

        size_t initial_size;
        size_t initial_total_coins{100};

        // Make some initial assertions about the contents of the chainstate.
        {
            LOCK(::cs_main);
            CCoinsViewCache& ibd_coinscache = chainman.ActiveChainstate().CoinsTip();
            initial_size = ibd_coinscache.GetCacheSize();
            size_t total_coins{0};

            for (CTransactionRef& txn : m_coinbase_txns) {
                COutPoint op{txn->GetHash(), 0};
                BOOST_CHECK(ibd_coinscache.HaveCoin(op));
                total_coins++;
            }

            BOOST_CHECK_EQUAL(total_coins, initial_total_coins);
            BOOST_CHECK_EQUAL(initial_size, initial_total_coins);
        }

        // Snapshot should refuse to load at this height.
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(this));
        BOOST_CHECK(!WITH_LOCK(::cs_main, return chainman.ActiveChainstate().m_from_snapshot_blockhash));

        // Mine 10 more blocks, putting at us height 110 where a valid assumeutxo value can
        // be found.
        constexpr int snapshot_height = 110;
        mineBlocks(10);
        initial_size += 10;
        initial_total_coins += 10;

        // Should not load malleated snapshots
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(
            this, [](AutoFile& auto_infile, SnapshotMetadata& metadata) {
                // A UTXO is missing but count is correct
                metadata.m_coins_count -= 1;

                Txid txid;
                auto_infile >> txid;
                // coins size
                (void)ReadCompactSize(auto_infile);
                // vout index
                (void)ReadCompactSize(auto_infile);
                Coin coin;
                auto_infile >> coin;
        }));

        BOOST_CHECK(!fs::exists(snapshot_dir));

        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(
            this, [](AutoFile& auto_infile, SnapshotMetadata& metadata) {
                // Coins count is larger than coins in file
                metadata.m_coins_count += 1;
        }));
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(
            this, [](AutoFile& auto_infile, SnapshotMetadata& metadata) {
                // Coins count is smaller than coins in file
                metadata.m_coins_count -= 1;
        }));
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(
            this, [](AutoFile& auto_infile, SnapshotMetadata& metadata) {
                // Wrong hash
                metadata.m_base_blockhash = uint256::ZERO;
        }));
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(
            this, [](AutoFile& auto_infile, SnapshotMetadata& metadata) {
                // Wrong hash
                metadata.m_base_blockhash = uint256::ONE;
        }));

        BOOST_REQUIRE(CreateAndActivateUTXOSnapshot(this));

        // The snapshot replaced the coins of the chainstate, whose previous
        // coins are kept to validate it.
        BOOST_CHECK(!fs::exists(snapshot_dir));
        BOOST_CHECK(fs::exists(historical_dir));

        {
            LOCK(::cs_main);
            BOOST_CHECK(!chainman.ActiveChainstate().m_from_snapshot_blockhash->IsNull());

            // Note: WriteSnapshotBaseBlockhash() is implicitly tested above.
            BOOST_CHECK_EQUAL(
                *node::ReadSnapshotBaseBlockhash(chainman.ActiveChainstate().StoragePath() / node::UNVALIDATED_SNAPSHOT_BLOCKHASH_FILENAME),
                *Assert(chainman.CurrentChainstate().m_from_snapshot_blockhash));
        }

        const auto& au_data = ::Params().AssumeutxoForHeight(snapshot_height);
        const CBlockIndex* tip = WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());

        BOOST_CHECK_EQUAL(tip->m_chain_tx_count, au_data->m_chain_tx_count);

        // To be checked against later when we try loading a subsequent snapshot.
        uint256 loaded_snapshot_blockhash{*Assert(WITH_LOCK(chainman.GetMutex(), return chainman.CurrentChainstate().m_from_snapshot_blockhash))};

        // Make some assertions about the coins of the chainstate and the
        // coins validating the snapshot. These checks ensure the previous coins
        // haven't changed and that the snapshot reflects the expected content.
        {
            LOCK(::cs_main);
            for (CCoinsViewCache* coinscache : {&chainman.ActiveChainstate().CoinsTip(), &test_chainman.HistoricalCoinsTip()}) {
                // Both caches will be empty initially.
                BOOST_CHECK_EQUAL((unsigned int)0, coinscache->GetCacheSize());

                size_t total_coins{0};

                for (CTransactionRef& txn : m_coinbase_txns) {
                    COutPoint op{txn->GetHash(), 0};
                    BOOST_CHECK(coinscache->HaveCoin(op));
                    total_coins++;
                }

                BOOST_CHECK_EQUAL(initial_size , coinscache->GetCacheSize());
                BOOST_CHECK_EQUAL(total_coins, initial_total_coins);
            }
        }

        // Mine some new blocks on top of the activated snapshot chainstate.
        constexpr size_t new_coins{100};
        mineBlocks(new_coins);  // Defined in TestChain100Setup.

        {
            LOCK(::cs_main);
            size_t coins_in_active{0};
            size_t coins_in_historical{0};
            size_t coins_missing_from_historical{0};

            for (CTransactionRef& txn : m_coinbase_txns) {
                COutPoint op{txn->GetHash(), 0};
                if (chainman.ActiveChainstate().CoinsTip().HaveCoin(op)) coins_in_active++;
                if (test_chainman.HistoricalCoinsTip().HaveCoin(op)) {
                    coins_in_historical++;
                } else {
                    coins_missing_from_historical++;
                }
            }

            BOOST_CHECK_EQUAL(coins_in_active, initial_total_coins + new_coins);
            BOOST_CHECK_EQUAL(coins_in_historical, initial_total_coins);
            BOOST_CHECK_EQUAL(coins_missing_from_historical, new_coins);
        }

        // Snapshot should refuse to load after one has already loaded.
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(this));

        // Snapshot blockhash should be unchanged.
        BOOST_CHECK_EQUAL(
            *WITH_LOCK(::cs_main, return chainman.ActiveChainstate().m_from_snapshot_blockhash),
            loaded_snapshot_blockhash);
    }

    // Simulate a restart of the node by flushing all state to disk, clearing the
    // existing ChainstateManager, and unloading the block index.
    //
    // @returns a reference to the "restarted" ChainstateManager
    ChainstateManager& SimulateNodeRestart()
    {
        ChainstateManager& chainman = *Assert(m_node.chainman);

        BOOST_TEST_MESSAGE("Simulating node restart");
        {
            LOCK(chainman.GetMutex());
            chainman.ResetHistoricalCoins();
            for (const auto& cs : chainman.m_chainstates) {
                if (cs->CanFlushToDisk()) cs->ForceFlushStateToDisk();
            }
        }
        {
            // Process all callbacks referring to the old manager before wiping it.
            m_node.validation_signals->SyncWithValidationInterfaceQueue();
            m_node.block_template_manager.reset();
            LOCK(::cs_main);
            chainman.ResetChainstates();
            BOOST_CHECK_EQUAL(chainman.m_chainstates.size(), 0);
            m_node.notifications = std::make_unique<KernelNotifications>(Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings));
            const ChainstateManager::Options chainman_opts{
                .chainparams = ::Params(),
                .datadir = chainman.m_options.datadir,
                .notifications = *m_node.notifications,
                .signals = m_node.validation_signals.get(),
            };
            const BlockManager::Options blockman_opts{
                .chainparams = chainman_opts.chainparams,
                .blocks_dir = m_args.GetBlocksDirPath(),
                .notifications = chainman_opts.notifications,
                .block_tree_db_params = DBParams{
                    .path = chainman.m_options.datadir / "blocks" / "index",
                    .cache_bytes = m_kernel_cache_sizes.block_tree_db,
                    .memory_only = m_block_tree_db_in_memory,
                },
            };
            // For robustness, ensure the old manager is destroyed before creating a
            // new one.
            m_node.chainman.reset();
            m_node.chainman = std::make_unique<ChainstateManager>(*Assert(m_node.shutdown_signal), chainman_opts, blockman_opts);
            CreateBlockTemplateManager();
        }
        return *Assert(m_node.chainman);
    }
};

//! Test basic snapshot activation.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_activate_snapshot, SnapshotTestSetup)
{
    this->SetupSnapshot();
}

//! Test LoadBlockIndex behavior when the chainstate is based on a snapshot.
//!
//! - First, verify that setBlockIndexCandidates is as expected when using a
//!   fully-validating chainstate.
//!
//! - Then mark a region of the chain as missing data and base the chainstate on
//!   a snapshot at its end, which tolerates assumed-valid blocks. Run
//!   LoadBlockIndex() and ensure that the chainstate has all blocks as
//!   candidates, except those marked assume-valid, because those entries don't
//!   HAVE_DATA.
//!
BOOST_FIXTURE_TEST_CASE(chainstatemanager_loadblockindex, TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& cs1 = chainman.ActiveChainstate();

    int num_indexes{0};
    // Blocks in range [assumed_valid_start_idx, last_assumed_valid_idx) will be
    // marked as assumed-valid and not having data.
    const int expected_assumed_valid{20};
    const int last_assumed_valid_idx{111};
    const int assumed_valid_start_idx = last_assumed_valid_idx - expected_assumed_valid;

    // Mine to height 120, past the hardcoded regtest assumeutxo snapshot at
    // height 110
    mineBlocks(20);

    CBlockIndex* validated_tip{nullptr};
    CBlockIndex* assumed_base{nullptr};
    CBlockIndex* assumed_tip{WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChain().Tip())};
    BOOST_CHECK_EQUAL(assumed_tip->nHeight, 120);

    auto reload_all_block_indexes = [&]() {
        LOCK(chainman.GetMutex());
        // For completeness, we also reset the block sequence counters to
        // ensure that no state which affects the ranking of tip-candidates is
        // retained (even though this isn't strictly necessary).
        chainman.ResetBlockSequenceCounters();
        cs1.ClearBlockIndexCandidates();
        BOOST_CHECK(cs1.setBlockIndexCandidates.empty());
        chainman.LoadBlockIndex();
        cs1.PopulateBlockIndexCandidates();
    };

    // Ensure that without any assumed-valid BlockIndex entries, only the current tip is
    // considered as a candidate.
    reload_all_block_indexes();
    BOOST_CHECK_EQUAL(cs1.setBlockIndexCandidates.size(), 1);

    // Reset some region of the chain's nStatus, removing the HAVE_DATA flag.
    for (int i = 0; i <= cs1.m_chain.Height(); ++i) {
        LOCK(::cs_main);
        auto index = cs1.m_chain[i];

        // Blocks with heights in range [91, 110] are marked as missing data.
        if (i < last_assumed_valid_idx && i >= assumed_valid_start_idx) {
            index->nStatus = BlockStatus::BLOCK_VALID_TREE;
            index->nTx = 0;
            index->m_chain_tx_count = 0;
        }

        ++num_indexes;

        // Note the last fully-validated block.
        if (i == (assumed_valid_start_idx - 1)) {
            validated_tip = index;
        }
        // Note the last assumed valid block as the snapshot base
        if (i == last_assumed_valid_idx - 1) {
            assumed_base = index;
        }
    }

    // Base the chainstate on a snapshot at the assume-valid block.
    {
        LOCK(::cs_main);
        cs1.m_from_snapshot_blockhash = assumed_base->GetBlockHash();
        cs1.m_assumeutxo = Assumeutxo::UNVALIDATED;
        cs1.m_chain.SetTip(*assumed_base);
    }

    // Sanity check test variables.
    BOOST_CHECK_EQUAL(num_indexes, 121); // 121 total blocks, including genesis
    BOOST_CHECK_EQUAL(assumed_tip->nHeight, 120);  // original chain has height 120
    BOOST_CHECK_EQUAL(validated_tip->nHeight, 90); // last block with data before the snapshot base
    BOOST_CHECK_EQUAL(assumed_base->nHeight, 110); // current chain has height 110

    // Regenerate cs1.setBlockIndexCandidates and check contents below.
    reload_all_block_indexes();

    // The assumed-valid tolerant chain has the assumed valid base as a
    // candidate, but otherwise has none of the assumed-valid (which do not
    // HAVE_DATA) blocks as candidates.
    //
    // Specifically:
    // - All blocks below height 110 are not candidates, because the chain tip
    //   has height 110 and they have less work than it does.
    //
    // - Block 110 is a candidate even though it does not have data, because it
    //   is the snapshot block, which is assumed valid.
    //
    // - Blocks 111-120 are added because they have data.

    // Check that block 90 is absent
    BOOST_CHECK_EQUAL(cs1.setBlockIndexCandidates.count(validated_tip), 0);
    // Check that block 109 is absent
    BOOST_CHECK_EQUAL(cs1.setBlockIndexCandidates.count(assumed_base->pprev), 0);
    // Check that block 110 is present
    BOOST_CHECK_EQUAL(cs1.setBlockIndexCandidates.count(assumed_base), 1);
    // Check that block 120 is present
    BOOST_CHECK_EQUAL(cs1.setBlockIndexCandidates.count(assumed_tip), 1);
    // Check that 11 blocks total are present.
    BOOST_CHECK_EQUAL(cs1.setBlockIndexCandidates.size(), num_indexes - last_assumed_valid_idx + 1);
}

BOOST_FIXTURE_TEST_CASE(loadblockindex_invalid_descendants, TestChain100Setup)
{
    LOCK(Assert(m_node.chainman)->GetMutex());
    // consider the chain of blocks grand_parent <- parent <- child
    // intentionally mark:
    //   - grand_parent: BLOCK_FAILED_VALID
    //   - parent: BLOCK_FAILED_CHILD
    //   - child: not invalid
    // Test that when the block index is loaded, all blocks are marked as BLOCK_FAILED_VALID
    auto* child{m_node.chainman->ActiveChain().Tip()};
    auto* parent{child->pprev};
    auto* grand_parent{parent->pprev};
    grand_parent->nStatus = (grand_parent->nStatus | BLOCK_FAILED_VALID);
    parent->nStatus = (parent->nStatus & ~BLOCK_FAILED_VALID) | BLOCK_FAILED_CHILD;
    child->nStatus = (child->nStatus & ~BLOCK_FAILED_VALID);

    // Reload block index to recompute block status validity flags.
    m_node.chainman->LoadBlockIndex();

    // check grand_parent, parent, child is marked as BLOCK_FAILED_VALID after reloading the block index
    BOOST_CHECK(grand_parent->nStatus & BLOCK_FAILED_VALID);
    BOOST_CHECK(parent->nStatus & BLOCK_FAILED_VALID);
    BOOST_CHECK(child->nStatus & BLOCK_FAILED_VALID);
}

//! Verify that ReconsiderBlock clears failure flags for the target block, its ancestors, and descendants,
//! but not for sibling forks that diverge from a shared ancestor.
BOOST_FIXTURE_TEST_CASE(invalidate_block_and_reconsider_fork, TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();

    // we have a chain of 100 blocks: genesis(0) <- ... <- block98 <- block99 <- block100
    CBlockIndex* block98;
    CBlockIndex* block99;
    CBlockIndex* block100;
    {
        LOCK(chainman.GetMutex());
        block98 = chainman.ActiveChain()[98];
        block99 = chainman.ActiveChain()[99];
        block100 = chainman.ActiveChain()[100];
    }

    // create the following block constellation:
    // genesis(0) <- ... <- block98 <- block99  <- block100
    //                              <- block99' <- block100'
    // by temporarily invalidating block99. the chain tip now falls to block98,
    // mine 2 new blocks on top of block 98 (block99' and block100') and then restore block99 and block 100.
    BlockValidationState state;
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, block99));
    BOOST_REQUIRE(WITH_LOCK(cs_main, return chainman.ActiveChain().Tip()) == block98);
    CScript coinbase_script = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    for (int i = 0; i < 2; ++i) {
        CreateAndProcessBlock({}, coinbase_script);
    }
    const CBlockIndex* fork_block99;
    const CBlockIndex* fork_block100;
    {
        LOCK(chainman.GetMutex());
        fork_block99 = chainman.ActiveChain()[99];
        BOOST_REQUIRE(fork_block99->pprev == block98);
        fork_block100 = chainman.ActiveChain()[100];
        BOOST_REQUIRE(fork_block100->pprev == fork_block99);
    }
    // Restore original block99 and block100
    {
        LOCK(chainman.GetMutex());
        chainstate.ResetBlockFailureFlags(block99);
        chainman.RecalculateBestHeader();
    }
    chainstate.ActivateBestChain(state);
    BOOST_REQUIRE(WITH_LOCK(cs_main, return chainman.ActiveChain().Tip()) == block100);

    {
        LOCK(chainman.GetMutex());
        BOOST_CHECK(!(block100->nStatus & BLOCK_FAILED_VALID));
        BOOST_CHECK(!(block99->nStatus & BLOCK_FAILED_VALID));
        BOOST_CHECK(!(fork_block100->nStatus & BLOCK_FAILED_VALID));
        BOOST_CHECK(!(fork_block99->nStatus & BLOCK_FAILED_VALID));
    }

    // Invalidate block98
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, block98));

    {
        LOCK(chainman.GetMutex());
        // block98 and all descendants of block98 are marked BLOCK_FAILED_VALID
        BOOST_CHECK(block98->nStatus & BLOCK_FAILED_VALID);
        BOOST_CHECK(block99->nStatus & BLOCK_FAILED_VALID);
        BOOST_CHECK(block100->nStatus & BLOCK_FAILED_VALID);
        BOOST_CHECK(fork_block99->nStatus & BLOCK_FAILED_VALID);
        BOOST_CHECK(fork_block100->nStatus & BLOCK_FAILED_VALID);
    }

    // Reconsider block99. ResetBlockFailureFlags clears BLOCK_FAILED_VALID from
    // block99 and its ancestors (block98) and descendants (block100)
    // but NOT from block99' and block100' (not a direct ancestor/descendant)
    {
        LOCK(chainman.GetMutex());
        chainstate.ResetBlockFailureFlags(block99);
        chainman.RecalculateBestHeader();
    }
    chainstate.ActivateBestChain(state);
    {
        LOCK(chainman.GetMutex());
        BOOST_CHECK(!(block98->nStatus & BLOCK_FAILED_VALID));
        BOOST_CHECK(!(block99->nStatus & BLOCK_FAILED_VALID));
        BOOST_CHECK(!(block100->nStatus & BLOCK_FAILED_VALID));
        BOOST_CHECK(fork_block99->nStatus & BLOCK_FAILED_VALID);
        BOOST_CHECK(fork_block100->nStatus & BLOCK_FAILED_VALID);
    }
}

//! Ensure that a chainstate based on a snapshot can be loaded after a restart,
//! and that the snapshot is validated by replaying the blocks leading up to its
//! base, resuming where the replay left off before the restart.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_snapshot_init, SnapshotTestSetup)
{
    using Step = ChainstateManager::HistoricalStep;
    ChainstateManager& chainman = *Assert(m_node.chainman);

    // Get to a valid assumeutxo tip (per chainparams) and keep the blocks up to
    // it, which are treated as not downloaded yet when loading the snapshot.
    mineBlocks(10);
    std::vector<std::shared_ptr<CBlock>> blocks;
    {
        LOCK(::cs_main);
        for (int height{1}; height <= chainman.ActiveHeight(); ++height) {
            auto block{std::make_shared<CBlock>()};
            BOOST_REQUIRE(chainman.m_blockman.ReadBlock(*block, *chainman.ActiveChain()[height]));
            blocks.push_back(std::move(block));
        }
    }
    BOOST_REQUIRE(CreateAndActivateUTXOSnapshot(this, NoMalleation, /*reset_chainstate=*/true));
    const uint256 snapshot_blockhash{*Assert(WITH_LOCK(::cs_main, return chainman.CurrentChainstate().m_from_snapshot_blockhash))};

    BOOST_CHECK_EQUAL(WITH_LOCK(::cs_main, return chainman.GetHistoricalBlockRange()->first->nHeight), 0);
    BOOST_CHECK(chainman.AdvanceHistoricalChain() == Step::WAITING);

    // Receive part of the blocks and validate them in the background.
    const auto process_blocks{[&](ChainstateManager& cm, size_t begin, size_t end) {
        for (size_t i{begin}; i < end; ++i) {
            BOOST_REQUIRE(cm.ProcessNewBlock(blocks[i], /*force_processing=*/true, /*min_pow_checked=*/true, /*new_block=*/nullptr));
        }
    }};
    process_blocks(chainman, 0, 50);
    Step step;
    while ((step = chainman.AdvanceHistoricalChain()) == Step::PROGRESS) {}
    BOOST_CHECK(step == Step::WAITING);
    BOOST_CHECK_EQUAL(WITH_LOCK(::cs_main, return chainman.GetHistoricalBlockRange()->first->nHeight), 50);

    // Test that simulating a shutdown (resetting ChainstateManager) and then
    // performing chainstate reinitializing successfully reloads the snapshot
    // chainstate and the coins validating it.
    ChainstateManager& chainman_restarted = this->SimulateNodeRestart();

    BOOST_TEST_MESSAGE("Performing Load/Verify/Activate of chainstate");

    // This call reinitializes the chainstate.
    this->LoadVerifyActivateChainstate();

    {
        LOCK(chainman_restarted.GetMutex());
        BOOST_CHECK_EQUAL(chainman_restarted.m_chainstates.size(), 1);
        BOOST_CHECK_EQUAL(*chainman_restarted.CurrentChainstate().m_from_snapshot_blockhash, snapshot_blockhash);
        BOOST_CHECK(chainman_restarted.CurrentChainstate().m_assumeutxo == Assumeutxo::UNVALIDATED);
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveTip()->GetBlockHash(), snapshot_blockhash);
        BOOST_CHECK_EQUAL(chainman_restarted.GetHistoricalBlockRange()->first->nHeight, 50);
    }

    BOOST_TEST_MESSAGE(
        "Ensure we can mine blocks on top of the initialized snapshot chainstate");
    mineBlocks(10);
    BOOST_CHECK_EQUAL(WITH_LOCK(chainman_restarted.GetMutex(), return chainman_restarted.ActiveHeight()), 120);
    BOOST_CHECK_EQUAL(WITH_LOCK(chainman_restarted.GetMutex(), return chainman_restarted.GetHistoricalBlockRange()->first->nHeight), 50);

    // Validating the remaining blocks completes the replay.
    process_blocks(chainman_restarted, 50, blocks.size());
    while ((step = chainman_restarted.AdvanceHistoricalChain()) == Step::PROGRESS) {}
    BOOST_CHECK(step == Step::AT_TARGET);
    BOOST_CHECK_EQUAL(chainman_restarted.ValidateSnapshot(), SnapshotCompletionResult::SUCCESS);
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman_restarted.CurrentChainstate().m_assumeutxo == Assumeutxo::VALIDATED));
    BOOST_CHECK_EQUAL(WITH_LOCK(chainman_restarted.GetMutex(), return chainman_restarted.ActiveHeight()), 120);
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_snapshot_completion, SnapshotTestSetup)
{
    this->SetupSnapshot();

    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& active_cs = chainman.ActiveChainstate();
    auto tip_cache_before_complete = active_cs.m_coinstip_cache_size_bytes;
    auto db_cache_before_complete = active_cs.m_coinsdb_cache_size_bytes;

    m_node.notifications->m_shutdown_on_fatal_error = false;

    const fs::path datadir{gArgs.GetDataDirNet()};
    BOOST_CHECK(fs::exists(datadir / "chainstate_verify"));
    BOOST_CHECK(fs::exists(datadir / "chainstate" / node::UNVALIDATED_SNAPSHOT_BLOCKHASH_FILENAME));

    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.CurrentChainstate().m_from_snapshot_blockhash));
    BOOST_CHECK_EQUAL(WITH_LOCK(::cs_main, return chainman.AssumedValidBase()), WITH_LOCK(::cs_main, return active_cs.SnapshotBase()));
    BOOST_CHECK(m_node.chain->hasAssumedValidChain());
    const uint256 snapshot_tip_hash = WITH_LOCK(chainman.GetMutex(),
        return chainman.ActiveTip()->GetBlockHash());

    // The coins validating the snapshot are at its base already.
    BOOST_CHECK(chainman.AdvanceHistoricalChain() == ChainstateManager::HistoricalStep::AT_TARGET);
    BOOST_CHECK_EQUAL(chainman.ValidateSnapshot(), SnapshotCompletionResult::SUCCESS);

    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.CurrentChainstate().m_assumeutxo == Assumeutxo::VALIDATED));
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.CurrentChainstate().m_from_snapshot_blockhash));
    BOOST_CHECK(!WITH_LOCK(::cs_main, return chainman.AssumedValidBase()));
    BOOST_CHECK(!m_node.chain->hasAssumedValidChain());
    BOOST_CHECK(!WITH_LOCK(::cs_main, return chainman.GetHistoricalBlockRange()));
    BOOST_CHECK(!WITH_LOCK(::cs_main, return chainman.HistoricalCoinsCacheSizes()));

    // Cache should have been rebalanced and reallocated to the only chainstate.
    BOOST_CHECK(active_cs.m_coinstip_cache_size_bytes > tip_cache_before_complete);
    BOOST_CHECK(active_cs.m_coinsdb_cache_size_bytes > db_cache_before_complete);

    // Trying completion again should be skipped.
    BOOST_CHECK_EQUAL(chainman.ValidateSnapshot(), SnapshotCompletionResult::SKIPPED);
    BOOST_CHECK(chainman.AdvanceHistoricalChain() == ChainstateManager::HistoricalStep::DONE);

    // Everything was cleaned up without a restart, and the invalid snapshot
    // paths were not used.
    BOOST_CHECK(!fs::exists(datadir / "chainstate_verify"));
    BOOST_CHECK(!fs::exists(datadir / "chainstate" / node::UNVALIDATED_SNAPSHOT_BLOCKHASH_FILENAME));
    BOOST_CHECK(!fs::exists(datadir / "chainstate_snapshot"));
    BOOST_CHECK(!fs::exists(datadir / "chainstate_snapshot_INVALID"));
    BOOST_CHECK(!fs::exists(datadir / "chainstate_fallback"));

    // Test that simulating a shutdown (resetting ChainstateManager) and then performing
    // chainstate reinitializing results in a single chainstate that is at tip.
    ChainstateManager& chainman_restarted = this->SimulateNodeRestart();

    BOOST_TEST_MESSAGE("Performing Load/Verify/Activate of chainstate");
    this->LoadVerifyActivateChainstate();

    const Chainstate& active_cs2 = chainman_restarted.ActiveChainstate();

    {
        LOCK(chainman_restarted.GetMutex());
        BOOST_CHECK_EQUAL(chainman_restarted.m_chainstates.size(), 1);
        BOOST_CHECK(!chainman_restarted.CurrentChainstate().m_from_snapshot_blockhash);
        BOOST_CHECK(active_cs2.m_coinstip_cache_size_bytes > tip_cache_before_complete);
        BOOST_CHECK(active_cs2.m_coinsdb_cache_size_bytes > db_cache_before_complete);

        BOOST_CHECK_EQUAL(chainman_restarted.ActiveTip()->GetBlockHash(), snapshot_tip_hash);
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveHeight(), 210);
    }

    BOOST_TEST_MESSAGE(
        "Ensure we can mine blocks on top of the \"new\" IBD chainstate");
    mineBlocks(10);
    {
        LOCK(chainman_restarted.GetMutex());
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveHeight(), 220);
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_snapshot_completion_hash_mismatch, SnapshotTestSetup)
{
    this->SetupSnapshot();
    ChainstateManager& chainman = *Assert(m_node.chainman);
    m_node.notifications->m_shutdown_on_fatal_error = false;

    // Test tampering with the coins validating the snapshot with an extra coin
    // to ensure it causes snapshot completion to fail.
    {
        LOCK(::cs_main);
        CCoinsViewCache& historical_coins{static_cast<TestChainstateManager&>(chainman).HistoricalCoinsTip()};
        Coin badcoin;
        badcoin.out.nValue = m_rng.rand32();
        badcoin.nHeight = 1;
        badcoin.out.scriptPubKey.assign(m_rng.randbits(6), 0);
        Txid txid = Txid::FromUint256(m_rng.rand256());
        historical_coins.AddCoin(COutPoint(txid, 0), std::move(badcoin), false);
    }

    const fs::path datadir{gArgs.GetDataDirNet()};
    {
        ASSERT_DEBUG_LOG("failed to validate the -assumeutxo snapshot state");
        BOOST_CHECK_EQUAL(chainman.ValidateSnapshot(), SnapshotCompletionResult::HASH_MISMATCH);
    }

    {
        LOCK(chainman.GetMutex());
        BOOST_CHECK_EQUAL(chainman.m_chainstates.size(), 1);
        BOOST_CHECK(chainman.CurrentChainstate().m_assumeutxo == Assumeutxo::INVALID);
        BOOST_CHECK(chainman.CurrentChainstate().SnapshotBase());
        BOOST_CHECK(!chainman.AssumedValidBase());
        BOOST_CHECK(!chainman.GetHistoricalBlockRange());
    }

    // The coins that were validating the snapshot replace the chainstate on
    // the next startup.
    BOOST_CHECK(fs::exists(datadir / "chainstate_fallback"));
    BOOST_CHECK(!fs::exists(datadir / "chainstate_verify"));

    // Test that simulating a shutdown (resetting ChainstateManager) and then performing
    // chainstate reinitializing successfully loads only the fully-validated
    // chainstate data, and we end up with a single chainstate that is at tip.
    ChainstateManager& chainman_restarted = this->SimulateNodeRestart();

    BOOST_TEST_MESSAGE("Performing Load/Verify/Activate of chainstate");
    this->LoadVerifyActivateChainstate();

    // The invalid snapshot chainstate is kept for diagnosis.
    BOOST_CHECK(fs::exists(datadir / "chainstate_snapshot_INVALID" / node::UNVALIDATED_SNAPSHOT_BLOCKHASH_FILENAME));
    BOOST_CHECK(!fs::exists(datadir / "chainstate_fallback"));
    BOOST_CHECK(!fs::exists(datadir / "chainstate" / node::UNVALIDATED_SNAPSHOT_BLOCKHASH_FILENAME));

    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainman_restarted.m_chainstates.size(), 1);
        BOOST_CHECK(!chainman_restarted.CurrentChainstate().m_from_snapshot_blockhash);
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveHeight(), 210);
    }

    BOOST_TEST_MESSAGE(
        "Ensure we can mine blocks on top of the \"new\" IBD chainstate");
    mineBlocks(10);
    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveHeight(), 220);
    }
}

//! Test that interrupted activation or validation of a snapshot is completed on
//! startup, and that the chainstate directories of older versions, which kept a
//! separate chainstate to validate the snapshot, are converted.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_snapshot_dir_recovery, SnapshotTestSetup)
{
    this->SetupSnapshot();
    const uint256 snapshot_blockhash{*Assert(WITH_LOCK(::cs_main, return m_node.chainman->CurrentChainstate().m_from_snapshot_blockhash))};

    const fs::path datadir{gArgs.GetDataDirNet()};
    const fs::path chainstate_dir{datadir / "chainstate"};
    const fs::path snapshot_dir{datadir / "chainstate_snapshot"};
    const fs::path historical_dir{datadir / "chainstate_verify"};

    const auto restart{[&](const std::function<void()>& change_dirs) -> ChainstateManager& {
        ChainstateManager& chainman_restarted{this->SimulateNodeRestart()};
        change_dirs();
        this->LoadVerifyActivateChainstate();
        return chainman_restarted;
    }};
    const auto check_snapshot_loaded{[&](ChainstateManager& chainman) {
        BOOST_CHECK(fs::exists(chainstate_dir / node::UNVALIDATED_SNAPSHOT_BLOCKHASH_FILENAME));
        BOOST_CHECK(fs::exists(historical_dir));
        BOOST_CHECK(!fs::exists(snapshot_dir));
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainman.m_chainstates.size(), 1);
        BOOST_CHECK_EQUAL(*chainman.CurrentChainstate().m_from_snapshot_blockhash, snapshot_blockhash);
        BOOST_CHECK_EQUAL(chainman.ActiveHeight(), 210);
        BOOST_CHECK_EQUAL(chainman.GetHistoricalBlockRange()->first->nHeight, 110);
    }};

    BOOST_TEST_MESSAGE("Convert the directories of older versions");
    check_snapshot_loaded(restart([&] {
        fs::rename(chainstate_dir, snapshot_dir);
        fs::rename(historical_dir, chainstate_dir);
        fs::rename(snapshot_dir / node::UNVALIDATED_SNAPSHOT_BLOCKHASH_FILENAME, snapshot_dir / node::SNAPSHOT_BLOCKHASH_FILENAME);
    }));

    BOOST_TEST_MESSAGE("Complete an activation that was interrupted between moving the directories");
    check_snapshot_loaded(restart([&] {
        fs::rename(chainstate_dir, snapshot_dir);
    }));

    BOOST_TEST_MESSAGE("Remove an incompletely loaded snapshot");
    check_snapshot_loaded(restart([&] {
        fs::create_directories(snapshot_dir);
    }));

    BOOST_TEST_MESSAGE("Remove the coins of a validated snapshot that were not removed yet");
    ChainstateManager& chainman_restarted{restart([&] {
        fs::remove(chainstate_dir / node::UNVALIDATED_SNAPSHOT_BLOCKHASH_FILENAME);
    })};
    BOOST_CHECK(!fs::exists(historical_dir));
    // The file older versions left behind after validating a snapshot does
    // not make the chainstate unvalidated.
    BOOST_CHECK(fs::exists(chainstate_dir / node::SNAPSHOT_BLOCKHASH_FILENAME));
    {
        LOCK(::cs_main);
        BOOST_CHECK(!chainman_restarted.CurrentChainstate().m_from_snapshot_blockhash);
        BOOST_CHECK(!chainman_restarted.GetHistoricalBlockRange());
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveHeight(), 210);
    }
}

/** Helper function to parse args into args_man and return the result of applying them to opts */
template <typename Options>
util::Result<Options> SetOptsFromArgs(ArgsManager& args_man, Options opts,
                                      const std::vector<const char*>& args)
{
    const auto argv{Cat({"ignore"}, args)};
    std::string error{};
    if (!args_man.ParseParameters(argv.size(), argv.data(), error)) {
        return util::Error{Untranslated("ParseParameters failed with error: " + error)};
    }
    const auto result{node::ApplyArgsManOptions(args_man, opts)};
    if (!result) return util::Error{util::ErrorString(result)};
    return opts;
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_args, BasicTestingSetup)
{
    //! Try to apply the provided args to a ChainstateManager::Options
    auto get_opts = [&](const std::vector<const char*>& args) {
        static kernel::Notifications notifications{};
        static const ChainstateManager::Options options{
            .chainparams = ::Params(),
            .datadir = {},
            .notifications = notifications};
        return SetOptsFromArgs(*this->m_node.args, options, args);
    };
    //! Like get_opts, but requires the provided args to be valid and unwraps the result
    auto get_valid_opts = [&](const std::vector<const char*>& args) {
        const auto result{get_opts(args)};
        BOOST_REQUIRE_MESSAGE(result, util::ErrorString(result).original);
        return *result;
    };

    // test -assumevalid
    BOOST_CHECK(!get_valid_opts({}).assumed_valid_block);
    BOOST_CHECK_EQUAL(get_valid_opts({"-assumevalid="}).assumed_valid_block, uint256::ZERO);
    BOOST_CHECK_EQUAL(get_valid_opts({"-assumevalid=0"}).assumed_valid_block, uint256::ZERO);
    BOOST_CHECK_EQUAL(get_valid_opts({"-noassumevalid"}).assumed_valid_block, uint256::ZERO);
    BOOST_CHECK_EQUAL(get_valid_opts({"-assumevalid=0x12"}).assumed_valid_block, uint256{0x12});

    std::string assume_valid{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"};
    BOOST_CHECK_EQUAL(get_valid_opts({("-assumevalid=" + assume_valid).c_str()}).assumed_valid_block, uint256::FromHex(assume_valid));

    BOOST_CHECK(!get_opts({"-assumevalid=xyz"}));                                                               // invalid hex characters
    BOOST_CHECK(!get_opts({"-assumevalid=01234567890123456789012345678901234567890123456789012345678901234"})); // > 64 hex chars

    // test -minimumchainwork
    BOOST_CHECK(!get_valid_opts({}).minimum_chain_work);
    BOOST_CHECK_EQUAL(get_valid_opts({"-minimumchainwork=0"}).minimum_chain_work, arith_uint256());
    BOOST_CHECK_EQUAL(get_valid_opts({"-nominimumchainwork"}).minimum_chain_work, arith_uint256());
    BOOST_CHECK_EQUAL(get_valid_opts({"-minimumchainwork=0x1234"}).minimum_chain_work, arith_uint256{0x1234});

    std::string minimum_chainwork{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"};
    BOOST_CHECK_EQUAL(get_valid_opts({("-minimumchainwork=" + minimum_chainwork).c_str()}).minimum_chain_work, UintToArith256(uint256::FromHex(minimum_chainwork).value()));

    BOOST_CHECK(!get_opts({"-minimumchainwork=xyz"}));                                                               // invalid hex characters
    BOOST_CHECK(!get_opts({"-minimumchainwork=01234567890123456789012345678901234567890123456789012345678901234"})); // > 64 hex chars

    BOOST_CHECK_EQUAL(get_valid_opts({}).prevoutfetch_threads_num, DEFAULT_PREVOUTFETCH_THREADS);
    BOOST_CHECK_EQUAL(get_valid_opts({"-prevoutfetchthreads=0"}).prevoutfetch_threads_num, 0);
    BOOST_CHECK_EQUAL(get_valid_opts({"-prevoutfetchthreads=3"}).prevoutfetch_threads_num, 3);
    BOOST_CHECK_EQUAL(get_valid_opts({"-prevoutfetchthreads=100"}).prevoutfetch_threads_num, MAX_PREVOUTFETCH_THREADS);
    BOOST_CHECK(!get_opts({"-prevoutfetchthreads=-1"}));
}

BOOST_AUTO_TEST_SUITE_END()
