// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <index/coinstatsindex.h>
#include <test/util/setup_common.h>
#include <validation.h>
//
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(coinstatsindex_tests)

BOOST_FIXTURE_TEST_CASE(coinstatsindex_initial_sync, TestChain100Setup)
{
    CoinStatsIndex coin_stats_index(0, false);

    CCoinsStats coin_stats;
    CBlockIndex* block_index = ::ChainActive().Tip();

    // UTXO set hash should not be found before it is started.
    BOOST_CHECK(!coin_stats_index.LookupStats(block_index, coin_stats));

    // BlockUntilSyncedToCurrentChain should return false before utxo_set_hash is started.
    BOOST_CHECK(!coin_stats_index.BlockUntilSyncedToCurrentChain());

    coin_stats_index.Start();

    // Allow the UTXO set hash to catch up with the block index.
    constexpr int64_t timeout_ms = 10 * 1000;
    int64_t time_start = GetTimeMillis();
    while (!coin_stats_index.BlockUntilSyncedToCurrentChain()) {
        BOOST_REQUIRE(time_start + timeout_ms > GetTimeMillis());
        MilliSleep(100);
    }

    // Check that UTXO set hash works for genesis block.
    CBlockIndex* genesis_block_index = ::ChainActive().Genesis();
    BOOST_CHECK(coin_stats_index.LookupStats(genesis_block_index, coin_stats));

    // Check that UTXO set hash updates with new blocks.
    block_index = ::ChainActive().Tip();
    coin_stats_index.LookupStats(block_index, coin_stats);

    CScript scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    std::vector<CMutableTransaction> noTxns;
    CreateAndProcessBlock(noTxns, scriptPubKey);

    time_start = GetTimeMillis();
    while (!coin_stats_index.BlockUntilSyncedToCurrentChain()) {
        BOOST_REQUIRE(time_start + timeout_ms > GetTimeMillis());
        MilliSleep(100);
    }

    CCoinsStats new_coin_stats;
    CBlockIndex* new_block_index = ::ChainActive().Tip();
    coin_stats_index.LookupStats(new_block_index, new_coin_stats);

    BOOST_CHECK(block_index != new_block_index);
    BOOST_CHECK(coin_stats.hashSerialized != new_coin_stats.hashSerialized);

    // shutdown sequence (c.f. Shutdown() in init.cpp)
    coin_stats_index.Stop();

    threadGroup.interrupt_all();
    threadGroup.join_all();

    // Rest of shutdown sequence and destructors happen in ~TestingSetup()
}

BOOST_AUTO_TEST_SUITE_END()
