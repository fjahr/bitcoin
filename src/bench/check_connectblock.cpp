// Copyright (c) 2016-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>

#include <addresstype.h>
#include <interfaces/chain.h>
#include <kernel/cs_main.h>
#include <script/interpreter.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <cassert>
#include <utility>
#include <vector>

CBlock CreateTestBlock(TestChain100Setup* test_setup, std::vector<CKey>& keys, std::vector<CScript>& scriptpubkeys)
{
    Chainstate& chainstate{test_setup->m_node.chainman->ActiveChainstate()};

    const int num_txs = 500;

    std::vector<CMutableTransaction> txs;
    txs.reserve(num_txs);

    auto input_tx{test_setup->m_coinbase_txns[0]};

    std::vector<COutPoint> inputs{COutPoint(input_tx->GetHash(), 0)};
    inputs.reserve(scriptpubkeys.size());

    std::vector<CTxOut> outputs;
    // Each transaction will create outputs for each scriptpubkey that are spent in the next transaction
    outputs.reserve(scriptpubkeys.size());

    for (int i{0}; i < num_txs; i++) {
        Txid txid = input_tx->GetHash();

        for (size_t j{0}; j < outputs.size(); j++) {
            inputs.emplace_back(txid, j);
        }

        outputs.clear();
        for (size_t j{0}; j < scriptpubkeys.size(); j++) {
            outputs.emplace_back(COIN, scriptpubkeys[j]);
        }
        const auto taproot_tx{test_setup->CreateValidTransaction(
            std::vector{input_tx}, inputs, chainstate.m_chain.Height() + 1, keys, outputs, std::nullopt, std::nullopt)};
        txs.push_back(taproot_tx.first);
        input_tx = MakeTransactionRef(taproot_tx.first);

        inputs.clear();
    }

    const WitnessV1Taproot taproot{XOnlyPubKey(test_setup->coinbaseKey.GetPubKey())};
    const CScript coinbase_spk{GetScriptForDestination(taproot)};
    return test_setup->CreateBlock(txs, coinbase_spk, chainstate);
}

static void ConnectBlockAllSchnorr(benchmark::Bench& bench)
{
    const auto test_setup{MakeNoLogFileContext<TestChain100Setup>()};

    size_t num_keys{4};
    std::vector<CKey> keys{test_setup->coinbaseKey};
    keys.reserve(num_keys + 1);

    std::vector<CScript> taproot_spks;
    taproot_spks.reserve(num_keys);

    for (size_t i{0}; i < num_keys; i++) {
        const CKey key{GenerateRandomKey()};
        keys.push_back(key);
        const CScript scriptpubkey{GetScriptForDestination(WitnessV1Taproot{XOnlyPubKey(key.GetPubKey())})};
        taproot_spks.push_back(scriptpubkey);
    }

    const auto test_block{CreateTestBlock(test_setup.get(), keys, taproot_spks)};
    auto pindex{std::make_unique<CBlockIndex>(test_block)};
    auto test_blockhash{std::make_unique<uint256>(test_block.GetHash())};

    Chainstate& chainstate{test_setup->m_node.chainman->ActiveChainstate()};

    pindex->nHeight = chainstate.m_chain.Height() + 1;
    pindex->phashBlock = test_blockhash.get();
    pindex->pprev = chainstate.m_chain.Tip();

    BlockValidationState test_block_state;
    bench.unit("block").run([&] {
        LOCK(cs_main);
        CCoinsViewCache viewNew{&chainstate.CoinsTip()};
        assert(chainstate.ConnectBlock(test_block, test_block_state, pindex.get(), viewNew, false));
    });
}

static void ConnectBlockMixed(benchmark::Bench& bench)
{
    const auto test_setup{MakeNoLogFileContext<TestChain100Setup>()};

    size_t num_taproot{2};
    size_t num_nontaproot{2};

    std::vector<CKey> keys{test_setup->coinbaseKey};
    keys.reserve(num_taproot + num_nontaproot + 1);

    std::vector<CScript> spks;
    spks.reserve(num_taproot + num_nontaproot);

    for (size_t i{0}; i < num_nontaproot; i++) {
        const CKey key{GenerateRandomKey()};
        keys.push_back(key);
        const CScript scriptpubkey{GetScriptForDestination(WitnessV0KeyHash{key.GetPubKey()})};
        spks.push_back(scriptpubkey);
    }

    for (size_t i{0}; i < num_taproot; i++) {
        const CKey key{GenerateRandomKey()};
        keys.push_back(key);
        const CScript scriptpubkey{GetScriptForDestination(WitnessV1Taproot{XOnlyPubKey(key.GetPubKey())})};
        spks.push_back(scriptpubkey);
    }

    const auto test_block{CreateTestBlock(test_setup.get(), keys, spks)};
    auto pindex{std::make_unique<CBlockIndex>(test_block)};
    auto test_blockhash{std::make_unique<uint256>(test_block.GetHash())};

    Chainstate& chainstate{test_setup->m_node.chainman->ActiveChainstate()};

    pindex->nHeight = chainstate.m_chain.Height() + 1;
    pindex->phashBlock = test_blockhash.get();
    pindex->pprev = chainstate.m_chain.Tip();

    BlockValidationState test_block_state;
    bench.unit("block").run([&] {
        LOCK(cs_main);
        CCoinsViewCache viewNew{&chainstate.CoinsTip()};
        assert(chainstate.ConnectBlock(test_block, test_block_state, pindex.get(), viewNew, false));
    });
}

static void ConnectBlockNoSchnorr(benchmark::Bench& bench)
{
    const auto test_setup{MakeNoLogFileContext<TestChain100Setup>()};

    size_t num_keys{4};
    std::vector<CKey> keys{test_setup->coinbaseKey};
    keys.reserve(num_keys + 1);

    std::vector<CScript> spks;
    spks.reserve(num_keys);

    for (size_t i{0}; i < num_keys; i++) {
        const CKey key{GenerateRandomKey()};
        keys.push_back(key);
        const CScript scriptpubkey{GetScriptForDestination(WitnessV0KeyHash{key.GetPubKey()})};
        spks.push_back(scriptpubkey);
    }

    const auto test_block{CreateTestBlock(test_setup.get(), keys, spks)};
    auto pindex{std::make_unique<CBlockIndex>(test_block)};
    auto test_blockhash{std::make_unique<uint256>(test_block.GetHash())};

    Chainstate& chainstate{test_setup->m_node.chainman->ActiveChainstate()};

    pindex->nHeight = chainstate.m_chain.Height() + 1;
    pindex->phashBlock = test_blockhash.get();
    pindex->pprev = chainstate.m_chain.Tip();

    BlockValidationState test_block_state;
    bench.unit("block").run([&] {
        LOCK(cs_main);
        CCoinsViewCache viewNew{&chainstate.CoinsTip()};
        assert(chainstate.ConnectBlock(test_block, test_block_state, pindex.get(), viewNew, false));
    });
}

BENCHMARK(ConnectBlockAllSchnorr, benchmark::PriorityLevel::HIGH);
BENCHMARK(ConnectBlockMixed, benchmark::PriorityLevel::HIGH);
BENCHMARK(ConnectBlockNoSchnorr, benchmark::PriorityLevel::HIGH);
