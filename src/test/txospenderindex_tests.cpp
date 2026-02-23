// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <index/txospenderindex.h>
#include <test/util/setup_common.h>
#include <util/time.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(txospenderindex_tests)

BOOST_FIXTURE_TEST_CASE(txospenderindex_initial_sync, TestChain100Setup)
{
    TxoSpenderIndex txospenderindex(interfaces::MakeChain(m_node), 1 << 20, true);
    BOOST_REQUIRE(txospenderindex.Init());

    // Mine blocks for coinbase maturity, so we can spend some coinbase outputs in the test.
    for (int i = 0; i < 50; i++) {
        std::vector<CMutableTransaction> no_txns;
        CreateAndProcessBlock(no_txns, this->m_coinbase_txns[i]->vout[0].scriptPubKey);
    }
    std::vector<COutPoint> spent(10);
    std::vector<CMutableTransaction> spender(spent.size());

    for (size_t i = 0; i < spent.size(); i++) {
        spent[i] = COutPoint(this->m_coinbase_txns[i]->GetHash(), 0);
        spender[i].version = 1;
        spender[i].vin.resize(1);
        spender[i].vin[0].prevout.hash = spent[i].hash;
        spender[i].vin[0].prevout.n = spent[i].n;
        spender[i].vout.resize(1);
        spender[i].vout[0].nValue = this->m_coinbase_txns[i]->GetValueOut();
        spender[i].vout[0].scriptPubKey = this->m_coinbase_txns[i]->vout[0].scriptPubKey;

        // Sign:
        std::vector<unsigned char> vchSig;
        const uint256 hash = SignatureHash(this->m_coinbase_txns[i]->vout[0].scriptPubKey, spender[i], 0, SIGHASH_ALL, 0, SigVersion::BASE);
        coinbaseKey.Sign(hash, vchSig);
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        spender[i].vin[0].scriptSig << vchSig;
    }

    CBlock block = CreateAndProcessBlock(spender, this->m_coinbase_txns[0]->vout[0].scriptPubKey);

    // Transaction should not be found in the index before it is started.
    for (const auto& outpoint : spent) {
        BOOST_CHECK(!txospenderindex.FindSpender(outpoint).value());
    }

    // BlockUntilSyncedToCurrentChain should return false before txospenderindex is started.
    BOOST_CHECK(!txospenderindex.BlockUntilSyncedToCurrentChain());

    txospenderindex.Sync();
    for (size_t i = 0; i < spent.size(); i++) {
        auto tx_spender = txospenderindex.FindSpender(spent[i]);
        if (!tx_spender->has_value()) {
            std::string hash_hex = spent[i].hash.GetHex();
            int height = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
            std::string tip_hash = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip()->GetBlockHash().GetHex());
            fprintf(stderr, "FindSpender returned nullopt for spent[%zu]: %s:%d\n",
                    i, hash_hex.c_str(), spent[i].n);
            fprintf(stderr, "Index synced=%d, best_height=%d, best_hash=%s\n",
                    txospenderindex.BlockUntilSyncedToCurrentChain(),
                    height, tip_hash.c_str());
            // Try calling FindSpender again to see if result changes
            auto tx_spender_retry = txospenderindex.FindSpender(spent[i]);
            fprintf(stderr, "Retry result: has_value=%d\n",
                    tx_spender_retry->has_value() ? 1 : 0);
            fflush(stderr);
        }
        BOOST_CHECK(tx_spender->has_value());
    }

    for (size_t i = 0; i < spent.size(); i++) {
        const auto tx_spender{txospenderindex.FindSpender(spent[i])};
        if (!tx_spender->has_value()) {
            BOOST_TEST_MESSAGE(strprintf("FindSpender returned nullopt for spent[%d]: %s:%d",
                                         i, spent[i].hash.GetHex(), spent[i].n));
            // Dump index summary to see if Sync() actually completed
            auto summary = txospenderindex.GetSummary();
            BOOST_TEST_MESSAGE(strprintf("Index synced=%d, best_height=%d, best_hash=%s",
                                         summary.synced, summary.best_block_height,
                                         summary.best_block_hash.GetHex()));
        }

        BOOST_REQUIRE(tx_spender.has_value());
        BOOST_REQUIRE(tx_spender->has_value());
        BOOST_CHECK_EQUAL((*tx_spender)->tx->GetHash(), spender[i].GetHash());
        BOOST_CHECK_EQUAL((*tx_spender)->block_hash, block.GetHash());
    }

    // It is not safe to stop and destroy the index until it finishes handling
    // the last BlockConnected notification. The BlockUntilSyncedToCurrentChain()
    // call above is sufficient to ensure this, but the
    // SyncWithValidationInterfaceQueue() call below is also needed to ensure
    // TSAN always sees the test thread waiting for the notification thread, and
    // avoid potential false positive reports.
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    // shutdown sequence (c.f. Shutdown() in init.cpp)
    txospenderindex.Stop();
}

BOOST_AUTO_TEST_SUITE_END()
