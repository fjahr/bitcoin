// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <index/utxosethash.h>
#include <test/setup_common.h>
#include <validation.h>
//
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(utxosethash_tests)

BOOST_FIXTURE_TEST_CASE(utxosethash_initial_sync, TestChain100Setup)
{
    UtxoSetHash utxo_set_hash(0, false);

    uint256 hash_digest;
    CBlockIndex* block_index = ::ChainActive().Tip();

    // UTXO set hash should not be found before it is started.
    BOOST_CHECK(!utxo_set_hash.LookupHash(block_index, hash_digest));

    // BlockUntilSyncedToCurrentChain should return false before utxo_set_hash is started.
    BOOST_CHECK(!utxo_set_hash.BlockUntilSyncedToCurrentChain());

    utxo_set_hash.Start();

    // Allow the UTXO set hash to catch up with the block index.
    constexpr int64_t timeout_ms = 10 * 1000;
    int64_t time_start = GetTimeMillis();
    while (!utxo_set_hash.BlockUntilSyncedToCurrentChain()) {
        BOOST_REQUIRE(time_start + timeout_ms > GetTimeMillis());
        MilliSleep(100);
    }

    // Check that UTXO set hash works for genesis block.
    CBlockIndex* genesis_block_index = ::ChainActive().Genesis();
    BOOST_CHECK(utxo_set_hash.LookupHash(genesis_block_index, hash_digest));

    // Check that UTXO set hash updates with new blocks.
    block_index = ::ChainActive().Tip();
    utxo_set_hash.LookupHash(block_index, hash_digest);

    CScript scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    std::vector<CMutableTransaction> noTxns;
    CreateAndProcessBlock(noTxns, scriptPubKey);

    time_start = GetTimeMillis();
    while (!utxo_set_hash.BlockUntilSyncedToCurrentChain()) {
        BOOST_REQUIRE(time_start + timeout_ms > GetTimeMillis());
        MilliSleep(100);
    }

    uint256 new_hash_digest;
    CBlockIndex* new_block_index = ::ChainActive().Tip();
    utxo_set_hash.LookupHash(new_block_index, new_hash_digest);

    BOOST_CHECK(block_index != new_block_index);
    BOOST_CHECK(hash_digest != new_hash_digest);

    // shutdown sequence (c.f. Shutdown() in init.cpp)
    utxo_set_hash.Stop();

    threadGroup.interrupt_all();
    threadGroup.join_all();

    // Rest of shutdown sequence and destructors happen in ~TestingSetup()
}

BOOST_AUTO_TEST_SUITE_END()
