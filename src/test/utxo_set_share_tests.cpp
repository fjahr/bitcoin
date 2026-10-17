// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hash.h>
#include <kernel/chainparams.h>
#include <node/utxo_set_share.h>
#include <node/utxo_snapshot.h>
#include <primitives/transaction.h>
#include <streams.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/fs.h>

#include <cstdint>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(utxo_set_share_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(merkle_root)
{
    const node::UTXOSetChunk a{m_rng.rand256(), 51}, b{m_rng.rand256(), 100}, c{m_rng.rand256(), 200};
    const auto leaf = [](const node::UTXOSetChunk& chunk) {
        return (HashWriter{} << uint8_t{0} << chunk.size << chunk.hash).GetHash();
    };
    const auto parent = [](const uint256& left, const uint256& right) {
        return (HashWriter{} << uint8_t{1} << left << right).GetHash();
    };
    BOOST_CHECK(node::ComputeUTXOSetMerkleRoot({}).IsNull());
    BOOST_CHECK(node::ComputeUTXOSetMerkleRoot({a}) == leaf(a));
    BOOST_CHECK(node::ComputeUTXOSetMerkleRoot({a, b}) == parent(leaf(a), leaf(b)));
    // An odd node is promoted, not duplicated.
    const auto root{node::ComputeUTXOSetMerkleRoot({a, b, c})};
    BOOST_CHECK(root == parent(parent(leaf(a), leaf(b)), leaf(c)));
    BOOST_CHECK(root != node::ComputeUTXOSetMerkleRoot({a, b, c, c}));
    BOOST_CHECK(root != node::ComputeUTXOSetMerkleRoot({b, a, c}));
    auto changed{c};
    ++changed.size;
    BOOST_CHECK(root != node::ComputeUTXOSetMerkleRoot({a, b, changed}));
    changed = c;
    changed.hash = m_rng.rand256();
    BOOST_CHECK(root != node::ComputeUTXOSetMerkleRoot({a, b, changed}));
}

BOOST_AUTO_TEST_CASE(snapshot_chunk_roundtrip)
{
    // One transaction has more unspent outputs than fit in a chunk. Exercise
    // CompactSize count transitions and vout indices above the VARINT ordering
    // discontinuity, while decoding every chunk without its predecessor.
    CMutableTransaction tx;
    tx.vout.assign(50'000, CTxOut{1, CScript{} << OP_TRUE});
    const auto txid{tx.GetHash()};
    std::vector<std::pair<uint32_t, Coin>> coins;
    for (uint32_t i{0}; i < tx.vout.size(); ++i) coins.emplace_back(i, Coin{tx.vout[i], 1, false});
    const auto path{m_path_root / "chunks.dat"};
    {
        AutoFile file{fsbridge::fopen(path, "wb")};
        node::SnapshotChunkWriter writer{file};
        writer.WriteCoins(txid, coins);
        writer.Flush();
        BOOST_REQUIRE_EQUAL(file.fclose(), 0);
    }
    AutoFile file{fsbridge::fopen(path, "rb")};
    size_t count{0};
    size_t chunks{0};
    while (count < coins.size()) {
        auto chunk{node::ReadSnapshotChunk(file)};
        BOOST_CHECK_LE(chunk.size(), node::SNAPSHOT_CHUNK_SIZE);
        Txid chunk_txid;
        chunk >> chunk_txid;
        BOOST_CHECK(chunk_txid == txid);
        const auto num{ReadCompactSize(chunk)};
        BOOST_REQUIRE_GT(num, 0U);
        for (size_t i{0}; i < num; ++i) {
            BOOST_CHECK_EQUAL(ReadCompactSize(chunk), count);
            Coin coin;
            chunk >> coin;
            const auto& expected{coins.at(count++).second};
            BOOST_CHECK(coin.out == expected.out);
            BOOST_CHECK_EQUAL(coin.nHeight, expected.nHeight);
            BOOST_CHECK_EQUAL(coin.fCoinBase, expected.fCoinBase);
        }
        BOOST_CHECK(chunk.empty());
        ++chunks;
    }
    BOOST_CHECK_GT(chunks, 1U);
    BOOST_CHECK_EQUAL(file.fclose(), 0);
}

BOOST_AUTO_TEST_CASE(provider_init_and_serve)
{
    // Create a share directory with a synthetic snapshot file that matches
    // regtest assumeutxo params at height 110.
    auto regtest_params{CChainParams::RegTest({})};
    auto au_data{regtest_params->AssumeutxoForHeight(110)};
    BOOST_REQUIRE(au_data.has_value());

    fs::path share_dir{m_path_root / "share"};
    fs::create_directories(share_dir);

    // Write a fake snapshot
    fs::path snapshot_path{share_dir / "utxo-snapshot-110.dat"};
    {
        AutoFile file{fsbridge::fopen(snapshot_path, "wb")};
        BOOST_REQUIRE(!file.IsNull());

        node::SnapshotMetadata metadata(regtest_params->MessageStart(), au_data->blockhash, /*coins_count=*/42);
        file << metadata;

        // Write some random body data
        std::vector<unsigned char> body{m_rng.randbytes(node::SNAPSHOT_CHUNK_SIZE)};
        file << body;
        file << m_rng.randbytes(500);
        BOOST_REQUIRE(file.fclose() == 0);
    }

    // Initialize the provider
    node::UTXOSetShareProvider provider;
    size_t count{provider.Initialize(share_dir, *regtest_params)};
    BOOST_CHECK_EQUAL(count, 1U);

    auto tree{provider.GetTree(au_data->blockhash)};
    BOOST_REQUIRE(tree.has_value());
    au_data->chunk_merkle_root = node::ComputeUTXOSetMerkleRoot(tree->chunks);
    BOOST_CHECK_EQUAL(tree->version, 3);
    BOOST_CHECK(tree->block_hash == au_data->blockhash);
    BOOST_CHECK(!provider.GetTree(m_rng.rand256()));

    const uint32_t total_chunks{static_cast<uint32_t>(tree->chunks.size())};
    BOOST_REQUIRE_EQUAL(total_chunks, 3U);
    for (uint32_t i{0}; i < total_chunks; ++i) {
        auto data{provider.GetChunk(tree->block_hash, i)};
        BOOST_REQUIRE(data.has_value());
        BOOST_CHECK_EQUAL(data->size(), tree->chunks[i].size);
        BOOST_CHECK(Hash(*data) == tree->chunks[i].hash);
    }
    BOOST_CHECK(!provider.GetChunk(tree->block_hash, total_chunks));

    // Verify sidecar file
    fs::path sidecar_path{snapshot_path};
    sidecar_path += ".merkle";
    BOOST_CHECK(fs::exists(sidecar_path));

    // Re-init should load from sidecar
    node::UTXOSetShareProvider provider2;
    BOOST_CHECK_EQUAL(provider2.Initialize(share_dir, *regtest_params), 1U);
    auto tree2{provider2.GetTree(au_data->blockhash)};
    BOOST_REQUIRE(tree2.has_value());
    BOOST_CHECK(node::ComputeUTXOSetMerkleRoot(tree2->chunks) == node::ComputeUTXOSetMerkleRoot(tree->chunks));
}

BOOST_AUTO_TEST_CASE(download_manager_lifecycle)
{
    // Use a provider-served snapshot as the source, then download it
    // through the download manager to verify the full lifecycle.
    auto regtest_params{CChainParams::RegTest({})};
    auto au_data{regtest_params->AssumeutxoForHeight(110)};
    BOOST_REQUIRE(au_data.has_value());

    fs::path share_dir{m_path_root / "share_test"};
    fs::create_directories(share_dir);

    // Make a small snapshot
    fs::path src_path{share_dir / "source.dat"};
    {
        AutoFile file{fsbridge::fopen(src_path, "wb")};
        BOOST_REQUIRE(!file.IsNull());
        node::SnapshotMetadata metadata(regtest_params->MessageStart(), au_data->blockhash, /*coins_count=*/1);
        file << metadata;
        std::vector<unsigned char> body{m_rng.randbytes(node::SNAPSHOT_CHUNK_SIZE)};
        file << body;
        file << m_rng.randbytes(500);
        BOOST_REQUIRE(file.fclose() == 0);
    }

    node::UTXOSetShareProvider provider;
    BOOST_REQUIRE_EQUAL(provider.Initialize(share_dir, *regtest_params), 1U);
    auto tree{provider.GetTree(au_data->blockhash)};
    BOOST_REQUIRE(tree.has_value());
    au_data->chunk_merkle_root = node::ComputeUTXOSetMerkleRoot(tree->chunks);

    // Exercise the prototype's existing null-root behavior as well as a
    // trusted commitment; both paths verify the announced chunk hashes/sizes.
    for (bool have_root : {false, true}) {
        auto download_params{*au_data};
        if (!have_root) download_params.chunk_merkle_root.SetNull();
        fs::path output_path{m_path_root / "downloaded.dat"};
        node::UTXOSetDownloadManager dm;
        BOOST_CHECK(dm.StartDownload(au_data->blockhash, download_params, output_path));
        BOOST_CHECK(dm.GetState() == node::UTXOSetDownloadManager::State::DISCOVERING);

        // No requests yet
        BOOST_CHECK(!dm.GetNextChunkRequest(1).has_value());

        // Process the descriptor list
        BOOST_CHECK(dm.ProcessUTXOTree(1, *tree));
        BOOST_CHECK(dm.GetState() == node::UTXOSetDownloadManager::State::DOWNLOADING);

        // Download the chunks
        uint32_t total_chunks{static_cast<uint32_t>(tree->chunks.size())};
        for (uint32_t i = 0; i < total_chunks; ++i) {
            auto req{dm.GetNextChunkRequest(1)};
            BOOST_REQUIRE(req.has_value());
            BOOST_CHECK_EQUAL(req->chunk_index, i);

            auto chunk_result{provider.GetChunk(req->block_hash, req->chunk_index)};
            BOOST_REQUIRE(chunk_result.has_value());

            node::MsgUTXOSet msg;
            msg.block_hash = req->block_hash;
            msg.chunk_index = req->chunk_index;
            msg.data = std::move(*chunk_result);

            BOOST_CHECK(dm.ProcessUTXOSetChunk(1, msg));
        }

        BOOST_CHECK(!dm.GetNextChunkRequest(1).has_value());
        BOOST_CHECK(dm.GetState() == node::UTXOSetDownloadManager::State::COMPLETE);
        BOOST_CHECK(fs::exists(output_path));

        // Variable-length chunks must reconstruct the original file exactly.
        const auto size{fs::file_size(src_path)};
        BOOST_REQUIRE_EQUAL(fs::file_size(output_path), size);
        std::vector<unsigned char> expected(size), actual(size);
        AutoFile source{fsbridge::fopen(src_path, "rb")};
        AutoFile downloaded{fsbridge::fopen(output_path, "rb")};
        source.read(MakeWritableByteSpan(expected));
        downloaded.read(MakeWritableByteSpan(actual));
        BOOST_CHECK(actual == expected);
    }
}

BOOST_AUTO_TEST_CASE(download_manager_invalid_chunk)
{
    auto regtest_params{CChainParams::RegTest({})};
    auto au_data{regtest_params->AssumeutxoForHeight(110)};
    BOOST_REQUIRE(au_data.has_value());

    fs::path share_dir{m_path_root / "share_test2"};
    fs::create_directories(share_dir);

    fs::path src_path{share_dir / "source2.dat"};
    {
        AutoFile file{fsbridge::fopen(src_path, "wb")};
        BOOST_REQUIRE(!file.IsNull());
        node::SnapshotMetadata metadata(regtest_params->MessageStart(), au_data->blockhash, /*coins_count=*/1);
        file << metadata;
        std::vector<unsigned char> body{m_rng.randbytes(1000)};
        file << body;
        file << m_rng.randbytes(500);
        BOOST_REQUIRE(file.fclose() == 0);
    }

    node::UTXOSetShareProvider provider;
    BOOST_REQUIRE_EQUAL(provider.Initialize(share_dir, *regtest_params), 1U);
    auto tree{provider.GetTree(au_data->blockhash)};
    BOOST_REQUIRE(tree.has_value());
    au_data->chunk_merkle_root = node::ComputeUTXOSetMerkleRoot(tree->chunks);

    fs::path output_path{m_path_root / "downloaded2.dat"};
    node::UTXOSetDownloadManager dm;
    dm.StartDownload(au_data->blockhash, *au_data, output_path);
    BOOST_CHECK(dm.ProcessUTXOTree(1, *tree));

    auto req{dm.GetNextChunkRequest(1)};
    BOOST_REQUIRE(req.has_value());

    auto chunk_result{provider.GetChunk(req->block_hash, req->chunk_index)};
    BOOST_REQUIRE(chunk_result.has_value());

    node::MsgUTXOSet msg;
    msg.block_hash = req->block_hash;
    msg.chunk_index = req->chunk_index;
    msg.data = std::move(*chunk_result);
    const auto valid{msg.data};
    msg.data.pop_back();
    BOOST_CHECK(!dm.ProcessUTXOSetChunk(1, msg));
    msg.data = valid;
    msg.data[0] ^= 0xff;
    BOOST_CHECK(!dm.ProcessUTXOSetChunk(1, msg));
    msg.data = valid;
    BOOST_CHECK(dm.ProcessUTXOSetChunk(1, msg));

}

BOOST_AUTO_TEST_CASE(download_manager_rejects_bad_merkle_root)
{
    auto regtest_params{CChainParams::RegTest({})};
    auto au_data{regtest_params->AssumeutxoForHeight(110)};
    BOOST_REQUIRE(au_data.has_value());

    fs::path share_dir{m_path_root / "share_test3"};
    fs::create_directories(share_dir);

    fs::path src_path{share_dir / "source3.dat"};
    {
        AutoFile file{fsbridge::fopen(src_path, "wb")};
        BOOST_REQUIRE(!file.IsNull());
        node::SnapshotMetadata metadata(regtest_params->MessageStart(), au_data->blockhash, /*coins_count=*/1);
        file << metadata;
        std::vector<unsigned char> body{m_rng.randbytes(1000)};
        file << body;
        file << m_rng.randbytes(500);
        BOOST_REQUIRE(file.fclose() == 0);
    }

    node::UTXOSetShareProvider provider;
    BOOST_REQUIRE_EQUAL(provider.Initialize(share_dir, *regtest_params), 1U);
    auto tree{provider.GetTree(au_data->blockhash)};
    BOOST_REQUIRE(tree.has_value());
    au_data->chunk_merkle_root = node::ComputeUTXOSetMerkleRoot(tree->chunks);

    // Create au_data with a specific non-null chunk_merkle_root that differs
    // from what the provider computed
    AssumeutxoData custom_au_data{*au_data};
    custom_au_data.chunk_merkle_root = uint256{"0000000000000000000000000000000000000000000000000000000000000001"};

    fs::path output_path{m_path_root / "downloaded3.dat"};
    node::UTXOSetDownloadManager dm;
    BOOST_CHECK(dm.StartDownload(au_data->blockhash, custom_au_data, output_path));

    BOOST_CHECK(!dm.ProcessUTXOTree(1, *tree));
    BOOST_CHECK(dm.GetState() == node::UTXOSetDownloadManager::State::DISCOVERING);

    ++tree->chunks.back().size;
    BOOST_CHECK(!dm.ProcessUTXOTree(1, *tree));
    tree->version = 2;
    BOOST_CHECK(!dm.ProcessUTXOTree(1, *tree));
    tree->version = 3;
    tree->chunks.front().size = 50;
    BOOST_CHECK(!dm.ProcessUTXOTree(1, *tree));
    tree->chunks.clear();
    BOOST_CHECK(!dm.ProcessUTXOTree(1, *tree));
    BOOST_CHECK(!fs::exists(output_path));

}

BOOST_AUTO_TEST_SUITE_END()
