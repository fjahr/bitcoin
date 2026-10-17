// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <coins.h>
#include <consensus/amount.h>
#include <hash.h>
#include <kernel/chainparams.h>
#include <kernel/coinstats.h>
#include <node/utxo_snapshot.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <txdb.h>
#include <validation.h>

#include <cstdlib>
#include <optional>
#include <stdexcept>

struct SnapshotBenchmarkFixture {
    int height;
    AssumeutxoHash hash;
};

static SnapshotBenchmarkFixture GetSnapshotFixture(const ChainstateManager& chainman, const node::SnapshotMetadata& metadata)
{
    if (const auto data{chainman.GetParams().AssumeutxoForBlockhash(metadata.m_base_blockhash)}) {
        return {data->height, data->hash_serialized};
    }
    // A verified v32 mainnet snapshot newer than this PR's chain parameters.
    // This benchmark fixture does not change which snapshots the node accepts.
    if (metadata.m_base_blockhash == uint256{"00000000000000000001595977e6000ce56129f5c9b4073e31ccc30b90b97da9"}) {
        return {965000, AssumeutxoHash{uint256{"4a8d794337118c0c615b574f817c7306c687584a537184b8d233df42bf477ec2"}}};
    }
    throw std::runtime_error("Unknown mainnet benchmark snapshot base");
}

//! Measure full snapshot import using the same sequential decoding, ordering
//! checks, commitment and writer as PopulateAndValidateSnapshot, without
//! downloading or fabricating 965k headers.
static void SnapshotImportMainnet(benchmark::Bench& bench)
{
    const char* snapshot{std::getenv("BITCOIN_BENCH_SNAPSHOT")};
    if (!snapshot) return;
    TestingSetup setup{ChainType::MAIN, {.setup_net=false, .setup_validation_interface=false, .min_validation_cache=true}};
    AutoFile file{fsbridge::fopen(fs::u8path(snapshot), "rb")};
    node::SnapshotMetadata metadata{setup.m_node.chainman->GetParams().MessageStart()};
    file >> metadata;
    const auto fixture{GetSnapshotFixture(*setup.m_node.chainman, metadata)};
    const auto start{file.tell()};
    bench.epochs(1).epochIterations(1).unit("snapshot").run([&] {
        file.seek(start, SEEK_SET);
        CCoinsViewDB db{{.path=setup.m_path_root / "snapshot-import", .cache_bytes=8 << 20,
            .memory_only=false, .wipe_data=true, .obfuscate=true}, {}};
        CCoinsViewDB::SnapshotWriter writer{db};
        HashWriter hash;
        std::optional<COutPoint> previous;
        uint64_t count{0};
        while (count < metadata.m_coins_count) {
            auto payload{node::ReadSnapshotChunk(file)};
            while (!payload.empty()) {
                Txid txid;
                payload >> txid;
                const auto group{ReadCompactSize(payload)};
                if (group == 0 || group > metadata.m_coins_count - count) throw std::runtime_error("Bad snapshot count");
                for (uint64_t i{0}; i < group; ++i) {
                    COutPoint outpoint{txid, static_cast<uint32_t>(ReadCompactSize(payload))};
                    Coin coin;
                    payload >> coin;
                    if (coin.nHeight > fixture.height || outpoint.n == UINT32_MAX || !MoneyRange(coin.out.nValue) ||
                        (previous && !(*previous < outpoint))) throw std::runtime_error("Bad snapshot coin or ordering");
                    previous = outpoint;
                    kernel::ApplyCoinHash(hash, outpoint, coin);
                    writer.AddCoin(outpoint, coin);
                    ++count;
                }
            }
        }
        if (file.tell() != file.size() || AssumeutxoHash{hash.GetHash()} != fixture.hash) {
            throw std::runtime_error("Snapshot commitment mismatch");
        }
        writer.Finish(metadata.m_base_blockhash);
    });
}

BENCHMARK(SnapshotImportMainnet);
