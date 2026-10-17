// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/utxo_snapshot.h>

#include <streams.h>
#include <sync.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/log.h>
#include <validation.h>

#include <cassert>
#include <cstdio>
#include <optional>
#include <string>

namespace node {

DataStream ReadSnapshotChunk(AutoFile& file)
{
    const auto size{ReadCompactSize(file)};
    if (size == 0 || size > SNAPSHOT_CHUNK_SIZE) {
        throw std::ios_base::failure("Invalid snapshot chunk size");
    }
    DataStream chunk;
    chunk.resize(size);
    file.read(MakeWritableByteSpan(chunk));
    return chunk;
}

void SnapshotChunkWriter::Flush()
{
    if (m_chunk.empty()) return;
    WriteCompactSize(m_file, m_chunk.size());
    m_file.write(MakeByteSpan(m_chunk));
    m_chunk.clear();
}

void SnapshotChunkWriter::WriteCoins(const Txid& txid, std::span<const std::pair<uint32_t, Coin>> coins)
{
    while (!coins.empty()) {
        size_t count{0};
        size_t size{0};
        while (count < coins.size()) {
            const auto& [index, coin]{coins[count]};
            const size_t next{size + GetSizeOfCompactSize(index) + GetSerializeSize(coin)};
            if (m_chunk.size() + 32 + GetSizeOfCompactSize(count + 1) + next > SNAPSHOT_CHUNK_SIZE) break;
            size = next;
            ++count;
        }
        if (count == 0) {
            if (m_chunk.empty()) throw std::ios_base::failure("Coin exceeds snapshot chunk size");
            Flush();
            continue;
        }
        m_chunk << txid;
        WriteCompactSize(m_chunk, count);
        for (const auto& [index, coin] : coins.first(count)) {
            WriteCompactSize(m_chunk, index);
            m_chunk << coin;
        }
        coins = coins.subspan(count);
        if (!coins.empty()) Flush();
    }
}

bool WriteSnapshotBaseBlockhash(Chainstate& snapshot_chainstate)
{
    AssertLockHeld(::cs_main);
    assert(snapshot_chainstate.m_from_snapshot_blockhash);

    const std::optional<fs::path> chaindir = snapshot_chainstate.StoragePath();
    assert(chaindir); // Sanity check that chainstate isn't in-memory.
    const fs::path write_to = *chaindir / node::SNAPSHOT_BLOCKHASH_FILENAME;

    FILE* file{fsbridge::fopen(write_to, "wb")};
    AutoFile afile{file};
    if (afile.IsNull()) {
        LogError("[snapshot] failed to open base blockhash file for writing: %s",
                  fs::PathToString(write_to));
        return false;
    }
    afile << *snapshot_chainstate.m_from_snapshot_blockhash;

    if (afile.fclose() != 0) {
        LogError("[snapshot] failed to close base blockhash file %s after writing",
                  fs::PathToString(write_to));
        return false;
    }
    return true;
}

std::optional<uint256> ReadSnapshotBaseBlockhash(fs::path chaindir)
{
    if (!fs::exists(chaindir)) {
        LogWarning("[snapshot] cannot read base blockhash: no chainstate dir "
            "exists at path %s", fs::PathToString(chaindir));
        return std::nullopt;
    }
    const fs::path read_from = chaindir / node::SNAPSHOT_BLOCKHASH_FILENAME;
    const std::string read_from_str = fs::PathToString(read_from);

    if (!fs::exists(read_from)) {
        LogWarning("[snapshot] snapshot chainstate dir is malformed! no base blockhash file "
            "exists at path %s. Try deleting %s and calling loadtxoutset again?",
            fs::PathToString(chaindir), read_from_str);
        return std::nullopt;
    }

    uint256 base_blockhash;
    FILE* file{fsbridge::fopen(read_from, "rb")};
    AutoFile afile{file};
    if (afile.IsNull()) {
        LogWarning("[snapshot] failed to open base blockhash file for reading: %s",
            read_from_str);
        return std::nullopt;
    }
    afile >> base_blockhash;

    int64_t position = afile.tell();
    afile.seek(0, SEEK_END);
    if (position != afile.tell()) {
        LogWarning("[snapshot] unexpected trailing data in %s", read_from_str);
    }
    return base_blockhash;
}

std::optional<fs::path> FindAssumeutxoChainstateDir(const fs::path& data_dir)
{
    fs::path possible_dir =
        data_dir / fs::u8path(strprintf("chainstate%s", SNAPSHOT_CHAINSTATE_SUFFIX));

    if (fs::exists(possible_dir)) {
        return possible_dir;
    }
    return std::nullopt;
}

} // namespace node
