// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/utxo_set_share.h>

#include <hash.h>
#include <kernel/chainparams.h>
#include <logging.h>
#include <node/utxo_snapshot.h>
#include <streams.h>
#include <util/fs.h>

namespace node {

uint256 ComputeUTXOSetMerkleRoot(const std::vector<UTXOSetChunk>& chunks)
{
    std::vector<uint256> hashes;
    hashes.reserve(chunks.size());
    for (const auto& chunk : chunks) {
        hashes.push_back((HashWriter{} << uint8_t{0} << chunk.size << chunk.hash).GetHash());
    }
    while (hashes.size() > 1) {
        size_t out{0};
        for (size_t i{0}; i < hashes.size(); i += 2) {
            hashes[out++] = i + 1 == hashes.size() ? hashes[i] :
                (HashWriter{} << uint8_t{1} << hashes[i] << hashes[i + 1]).GetHash();
        }
        hashes.resize(out);
    }
    return hashes.empty() ? uint256{} : hashes.front();
}

size_t UTXOSetShareProvider::Initialize(const fs::path& share_dir, const CChainParams& params)
{
    m_snapshots.clear();
    std::error_code error;
    if (!fs::is_directory(share_dir, error)) return 0;

    for (const auto& entry : fs::directory_iterator(share_dir, error)) {
        if (!entry.is_regular_file(error) || entry.path().extension() == ".merkle") continue;
        AutoFile file{fsbridge::fopen(entry.path(), "rb")};
        if (file.IsNull()) continue;
        try {
            SnapshotMetadata metadata{params.MessageStart()};
            file >> metadata;
            if (!params.AssumeutxoForBlockhash(metadata.m_base_blockhash)) continue;
            const auto file_size{fs::file_size(entry.path())};
            SnapshotData snapshot;
            snapshot.path = entry.path();
            snapshot.tree.block_hash = metadata.m_base_blockhash;

            // A sidecar is only an acceleration cache. Its version and source
            // length must match; offsets are derived from the chunk sizes.
            fs::path sidecar{entry.path()};
            sidecar += ".merkle";
            bool cached{false};
            {
                AutoFile cache{fsbridge::fopen(sidecar, "rb")};
                if (!cache.IsNull()) {
                    try {
                        uint16_t version;
                        uint64_t size;
                        cache >> version >> size;
                        if (version == 3 && size == file_size) {
                            cache >> snapshot.tree.chunks;
                            cached = true;
                        }
                    } catch (const std::exception&) { }
                }
            }
            if (!cached) {
                snapshot.tree.chunks.clear();
                DataStream header;
                header << metadata;
                snapshot.tree.chunks.push_back({Hash(header), static_cast<uint32_t>(header.size())});
                while (static_cast<uint64_t>(file.tell()) < file_size) {
                    const auto payload{ReadSnapshotChunk(file)};
                    DataStream frame;
                    WriteCompactSize(frame, payload.size());
                    frame.write(MakeByteSpan(payload));
                    snapshot.tree.chunks.push_back({Hash(frame), static_cast<uint32_t>(frame.size())});
                }
                AutoFile cache{fsbridge::fopen(sidecar, "wb")};
                if (!cache.IsNull()) {
                    try {
                        cache << uint16_t{3} << file_size << snapshot.tree.chunks;
                    } catch (const std::exception& e) {
                        LogWarning("Failed to write snapshot sidecar: %s", e.what());
                    }
                    if (cache.fclose() != 0) LogWarning("Failed to close snapshot sidecar %s", fs::PathToString(sidecar));
                }
            }
            uint64_t offset{0};
            for (const auto& chunk : snapshot.tree.chunks) {
                snapshot.offsets.push_back(offset);
                offset += chunk.size;
            }
            if (offset != file_size || snapshot.tree.chunks.size() > MAX_UTXO_SET_CHUNKS) continue;
            LogInfo("Serving UTXO set for block %s", metadata.m_base_blockhash.ToString());
            m_snapshots.push_back(std::move(snapshot));
        } catch (const std::exception& e) {
            LogDebug(BCLog::UTXOSETSHARE, "Unable to read snapshot %s: %s", fs::PathToString(entry.path()), e.what());
        }
    }
    return m_snapshots.size();
}

std::optional<MsgUTXOTree> UTXOSetShareProvider::GetTree(const uint256& block_hash) const
{
    for (const auto& snapshot : m_snapshots) {
        if (snapshot.tree.block_hash == block_hash) return snapshot.tree;
    }
    return std::nullopt;
}

std::optional<std::vector<unsigned char>> UTXOSetShareProvider::GetChunk(const uint256& block_hash, uint32_t chunk_index) const
{
    for (const auto& snapshot : m_snapshots) {
        if (snapshot.tree.block_hash != block_hash || chunk_index >= snapshot.tree.chunks.size()) continue;
        AutoFile file{fsbridge::fopen(snapshot.path, "rb")};
        if (file.IsNull()) return std::nullopt;
        std::vector<unsigned char> data(snapshot.tree.chunks[chunk_index].size);
        file.seek(snapshot.offsets[chunk_index], SEEK_SET);
        file.read(MakeWritableByteSpan(data));
        return data;
    }
    return std::nullopt;
}

bool UTXOSetDownloadManager::StartDownload(const uint256& target_blockhash,
                                         const AssumeutxoData& au_data,
                                         const fs::path& output_path)
{
    LOCK(m_mutex);
    if (m_state != State::IDLE) return false;
    m_target_blockhash = target_blockhash;
    m_expected_chunk_merkle_root = au_data.chunk_merkle_root;
    m_output_path = output_path;
    m_state = State::DISCOVERING;
    return true;
}

uint256 UTXOSetDownloadManager::GetTargetBlockhash() const
{
    LOCK(m_mutex);
    return m_target_blockhash;
}

bool UTXOSetDownloadManager::ProcessUTXOTree(int64_t peer_id, const MsgUTXOTree& tree)
{
    LOCK(m_mutex);
    if (m_state != State::DISCOVERING) return true;
    if (tree.block_hash != m_target_blockhash || tree.version != 3 ||
        tree.chunks.empty() || tree.chunks.size() > MAX_UTXO_SET_CHUNKS || tree.chunks.front().size != 51) return false;
    for (size_t i{1}; i < tree.chunks.size(); ++i) {
        if (tree.chunks[i].size < 35 || tree.chunks[i].size > SNAPSHOT_CHUNK_SIZE + 5) return false;
    }
    const auto root{ComputeUTXOSetMerkleRoot(tree.chunks)};
    if (!m_expected_chunk_merkle_root.IsNull() && root != m_expected_chunk_merkle_root) return false;

    m_chunks.clear();
    uint64_t offset{0};
    for (const auto& expected : tree.chunks) {
        ChunkInfo chunk;
        chunk.offset = offset;
        chunk.expected = expected;
        m_chunks.push_back(chunk);
        offset += expected.size;
    }
    m_chunks_done = 0;
    AutoFile file{fsbridge::fopen(m_output_path, "wb")};
    if (file.IsNull() || file.fclose() != 0) {
        m_state = State::FAILED;
        return true;
    }
    m_state = State::DOWNLOADING;
    LogInfo("UTXO set download: %d chunks (%d bytes), from peer=%d", m_chunks.size(), offset, peer_id);
    return true;
}

bool UTXOSetDownloadManager::ProcessUTXOSetChunk(int64_t peer_id, const MsgUTXOSet& chunk)
{
    LOCK(m_mutex);
    if (m_state != State::DOWNLOADING) return true;
    if (chunk.block_hash != m_target_blockhash || chunk.chunk_index >= m_chunks.size()) return false;
    auto& info{m_chunks[chunk.chunk_index]};
    if (chunk.data.size() != info.expected.size || Hash(chunk.data) != info.expected.hash) return false;
    if (info.state == ChunkState::DONE) return true;

    // Mark a chunk complete only after the write succeeds. Keep completion and
    // file writes serialized so activation cannot race an outstanding write.
    AutoFile file{fsbridge::fopen(m_output_path, "rb+")};
    try {
        if (file.IsNull()) throw std::ios_base::failure("Cannot open snapshot download");
        file.seek(info.offset, SEEK_SET);
        file.write(MakeByteSpan(chunk.data));
        if (!file.Commit()) throw std::ios_base::failure("Cannot commit snapshot chunk");
    } catch (const std::exception& e) {
        LogWarning("Unable to write snapshot chunk: %s", e.what());
        m_state = State::FAILED;
    }
    if (file.fclose() != 0) m_state = State::FAILED;
    if (m_state == State::FAILED) return true;
    info.state = ChunkState::DONE;
    info.assigned_peer = -1;
    if (++m_chunks_done == m_chunks.size()) {
        m_state = State::COMPLETE;
        LogInfo("UTXO set download complete: %s", fs::PathToString(m_output_path));
    }
    return true;
}

std::optional<MsgGetUTXOSet> UTXOSetDownloadManager::GetNextChunkRequest(int64_t peer_id)
{
    LOCK(m_mutex);
    if (m_state != State::DOWNLOADING) return std::nullopt;

    for (uint32_t i = 0; i < m_chunks.size(); ++i) {
        if (m_chunks[i].state == ChunkState::NEEDED) {
            m_chunks[i].state = ChunkState::IN_FLIGHT;
            m_chunks[i].assigned_peer = peer_id;
            m_chunks[i].request_time = std::chrono::time_point_cast<std::chrono::seconds>(SteadyClock::now());

            MsgGetUTXOSet req;
            req.block_hash = m_target_blockhash;
            req.chunk_index = i;
            return req;
        }
    }
    return std::nullopt;
}

void UTXOSetDownloadManager::RequeueChunksForPeer(int64_t peer_id)
{
    LOCK(m_mutex);
    for (auto& ci : m_chunks) {
        if (ci.state == ChunkState::IN_FLIGHT && ci.assigned_peer == peer_id) {
            ci.state = ChunkState::NEEDED;
            ci.assigned_peer = -1;
        }
    }
}

void UTXOSetDownloadManager::HandleTimeouts(SteadySeconds now)
{
    LOCK(m_mutex);
    if (m_state != State::DOWNLOADING) return;

    for (auto& ci : m_chunks) {
        if (ci.state == ChunkState::IN_FLIGHT && (now - ci.request_time) > CHUNK_TIMEOUT) {
            LogDebug(BCLog::UTXOSETSHARE, "Chunk timed out from peer=%d, re-queuing", ci.assigned_peer);
            ci.state = ChunkState::NEEDED;
            ci.assigned_peer = -1;
        }
    }
}

bool UTXOSetDownloadManager::PeerHasInflightChunks(int64_t peer_id) const
{
    LOCK(m_mutex);
    if (m_state != State::DOWNLOADING) return false;
    for (const auto& ci : m_chunks) {
        if (ci.state == ChunkState::IN_FLIGHT && ci.assigned_peer == peer_id) return true;
    }
    return false;
}

int UTXOSetDownloadManager::CountInFlightForPeer(int64_t peer_id) const
{
    LOCK(m_mutex);
    int count{0};
    for (const auto& ci : m_chunks) {
        if (ci.state == ChunkState::IN_FLIGHT && ci.assigned_peer == peer_id) ++count;
    }
    return count;
}

UTXOSetDownloadManager::State UTXOSetDownloadManager::GetState() const
{
    LOCK(m_mutex);
    return m_state;
}

fs::path UTXOSetDownloadManager::GetOutputPath() const
{
    LOCK(m_mutex);
    return m_output_path;
}

} // namespace node
