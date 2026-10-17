// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_UTXO_SET_SHARE_H
#define BITCOIN_NODE_UTXO_SET_SHARE_H

#include <cstddef>
#include <cstdint>
#include <chrono>
#include <optional>
#include <utility>
#include <vector>

#include <serialize.h>
#include <sync.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/time.h>

class CChainParams;
struct AssumeutxoData;

namespace node {

//! Bound the single announcement to less than the 4 MB P2P message limit.
inline constexpr size_t MAX_UTXO_SET_CHUNKS{100'000};

struct UTXOSetChunk {
    uint256 hash;
    uint32_t size{0};
    SERIALIZE_METHODS(UTXOSetChunk, obj) { READWRITE(obj.hash, obj.size); }
};

uint256 ComputeUTXOSetMerkleRoot(const std::vector<UTXOSetChunk>& chunks);

struct MsgUTXOTree {
    uint256 block_hash;
    uint16_t version{3};
    std::vector<UTXOSetChunk> chunks;
    SERIALIZE_METHODS(MsgUTXOTree, obj) { READWRITE(obj.block_hash, obj.version, obj.chunks); }
};

struct MsgGetUTXOSet {
    uint256 block_hash;
    uint32_t chunk_index{0};
    SERIALIZE_METHODS(MsgGetUTXOSet, obj) { READWRITE(obj.block_hash, obj.chunk_index); }
};

struct MsgUTXOSet {
    uint256 block_hash;
    uint32_t chunk_index{0};
    std::vector<unsigned char> data;
    SERIALIZE_METHODS(MsgUTXOSet, obj) { READWRITE(obj.block_hash, obj.chunk_index, obj.data); }
};

/** Serves independently decodable version 3 snapshot chunks. */
class UTXOSetShareProvider
{
public:
    size_t Initialize(const fs::path& share_dir, const CChainParams& params);
    std::optional<MsgUTXOTree> GetTree(const uint256& block_hash) const;
    std::optional<std::vector<unsigned char>> GetChunk(const uint256& block_hash, uint32_t chunk_index) const;

private:
    struct SnapshotData {
        fs::path path;
        MsgUTXOTree tree;
        std::vector<uint64_t> offsets;
    };
    std::vector<SnapshotData> m_snapshots;
};

/** Manages downloading a UTXO set snapshot from peers */
class UTXOSetDownloadManager
{
public:
    enum class State { IDLE, DISCOVERING, DOWNLOADING, COMPLETE, FAILED };

    /** Begin a download targeting the given assumeutxo snapshot.
     *  Output is written to output_path. */
    bool StartDownload(const uint256& target_blockhash,
                       const AssumeutxoData& au_data,
                       const fs::path& output_path) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Authenticate the chunk list against the expected snapshot commitment. */
    bool ProcessUTXOTree(int64_t peer_id, const MsgUTXOTree& tree) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Verify a chunk against the announced hash and size, then write it. */
    bool ProcessUTXOSetChunk(int64_t peer_id, const MsgUTXOSet& chunk) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    uint256 GetTargetBlockhash() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Get the next chunk request to send to a peer, or nullopt if none
     *  available. Marks the chunk as in-flight for this peer. */
    std::optional<MsgGetUTXOSet> GetNextChunkRequest(int64_t peer_id) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Re-queue any in-flight chunks assigned to this peer */
    void RequeueChunksForPeer(int64_t peer_id) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Re-assign chunks that have been in-flight for too long */
    void HandleTimeouts(SteadySeconds now) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Whether peer has any chunks currently assigned to it */
    bool PeerHasInflightChunks(int64_t peer_id) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Count chunks currently in-flight for a given peer */
    int CountInFlightForPeer(int64_t peer_id) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    State GetState() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    fs::path GetOutputPath() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    enum class ChunkState { NEEDED, IN_FLIGHT, DONE };

    struct ChunkInfo {
        ChunkState state{ChunkState::NEEDED};
        int64_t assigned_peer{-1};
        SteadySeconds request_time{};
        uint64_t offset{0};
        UTXOSetChunk expected;
    };

    mutable Mutex m_mutex;

    State m_state GUARDED_BY(m_mutex){State::IDLE};
    fs::path m_output_path GUARDED_BY(m_mutex);

    // Target snapshot info
    uint256 m_target_blockhash GUARDED_BY(m_mutex);
    uint256 m_expected_chunk_merkle_root GUARDED_BY(m_mutex);

    std::vector<ChunkInfo> m_chunks GUARDED_BY(m_mutex);
    uint32_t m_chunks_done GUARDED_BY(m_mutex){0};
    static constexpr std::chrono::seconds CHUNK_TIMEOUT{60};
};

} // namespace node

#endif // BITCOIN_NODE_UTXO_SET_SHARE_H
