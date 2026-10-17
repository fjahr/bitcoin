// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXDB_H
#define BITCOIN_TXDB_H

#include <coins.h>
#include <dbwrapper.h>
#include <kernel/caches.h>
#include <kernel/cs_main.h>
#include <sync.h>
#include <util/fs.h>

#include <condition_variable>
#include <cstddef>
#include <exception>
#include <cstdint>
#include <memory>
#include <optional>
#include <thread>
#include <vector>

class COutPoint;
class uint256;

//! User-controlled performance and debug options.
struct CoinsViewOptions {
    //! Maximum database write batch size in bytes.
    size_t batch_write_bytes{DEFAULT_DB_CACHE_BATCH};
    //! If non-zero, randomly exit when the database is flushed with (1/ratio) probability.
    int simulate_crash_ratio{0};
};

/** CCoinsView backed by the coin database (chainstate/) */
class CCoinsViewDB final : public CCoinsView
{
protected:
    DBParams m_db_params;
    CoinsViewOptions m_options;
    std::unique_ptr<CDBWrapper> m_db;
public:
    explicit CCoinsViewDB(DBParams db_params, CoinsViewOptions options);

    class SnapshotWriter;

    std::optional<Coin> GetCoin(const COutPoint& outpoint) const override;
    bool HaveCoin(const COutPoint &outpoint) const override;
    uint256 GetBestBlock() const override;
    std::vector<uint256> GetHeadBlocks() const override;
    void BatchWrite(CoinsViewCacheCursor& cursor, const uint256& hashBlock) override;
    std::unique_ptr<CCoinsViewCursor> Cursor() const override;

    //! Whether an unsupported database format is used.
    bool NeedsUpgrade();
    size_t EstimateSize() const override;

    //! Dynamically alter the underlying leveldb cache size.
    void ResizeCache(size_t new_cache_size) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
};

/** Bulk load a fresh, private snapshot database without a coins hash-map cache.
 * The caller must validate coins and reject duplicate outpoints. Partial writes
 * are disposable: the database has no best block until Finish() succeeds.
 * A worker writes one batch while the caller fills the next, bounding buffered
 * data to two batches (plus at most one coin per batch). The database must
 * outlive the writer and must not otherwise be modified during import.
 */
class CCoinsViewDB::SnapshotWriter
{
    CDBWrapper& m_db;
    const size_t m_batch_bytes;
    std::unique_ptr<CDBBatch> m_batch;
    Mutex m_mutex;
    std::condition_variable m_ready;
    std::unique_ptr<CDBBatch> m_pending GUARDED_BY(m_mutex);
    bool m_writing GUARDED_BY(m_mutex){false};
    std::exception_ptr m_error GUARDED_BY(m_mutex);
    bool m_stopping GUARDED_BY(m_mutex){false};
    std::thread m_thread;

    void Flush() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void Run() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

public:
    explicit SnapshotWriter(CCoinsViewDB& db);
    //! Join an outstanding write and discard unsubmitted coins on cancellation.
    ~SnapshotWriter();
    void AddCoin(const COutPoint& outpoint, const Coin& coin) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    //! Wait for all writes, propagating database errors before activation.
    void Finish(const uint256& block_hash) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
};

#endif // BITCOIN_TXDB_H
