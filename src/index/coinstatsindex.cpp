// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <coins.h>
#include <crypto/muhash.h>
#include <hash.h>
#include <index/coinstatsindex.h>
#include <node/coinstats.h>
#include <serialize.h>
#include <txdb.h>
#include <undo.h>
#include <validation.h>

constexpr char DB_BLOCK_HASH = 's';
constexpr char DB_BLOCK_HEIGHT = 't';
constexpr char DB_MUHASH = 'M';

namespace {

struct DBVal {
    uint256 muhash;
    uint64_t nTransactionOutputs;
    uint64_t nBogoSize;
    CAmount nTotalAmount;
    uint64_t nDiskSize;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(muhash);
        READWRITE(nTransactionOutputs);
        READWRITE(nBogoSize);
        READWRITE(nTotalAmount);
        READWRITE(nDiskSize);
    }
};

struct DBHeightKey {
    int height;

    DBHeightKey() : height(0) {}
    explicit DBHeightKey(int height_in) : height(height_in) {}

    template<typename Stream>
    void Serialize(Stream& s) const
    {
        ser_writedata8(s, DB_BLOCK_HEIGHT);
        ser_writedata32be(s, height);
    }

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        char prefix = ser_readdata8(s);
        if (prefix != DB_BLOCK_HEIGHT) {
            throw std::ios_base::failure("Invalid format for block filter index DB height key");
        }
        height = ser_readdata32be(s);
    }
};

struct DBHashKey {
    uint256 block_hash;

    explicit DBHashKey(const uint256& hash_in) : block_hash(hash_in) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        char prefix = DB_BLOCK_HASH;
        READWRITE(prefix);
        if (prefix != DB_BLOCK_HASH) {
            throw std::ios_base::failure("Invalid format for block filter index DB hash key");
        }

        READWRITE(block_hash);
    }
};

struct DBMuhash {
    MuHash3072 hash;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(hash);
    }
};

}; // namespace

std::unique_ptr<CoinStatsIndex> g_coin_stats_index;

CoinStatsIndex::CoinStatsIndex(size_t n_cache_size, bool f_memory, bool f_wipe)
{
    fs::path path = GetDataDir() / "indexes" / "coinstats";
    fs::create_directories(path);

    m_db = MakeUnique<CoinStatsIndex::DB>(path / "db", n_cache_size, f_memory, f_wipe);
}

bool CoinStatsIndex::Init()
{
    if (!m_db->Read(DB_MUHASH, m_muhash)) {
        // Check that the cause of the read failure is that the key does not exist. Any other errors
        // indicate database corruption or a disk failure, and starting the index would cause
        // further corruption.
        if (m_db->Exists(DB_MUHASH)) {
            return error("%s: Cannot read current %s state; index may be corrupted",
                         __func__, GetName());
        }

        // If the DB_MUHASH is not set, initialize empty values
        m_muhash = MuHash3072();
        m_nTransactionOutputs = 0;
        m_nBogoSize = 0;
        m_nTotalAmount = 0;
        m_nDiskSize = 0;
    }

    return BaseIndex::Init();
}

bool CoinStatsIndex::WriteBlock(const CBlock& block, const CBlockIndex* pindex)
{
    CBlockUndo block_undo;

    // Ignore genesis block
    if (pindex->nHeight > 0) {
        if (!UndoReadFromDisk(block_undo, pindex)) {
            return false;
        }

        std::pair<uint256, DBVal> read_out;
        if (!m_db->Read(DBHeightKey(pindex->nHeight - 1), read_out)) {
            return false;
        }

        uint256 expected_block_hash = pindex->pprev->GetBlockHash();
        if (read_out.first != expected_block_hash) {
            return error("%s: previous block header belongs to unexpected block %s; expected %s",
                         __func__, read_out.first.ToString(), expected_block_hash.ToString());
        }

        bool is_bip30_block = (pindex->nHeight==91842 && pindex->GetBlockHash() == uint256S("0x00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec")) ||
                              (pindex->nHeight==91880 && pindex->GetBlockHash() == uint256S("0x00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"));
        std::set<uint256> bip30_block_txs;
        MuHash3072 undo_muhash;

        // Add the new utxos created from the block
        for (size_t i = 0; i < block.vtx.size(); ++i) {
            const auto& tx = block.vtx.at(i);

            // Skip the second one of the BIP30 dublicate transactions.
            if (is_bip30_block) {
                if (!bip30_block_txs.insert(tx->GetHash()).second) {
                    continue;
                }
            }

            for (size_t j = 0; j < tx->vout.size(); ++j) {
                const CTxOut& out = tx->vout[j];
                COutPoint outpoint = COutPoint(tx->GetHash(), j);
                Coin coin = Coin(out, pindex->nHeight, tx->IsCoinBase());

                // Skip unspendable coins
                if (coin.out.scriptPubKey.IsUnspendable()) continue;

                TruncatedSHA512Writer ss(SER_DISK, 0);
                ss << outpoint;
                ss << (uint32_t)(coin.nHeight * 2 + coin.fCoinBase);
                ss << coin.out;
                m_muhash *= MuHash3072(ss.GetHash().begin());

                m_nTransactionOutputs++;
                m_nTotalAmount += coin.out.nValue;
                m_nBogoSize += 32 /* txid */ + 4 /* vout index */ + 4 /* height + coinbase */ + 8 /* amount */ +
                               2 /* scriptPubKey len */ + coin.out.scriptPubKey.size() /* scriptPubKey */;
            }

            // The coinbase tx has no undo data since no former output is spent
            if (i > 0) {
                const auto& tx_undo = block_undo.vtxundo.at(i-1);

                for (size_t j = 0; j < tx_undo.vprevout.size(); ++j) {
                    Coin coin = tx_undo.vprevout[j];
                    COutPoint outpoint = COutPoint(tx->vin[j].prevout.hash, tx->vin[j].prevout.n);

                    TruncatedSHA512Writer ss(SER_DISK, 0);
                    ss << outpoint;
                    ss << (uint32_t)(coin.nHeight * 2 + coin.fCoinBase);
                    ss << coin.out;
                    undo_muhash *= MuHash3072(ss.GetHash().begin());

                    m_nTransactionOutputs--;
                    m_nTotalAmount -= coin.out.nValue;
                    m_nBogoSize -= 32 /* txid */ + 4 /* vout index */ + 4 /* height + coinbase */ + 8 /* amount */ +
                                   2 /* scriptPubKey len */ + coin.out.scriptPubKey.size() /* scriptPubKey */;
                }
            }
        }

        m_muhash /= undo_muhash;
    }

    CCoinsView* coins_view = WITH_LOCK(cs_main, return &ChainstateActive().CoinsDB());
    m_nDiskSize = coins_view->EstimateSize();

    std::pair<uint256, DBVal> value;
    value.first = pindex->GetBlockHash();
    value.second.muhash = currentHashInternal();
    value.second.nDiskSize = m_nDiskSize;
    value.second.nTransactionOutputs = m_nTransactionOutputs;
    value.second.nBogoSize = m_nBogoSize;
    value.second.nTotalAmount = m_nTotalAmount;

    if (!m_db->Write(DBHeightKey(pindex->nHeight), value)) {
        return false;
    }

    if (!m_db->Write(DB_MUHASH, m_muhash)) {
        return false;
    }

    return true;
}

static bool CopyHeightIndexToHashIndex(CDBIterator& db_it, CDBBatch& batch,
                                       const std::string& index_name,
                                       int start_height, int stop_height)
{
    DBHeightKey key(start_height);
    db_it.Seek(key);

    for (int height = start_height; height <= stop_height; ++height) {
        if (!db_it.GetKey(key) || key.height != height) {
            return error("%s: unexpected key in %s: expected (%c, %d)",
                         __func__, index_name, DB_BLOCK_HEIGHT, height);
        }

        std::pair<uint256, DBVal> value;
        if (!db_it.GetValue(value)) {
            return error("%s: unable to read value in %s at key (%c, %d)",
                         __func__, index_name, DB_BLOCK_HEIGHT, height);
        }

        batch.Write(DBHashKey(value.first), std::move(value.second));

        db_it.Next();
    }
    return true;
}

bool CoinStatsIndex::Rewind(const CBlockIndex* current_tip, const CBlockIndex* new_tip)
{
    assert(current_tip->GetAncestor(new_tip->nHeight) == new_tip);

    CDBBatch batch(*m_db);
    std::unique_ptr<CDBIterator> db_it(m_db->NewIterator());

    {
        LOCK(cs_main);
        CBlockIndex* iter_tip = LookupBlockIndex(current_tip->GetBlockHash());
        auto& consensus_params = Params().GetConsensus();

        do {
            CBlock block;

            if (!ReadBlockFromDisk(block, iter_tip, consensus_params)) {
                return error("%s: Failed to read block %s from disk",
                               __func__, iter_tip->GetBlockHash().ToString());
            }

            ReverseBlock(block, iter_tip);

            iter_tip = iter_tip->GetAncestor(iter_tip->nHeight - 1);
        } while (new_tip != iter_tip);
    }

    // During a reorg, we need to copy all hash digests for blocks that are getting disconnected from the
    // height index to the hash index so we can still find them when the height index entries are
    // overwritten.
    if (!CopyHeightIndexToHashIndex(*db_it, batch, m_name, new_tip->nHeight, current_tip->nHeight)) {
        return false;
    }

    if (!m_db->WriteBatch(batch)) return false;

    return BaseIndex::Rewind(current_tip, new_tip);
}

static bool LookupOne(const CDBWrapper& db, const CBlockIndex* block_index, DBVal& result)
{
    // First check if the result is stored under the height index and the value there matches the
    // block hash. This should be the case if the block is on the active chain.
    std::pair<uint256, DBVal> read_out;
    if (!db.Read(DBHeightKey(block_index->nHeight), read_out)) {
        return false;
    }
    if (read_out.first == block_index->GetBlockHash()) {
        result = std::move(read_out.second);
        return true;
    }

    // If value at the height index corresponds to an different block, the result will be stored in
    // the hash index.
    return db.Read(DBHashKey(block_index->GetBlockHash()), result);
}

bool CoinStatsIndex::LookupStats(const CBlockIndex* block_index, CCoinsStats& coins_stats) const
{
    DBVal entry;
    if (!LookupOne(*m_db, block_index, entry)) {
        return false;
    }

    coins_stats.hashSerialized = entry.muhash;
    coins_stats.nTransactionOutputs = entry.nTransactionOutputs;
    coins_stats.nBogoSize = entry.nBogoSize;
    coins_stats.nTotalAmount = entry.nTotalAmount;
    coins_stats.nDiskSize = entry.nDiskSize;

    return true;
}

uint256 CoinStatsIndex::currentHashInternal()
{
    unsigned char out[384];
    m_muhash.Finalize(out);
    return (TruncatedSHA512Writer(SER_DISK, 0) << out).GetHash();
}

// Reverse Block in case of reorg
bool CoinStatsIndex::ReverseBlock(const CBlock& block, const CBlockIndex* pindex)
{
    CBlockUndo block_undo;
    std::pair<uint256, DBVal> read_out;

    if (pindex->nHeight > 0) {
        if (!UndoReadFromDisk(block_undo, pindex)) {
            return false;
        }

        if (!m_db->Read(DBHeightKey(pindex->nHeight - 1), read_out)) {
            return false;
        }

        uint256 expected_block_hash = pindex->pprev->GetBlockHash();
        if (read_out.first != expected_block_hash) {
            return error("%s: previous block header belongs to unexpected block %s; expected %s",
                         __func__, read_out.first.ToString(), expected_block_hash.ToString());
        }
    }

    MuHash3072 do_muhash;

    // Remove the new utxos that were created from the block
    for (size_t i = 0; i < block.vtx.size(); ++i) {
        const auto& tx = block.vtx.at(i);

        for (size_t j = 0; j < tx->vout.size(); ++j) {
            const CTxOut& out = tx->vout[j];
            COutPoint outpoint = COutPoint(tx->GetHash(), j);
            Coin coin = Coin(out, pindex->nHeight, tx->IsCoinBase());

            // Skip unspendable coins
            if (coin.out.scriptPubKey.IsUnspendable()) continue;

            TruncatedSHA512Writer ss(SER_DISK, 0);
            ss << outpoint;
            ss << (uint32_t)(coin.nHeight * 2 + coin.fCoinBase);
            ss << coin.out;
            do_muhash *= MuHash3072(ss.GetHash().begin());
        }

        // The coinbase tx has no undo data since no former output is spent
        if (i > 0) {
            const auto& tx_undo = block_undo.vtxundo.at(i-1);

            for (size_t j = 0; j < tx_undo.vprevout.size(); ++j) {
                Coin coin = tx_undo.vprevout[j];
                COutPoint outpoint = COutPoint(tx->vin[j].prevout.hash, tx->vin[j].prevout.n);

                TruncatedSHA512Writer ss(SER_DISK, 0);
                ss << outpoint;
                ss << (uint32_t)(coin.nHeight * 2 + coin.fCoinBase);
                ss << coin.out;
                m_muhash *= MuHash3072(ss.GetHash().begin());
            }
        }
    }

    m_muhash /= do_muhash;

    m_nTransactionOutputs = read_out.second.nTransactionOutputs;
    m_nTotalAmount = read_out.second.nTotalAmount;
    m_nBogoSize = read_out.second.nBogoSize;
    m_nDiskSize = read_out.second.nDiskSize;

    if (!m_db->Write(DB_MUHASH, m_muhash)) {
        return false;
    }

    return true;
}
