// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INDEX_COINSTATSINDEX_H
#define BITCOIN_INDEX_COINSTATSINDEX_H

#include <chain.h>
#include <crypto/muhash.h>
#include <flatfile.h>
#include <index/base.h>
#include <node/coinstats.h>

/**
 * UtxoHashSet maintains a rolling hash of the utxo set and
 * caches a hash digest for every block.
 */
class CoinStatsIndex final : public BaseIndex
{
private:
    std::string m_name;
    std::unique_ptr<BaseIndex::DB> m_db;
    MuHash3072 m_muhash;

    // Digest of the current Muhash object
    uint256 currentHashInternal();

    // Roll back the Muhash of a particular block
    bool ReverseBlock(const CBlock& block, const CBlockIndex* pindex);
protected:
    bool Init() override;

    bool WriteBlock(const CBlock& block, const CBlockIndex* pindex) override;

    bool Rewind(const CBlockIndex* current_tip, const CBlockIndex* new_tip) override;

    BaseIndex::DB& GetDB() const override { return *m_db; }

    const char* GetName() const override { return "coinstatsindex"; }

public:
    // Constructs the index, which becomes available to be queried.
    explicit CoinStatsIndex(size_t n_cache_size, bool f_memory = false, bool f_wipe = false);

    // Look up hash digest for a specific block using CBlockIndex
    bool LookupStats(const CBlockIndex* block_index, CCoinsStats& coins_stats) const;
};

/// The global UTXO set hash object.
extern std::unique_ptr<CoinStatsIndex> g_coin_stats_index;

#endif // BITCOIN_INDEX_COINSTATSINDEX_H
