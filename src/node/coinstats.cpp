// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/coinstats.h>

#include <coins.h>
#include <hash.h>
#include <index/coinstatsindex.h>
#include <serialize.h>
#include <uint256.h>
#include <util/system.h>
#include <validation.h>

#include <map>

// Database-independent, meaningless metric indicating the UTXO set size
uint64_t GetBogoSize(const CScript& scriptPubKey)
{
    return 32 /* txid */ +
           4 /* vout index */ +
           4 /* height + coinbase */ +
           8 /* amount */ +
           2 /* scriptPubKey len */ +
           scriptPubKey.size() /* scriptPubKey */;
}

static bool CanUseIndex(CHashWriter& ss)
{
    return false;
}
static bool CanUseIndex(std::nullptr_t)
{
    if (g_coin_stats_index) {
        return true;
    }
    return false;
}

static void ApplyStats(CCoinsStats& stats, CHashWriter& ss, const uint256& hash, const std::map<uint32_t, Coin>& outputs)
{
    assert(!outputs.empty());
    ss << hash;
    ss << VARINT(outputs.begin()->second.nHeight * 2 + outputs.begin()->second.fCoinBase ? 1u : 0u);
    for (const auto& output : outputs) {
        ss << VARINT(output.first + 1);
        ss << output.second.out.scriptPubKey;
        ss << VARINT_MODE(output.second.out.nValue, VarIntMode::NONNEGATIVE_SIGNED);
        stats.nTransactionOutputs++;
        stats.nTotalAmount += output.second.out.nValue;
        stats.nBogoSize += GetBogoSize(output.second.out.scriptPubKey);
    }
    ss << VARINT(0u);
}

static void ApplyStats(CCoinsStats& stats, std::nullptr_t, const uint256& hash, const std::map<uint32_t, Coin>& outputs)
{
    assert(!outputs.empty());
    for (const auto& output : outputs) {
        stats.nTransactionOutputs++;
        stats.nTotalAmount += output.second.out.nValue;
        stats.nBogoSize += GetBogoSize(output.second.out.scriptPubKey);
    }
}

//! Calculate statistics about the unspent transaction output set
template <typename T>
static bool GetUTXOStats(CCoinsView* view, CCoinsStats& stats, T hash_obj, const std::function<void()>& interruption_point, const CBlockIndex* pindex)
{
    stats = CCoinsStats();
    std::unique_ptr<CCoinsViewCursor> pcursor(view->Cursor());
    assert(pcursor);

    if (pindex == nullptr) {
        {
            LOCK(cs_main);
            pindex = LookupBlockIndex(pcursor->GetBestBlock());
        }
    }

    stats.hashBlock = pindex->GetBlockHash();
    stats.nHeight = pindex->nHeight;

    // Use CoinStatsIndex if it is available and hash_type none was requested
    if (CanUseIndex(hash_obj)) {
        if (g_coin_stats_index->LookupStats(pindex, stats)) {
            return true;
        } else {
            return false;
        }
    }

    PrepareHash(hash_obj, stats);

    uint256 prevkey;
    std::map<uint32_t, Coin> outputs;
    while (pcursor->Valid()) {
        interruption_point();
        COutPoint key;
        Coin coin;
        if (pcursor->GetKey(key) && pcursor->GetValue(coin)) {
            if (!outputs.empty() && key.hash != prevkey) {
                ApplyStats(stats, hash_obj, prevkey, outputs);
                outputs.clear();
            }
            prevkey = key.hash;
            outputs[key.n] = std::move(coin);
            stats.coins_count++;
        } else {
            return error("%s: unable to read value", __func__);
        }
        pcursor->Next();
    }
    if (!outputs.empty()) {
        ApplyStats(stats, hash_obj, prevkey, outputs);
    }

    FinalizeHash(hash_obj, stats);

    stats.nDiskSize = view->EstimateSize();
    return true;
}

bool GetUTXOStats(CCoinsView* view, CCoinsStats& stats, CoinStatsHashType hash_type, const std::function<void()>& interruption_point, const CBlockIndex* pindex)
{
    switch (hash_type) {
    case(CoinStatsHashType::HASH_SERIALIZED): {
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        return GetUTXOStats(view, stats, ss, interruption_point, pindex);
    }
    case(CoinStatsHashType::NONE): {
        return GetUTXOStats(view, stats, nullptr, interruption_point, pindex);
    }
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

// The legacy hash serializes the hashBlock
static void PrepareHash(CHashWriter& ss, CCoinsStats& stats)
{
    ss << stats.hashBlock;
}
static void PrepareHash(std::nullptr_t, CCoinsStats& stats) {}

static void FinalizeHash(CHashWriter& ss, CCoinsStats& stats)
{
    stats.hashSerialized = ss.GetHash();
}
static void FinalizeHash(std::nullptr_t, CCoinsStats& stats) {}
