// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
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

static void ApplyStats(CCoinsStats &stats, CHashWriter& ss, const uint256& hash, const std::map<uint32_t, Coin>& outputs)
{
    assert(!outputs.empty());
    ss << hash;
    ss << VARINT(outputs.begin()->second.nHeight * 2 + outputs.begin()->second.fCoinBase ? 1u : 0u);
    stats.nTransactions++;
    for (const auto& output : outputs) {
        ss << VARINT(output.first + 1);
        ss << output.second.out.scriptPubKey;
        ss << VARINT(output.second.out.nValue, VarIntMode::NONNEGATIVE_SIGNED);
        stats.nTransactionOutputs++;
        stats.nTotalAmount += output.second.out.nValue;
        stats.nBogoSize += 32 /* txid */ + 4 /* vout index */ + 4 /* height + coinbase */ + 8 /* amount */ +
                           2 /* scriptPubKey len */ + output.second.out.scriptPubKey.size() /* scriptPubKey */;
    }
    ss << VARINT(0u);
}

//! Calculate statistics about the unspent transaction output set
bool GetUTXOStats(CCoinsView *view, CCoinsStats &stats)
{
    stats = CCoinsStats();
    std::unique_ptr<CCoinsViewCursor> pcursor(view->Cursor());
    assert(pcursor);

    // Use CoinStatsIndex if possible
    if (g_coin_stats_index) {
        const CBlockIndex* block_index;
        {
            LOCK(cs_main);
            block_index = LookupBlockIndex(pcursor->GetBestBlock());
        }

        if (g_coin_stats_index->LookupStats(block_index, stats)) {
            return true;
        } else {
            return false;
        }
    }

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    stats.hashBlock = pcursor->GetBestBlock();
    {
        LOCK(cs_main);
        stats.nHeight = LookupBlockIndex(stats.hashBlock)->nHeight;
    }
    ss << stats.hashBlock;
    uint256 prevkey;
    std::map<uint32_t, Coin> outputs;
    while (pcursor->Valid()) {
        COutPoint key;
        Coin coin;
        if (pcursor->GetKey(key) && pcursor->GetValue(coin)) {
            if (!outputs.empty() && key.hash != prevkey) {
                ApplyStats(stats, ss, prevkey, outputs);
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
        ApplyStats(stats, ss, prevkey, outputs);
    }
    stats.hashSerialized = ss.GetHash();
    stats.nDiskSize = view->EstimateSize();
    return true;
}

// static void ApplyStats(CCoinsStats &stats, const COutPoint outpoint, const Coin& coin)
// {
//     stats.nTransactions++;
//     stats.nTransactionOutputs++;
//     stats.nTotalAmount += coin.out.nValue;
//     stats.nBogoSize += 32 #<{(| txid |)}># + 4 #<{(| vout index |)}># + 4 #<{(| height + coinbase |)}># + 8 #<{(| amount |)}># +
//                        2 #<{(| scriptPubKey len |)}># + coin.out.scriptPubKey.size() #<{(| scriptPubKey |)}>#;
// }
//
// //! Calculate statistics about the unspent transaction output set
// bool GetUTXOStats(CCoinsView *view, CCoinsStats &stats)
// {
//     stats = CCoinsStats();
//     std::unique_ptr<CCoinsViewCursor> pcursor(view->Cursor());
//     assert(pcursor);
//
//     uint256 muhash_buf;
//     const CBlockIndex* block_index;
//     stats.hashBlock = pcursor->GetBestBlock();
//     {
//         LOCK(cs_main);
//         block_index = LookupBlockIndex(stats.hashBlock);
//     }
//
//     stats.nHeight = block_index->nHeight;
//
//     if (!g_coin_stats_index->LookupHash(block_index, muhash_buf)) {
//         return false;
//     }
//
//     stats.hashSerialized = muhash_buf;
//
//     while (pcursor->Valid()) {
//         COutPoint key;
//         Coin coin;
//         if (pcursor->GetKey(key) && pcursor->GetValue(coin)) {
//             ApplyStats(stats, key, coin);
//             stats.coins_count++;
//         } else {
//             return error("%s: unable to read value", __func__);
//         }
//         pcursor->Next();
//     }
//
//     stats.nDiskSize = view->EstimateSize();
//     return true;
// }
