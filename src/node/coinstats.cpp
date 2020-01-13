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

static void ApplyStats(CCoinsStats &stats, const COutPoint outpoint, const Coin& coin)
{
    stats.nTransactions++;
    stats.nTransactionOutputs++;
    stats.nTotalAmount += coin.out.nValue;
    stats.nBogoSize += 32 /* txid */ + 4 /* vout index */ + 4 /* height + coinbase */ + 8 /* amount */ +
                       2 /* scriptPubKey len */ + coin.out.scriptPubKey.size() /* scriptPubKey */;
}

//! Calculate statistics about the unspent transaction output set
bool GetUTXOStats(CCoinsView *view, CCoinsStats &stats)
{
    stats = CCoinsStats();
    std::unique_ptr<CCoinsViewCursor> pcursor(view->Cursor());
    assert(pcursor);

    uint256 muhash_buf;
    const CBlockIndex* block_index;
    stats.hashBlock = pcursor->GetBestBlock();
    {
        LOCK(cs_main);
        block_index = LookupBlockIndex(stats.hashBlock);
    }

    stats.nHeight = block_index->nHeight;

    if (!g_coin_stats_index->LookupHash(block_index, muhash_buf)) {
        return false;
    }

    stats.hashSerialized = muhash_buf;

    while (pcursor->Valid()) {
        COutPoint key;
        Coin coin;
        if (pcursor->GetKey(key) && pcursor->GetValue(coin)) {
            ApplyStats(stats, key, coin);
            stats.coins_count++;
        } else {
            return error("%s: unable to read value", __func__);
        }
        pcursor->Next();
    }

    stats.nDiskSize = view->EstimateSize();
    return true;
}
