// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_LTHASH_H
#define BITCOIN_CRYPTO_LTHASH_H

#include <stdint.h>

class LtHash
{
public:
    /* Default checksum is a 256 values array of 64 bit values */
    uint64_t checksum_[256];

    /* The empty set. */
    LtHash() noexcept;

    /* Initialize with a single 32-byte key in it. */
    explicit LtHash(const unsigned char* key32) noexcept;

    /* Add a hash (resulting in a union of the sets). */
    LtHash& add(const LtHash& addHash) noexcept;

    /* Remove a hash (resulting in a difference of the sets). */
    LtHash& remove(const LtHash& removeHash) noexcept;

    /* Finalize output of the 2048 byte checksum. Does not change this object's value. */
    void Finalize(unsigned char* out) noexcept;
};

#endif // BITCOIN_CRYPTO_LTHASH_H
