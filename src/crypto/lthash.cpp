// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/lthash.h>
#include <crypto/chacha20.h>
#include <vector>
#include <compat/endian.h>
#include <crypto/common.h>

const uint64_t kMaskA = 0xffff0000ffff0000ULL;
const uint64_t kMaskB = ~kMaskA;

LtHash::LtHash() noexcept
{
    std::fill(std::begin(this->checksum_), std::end(this->checksum_), 0);
};

LtHash::LtHash(const unsigned char* key32) noexcept
{
    std::vector<unsigned char> tmp(2048);
    ChaCha20 ccBase = ChaCha20(key32, 32);
    ccBase.Keystream(tmp.data(), tmp.size());

    for (size_t pos = 0; pos < 256; pos += 1) {
        this->checksum_[pos] = ReadLE64(tmp.data() + pos * 8);
    }
}

LtHash& LtHash::add(const LtHash& addHash) noexcept
{
    for (size_t pos = 0; pos < 256; pos += 1) {
        uint64_t v1 = this->checksum_[pos];
        uint64_t v2 = addHash.checksum_[pos];
        uint64_t v1a = v1 & kMaskA;
        uint64_t v1b = v1 & kMaskB;
        uint64_t v2a = v2 & kMaskA;
        uint64_t v2b = v2 & kMaskB;
        uint64_t v3a = (v1a + v2a) & kMaskA;
        uint64_t v3b = (v1b + v2b) & kMaskB;
        this->checksum_[pos] = v3a | v3b;
    }
    return *this;
}

LtHash& LtHash::remove(const LtHash& removeHash) noexcept
{
    for (size_t pos = 0; pos < 256; pos += 1) {
        uint64_t v1 = this->checksum_[pos];
        uint64_t v2 = removeHash.checksum_[pos];
        uint64_t v1a = v1 & kMaskA;
        uint64_t v1b = v1 & kMaskB;
        uint64_t v2a = v2 & kMaskA;
        uint64_t v2b = v2 & kMaskB;
        uint64_t v3a = (v1a + (kMaskB - v2a)) & kMaskA;
        uint64_t v3b = (v1b + (kMaskA - v2b)) & kMaskB;
        this->checksum_[pos] = v3a | v3b;
    }

    return *this;
}

void LtHash::Finalize(unsigned char* out) noexcept
{
    for (size_t pos = 0; pos < 256; pos += 1) {
        uint64_t x = this->checksum_[pos];
        unsigned char value[sizeof(x)];
        std::memcpy(value,&x,sizeof(x));

        for (size_t i = 0; i < 8; i += 1) {
            WriteLE64(out + pos * 8 + i, value[i]);
        }
    }
}
