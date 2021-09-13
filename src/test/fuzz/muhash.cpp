// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/muhash.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <vector>

FUZZ_TARGET(muhash)
{
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    std::vector<uint8_t> data{ConsumeRandomLengthByteVector(fuzzed_data_provider)};
    std::vector<uint8_t> data2{ConsumeRandomLengthByteVector(fuzzed_data_provider)};

    MuHash3072 muhash;

    muhash.Insert(data);
    muhash.Insert(data2);

    CallOneOf(
        fuzzed_data_provider,
        [&] {
            // Test that MuHash result is consistent independent of order of operations
            uint256 out;
            muhash.Finalize(out);
            CallOneOf(
                fuzzed_data_provider,
                [&] {
                    MuHash3072 muhash_inverse_order;
                    muhash_inverse_order = MuHash3072();
                    muhash_inverse_order.Insert(data2);
                    muhash_inverse_order.Insert(data);
                    uint256 out2;
                    muhash_inverse_order.Finalize(out2);
                    assert(out == out2);
                },
                [&] {
                    MuHash3072 muhash3;
                    muhash3 *= muhash;
                    uint256 out3;
                    muhash3.Finalize(out3);
                    assert(out == out3);
                });
        },
        [&] {
            // Test that removing all added elements brings the object back to it's initial state
            MuHash3072 muhash3;
            muhash3 *= muhash;
            uint256 out;
            muhash /= muhash;
            muhash.Finalize(out);
            CallOneOf(
                fuzzed_data_provider,
                [&] {
                    uint256 out2;
                    MuHash3072 muhash2;
                    muhash2.Finalize(out2);
                    assert(out == out2);
                },
                [&] {
                    uint256 out3;
                    muhash3.Remove(data);
                    muhash3.Remove(data2);
                    muhash3.Finalize(out3);
                    assert(out == out3);
                });
        });
}
