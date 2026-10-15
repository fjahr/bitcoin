// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/utxo_snapshot.h>

#include <streams.h>
#include <sync.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/log.h>

#include <cstdio>
#include <optional>
#include <string>

namespace node {

bool WriteSnapshotBaseBlockhash(const fs::path& path, const uint256& base_blockhash)
{
    FILE* file{fsbridge::fopen(path, "wb")};
    AutoFile afile{file};
    if (afile.IsNull()) {
        LogError("[snapshot] failed to open base blockhash file for writing: %s",
                  fs::PathToString(path));
        return false;
    }
    afile << base_blockhash;

    if (afile.fclose() != 0) {
        LogError("[snapshot] failed to close base blockhash file %s after writing",
                  fs::PathToString(path));
        return false;
    }
    return true;
}

std::optional<uint256> ReadSnapshotBaseBlockhash(const fs::path& path)
{
    const std::string path_str = fs::PathToString(path);

    uint256 base_blockhash;
    FILE* file{fsbridge::fopen(path, "rb")};
    AutoFile afile{file};
    if (afile.IsNull()) {
        LogWarning("[snapshot] failed to open base blockhash file for reading: %s",
            path_str);
        return std::nullopt;
    }
    afile >> base_blockhash;

    int64_t position = afile.tell();
    afile.seek(0, SEEK_END);
    if (position != afile.tell()) {
        LogWarning("[snapshot] unexpected trailing data in %s", path_str);
    }
    return base_blockhash;
}

std::optional<fs::path> FindAssumeutxoChainstateDir(const fs::path& data_dir)
{
    fs::path possible_dir =
        data_dir / fs::u8path(strprintf("chainstate%s", SNAPSHOT_CHAINSTATE_SUFFIX));

    if (fs::exists(possible_dir)) {
        return possible_dir;
    }
    return std::nullopt;
}

} // namespace node
