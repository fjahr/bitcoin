#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Compute a version 3 snapshot's hash-and-size chunk Merkle commitment."""
import argparse
import hashlib
import struct

CHUNK_SIZE = 262144


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def read_exact(f, size):
    data = f.read(size)
    if len(data) != size:
        raise ValueError("Truncated snapshot")
    return data


def chunk_descriptors(f):
    header = read_exact(f, 51)
    if header[:5] != b'utxo\xff' or int.from_bytes(header[5:7], 'little') != 3:
        raise ValueError("Expected a version 3 snapshot")
    yield sha256d(header), len(header)
    while first := f.read(1):
        marker = first[0]
        extra = {253: 2, 254: 4, 255: 8}.get(marker, 0)
        prefix = first + read_exact(f, extra)
        size = int.from_bytes(prefix[1:], 'little') if extra else marker
        if not 0 < size <= CHUNK_SIZE or (extra and size < {2: 253, 4: 65536, 8: 2**32}[extra]):
            raise ValueError("Invalid snapshot chunk size")
        chunk = prefix + read_exact(f, size)
        yield sha256d(chunk), len(chunk)


def compute_merkle_root(chunks):
    hashes = [sha256d(b'\x00' + struct.pack('<I', size) + hash) for hash, size in chunks]
    while len(hashes) > 1:
        hashes = [sha256d(b'\x01' + hashes[i] + hashes[i + 1]) if i + 1 < len(hashes) else hashes[i]
                  for i in range(0, len(hashes), 2)]
    return hashes[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", help="Path to the version 3 dumptxoutset snapshot")
    args = parser.parse_args()
    with open(args.snapshot, 'rb') as f:
        chunks = list(chunk_descriptors(f))
    if len(chunks) > 100000:
        raise ValueError("Too many chunks for a single utxotree message")
    print(f"Size: {sum(size for _, size in chunks)} bytes")
    print(f"Chunks: {len(chunks)}")
    print(f"Merkle root: {compute_merkle_root(chunks)[::-1].hex()}")


if __name__ == "__main__":
    main()
