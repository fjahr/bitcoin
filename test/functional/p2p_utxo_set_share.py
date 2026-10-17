#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test P2P UTXO set sharing."""

import io
import os
import shutil

from test_framework.messages import (
    hash256,
    msg_getutxoset,
    msg_getutxotree,
    msg_utxoset,
    NODE_NETWORK,
    NODE_UTXO_SET,
    NODE_WITNESS,
    deser_compact_size,
    ser_uint256,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet

# Using height 299 because it has a valid assumeutxo param
START_HEIGHT = 199
SNAPSHOT_HEIGHT = 299
CHUNK_SIZE = 262144
EXPECTED_ROOT = "e4b897c61c1524fa3cee065d06001eda5d23a34ecb9dc684dcc890dc8f4ac4df"


def chunk_merkle_root(chunks):
    hashes = [hash256(b'\x00' + chunk.size.to_bytes(4, 'little') + ser_uint256(chunk.hash)) for chunk in chunks]
    while len(hashes) > 1:
        hashes = [hash256(b'\x01' + hashes[i] + hashes[i + 1]) if i + 1 < len(hashes) else hashes[i]
                  for i in range(0, len(hashes), 2)]
    return int.from_bytes(hashes[0], 'little')


class PausingSnapshotPeer(P2PInterface):
    """Serve the header but withhold the coin data to stall the importer."""

    def __init__(self, tree, header):
        super().__init__()
        self.tree = tree
        self.header = header

    def on_getutxotree(self, message):
        self.send_without_ping(self.tree)

    def on_getutxoset(self, message):
        if message.chunk_index == 0:
            self.send_without_ping(msg_utxoset(block_hash=self.tree.block_hash, chunk_index=0, data=self.header))


class UTXOSetShareTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [[], []]

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        self.start_nodes(extra_args=self.extra_args)

    def run_test(self):
        n0 = self.nodes[0]
        n1 = self.nodes[1]
        wallet = MiniWallet(n0)

        # Generate blocks to SNAPSHOT_HEIGHT so blockhash matches the hardcoded
        # assumeutxo parameters for height 299.
        for n in self.nodes:
            n.setmocktime(n.getblockheader(n.getbestblockhash())['time'])

        assert_equal(n0.getblockcount(), START_HEIGHT)
        for i in range(100):
            if i % 3 == 0:
                wallet.send_self_transfer(from_node=n0)
            self.generate(n0, nblocks=1, sync_fun=self.no_op)
            if i == 4:
                temp_invalid = n0.getbestblockhash()
                n0.invalidateblock(temp_invalid)
                self.generateblock(n0, output="raw(aaaa)", transactions=[], sync_fun=self.no_op)
                stale_hash = n0.getbestblockhash()
                n0.invalidateblock(stale_hash)
                n0.reconsiderblock(temp_invalid)
        assert_equal(n0.getblockcount(), SNAPSHOT_HEIGHT)

        # Create UTXO snapshot and place in share directory
        dump_output = n0.dumptxoutset("utxos.dat", "latest")
        snapshot_path = dump_output['path']

        share_dir = os.path.join(n0.datadir_path, "regtest", "share")
        os.makedirs(share_dir, exist_ok=True)
        shutil.copy(snapshot_path, os.path.join(share_dir, "utxos.dat"))

        # Restart serving node to pick up the snapshot. We also start the
        # node in prune mode to have it signal NODE_NETWORK_LIMITED. This
        # means the downloading node won't sync any blocks from the sharing
        # nodes after activating the downloaded snapshot. This avoids a
        # potential race between downloading and validating the (very short
        # chain) and activating the downloaded snapshot.
        self.restart_node(0, extra_args=["-prune=1"])
        n0.setmocktime(n0.getblockheader(n0.getbestblockhash())['time'])

        self.log.info("Test NODE_UTXO_SET service bit is advertised")
        services = n0.getnetworkinfo()['localservicesnames']
        assert 'UTXO_SET' in services

        block_hash = int(dump_output['base_hash'], 16)
        peer = n0.add_p2p_connection(P2PInterface())
        peer.send_and_ping(msg_getutxotree(block_hash))

        self.log.info("Test utxotree hash-and-size list")
        tree = peer.last_message['utxotree']
        assert_equal(tree.block_hash, block_hash)
        assert_equal(tree.version, 3)
        assert_greater_than(len(tree.chunks), 1)
        assert_equal(tree.chunks[0].size, 51)
        # This commitment is independently computed and hardcoded in chainparams.
        assert_equal(chunk_merkle_root(tree.chunks), int(EXPECTED_ROOT, 16))

        self.log.info("Test requesting chunks in reverse order")
        total_chunks = len(tree.chunks)
        chunks = [None] * total_chunks
        for i in reversed(range(total_chunks)):
            peer.send_and_ping(msg_getutxoset(block_hash=block_hash, chunk_index=i))
            chunk = peer.last_message['utxoset']
            assert_equal(chunk.block_hash, block_hash)
            assert_equal(chunk.chunk_index, i)
            assert_equal(len(chunk.data), tree.chunks[i].size)
            assert_equal(int.from_bytes(hash256(chunk.data), 'little'), tree.chunks[i].hash)
            if i:
                payload = io.BytesIO(chunk.data)
                length = deser_compact_size(payload)
                assert 0 < length <= CHUNK_SIZE
                assert_equal(len(payload.read()), length)
            chunks[i] = chunk.data

        self.log.info("Test reassembled data matches original snapshot")
        with open(snapshot_path, 'rb') as f:
            assert_equal(b"".join(chunks), f.read())

        self.log.info("Test invalid chunk index causes disconnect")
        peer2 = n0.add_p2p_connection(P2PInterface())
        bad_req = msg_getutxoset(block_hash=block_hash, chunk_index=total_chunks)
        peer2.send_without_ping(bad_req)
        peer2.wait_for_disconnect()

        self.log.info("Test wrong block hash causes disconnect")
        peer3 = n0.add_p2p_connection(P2PInterface())
        bad_req = msg_getutxoset(block_hash=0xdeadbeef, chunk_index=0)
        peer3.send_without_ping(bad_req)
        peer3.wait_for_disconnect()

        self.log.info("Test node without snapshot does not advertise NODE_UTXO_SET")
        n1_services = n1.getnetworkinfo()['localservicesnames']
        assert 'UTXO_SET' not in n1_services

        self.log.info("Test getutxotree to non-serving node gets no response")
        peer5 = n1.add_p2p_connection(P2PInterface())
        peer5.send_and_ping(msg_getutxotree(block_hash))
        assert 'utxotree' not in peer5.last_message

        self.log.info("Test downloadutxoset with invalid height")
        assert_raises_rpc_error(-8, "No assumeutxo data for height", n1.downloadutxoset, 12345)

        # Transfer headers to downloading node so it can activate snapshot
        for i in range(1, SNAPSHOT_HEIGHT + 1):
            block = n0.getblock(n0.getblockhash(i), 0)
            n1.submitheader(block)
        assert_equal(n1.getblockchaininfo()["headers"], SNAPSHOT_HEIGHT)

        self.log.info("Test importing starts before download completion and shutdown wakes the worker")
        with n1.assert_debug_log([f"[snapshot] loading {dump_output['coins_written']} coins"]):
            n1.downloadutxoset(SNAPSHOT_HEIGHT)
            paused_peer = n1.add_p2p_connection(
                PausingSnapshotPeer(tree, chunks[0]), services=NODE_NETWORK | NODE_WITNESS | NODE_UTXO_SET)
            paused_peer.wait_until(lambda: 'getutxoset' in paused_peer.last_message)
        assert_equal(len(n1.getchainstates()['chainstates']), 1)
        self.restart_node(1)
        assert_equal(n1.getblockchaininfo()['headers'], SNAPSHOT_HEIGHT)
        assert 'UTXO_SET' not in n1.getnetworkinfo()['localservicesnames']

        self.log.info("Test full P2P download via downloadutxoset RPC")
        result = n1.downloadutxoset(SNAPSHOT_HEIGHT)
        assert_equal(result['height'], SNAPSHOT_HEIGHT)

        self.log.info("Test duplicate downloadutxoset is rejected")
        assert_raises_rpc_error(-1, "Failed to start download. A download may already be in progress.", n1.downloadutxoset, SNAPSHOT_HEIGHT)

        # Connect nodes so download can proceed
        self.connect_nodes(0, 1)
        self.wait_until(lambda: len(n1.getchainstates()['chainstates']) == 2, timeout=30)


if __name__ == '__main__':
    UTXOSetShareTest(__file__).main()
