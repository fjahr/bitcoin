#!/usr/bin/env python3
# Copyright (c) 2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the getblockfrompeer RPC."""

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

class GetBlockFromPeerTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.extra_args = [
            [],
            [],
            ["-fastprune", "-prune=1"]
        ]

    def setup_network(self):
        self.setup_nodes()

    def check_for_block(self, node, hash):
        try:
            node.getblock(hash)
            return True
        except JSONRPCException:
            return False

    def run_test(self):
        self.log.info("Mine 4 blocks on Node 0")
        self.nodes[0].generate(4)
        assert_equal(self.nodes[0].getblockcount(), 204)

        self.log.info("Mine competing 3 blocks on Node 1")
        self.nodes[1].generate(3)
        assert_equal(self.nodes[1].getblockcount(), 203)
        short_tip = self.nodes[1].getbestblockhash()

        self.log.info("Connect nodes to sync headers")
        self.connect_nodes(0, 1)
        self.sync_blocks(self.nodes[0:1])

        self.log.info("Node 0 should only have the header for node 1's block 3")
        for x in self.nodes[0].getchaintips():
            if x['hash'] == short_tip:
                assert_equal(x['status'], "headers-only")
                break
        else:
            raise AssertionError("short tip not synced")
        assert_raises_rpc_error(-1, "Block not found on disk", self.nodes[0].getblock, short_tip)

        self.log.info("Fetch block from node 1")
        peers = self.nodes[0].getpeerinfo()
        assert_equal(len(peers), 1)
        peer_0_peer_1_id = peers[0]["id"]

        self.log.info("Arguments must be sensible")
        assert_raises_rpc_error(-8, "hash must be of length 64 (not 4, for '1234')", self.nodes[0].getblockfrompeer, "1234", 0)

        self.log.info("We must already have the header")
        assert_raises_rpc_error(-1, "Block header missing", self.nodes[0].getblockfrompeer, "00" * 32, 0)

        self.log.info("Non-existent peer generates error")
        assert_raises_rpc_error(-1, "Failed to fetch block from peer", self.nodes[0].getblockfrompeer, short_tip, peer_0_peer_1_id + 1)

        self.log.info("Successful fetch")
        result = self.nodes[0].getblockfrompeer(short_tip, peer_0_peer_1_id)
        self.wait_until(lambda: self.check_for_block(self.nodes[0], short_tip), timeout=1)
        assert(not "warnings" in result)

        self.log.info("Don't fetch blocks we already have")
        result = self.nodes[0].getblockfrompeer(short_tip, peer_0_peer_1_id)
        assert("warnings" in result)
        assert_equal(result["warnings"], "Block already downloaded")

        self.log.info("Connect pruned node")
        # We need to generate more blocks to be able to prune
        self.generate(self.nodes[0], 400)
        self.connect_nodes(0, 2)
        self.sync_blocks()
        pruneheight = self.nodes[2].pruneblockchain(300)
        assert_equal(pruneheight, 248)
        # Ensure the block is actually pruned
        pruned_block = self.nodes[0].getblockhash(2)
        assert_raises_rpc_error(-1, "Block not available (pruned data)", self.nodes[2].getblock, pruned_block)

        self.log.info("Fetch pruned block")
        peers = self.nodes[2].getpeerinfo()
        assert_equal(len(peers), 1)
        peer_2_peer_0_id = peers[0]["id"]
        result = self.nodes[2].getblockfrompeer(pruned_block, peer_2_peer_0_id)
        self.wait_until(lambda: self.check_for_block(self.nodes[2], pruned_block), timeout=1)
        assert(not "warnings" in result)


if __name__ == '__main__':
    GetBlockFromPeerTest().main()
