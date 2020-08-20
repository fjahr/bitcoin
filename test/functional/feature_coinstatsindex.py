#!/usr/bin/env python3
# Copyright (c) 2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test CoinStatsIndex across nodes.

Test that the values returned by gettxoutsetinfo are consistent
between a node running the coinstatsindex and a node without
the index.
"""

from decimal import Decimal

from test_framework.address import script_to_p2sh
from test_framework.blocktools import (
    create_block,
    create_coinbase,
    create_tx_with_script,
)
from test_framework.messages import (
    CTransaction,
    FromHex,
    ToHex,
    CTxIn,
    COutPoint,
    CTxOut,
    COIN,
    msg_block
)
from test_framework.script import (
    CScript,
    OP_RETURN,
    OP_FALSE,
    SIGHASH_ALL,
    LegacySignatureHash,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    try_rpc,
    wait_until,
)

class CoinStatsIndexTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.supports_cli = False
        self.extra_args = [
            [],
            ["-coinstatsindex"]
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self._test_coin_stats_index()

    def block_sanity_check(self, block_info):
        block_subsidy = 50
        assert_equal(
            block_info['total_prevout_spent_amount'] + block_subsidy,
            block_info['total_new_outputs_ex_coinbase_amount'] + block_info['coinbase_amount'] + block_info['unspendable_amount']
        )

    def _test_coin_stats_index(self):
        node = self.nodes[0]
        index_node = self.nodes[1]

        # Generate a normal transaction and mine it
        node.generate(101)
        address = self.nodes[0].get_deterministic_priv_key().address
        node.sendtoaddress(address=address, amount=10, subtractfeefromamount=True)
        node.generate(1)

        self.sync_blocks(timeout=120)

        self.log.info("Test that gettxoutsetinfo() output is consistent with or without coinstatsindex option")
        wait_until(lambda: not try_rpc(-32603, "Unable to read UTXO set", node.gettxoutsetinfo))
        res0 = node.gettxoutsetinfo('none')
        wait_until(lambda: not try_rpc(-32603, "Unable to read UTXO set", index_node.gettxoutsetinfo))
        res1 = index_node.gettxoutsetinfo('none')

        # The field 'disk_size' is non-deterministic and can thus not be
        # compared across different nodes.
        del res1['disk_size'], res0['disk_size']

        # Everything left should be the same
        assert_equal(res1, res0)

        self.log.info("Test that gettxoutsetinfo() can get fetch data on specific heights with index")

        # Generate a new tip
        node.generate(5)

        # Fetch old stats by height
        res2 = index_node.gettxoutsetinfo('none', 102)
        del res2['disk_size']
        assert_equal(res0, res2)

        # Fetch old stats by hash
        res3 = index_node.gettxoutsetinfo('none', res0['bestblock'])
        del res3['disk_size']
        assert_equal(res0, res3)

        # It does not work without coinstatsindex
        assert_raises_rpc_error(-8, "Querying specific block heights requires CoinStatsIndex", node.gettxoutsetinfo, 'none', 102)

        self.log.info("Test gettxoutsetinfo() with index and verbose flag")

        # Test an older block height that included a normal tx
        res4 = index_node.gettxoutsetinfo('none', 102, True)
        # Genesis block is unspendable
        assert_equal(res4['total_unspendable_amount'], 50)
        assert_equal(res4['block_info'], {
            'unspendable_amount': 0,
            'total_prevout_spent_amount': 50,
            'total_new_outputs_ex_coinbase_amount': Decimal('49.99995560'),
            'coinbase_amount': Decimal('50.00004440')
        })
        self.block_sanity_check(res4['block_info'])

        # Generate and send a normal tx with two outputs
        tx1_inputs = []
        tx1_outputs = {self.nodes[0].getnewaddress(): 21, self.nodes[0].getnewaddress(): 42}
        raw_tx1 = self.nodes[0].createrawtransaction(tx1_inputs, tx1_outputs)
        funded_tx1 = self.nodes[0].fundrawtransaction(raw_tx1)
        signed_tx1 = self.nodes[0].signrawtransactionwithwallet(funded_tx1['hex'])
        tx1_txid = self.nodes[0].sendrawtransaction(signed_tx1['hex'])

        # Find the right position of the 21 BTC output
        tx1_final = self.nodes[0].gettransaction(tx1_txid)
        for output in tx1_final['details']:
            if output['amount'] == Decimal('21.00000000') and output['category'] == 'receive':
                n = output['vout']

        # Generate and send another tx with an OP_RETURN output (which is unspendable)
        tx2 = CTransaction()
        tx2.vin.append(CTxIn(COutPoint(int(tx1_txid, 16), n), b''))
        tx2.vout.append(CTxOut(int(20.99 * COIN), CScript([OP_RETURN] + [OP_FALSE]*30)))
        tx2_hex = self.nodes[0].signrawtransactionwithwallet(ToHex(tx2))['hex']
        self.nodes[0].sendrawtransaction(tx2_hex)

        # Include both txs in a block
        self.nodes[0].generate(1)
        self.sync_all()

        # Check all amounts were registered correctly
        res5 = index_node.gettxoutsetinfo('none', 108, True)
        assert_equal(res5['total_unspendable_amount'], Decimal('70.98999999'))
        assert_equal(res5['block_info'], {
            'unspendable_amount': Decimal('20.98999999'),
            'total_prevout_spent_amount': 111,
            'total_new_outputs_ex_coinbase_amount': Decimal('89.99993620'),
            'coinbase_amount': Decimal('50.01006381')
        })
        self.block_sanity_check(res5['block_info'])

        # Generate a block that does not claim the full block subsidy
        tip = self.nodes[0].getbestblockhash()
        block_time = self.nodes[0].getblock(tip)['time'] + 1
        block = create_block(int(tip, 16), create_coinbase(109, nValue=40), block_time)
        block.solve()
        self.nodes[0].submitblock(ToHex(block))
        self.sync_all()

        res6 = index_node.gettxoutsetinfo('none', 109, True)
        assert_equal(res6['total_unspendable_amount'], Decimal('80.98999999'))
        assert_equal(res6['block_info'], {
            'unspendable_amount': 10,
            'total_prevout_spent_amount': 0,
            'total_new_outputs_ex_coinbase_amount': 0,
            'coinbase_amount': 40,
        })
        self.block_sanity_check(res6['block_info'])

if __name__ == '__main__':
    CoinStatsIndexTest().main()
