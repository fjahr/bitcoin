#!/usr/bin/env python3
# Copyright (c) 2025-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test CISA (Cross-Input Signature Aggregation) for witness v2.

Tests witness version 2 output creation, opt-out keypath spending,
half-aggregated spending, and invalid witness rejection.
"""

import hashlib

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.key import (
    compute_xonly_pubkey,
    generate_privkey,
    ORDER,
    sign_schnorr,
    TaggedHash,
    tweak_add_privkey,
    tweak_add_pubkey,
)
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    SEQUENCE_FINAL,
)
from test_framework.script import (
    CScript,
    OP_1,
    OP_2,
    SIGHASH_ALL,
    SIGHASH_DEFAULT,
    TaprootSignatureHash,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet


CISA_MARKER_OPTOUT  = 0xbb
CISA_MARKER_HALFAGG = 0xbc
CISA_MARKER_FULLAGG = 0xbd

WITNESS_V2_PROGRAM_SIZE = 32


def make_v2_key():
    """Generate a keypair tweaked for witness v2 keypath spending (no scripts).

    Returns (internal_privkey, tweaked_privkey, tweaked_xonly_pubkey, scriptPubKey).
    """
    internal_privkey = generate_privkey()
    internal_pubkey, _ = compute_xonly_pubkey(internal_privkey)

    # Taproot-style tweak with empty merkle root (keypath only)
    tweak = TaggedHash("TapTweak", internal_pubkey)
    tweaked_privkey = tweak_add_privkey(internal_privkey, tweak)
    tweaked_pubkey, _ = tweak_add_pubkey(internal_pubkey, tweak)

    spk = CScript([OP_2, tweaked_pubkey])
    assert len(spk) == 34  # OP_2 (1) + push 0x20 (1) + 32 bytes
    return internal_privkey, tweaked_privkey, tweaked_pubkey, spk


def half_aggregate_schnorr(pubkeys, msgs, sigs):
    """Half-aggregate n BIP340 signatures."""
    n = len(sigs)
    assert n > 0 and len(pubkeys) == n and len(msgs) == n

    rs = [sig[:32] for sig in sigs]
    ss = [int.from_bytes(sig[32:], 'big') for sig in sigs]

    # Tagged hash: SHA256(SHA256("HalfAgg/randomizer") || SHA256("HalfAgg/randomizer"))
    tag = hashlib.sha256(b"HalfAgg/randomizer").digest()
    h = hashlib.sha256(tag + tag)

    s_agg = 0
    for i in range(n):
        # Feed R_i || pk_i || msg_i into running hash
        h.update(rs[i])
        h.update(pubkeys[i])
        h.update(msgs[i])

        if i == 0:
            # z_0 = 1 implicitly
            s_agg = ss[0]
        else:
            z_i = int.from_bytes(h.copy().digest(), 'big') % ORDER
            s_agg = (s_agg + z_i * ss[i]) % ORDER

    return b''.join(rs) + s_agg.to_bytes(32, 'big')


def fund_v2_output(wallet, node, spk, amount=100_000):
    """Fund a v2 output and mine it. Returns (txid, vout, amount)."""
    res = wallet.send_to(from_node=node, scriptPubKey=spk, amount=amount)
    txid = res["txid"]
    vout = res["sent_vout"]
    return txid, vout, amount


class CISATest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[]]

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.nodes[0], COINBASE_MATURITY + 10)

        self.test_v2_output_standardness()
        self.test_optout_keypath_spend()
        self.test_optout_explicit_sighash()
        self.test_halfagg_two_inputs()
        self.test_halfagg_three_inputs()
        self.test_mixed_v1_v2_inputs()
        self.test_invalid_empty_witness()
        self.test_invalid_bad_marker()
        self.test_invalid_bad_optout_sig()
        self.test_invalid_orphaned_marker()

    def fund_and_mine(self, spk, amount=100_000):
        """Fund a v2 output and mine it into a block."""
        txid, vout, amt = fund_v2_output(self.wallet, self.nodes[0], spk, amount)
        self.generate(self.nodes[0], 1)
        return txid, vout, amt

    def spend_v2(self, inputs, out_spk, out_amount, witness_fn):
        """Build a tx spending v2 inputs and set witnesses via witness_fn."""
        tx = CTransaction()
        tx.version = 2
        tx.vin = [
            CTxIn(outpoint=COutPoint(int(txid, 16), vout), nSequence=SEQUENCE_FINAL)
            for txid, vout, *_ in inputs
        ]
        tx.vout = [CTxOut(out_amount, out_spk)]

        spent_utxos = [CTxOut(amt, spk) for _, _, amt, _, _, spk in inputs]
        keys = [(tpriv, tpub) for _, _, _, tpriv, tpub, _ in inputs]

        witness_fn(tx, spent_utxos, keys)
        return tx

    def send_and_mine(self, tx, expect_accept=True):
        """Send a tx and optionally mine it."""
        node = self.nodes[0]
        tx_hex = tx.serialize().hex()
        if expect_accept:
            node.sendrawtransaction(tx_hex, 0)
            self.generate(node, 1)
        else:
            assert_raises_rpc_error(-26, None, node.sendrawtransaction, tx_hex, 0)

    def anyone_can_spend_spk(self):
        """Simple OP_1 output for change/destinations."""
        return CScript([OP_1, bytes(32)])

    def test_v2_output_standardness(self):
        self.log.info("Testing v2 output creation and standardness")

        _, _, _, spk = make_v2_key()
        txid, vout, amt = fund_v2_output(self.wallet, self.nodes[0], spk)

        # Verify it's in the mempool
        mempool = self.nodes[0].getrawmempool()
        assert txid in mempool

        # Mine it
        self.generate(self.nodes[0], 1)

        # Verify the UTXO exists
        utxo = self.nodes[0].gettxout(txid, vout)
        assert utxo is not None
        assert_equal(utxo["scriptPubKey"]["type"], "witness_v2_cisa")

    def test_optout_keypath_spend(self):
        self.log.info("Testing opt-out keypath spend (SIGHASH_DEFAULT)")

        _, tpriv, tpub, spk = make_v2_key()
        txid, vout, amt = self.fund_and_mine(spk)

        fee = 1000
        dest_spk = self.anyone_can_spend_spk()

        def set_optout_witness(tx, spent_utxos, keys):
            sighash = TaprootSignatureHash(tx, spent_utxos, SIGHASH_DEFAULT, input_index=0)
            sig = sign_schnorr(keys[0][0], sighash)
            # Opt-out witness: single element [0xbb || 64-byte sig]
            witness_elem = bytes([CISA_MARKER_OPTOUT]) + sig
            tx.wit.vtxinwit = [CTxInWitness()]
            tx.wit.vtxinwit[0].scriptWitness.stack = [witness_elem]

        inputs = [(txid, vout, amt, tpriv, tpub, spk)]
        tx = self.spend_v2(inputs, dest_spk, amt - fee, set_optout_witness)
        self.send_and_mine(tx, expect_accept=True)

    def test_optout_explicit_sighash(self):
        self.log.info("Testing opt-out keypath spend (SIGHASH_ALL)")

        _, tpriv, tpub, spk = make_v2_key()
        txid, vout, amt = self.fund_and_mine(spk)

        fee = 1000
        dest_spk = self.anyone_can_spend_spk()

        def set_optout_witness_all(tx, spent_utxos, keys):
            sighash = TaprootSignatureHash(tx, spent_utxos, SIGHASH_ALL, input_index=0)
            sig = sign_schnorr(keys[0][0], sighash)
            # Opt-out with explicit sighash: [0xbb || sighash_byte || 64-byte sig]
            witness_elem = bytes([CISA_MARKER_OPTOUT, SIGHASH_ALL]) + sig
            tx.wit.vtxinwit = [CTxInWitness()]
            tx.wit.vtxinwit[0].scriptWitness.stack = [witness_elem]

        inputs = [(txid, vout, amt, tpriv, tpub, spk)]
        tx = self.spend_v2(inputs, dest_spk, amt - fee, set_optout_witness_all)
        self.send_and_mine(tx, expect_accept=True)

    def test_halfagg_two_inputs(self):
        self.log.info("Testing half-aggregated spend (2 inputs)")

        # Create two separate v2 outputs
        _, tpriv0, tpub0, spk0 = make_v2_key()
        _, tpriv1, tpub1, spk1 = make_v2_key()
        txid0, vout0, amt0 = self.fund_and_mine(spk0)
        txid1, vout1, amt1 = self.fund_and_mine(spk1)

        fee = 1500
        dest_spk = self.anyone_can_spend_spk()

        def set_halfagg_witness(tx, spent_utxos, keys):
            # Compute individual sighashes
            sighash0 = TaprootSignatureHash(tx, spent_utxos, SIGHASH_DEFAULT, input_index=0)
            sighash1 = TaprootSignatureHash(tx, spent_utxos, SIGHASH_DEFAULT, input_index=1)

            # Sign individually
            sig0 = sign_schnorr(keys[0][0], sighash0)
            sig1 = sign_schnorr(keys[1][0], sighash1)

            # Half-aggregate
            aggsig = half_aggregate_schnorr(
                [keys[0][1], keys[1][1]],  # tweaked x-only pubkeys
                [sighash0, sighash1],
                [sig0, sig1],
            )
            assert len(aggsig) == (2 + 1) * 32  # 96 bytes for n=2

            # Input 0 (non-final): marker only
            # Input 1 (final): marker + aggsig
            tx.wit.vtxinwit = [CTxInWitness(), CTxInWitness()]
            tx.wit.vtxinwit[0].scriptWitness.stack = [bytes([CISA_MARKER_HALFAGG])]
            tx.wit.vtxinwit[1].scriptWitness.stack = [bytes([CISA_MARKER_HALFAGG]) + aggsig]

        inputs = [
            (txid0, vout0, amt0, tpriv0, tpub0, spk0),
            (txid1, vout1, amt1, tpriv1, tpub1, spk1),
        ]
        tx = self.spend_v2(inputs, dest_spk, amt0 + amt1 - fee, set_halfagg_witness)
        self.send_and_mine(tx, expect_accept=True)

    def test_halfagg_three_inputs(self):
        self.log.info("Testing half-aggregated spend (3 inputs)")

        keys = [make_v2_key() for _ in range(3)]
        funded = [self.fund_and_mine(k[3]) for k in keys]

        fee = 2000
        dest_spk = self.anyone_can_spend_spk()

        def set_halfagg_witness_3(tx, spent_utxos, key_pairs):
            sighashes = [
                TaprootSignatureHash(tx, spent_utxos, SIGHASH_DEFAULT, input_index=i)
                for i in range(3)
            ]
            sigs = [sign_schnorr(key_pairs[i][0], sighashes[i]) for i in range(3)]
            pubkeys = [key_pairs[i][1] for i in range(3)]

            aggsig = half_aggregate_schnorr(pubkeys, sighashes, sigs)
            assert len(aggsig) == (3 + 1) * 32  # 128 bytes for n=3

            tx.wit.vtxinwit = [CTxInWitness() for _ in range(3)]
            tx.wit.vtxinwit[0].scriptWitness.stack = [bytes([CISA_MARKER_HALFAGG])]
            tx.wit.vtxinwit[1].scriptWitness.stack = [bytes([CISA_MARKER_HALFAGG])]
            tx.wit.vtxinwit[2].scriptWitness.stack = [bytes([CISA_MARKER_HALFAGG]) + aggsig]

        total = sum(f[2] for f in funded)
        inputs = [
            (funded[i][0], funded[i][1], funded[i][2], keys[i][1], keys[i][2], keys[i][3])
            for i in range(3)
        ]
        tx = self.spend_v2(inputs, dest_spk, total - fee, set_halfagg_witness_3)
        self.send_and_mine(tx, expect_accept=True)

    def test_mixed_v1_v2_inputs(self):
        self.log.info("Testing mixed v1 + v2 input transaction")

        node = self.nodes[0]

        # Create a v2 output
        _, tpriv_v2, tpub_v2, spk_v2 = make_v2_key()
        txid_v2, vout_v2, amt_v2 = self.fund_and_mine(spk_v2)

        # Create a v1 (taproot) output with the same key structure
        internal_privkey = generate_privkey()
        internal_pubkey, _ = compute_xonly_pubkey(internal_privkey)
        tweak = TaggedHash("TapTweak", internal_pubkey)
        tpriv_v1 = tweak_add_privkey(internal_privkey, tweak)
        tpub_v1, _ = tweak_add_pubkey(internal_pubkey, tweak)
        spk_v1 = CScript([OP_1, tpub_v1])  # v1 taproot
        txid_v1, vout_v1, amt_v1 = self.fund_and_mine(spk_v1)

        fee = 1500
        dest_spk = self.anyone_can_spend_spk()
        total = amt_v1 + amt_v2

        tx = CTransaction()
        tx.version = 2
        tx.vin = [
            CTxIn(outpoint=COutPoint(int(txid_v1, 16), vout_v1), nSequence=SEQUENCE_FINAL),
            CTxIn(outpoint=COutPoint(int(txid_v2, 16), vout_v2), nSequence=SEQUENCE_FINAL),
        ]
        tx.vout = [CTxOut(total - fee, dest_spk)]

        spent_utxos = [CTxOut(amt_v1, spk_v1), CTxOut(amt_v2, spk_v2)]

        # v1 input: standard BIP341 keypath sig
        sighash_v1 = TaprootSignatureHash(tx, spent_utxos, SIGHASH_DEFAULT, input_index=0)
        sig_v1 = sign_schnorr(tpriv_v1, sighash_v1)

        # v2 input: opt-out keypath
        sighash_v2 = TaprootSignatureHash(tx, spent_utxos, SIGHASH_DEFAULT, input_index=1)
        sig_v2 = sign_schnorr(tpriv_v2, sighash_v2)

        tx.wit.vtxinwit = [CTxInWitness(), CTxInWitness()]
        # v1: bare 64-byte sig (standard taproot)
        tx.wit.vtxinwit[0].scriptWitness.stack = [sig_v1]
        # v2: opt-out [0xbb || sig]
        tx.wit.vtxinwit[1].scriptWitness.stack = [bytes([CISA_MARKER_OPTOUT]) + sig_v2]

        self.send_and_mine(tx, expect_accept=True)

    def test_invalid_empty_witness(self):
        self.log.info("Testing rejection of empty witness")

        _, tpriv, tpub, spk = make_v2_key()
        txid, vout, amt = self.fund_and_mine(spk)

        fee = 1000
        dest_spk = self.anyone_can_spend_spk()

        def set_empty_witness(tx, spent_utxos, keys):
            tx.wit.vtxinwit = [CTxInWitness()]
            tx.wit.vtxinwit[0].scriptWitness.stack = []

        inputs = [(txid, vout, amt, tpriv, tpub, spk)]
        tx = self.spend_v2(inputs, dest_spk, amt - fee, set_empty_witness)
        self.send_and_mine(tx, expect_accept=False)

    def test_invalid_bad_marker(self):
        self.log.info("Testing rejection of bad marker byte")

        _, tpriv, tpub, spk = make_v2_key()
        txid, vout, amt = self.fund_and_mine(spk)

        fee = 1000
        dest_spk = self.anyone_can_spend_spk()

        def set_bad_marker(tx, spent_utxos, keys):
            sighash = TaprootSignatureHash(tx, spent_utxos, SIGHASH_DEFAULT, input_index=0)
            sig = sign_schnorr(keys[0][0], sighash)
            # Use an invalid marker byte (0xaa instead of 0xbb/0xbc/0xbd)
            witness_elem = bytes([0xaa]) + sig
            tx.wit.vtxinwit = [CTxInWitness()]
            tx.wit.vtxinwit[0].scriptWitness.stack = [witness_elem]

        inputs = [(txid, vout, amt, tpriv, tpub, spk)]
        tx = self.spend_v2(inputs, dest_spk, amt - fee, set_bad_marker)
        self.send_and_mine(tx, expect_accept=False)

    def test_invalid_bad_optout_sig(self):
        self.log.info("Testing rejection of invalid opt-out signature")

        _, tpriv, tpub, spk = make_v2_key()
        txid, vout, amt = self.fund_and_mine(spk)

        fee = 1000
        dest_spk = self.anyone_can_spend_spk()

        def set_bad_sig(tx, spent_utxos, keys):
            # Sign with a random wrong key
            wrong_key = generate_privkey()
            sighash = TaprootSignatureHash(tx, spent_utxos, SIGHASH_DEFAULT, input_index=0)
            sig = sign_schnorr(wrong_key, sighash)
            witness_elem = bytes([CISA_MARKER_OPTOUT]) + sig
            tx.wit.vtxinwit = [CTxInWitness()]
            tx.wit.vtxinwit[0].scriptWitness.stack = [witness_elem]

        inputs = [(txid, vout, amt, tpriv, tpub, spk)]
        tx = self.spend_v2(inputs, dest_spk, amt - fee, set_bad_sig)
        self.send_and_mine(tx, expect_accept=False)

    def test_invalid_orphaned_marker(self):
        self.log.info("Testing rejection of orphaned half-agg marker")

        _, tpriv, tpub, spk = make_v2_key()
        txid, vout, amt = self.fund_and_mine(spk)

        fee = 1000
        dest_spk = self.anyone_can_spend_spk()

        def set_orphaned_marker(tx, spent_utxos, keys):
            # Just a half-agg marker with no aggregate signature
            tx.wit.vtxinwit = [CTxInWitness()]
            tx.wit.vtxinwit[0].scriptWitness.stack = [bytes([CISA_MARKER_HALFAGG])]

        inputs = [(txid, vout, amt, tpriv, tpub, spk)]
        tx = self.spend_v2(inputs, dest_spk, amt - fee, set_orphaned_marker)
        self.send_and_mine(tx, expect_accept=False)


if __name__ == '__main__':
    CISATest(__file__).main()
