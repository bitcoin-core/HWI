#! /usr/bin/env python3

import unittest

from hwilib.devices.ledger import _prepare_musig2_psbt_for_signing
from hwilib.key import KeyOriginInfo
from hwilib.psbt import PSBT, PartiallySignedInput


class TestLedgerMuSig2(unittest.TestCase):
    MASTER_FP = bytes.fromhex("f5acc2fd")
    OUR_PUBKEY = bytes.fromhex("02" + "11" * 32)
    PEER_PUBKEY = bytes.fromhex("03" + "22" * 32)
    AGGREGATE_PUBKEY = bytes.fromhex("02" + "33" * 32)

    def make_psbt(self):
        psbt = PSBT()
        psbt.version = 2
        psbt_in = PartiallySignedInput(psbt.version)
        psbt_in.tap_bip32_paths[self.OUR_PUBKEY[1:]] = (
            set(),
            KeyOriginInfo(self.MASTER_FP, []),
        )
        psbt.inputs.append(psbt_in)
        return psbt, psbt_in

    def test_peer_pubnonce_is_hidden_during_round_one(self):
        psbt, psbt_in = self.make_psbt()
        peer_key = (self.PEER_PUBKEY, self.AGGREGATE_PUBKEY, None)
        psbt_in.musig2_pub_nonces[peer_key] = b"\x44" * 66

        _prepare_musig2_psbt_for_signing(psbt, self.MASTER_FP)

        self.assertEqual(psbt_in.musig2_pub_nonces, {})

    def test_our_pubnonce_selects_round_two(self):
        psbt, psbt_in = self.make_psbt()
        our_key = (self.OUR_PUBKEY, self.AGGREGATE_PUBKEY, None)
        peer_key = (self.PEER_PUBKEY, self.AGGREGATE_PUBKEY, None)
        psbt_in.musig2_pub_nonces[our_key] = b"\x44" * 66
        psbt_in.musig2_pub_nonces[peer_key] = b"\x55" * 66
        psbt_in.musig2_partial_sigs[peer_key] = b"\x66" * 32

        _prepare_musig2_psbt_for_signing(psbt, self.MASTER_FP)

        self.assertEqual(
            set(psbt_in.musig2_pub_nonces),
            {our_key, peer_key},
        )
        self.assertEqual(psbt_in.musig2_partial_sigs, {})

    def test_partial_signature_still_selects_round_two(self):
        psbt, psbt_in = self.make_psbt()
        peer_key = (self.PEER_PUBKEY, self.AGGREGATE_PUBKEY, None)
        psbt_in.musig2_pub_nonces[peer_key] = b"\x44" * 66
        psbt_in.musig2_partial_sigs[peer_key] = b"\x55" * 32

        _prepare_musig2_psbt_for_signing(psbt, self.MASTER_FP)

        self.assertIn(peer_key, psbt_in.musig2_pub_nonces)
        self.assertEqual(psbt_in.musig2_partial_sigs, {})


if __name__ == "__main__":
    unittest.main()
