#! /usr/bin/env python3

import unittest

from hwilib._serialize import ser_compact_size
from hwilib.devices.ledger_bitcoin.client import _decode_signpsbt_yielded_value
from hwilib.devices.ledger_bitcoin.client_base import (
    MusigPartialSignature,
    MusigPubNonce,
    PartialSignature,
    UnknownSignPsbtYieldedObject,
)
from hwilib.devices.ledger_bitcoin.client_command import (
    CCMD_YIELD_MUSIG_PARTIALSIGNATURE_TAG,
    CCMD_YIELD_MUSIG_PUBNONCE_TAG,
)


class TestLedgerBitcoinClient(unittest.TestCase):
    PARTICIPANT_PUBKEY = bytes.fromhex("02" + "11" * 32)
    AGGREGATE_PUBKEY = bytes.fromhex("03" + "22" * 32)
    TAPLEAF_HASH = bytes.fromhex("33" * 32)

    def test_decode_partial_signature(self):
        pubkey = bytes.fromhex("02" + "44" * 32)
        signature = bytes.fromhex("55" * 64)
        result = _decode_signpsbt_yielded_value(
            ser_compact_size(3) + bytes([len(pubkey)]) + pubkey + signature
        )
        self.assertEqual(result, (3, PartialSignature(pubkey, signature)))

    def test_decode_musig_pubnonce(self):
        pubnonce = bytes.fromhex("66" * 66)
        result = _decode_signpsbt_yielded_value(
            ser_compact_size(CCMD_YIELD_MUSIG_PUBNONCE_TAG)
            + ser_compact_size(4)
            + pubnonce
            + self.PARTICIPANT_PUBKEY
            + self.AGGREGATE_PUBKEY
            + self.TAPLEAF_HASH
        )
        self.assertEqual(
            result,
            (
                4,
                MusigPubNonce(
                    participant_pubkey=self.PARTICIPANT_PUBKEY,
                    aggregate_pubkey=self.AGGREGATE_PUBKEY,
                    tapleaf_hash=self.TAPLEAF_HASH,
                    pubnonce=pubnonce,
                ),
            ),
        )

    def test_decode_musig_partial_signature(self):
        partial_signature = bytes.fromhex("77" * 32)
        result = _decode_signpsbt_yielded_value(
            ser_compact_size(CCMD_YIELD_MUSIG_PARTIALSIGNATURE_TAG)
            + ser_compact_size(5)
            + partial_signature
            + self.PARTICIPANT_PUBKEY
            + self.AGGREGATE_PUBKEY
        )
        self.assertEqual(
            result,
            (
                5,
                MusigPartialSignature(
                    participant_pubkey=self.PARTICIPANT_PUBKEY,
                    aggregate_pubkey=self.AGGREGATE_PUBKEY,
                    tapleaf_hash=None,
                    partial_signature=partial_signature,
                ),
            ),
        )

    def test_decode_unknown_yielded_object(self):
        tag = 0x80000001
        opaque_data = bytes.fromhex("deadbeef")
        result = _decode_signpsbt_yielded_value(
            ser_compact_size(tag)
            + ser_compact_size(6)
            + opaque_data
        )
        self.assertEqual(
            result,
            (6, UnknownSignPsbtYieldedObject(tag, opaque_data)),
        )


if __name__ == "__main__":
    unittest.main()
