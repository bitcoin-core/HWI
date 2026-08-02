#!/usr/bin/env python3

import unittest

from hwilib.devices.ledger_registration import (
    decode_policy_registration,
    encode_policy_registration,
)
from hwilib.errors import BadArgumentError


class TestLedgerRegistration(unittest.TestCase):
    def test_round_trip(self) -> None:
        registration = encode_policy_registration(b"\xaa\xbb\xcc", "Møøse")

        self.assertEqual(registration, "03aabbcc054df8f87365")
        self.assertEqual(
            decode_policy_registration(registration),
            (b"\xaa\xbb\xcc", "Møøse"),
        )

    def test_ignores_additional_fields(self) -> None:
        registration = encode_policy_registration(b"\xaa", "name") + "01ff"

        self.assertEqual(decode_policy_registration(registration), (b"\xaa", "name"))

    def test_rejects_invalid_encoding(self) -> None:
        for registration in ["", "zz", "01", "02aa", "01aa"]:
            with self.subTest(registration=registration):
                with self.assertRaises(BadArgumentError):
                    decode_policy_registration(registration)

    def test_rejects_long_fields(self) -> None:
        with self.assertRaises(BadArgumentError):
            encode_policy_registration(b"\x00" * 256, "name")
        with self.assertRaises(BadArgumentError):
            encode_policy_registration(b"\x00", "a" * 256)


if __name__ == "__main__":
    unittest.main()
