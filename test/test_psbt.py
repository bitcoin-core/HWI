#! /usr/bin/env python3

from hwilib.psbt import PSBT
from hwilib.errors import PSBTSerializationError
import json
import os
import unittest

class TestPSBT(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Open the data file
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/test_psbt.json'), encoding='utf-8') as f:
            cls.data = json.load(f)

    def test_invalid_psbt(self):
        for invalid in self.data['invalid']:
            with self.subTest(invalid=invalid):
                with self.assertRaises(PSBTSerializationError):
                    psbt = PSBT()
                    psbt.deserialize(invalid)

    def test_valid_psbt(self):
        for valid in self.data['valid']:
            with self.subTest(valid=valid):
                psbt = PSBT()
                psbt.deserialize(valid)
                serd = psbt.serialize()
                self.assertEqual(valid, serd)

    def test_lock_time(self):
        for valid, lock_time in self.data['locktimes']:
            with self.subTest(valid=valid):
                psbt = PSBT()
                psbt.deserialize(valid)
                self.assertEqual(psbt.compute_lock_time(), lock_time)

    def test_conflicting_lock_time(self):
        for valid in self.data['conflicting_locktimes']:
            with self.subTest(valid=valid):
                psbt = PSBT()
                psbt.deserialize(valid)
                with self.assertRaises(PSBTSerializationError):
                    psbt.compute_lock_time()

    def test_convert_to_v0(self):
        # BIP 370 vector "1 input, 2 output updated PSBTv2, with PSBT_IN_SEQUENCE,
        # and all locktime fields"; the height locktime of 10000 wins
        psbt = PSBT()
        psbt.deserialize("cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQECAfsEAgAAAAABAFICAAAAAcGqJW4hS5ahgi+T3kK/87Xz/40FGTBuNRXXUVpegFsSAAAAAAD/////ARjGmjsAAAAAFgAUsKOvFEIIQSaTyn0WaFK1LbCu8G4AAAAAAQEfGMaaOwAAAAAWABSwo68UQghBJpPKfRZoUrUtsK7wbgEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAEQBP7///8BEQSMjcRiARIEECcAAAAiAgLWAfhIRqZ1X3dr4A49nej7EKzJNfuDxF+wFi1MrVq3khj2nYc+VAAAgAEAAIAAAACAAAAAACoAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAIgIC42+/9T3VNAcM+P05ZhRoDzV6m4Xbc0C/HPp0XSrXs0AY9p2HPlQAAIABAACAAAAAgAEAAABkAAAAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==")
        psbt.convert_to_v0()

        self.assertEqual(psbt.version, 0)
        self.assertEqual(psbt.tx.nVersion, 2)
        self.assertEqual(len(psbt.tx.vin), 1)
        self.assertEqual(psbt.tx.vin[0].nSequence, 0xfffffffe)
        self.assertEqual(len(psbt.tx.vout), 2)
        self.assertEqual(psbt.tx.nLockTime, 10000)

        # BIP 370 vector "1 input, 2 output PSBTv2, required fields only",
        # which omits PSBT_IN_SEQUENCE
        psbt = PSBT()
        psbt.deserialize("cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==")
        psbt.convert_to_v0()

        self.assertEqual(psbt.tx.vin[0].nSequence, 0xffffffff)

    def test_has_fingerprint(self):
        cases = [
            ("BIP32", 7, {"19542eb0": True, "00000001": False}),
            ("Taproot BIP32", 22, {"7c461e5d": True, "00000001": False}),
        ]
        for name, vector, fingerprints in cases:
            with self.subTest(name=name):
                psbt = PSBT()
                psbt.deserialize(self.data["valid"][vector])
                for fingerprint, expected in fingerprints.items():
                    self.assertEqual(
                        psbt.inputs[0].has_fingerprint(bytes.fromhex(fingerprint)),
                        expected,
                    )

    def test_has_signature(self):
        cases = [
            ("partial signature", 4, {"b4a6ba67": True}),
            (
                "partial signature for another fingerprint",
                7,
                {"19542eb0": True, "e81a5744": False},
            ),
            ("Taproot key path", 9, {"772b2da7": True}),
            (
                "Taproot script path",
                22,
                {"2680dd6e": True, "580b0887": False},
            ),
        ]
        for name, vector, fingerprints in cases:
            with self.subTest(name=name):
                psbt = PSBT()
                psbt.deserialize(self.data["valid"][vector])
                for fingerprint, expected in fingerprints.items():
                    self.assertEqual(
                        psbt.inputs[0].has_signature(bytes.fromhex(fingerprint)),
                        expected,
                    )

if __name__ == "__main__":
    unittest.main()
