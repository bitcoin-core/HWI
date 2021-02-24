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

if __name__ == "__main__":
    unittest.main()
