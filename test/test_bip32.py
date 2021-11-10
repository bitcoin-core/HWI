#!/usr/bin/env python3
# Copyright (c) 2020 The HWI developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from hwilib.key import (
    ExtendedKey,
    parse_path,
)

import binascii
import json
import os
import unittest

class TestBIP32(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "data/test_bip32.json"), encoding="utf-8") as f:
            cls.data = json.load(f)
            for key in cls.data["serialization"]:
                deser = key["deser"]
                deser["pub_version"] = binascii.unhexlify(deser["pub_version"])
                deser["priv_version"] = binascii.unhexlify(deser["priv_version"])
                deser["hex_parent_fingerprint"] = deser["parent_fingerprint"]
                deser["parent_fingerprint"] = binascii.unhexlify(deser["parent_fingerprint"])
                deser["hex_chaincode"] = deser["chaincode"]
                deser["chaincode"] = binascii.unhexlify(deser["chaincode"])
                deser["hex_pubkey"] = deser["pubkey"]
                deser["pubkey"] = binascii.unhexlify(deser["pubkey"])
                deser["hex_privkey"] = deser["privkey"]
                deser["privkey"] = binascii.unhexlify(deser["privkey"])

    def test_serialization(self):
        for key in self.data["serialization"]:
            xpub = key["xpub"]
            xprv = key["xprv"]
            deser = key["deser"]
            with self.subTest(key=key):
                key_pub = ExtendedKey.deserialize(xpub)
                key_prv = ExtendedKey.deserialize(xprv)

                # Make sure they roundtrip
                self.assertEqual(key_pub.to_string(), xpub)
                self.assertEqual(key_prv.to_string(), xprv)

                # Make sure they agree
                self.assertEqual(key_pub.is_testnet, key_prv.is_testnet)
                self.assertEqual(key_pub.depth, key_prv.depth)
                self.assertEqual(key_pub.parent_fingerprint, key_prv.parent_fingerprint)
                self.assertEqual(key_pub.child_num, key_prv.child_num)
                self.assertEqual(key_pub.chaincode, key_prv.chaincode)
                self.assertEqual(key_pub.pubkey, key_prv.pubkey)

                # Make sure they are correct
                self.assertEqual(key_pub.version, deser["pub_version"])
                self.assertEqual(key_pub.is_testnet, deser["is_testnet"])
                self.assertEqual(key_pub.is_private, False)
                self.assertEqual(key_pub.depth, deser["depth"])
                self.assertEqual(key_pub.parent_fingerprint, deser["parent_fingerprint"])
                self.assertEqual(key_pub.child_num, deser["child_num"])
                self.assertEqual(key_pub.chaincode, deser["chaincode"])
                self.assertEqual(key_pub.pubkey, deser["pubkey"])
                self.assertEqual(key_prv.version, deser["priv_version"])
                self.assertEqual(key_prv.is_testnet, deser["is_testnet"])
                self.assertEqual(key_prv.is_private, True)
                self.assertEqual(key_prv.depth, deser["depth"])
                self.assertEqual(key_prv.parent_fingerprint, deser["parent_fingerprint"])
                self.assertEqual(key_prv.child_num, deser["child_num"])
                self.assertEqual(key_prv.chaincode, deser["chaincode"])
                self.assertEqual(key_prv.pubkey, deser["pubkey"])
                self.assertEqual(key_prv.privkey, deser["privkey"])

                # Make sure the printable dict is right
                key_dict = key_pub.get_printable_dict()
                self.assertEqual(key_dict["testnet"], deser["is_testnet"])
                self.assertEqual(key_dict["private"], False)
                self.assertEqual(key_dict["depth"], deser["depth"])
                self.assertEqual(key_dict["parent_fingerprint"], deser["hex_parent_fingerprint"])
                self.assertEqual(key_dict["child_num"], deser["child_num"])
                self.assertEqual(key_dict["chaincode"], deser["hex_chaincode"])
                self.assertEqual(key_dict["pubkey"], deser["hex_pubkey"])
                key_dict = key_prv.get_printable_dict()
                self.assertEqual(key_dict["testnet"], deser["is_testnet"])
                self.assertEqual(key_dict["private"], True)
                self.assertEqual(key_dict["depth"], deser["depth"])
                self.assertEqual(key_dict["parent_fingerprint"], deser["hex_parent_fingerprint"])
                self.assertEqual(key_dict["child_num"], deser["child_num"])
                self.assertEqual(key_dict["chaincode"], deser["hex_chaincode"])
                self.assertEqual(key_dict["pubkey"], deser["hex_pubkey"])
                self.assertEqual(key_dict["privkey"], deser["hex_privkey"])

    def test_deriv(self):
        for test in self.data["deriv"]:
            with self.subTest(test=test):
                # Deser
                par_xpub = ExtendedKey.deserialize(test["parent_xpub"])
                par_xprv = ExtendedKey.deserialize(test["parent_xprv"])

                # Derive
                i = test["index"]
                child_xpub = test["child_xpub"]
                xpub_der = par_xpub.derive_pub(i)
                self.assertEqual(xpub_der.to_string(), child_xpub)
                xprv_der = par_xprv.derive_pub(i)
                self.assertEqual(xprv_der.to_string(), child_xpub)

    def test_deriv_path(self):
        for test in self.data["deriv_path"]:
            with self.subTest(test=test):
                # Deser
                par_xpub = ExtendedKey.deserialize(test["parent_xpub"])
                par_xprv = ExtendedKey.deserialize(test["parent_xprv"])

                # Parse the path
                path = parse_path(test["path"])

                # Derive
                child_xpub = test["child_xpub"]
                xpub_der = par_xpub.derive_pub_path(path)
                self.assertEqual(xpub_der.to_string(), child_xpub)
                xprv_der = par_xprv.derive_pub_path(path)
                self.assertEqual(xprv_der.to_string(), child_xpub)


if __name__ == "__main__":
    unittest.main()
