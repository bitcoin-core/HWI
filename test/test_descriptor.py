#! /usr/bin/env python3

from hwilib.descriptor import (
    parse_descriptor,
    MultisigDescriptor,
    SHDescriptor,
    TRDescriptor,
    PKHDescriptor,
    WPKHDescriptor,
    WSHDescriptor,
)
from hwilib.common import AddressType
from hwilib.errors import InvalidPolicyError

import unittest

class TestDescriptor(unittest.TestCase):
    def test_derive(self):
        xpub = "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B"
        descriptor_str = "wsh(multi(1,{0}/<0;1;2>/*,{0}/<10;11;12>/*))".format(xpub)
        descriptor = parse_descriptor(descriptor_str)

        self.assertEqual(
            descriptor.derive(7).to_string_no_checksum(),
            "wsh(multi(1,{0}/0/7,{0}/10/7))".format(xpub),
        )
        self.assertEqual(
            descriptor.derive(7, multipath_index=2).to_string_no_checksum(),
            "wsh(multi(1,{0}/2/7,{0}/12/7))".format(xpub),
        )
        self.assertEqual(descriptor.to_string_no_checksum(), descriptor_str)

    def test_get_address_type(self):
        key = "02c97dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c7"
        descriptors = {
            f"pk({key})": None,
            f"multi(1,{key})": None,
            f"pkh({key})": AddressType.LEGACY,
            f"sh(multi(1,{key}))": AddressType.LEGACY,
            f"wpkh({key})": AddressType.WIT,
            f"wsh(multi(1,{key}))": AddressType.WIT,
            f"sh(wpkh({key}))": AddressType.SH_WIT,
            f"sh(wsh(multi(1,{key})))": AddressType.SH_WIT,
            f"tr({key})": AddressType.TAP,
        }
        for descriptor, address_type in descriptors.items():
            with self.subTest(descriptor=descriptor):
                self.assertEqual(parse_descriptor(descriptor).get_address_type(), address_type)

    def test_parse_descriptor_with_origin(self):
        d = "wpkh([00000001/84h/1h/0h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0)"
        desc = parse_descriptor(d)
        self.assertTrue(isinstance(desc, WPKHDescriptor))
        self.assertEqual(desc.pubkeys[0].origin.fingerprint.hex(), "00000001")
        self.assertEqual(desc.pubkeys[0].origin.get_derivation_path(), "m/84h/1h/0h")
        self.assertEqual(desc.pubkeys[0].pubkey, "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B")
        self.assertEqual(desc.pubkeys[0].deriv_path, [[0], [0]])
        self.assertEqual(desc.pubkeys[0].expr_index, 0)
        self.assertEqual(desc.to_string_no_checksum(), d)

    def test_parse_multisig_descriptor_with_origin(self):
        d = "wsh(multi(2,[00000001/48h/0h/0h/2h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0,[00000002/48h/0h/0h/2h]tpubDFHiBJDeNvqPWNJbzzxqDVXmJZoNn2GEtoVcFhMjXipQiorGUmps3e5ieDGbRrBPTFTh9TXEKJCwbAGW9uZnfrVPbMxxbFohuFzfT6VThty/0/0))"
        desc = parse_descriptor(d)
        self.assertTrue(isinstance(desc, WSHDescriptor))
        self.assertTrue(isinstance(desc.subdescriptors[0], MultisigDescriptor))
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].origin.fingerprint.hex(), "00000001")
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].origin.get_derivation_path(), "m/48h/0h/0h/2h")
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].pubkey, "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B")
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].deriv_path, [[0], [0]])
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].expr_index, 0)

        self.assertEqual(desc.subdescriptors[0].pubkeys[1].origin.fingerprint.hex(), "00000002")
        self.assertEqual(desc.subdescriptors[0].pubkeys[1].origin.get_derivation_path(), "m/48h/0h/0h/2h")
        self.assertEqual(desc.subdescriptors[0].pubkeys[1].pubkey, "tpubDFHiBJDeNvqPWNJbzzxqDVXmJZoNn2GEtoVcFhMjXipQiorGUmps3e5ieDGbRrBPTFTh9TXEKJCwbAGW9uZnfrVPbMxxbFohuFzfT6VThty")
        self.assertEqual(desc.subdescriptors[0].pubkeys[1].deriv_path, [[0], [0]])
        self.assertEqual(desc.subdescriptors[0].pubkeys[1].expr_index, 1)
        self.assertEqual(desc.to_string_no_checksum(), d)

        d = "sh(multi(2,[00000001/48h/0h/0h/2h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0,[00000002/48h/0h/0h/2h]tpubDFHiBJDeNvqPWNJbzzxqDVXmJZoNn2GEtoVcFhMjXipQiorGUmps3e5ieDGbRrBPTFTh9TXEKJCwbAGW9uZnfrVPbMxxbFohuFzfT6VThty/0/0))"
        desc = parse_descriptor(d)
        self.assertTrue(isinstance(desc, SHDescriptor))
        self.assertTrue(isinstance(desc.subdescriptors[0], MultisigDescriptor))
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].origin.fingerprint.hex(), "00000001")
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].origin.get_derivation_path(), "m/48h/0h/0h/2h")
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].pubkey, "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B")
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].deriv_path, [[0], [0]])
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].expr_index, 0)

        self.assertEqual(desc.subdescriptors[0].pubkeys[1].origin.fingerprint.hex(), "00000002")
        self.assertEqual(desc.subdescriptors[0].pubkeys[1].origin.get_derivation_path(), "m/48h/0h/0h/2h")
        self.assertEqual(desc.subdescriptors[0].pubkeys[1].pubkey, "tpubDFHiBJDeNvqPWNJbzzxqDVXmJZoNn2GEtoVcFhMjXipQiorGUmps3e5ieDGbRrBPTFTh9TXEKJCwbAGW9uZnfrVPbMxxbFohuFzfT6VThty")
        self.assertEqual(desc.subdescriptors[0].pubkeys[1].deriv_path, [[0], [0]])
        self.assertEqual(desc.subdescriptors[0].pubkeys[1].expr_index, 1)
        self.assertEqual(desc.to_string_no_checksum(), d)

        d = "sh(wsh(multi(2,[00000001/48h/0h/0h/2h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0,[00000002/48h/0h/0h/2h]tpubDFHiBJDeNvqPWNJbzzxqDVXmJZoNn2GEtoVcFhMjXipQiorGUmps3e5ieDGbRrBPTFTh9TXEKJCwbAGW9uZnfrVPbMxxbFohuFzfT6VThty/0/0)))"
        desc = parse_descriptor(d)
        self.assertTrue(isinstance(desc, SHDescriptor))
        self.assertTrue(isinstance(desc.subdescriptors[0], WSHDescriptor))
        self.assertTrue(isinstance(desc.subdescriptors[0].subdescriptors[0], MultisigDescriptor))
        self.assertEqual(desc.subdescriptors[0].subdescriptors[0].pubkeys[0].origin.fingerprint.hex(), "00000001")
        self.assertEqual(desc.subdescriptors[0].subdescriptors[0].pubkeys[0].origin.get_derivation_path(), "m/48h/0h/0h/2h")
        self.assertEqual(desc.subdescriptors[0].subdescriptors[0].pubkeys[0].pubkey, "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B")
        self.assertEqual(desc.subdescriptors[0].subdescriptors[0].pubkeys[0].deriv_path, [[0], [0]])
        self.assertEqual(desc.subdescriptors[0].subdescriptors[0].pubkeys[0].expr_index, 0)

        self.assertEqual(desc.subdescriptors[0].subdescriptors[0].pubkeys[1].origin.fingerprint.hex(), "00000002")
        self.assertEqual(desc.subdescriptors[0].subdescriptors[0].pubkeys[1].origin.get_derivation_path(), "m/48h/0h/0h/2h")
        self.assertEqual(desc.subdescriptors[0].subdescriptors[0].pubkeys[1].pubkey, "tpubDFHiBJDeNvqPWNJbzzxqDVXmJZoNn2GEtoVcFhMjXipQiorGUmps3e5ieDGbRrBPTFTh9TXEKJCwbAGW9uZnfrVPbMxxbFohuFzfT6VThty")
        self.assertEqual(desc.subdescriptors[0].subdescriptors[0].pubkeys[1].deriv_path, [[0], [0]])
        self.assertEqual(desc.subdescriptors[0].subdescriptors[0].pubkeys[1].expr_index, 1)
        self.assertEqual(desc.to_string_no_checksum(), d)

    def test_parse_descriptor_without_origin(self):
        d = "wpkh(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0)"
        desc = parse_descriptor(d)
        self.assertTrue(isinstance(desc, WPKHDescriptor))
        self.assertEqual(desc.pubkeys[0].origin, None)
        self.assertEqual(desc.pubkeys[0].pubkey, "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B")
        self.assertEqual(desc.pubkeys[0].deriv_path, [[0], [0]])
        self.assertEqual(desc.to_string_no_checksum(), d)

    def test_parse_descriptor_with_origin_fingerprint_only(self):
        d = "wpkh([00000001]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0)"
        desc = parse_descriptor(d)
        self.assertTrue(isinstance(desc, WPKHDescriptor))
        self.assertEqual(desc.pubkeys[0].origin.fingerprint.hex(), "00000001")
        self.assertEqual(len(desc.pubkeys[0].origin.path), 0)
        self.assertEqual(desc.pubkeys[0].pubkey, "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B")
        self.assertEqual(desc.pubkeys[0].deriv_path, [[0], [0]])
        self.assertEqual(desc.pubkeys[0].expr_index, 0)
        self.assertEqual(desc.to_string_no_checksum(), d)

    def test_parse_descriptor_with_key_at_end_with_origin(self):
        d = "wpkh([00000001/84h/1h/0h/0/0]02c97dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c7)"
        desc = parse_descriptor(d)
        self.assertTrue(isinstance(desc, WPKHDescriptor))
        self.assertEqual(desc.pubkeys[0].origin.fingerprint.hex(), "00000001")
        self.assertEqual(desc.pubkeys[0].origin.get_derivation_path(), "m/84h/1h/0h/0/0")
        self.assertEqual(desc.pubkeys[0].pubkey, "02c97dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c7")
        self.assertEqual(desc.pubkeys[0].deriv_path, None)
        self.assertEqual(desc.pubkeys[0].expr_index, 0)
        self.assertEqual(desc.to_string_no_checksum(), d)

        d = "pkh([00000001/84h/1h/0h/0/0]02c97dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c7)"
        desc = parse_descriptor(d)
        self.assertTrue(isinstance(desc, PKHDescriptor))
        self.assertEqual(desc.pubkeys[0].origin.fingerprint.hex(), "00000001")
        self.assertEqual(desc.pubkeys[0].origin.get_derivation_path(), "m/84h/1h/0h/0/0")
        self.assertEqual(desc.pubkeys[0].pubkey, "02c97dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c7")
        self.assertEqual(desc.pubkeys[0].deriv_path, None)
        self.assertEqual(desc.pubkeys[0].expr_index, 0)
        self.assertEqual(desc.to_string_no_checksum(), d)

    def test_parse_descriptor_with_key_at_end_without_origin(self):
        d = "wpkh(02c97dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c7)"
        desc = parse_descriptor(d)
        self.assertTrue(isinstance(desc, WPKHDescriptor))
        self.assertEqual(desc.pubkeys[0].origin, None)
        self.assertEqual(desc.pubkeys[0].pubkey, "02c97dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c7")
        self.assertEqual(desc.pubkeys[0].deriv_path, None)
        self.assertEqual(desc.pubkeys[0].expr_index, 0)
        self.assertEqual(desc.to_string_no_checksum(), d)

    def test_parse_empty_descriptor(self):
        self.assertRaises(ValueError, parse_descriptor, "")

    def test_parse_descriptor_replace_h(self):
        d = "wpkh([00000001/84h/1h/0h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0)"
        desc = parse_descriptor(d)
        self.assertIsNotNone(desc)
        self.assertEqual(desc.pubkeys[0].origin.get_derivation_path(), "m/84h/1h/0h")

    def test_checksums(self):
        with self.subTest(msg="Valid checksum"):
            self.assertIsNotNone(parse_descriptor("sh(multi(2,[00000000/111h/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#5js07kwj"))
            self.assertIsNotNone(parse_descriptor("sh(multi(2,[00000000/111h/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#hgmsckna"))
            self.assertIsNotNone(parse_descriptor("sh(multi(2,[00000000/111h/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))"))
            self.assertIsNotNone(parse_descriptor("sh(multi(2,[00000000/111h/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))"))
        with self.subTest(msg="Empty Checksum"):
            self.assertRaises(ValueError, parse_descriptor, "sh(multi(2,[00000000/111h/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#")
            self.assertRaises(ValueError, parse_descriptor, "sh(multi(2,[00000000/111h/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#")
        with self.subTest(msg="Too long Checksum"):
            self.assertRaises(ValueError, parse_descriptor, "sh(multi(2,[00000000/111h/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#5js07kwjq")
            self.assertRaises(ValueError, parse_descriptor, "sh(multi(2,[00000000/111h/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#hgmscknaq")
        with self.subTest(msg="Too Short Checksum"):
            self.assertRaises(ValueError, parse_descriptor, "sh(multi(2,[00000000/111h/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#5js07kw")
            self.assertRaises(ValueError, parse_descriptor, "sh(multi(2,[00000000/111h/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#hgmsckn")
        with self.subTest(msg="Error in Payload"):
            self.assertRaises(ValueError, parse_descriptor, "sh(multi(3,[00000000/111h/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#ggrsrxf")
            self.assertRaises(ValueError, parse_descriptor, "sh(multi(3,[00000000/111h/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjg09x5")
        with self.subTest(msg="Error in Checksum"):
            self.assertRaises(ValueError, parse_descriptor, "sh(multi(2,[00000000/111h/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#5js07kej")
            self.assertRaises(ValueError, parse_descriptor, "sh(multi(2,[00000000/111h/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjg09y5")

    def test_tr_descriptor(self):
        d = "tr([00000001/84h/1h/0h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0)"
        desc = parse_descriptor(d)
        self.assertTrue(isinstance(desc, TRDescriptor))
        self.assertEqual(len(desc.pubkeys), 1)
        self.assertEqual(len(desc.subdescriptors), 0)
        self.assertEqual(desc.pubkeys[0].origin.fingerprint.hex(), "00000001")
        self.assertEqual(desc.pubkeys[0].origin.get_derivation_path(), "m/84h/1h/0h")
        self.assertEqual(desc.pubkeys[0].pubkey, "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B")
        self.assertEqual(desc.pubkeys[0].deriv_path, [[0], [0]])
        self.assertEqual(desc.pubkeys[0].expr_index, 0)
        self.assertEqual(desc.to_string_no_checksum(), d)

        d = "tr([00000001/84h/1h/0h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0,{pk(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B),{{pk(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B),pk(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B)},pk(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B)}})"
        desc = parse_descriptor(d)
        self.assertTrue(isinstance(desc, TRDescriptor))
        self.assertEqual(len(desc.subdescriptors), 4)
        self.assertEqual(desc.pubkeys[0].origin.fingerprint.hex(), "00000001")
        self.assertEqual(desc.pubkeys[0].origin.get_derivation_path(), "m/84h/1h/0h")
        self.assertEqual(desc.pubkeys[0].pubkey, "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B")
        self.assertEqual(desc.pubkeys[0].deriv_path, [[0], [0]])
        self.assertEqual(desc.pubkeys[0].expr_index, 0)
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].expr_index, 1)
        self.assertEqual(desc.subdescriptors[1].pubkeys[0].expr_index, 2)
        self.assertEqual(desc.subdescriptors[2].pubkeys[0].expr_index, 3)
        self.assertEqual(desc.subdescriptors[3].pubkeys[0].expr_index, 4)
        self.assertEqual(desc.depths, [1, 3, 3, 2])
        self.assertEqual(desc.to_string_no_checksum(), d)

        d = "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,pk(669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0))"
        desc = parse_descriptor(d)
        self.assertTrue(isinstance(desc, TRDescriptor))
        self.assertEqual(len(desc.subdescriptors), 1)
        self.assertEqual(desc.pubkeys[0].pubkey, "a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd")
        self.assertEqual(desc.depths, [0])
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].pubkey, "669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0")
        self.assertEqual(desc.to_string_no_checksum(), d)
        self.assertEqual(desc.pubkeys[0].expr_index, 0)
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].expr_index, 1)

    def test_multipath_descriptors(self):
        d = "pk(xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/<0;1>)"
        desc = parse_descriptor(d)
        self.assertEqual(desc.pubkeys[0].deriv_path, [[0, 1]])
        self.assertFalse(desc.pubkeys[0].ranged)
        self.assertEqual(d, desc.to_string_no_checksum())

        d = "pkh(xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/<2147483647h;0>/0)"
        desc = parse_descriptor(d)
        self.assertEqual(desc.pubkeys[0].deriv_path, [[0xffffffff, 0], [0]])
        self.assertFalse(desc.pubkeys[0].ranged)
        self.assertEqual(d, desc.to_string_no_checksum())

        d = "wpkh([ffffffff/13h]xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/<1;3>/2/*)"
        desc = parse_descriptor(d)
        self.assertEqual(desc.pubkeys[0].deriv_path, [[1, 3], [2]])
        self.assertTrue(desc.pubkeys[0].ranged)
        self.assertEqual(d, desc.to_string_no_checksum())

        d = "sh(multi(2,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/<1;2>/*,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/<3;4>/0/*))"
        desc = parse_descriptor(d)
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].deriv_path, [[1, 2]])
        self.assertTrue(desc.subdescriptors[0].pubkeys[0].ranged)
        self.assertEqual(desc.subdescriptors[0].pubkeys[1].deriv_path, [[3, 4], [0]])
        self.assertTrue(desc.subdescriptors[0].pubkeys[1].ranged)
        self.assertEqual(d, desc.to_string_no_checksum())

        d = "pkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/<0;1;2>)"
        desc = parse_descriptor(d)
        self.assertTrue(desc.pubkeys[0].deriv_path, [[0, 1, 2]])
        self.assertFalse(desc.pubkeys[0].ranged)
        self.assertEqual(d, desc.to_string_no_checksum())

        d = "sh(multi(2,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/<1;2;3>/0/*,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0/*,xpub661MyMwAqRbcGDZQUKLqmWodYLcoBQnQH33yYkkF3jjxeLvY8qr2wWGEWkiKFaaQfJCoi3HeEq3Dc5DptfbCyjD38fNhSqtKc1UHaP4ba3t/0/0/<3;4;5>/*))"
        desc = parse_descriptor(d)
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].deriv_path, [[1, 2, 3], [0]])
        self.assertTrue(desc.subdescriptors[0].pubkeys[0].ranged)
        self.assertEqual(desc.subdescriptors[0].pubkeys[1].deriv_path, [[0]])
        self.assertTrue(desc.subdescriptors[0].pubkeys[1].ranged)
        self.assertEqual(desc.subdescriptors[0].pubkeys[2].deriv_path, [[0], [0], [3, 4, 5]])
        self.assertTrue(desc.subdescriptors[0].pubkeys[2].ranged)
        self.assertEqual(d, desc.to_string_no_checksum())

    def test_invalid_multipath_descriptors(self):
        with self.assertRaisesRegex(ValueError, "Cannot have multiple multipath specifiers"):
            parse_descriptor("pkh(xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/<0;1>/<2;3>)")
        with self.assertRaisesRegex(ValueError, "Multipath specifier not allowed"):
            parse_descriptor("pkh([deadbeef/<0;1>]xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/0)")
        with self.assertRaisesRegex(ValueError, "Mismatched multipath paths"):
            parse_descriptor("tr(xpub661MyMwAqRbcF3yVrV2KyYetLMYA5mCbv4BhrKwUrFE9LZM6JRR1AEt8Jq4V4C8LwtTke6YEEdCZqgXp85YRk2j74EfJKhe3QybQ9kcUjs4/<6;7;8;9>/*,{pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/<1;2;3>/0/*),pk(xpub661MyMwAqRbcGDZQUKLqmWodYLcoBQnQH33yYkkF3jjxeLvY8qr2wWGEWkiKFaaQfJCoi3HeEq3Dc5DptfbCyjD38fNhSqtKc1UHaP4ba3t/0/0/<3;4;5>/*)})")
        with self.assertRaisesRegex(ValueError, "Mismatched multipath paths"):
            parse_descriptor("sh(multi(2,xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/<1;2;3>/0/*,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0/*,xprv9s21ZrQH143K3jUwNHoqQNrtzJnJmx4Yup8NkNLdVQCymYbPbJXnPhwkfTfxZfptcs3rLAPUXS39oDLgrNKQGwbGsEmJJ8BU3RzQuvShEG4/0/0/<3;4>/*))")
        with self.assertRaisesRegex(ValueError, "Invalid multipath specification, less than 2 indexes specified: <>"):
            parse_descriptor("wpkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/<>/*)")
        with self.assertRaisesRegex(ValueError, "invalid literal for int()"):
            parse_descriptor("wpkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/0>/*)")
        with self.assertRaisesRegex(ValueError, "Invalid multipath specification, missing trailing '>'"):
            parse_descriptor("wpkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/<0/*)")
        with self.assertRaisesRegex(ValueError, "invalid literal for int()"):
            parse_descriptor("wpkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/<0;>/*)")

    def test_wpkh_rejects_multiple_pubkeys(self):
        pk1 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        pk2 = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        with self.assertRaisesRegex(ValueError, "More than one pubkey in wpkh descriptor"):
            parse_descriptor("wpkh({},{})".format(pk1, pk2))

    def test_bare_multisig_too_many_pubkeys_reports_count(self):
        pk1 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        pk2 = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        pk3 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
        pk4 = "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13"
        with self.assertRaisesRegex(ValueError, "Cannot have 4 pubkeys in bare multisig: only at most 3 pubkeys"):
            parse_descriptor("multi(1,{},{},{},{})".format(pk1, pk2, pk3, pk4))

    def test_valid_bip388_conversion(self):
        def check(descriptor, keys, template):
            d = parse_descriptor(descriptor)
            self.assertEqual(d.get_bip388_template(), template)
            self.assertEqual([p.get_bip388_key_info() for p in d.get_pubkey_providers()], keys)

        check(
            "pkh([6738736c/44'/0'/0']xpub6Br37sWxruYfT8ASpCjVHKGwgdnYFEn98DwiN76i2oyY6fgH1LAPmmDcF46xjxJr22gw4jmVjTE2E3URMnRPEPYyo1zoPSUba563ESMXCeb/<0;1>/*)",
            ["[6738736c/44'/0'/0']xpub6Br37sWxruYfT8ASpCjVHKGwgdnYFEn98DwiN76i2oyY6fgH1LAPmmDcF46xjxJr22gw4jmVjTE2E3URMnRPEPYyo1zoPSUba563ESMXCeb"],
            "pkh(@0/<0;1>/*)"
        )
        check(
            "sh(wpkh([6738736c/49'/0'/1']xpub6Bex1CHWGXNNwGVKHLqNC7kcV348FxkCxpZXyCWp1k27kin8sRPayjZUKDjyQeZzGUdyeAj2emoW5zStFFUAHRgd5w8iVVbLgZ7PmjAKAm9/<0;1>/*))",
            ["[6738736c/49'/0'/1']xpub6Bex1CHWGXNNwGVKHLqNC7kcV348FxkCxpZXyCWp1k27kin8sRPayjZUKDjyQeZzGUdyeAj2emoW5zStFFUAHRgd5w8iVVbLgZ7PmjAKAm9"],
            "sh(wpkh(@0/<0;1>/*))"
        )
        check(
            "wpkh([6738736c/84'/0'/2']xpub6CRQzb8u9dmMcq5XAwwRn9gcoYCjndJkhKgD11WKzbVGd932UmrExWFxCAvRnDN3ez6ZujLmMvmLBaSWdfWVn75L83Qxu1qSX4fJNrJg2Gt/<0;1>/*)",
            ["[6738736c/84'/0'/2']xpub6CRQzb8u9dmMcq5XAwwRn9gcoYCjndJkhKgD11WKzbVGd932UmrExWFxCAvRnDN3ez6ZujLmMvmLBaSWdfWVn75L83Qxu1qSX4fJNrJg2Gt"],
            "wpkh(@0/<0;1>/*)"
        )
        check(
            "tr([6738736c/86'/0'/0']xpub6CryUDWPS28eR2cDyojB8G354izmx294BdjeSvH469Ty3o2E6Tq5VjBJCn8rWBgesvTJnyXNAJ3QpLFGuNwqFXNt3gn612raffLWfdHNkYL/<0;1>/*)",
            ["[6738736c/86'/0'/0']xpub6CryUDWPS28eR2cDyojB8G354izmx294BdjeSvH469Ty3o2E6Tq5VjBJCn8rWBgesvTJnyXNAJ3QpLFGuNwqFXNt3gn612raffLWfdHNkYL"],
            "tr(@0/<0;1>/*)"
        )
        check(
            "wsh(sortedmulti(2,[6738736c/48'/0'/0'/2']xpub6FC1fXFP1GXLX5TKtcjHGT4q89SDRehkQLtbKJ2PzWcvbBHtyDsJPLtpLtkGqYNYZdVVAjRQ5kug9CsapegmmeRutpP7PW4u4wVF9JfkDhw/<0;1>/*,[b2b1f0cf/48'/0'/0'/2']xpub6EWhjpPa6FqrcaPBuGBZRJVjzGJ1ZsMygRF26RwN932Vfkn1gyCiTbECVitBjRCkexEvetLdiqzTcYimmzYxyR1BZ79KNevgt61PDcukmC7/<0;1>/*))",
            ["[6738736c/48'/0'/0'/2']xpub6FC1fXFP1GXLX5TKtcjHGT4q89SDRehkQLtbKJ2PzWcvbBHtyDsJPLtpLtkGqYNYZdVVAjRQ5kug9CsapegmmeRutpP7PW4u4wVF9JfkDhw", "[b2b1f0cf/48'/0'/0'/2']xpub6EWhjpPa6FqrcaPBuGBZRJVjzGJ1ZsMygRF26RwN932Vfkn1gyCiTbECVitBjRCkexEvetLdiqzTcYimmzYxyR1BZ79KNevgt61PDcukmC7"],
            "wsh(sortedmulti(2,@0/<0;1>/*,@1/<0;1>/*))"
        )
        check(
            "pkh([6738736c/44h/0h/0h]xpub6Br37sWxruYfT8ASpCjVHKGwgdnYFEn98DwiN76i2oyY6fgH1LAPmmDcF46xjxJr22gw4jmVjTE2E3URMnRPEPYyo1zoPSUba563ESMXCeb/<0h;1>/*)",
            ["[6738736c/44'/0'/0']xpub6Br37sWxruYfT8ASpCjVHKGwgdnYFEn98DwiN76i2oyY6fgH1LAPmmDcF46xjxJr22gw4jmVjTE2E3URMnRPEPYyo1zoPSUba563ESMXCeb"],
            "pkh(@0/<0';1>/*)"
        )

    def test_invalid_bip388_converstion(self):
        def check(descriptor, error):
            with self.assertRaisesRegex(InvalidPolicyError, error):
                d = parse_descriptor(descriptor)
                d.get_bip388_template()

        check(
            "pkh([6738736c/44'/0'/0']xpub6Br37sWxruYfT8ASpCjVHKGwgdnYFEn98DwiN76i2oyY6fgH1LAPmmDcF46xjxJr22gw4jmVjTE2E3URMnRPEPYyo1zoPSUba563ESMXCeb/<0;1>)",
            "BIP 388 requires all pubkeys to be ranged"
        )
        check(
            "pkh([6738736c/44'/0'/0']xpub6Br37sWxruYfT8ASpCjVHKGwgdnYFEn98DwiN76i2oyY6fgH1LAPmmDcF46xjxJr22gw4jmVjTE2E3URMnRPEPYyo1zoPSUba563ESMXCeb/0/1)",
            "BIP 388 requires all pubkeys to be ranged"
        )
        check(
            "pkh([6738736c/44'/0'/0']xpub6Br37sWxruYfT8ASpCjVHKGwgdnYFEn98DwiN76i2oyY6fgH1LAPmmDcF46xjxJr22gw4jmVjTE2E3URMnRPEPYyo1zoPSUba563ESMXCeb/<0;1;2>/*)",
            "BIP 388 requires all multipath specifiers to be exactly 2 elements"
        )


if __name__ == "__main__":
    unittest.main()
