#! /usr/bin/env python3

from hwilib.descriptor import Descriptor
import unittest

class TestDescriptor(unittest.TestCase):
    def test_parse_descriptor_with_origin(self):
        desc = Descriptor.parse("wpkh([00000001/84'/1'/0']tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0)", True)
        self.assertIsNotNone(desc)
        self.assertEqual(desc.wpkh, True)
        self.assertEqual(desc.sh_wpkh, None)
        self.assertEqual(desc.origin_fingerprint, "00000001")
        self.assertEqual(desc.origin_path, "/84'/1'/0'")
        self.assertEqual(desc.base_key, "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B")
        self.assertEqual(desc.path_suffix, "/0/0")
        self.assertEqual(desc.testnet, True)
        self.assertEqual(desc.m_path, "m/84'/1'/0'/0/0")

    def test_parse_multisig_descriptor_with_origin(self):
        desc = Descriptor.parse("wsh(multi(2,[00000001/48'/0'/0'/2']tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0,[00000002/48'/0'/0'/2']tpubDFHiBJDeNvqPWNJbzzxqDVXmJZoNn2GEtoVcFhMjXipQiorGUmps3e5ieDGbRrBPTFTh9TXEKJCwbAGW9uZnfrVPbMxxbFohuFzfT6VThty/0/0))", True)
        self.assertIsNotNone(desc)
        self.assertEqual(desc.wsh, True)
        self.assertEqual(desc.origin_fingerprint, ["00000001", "00000002"])
        self.assertEqual(desc.origin_path, ["/48'/0'/0'/2'", "/48'/0'/0'/2'"])
        self.assertEqual(desc.base_key, ["tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B", "tpubDFHiBJDeNvqPWNJbzzxqDVXmJZoNn2GEtoVcFhMjXipQiorGUmps3e5ieDGbRrBPTFTh9TXEKJCwbAGW9uZnfrVPbMxxbFohuFzfT6VThty"])
        self.assertEqual(desc.path_suffix, ["/0/0", "/0/0"])
        self.assertEqual(desc.testnet, True)
        self.assertEqual(desc.m_path_base, ["m/48'/0'/0'/2'", "m/48'/0'/0'/2'"])
        self.assertEqual(desc.m_path, ["m/48'/0'/0'/2'/0/0", "m/48'/0'/0'/2'/0/0"])

    def test_parse_descriptor_without_origin(self):
        desc = Descriptor.parse("wpkh(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0)", True)
        self.assertIsNotNone(desc)
        self.assertEqual(desc.wpkh, True)
        self.assertEqual(desc.sh_wpkh, None)
        self.assertEqual(desc.origin_fingerprint, None)
        self.assertEqual(desc.origin_path, None)
        self.assertEqual(desc.base_key, "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B")
        self.assertEqual(desc.path_suffix, "/0/0")
        self.assertEqual(desc.testnet, True)
        self.assertEqual(desc.m_path, None)

    def test_parse_descriptor_with_origin_fingerprint_only(self):
        desc = Descriptor.parse("wpkh([00000001]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0)", True)
        self.assertIsNotNone(desc)
        self.assertEqual(desc.wpkh, True)
        self.assertEqual(desc.sh_wpkh, None)
        self.assertEqual(desc.origin_fingerprint, "00000001")
        self.assertEqual(desc.origin_path, "")
        self.assertEqual(desc.base_key, "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B")
        self.assertEqual(desc.path_suffix, "/0/0")
        self.assertEqual(desc.testnet, True)
        self.assertEqual(desc.m_path, None)

    def test_parse_descriptor_with_key_at_end_with_origin(self):
        desc = Descriptor.parse("wpkh([00000001/84'/1'/0'/0/0]0297dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c7)", True)
        self.assertIsNotNone(desc)
        self.assertEqual(desc.wpkh, True)
        self.assertEqual(desc.sh_wpkh, None)
        self.assertEqual(desc.origin_fingerprint, "00000001")
        self.assertEqual(desc.origin_path, "/84'/1'/0'/0/0")
        self.assertEqual(desc.base_key, "0297dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c7")
        self.assertEqual(desc.path_suffix, None)
        self.assertEqual(desc.testnet, True)
        self.assertEqual(desc.m_path, "m/84'/1'/0'/0/0")

    def test_parse_descriptor_with_key_at_end_without_origin(self):
        desc = Descriptor.parse("wpkh(0297dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c7)", True)
        self.assertIsNotNone(desc)
        self.assertEqual(desc.wpkh, True)
        self.assertEqual(desc.sh_wpkh, None)
        self.assertEqual(desc.origin_fingerprint, None)
        self.assertEqual(desc.origin_path, None)
        self.assertEqual(desc.base_key, "0297dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c7")
        self.assertEqual(desc.path_suffix, None)
        self.assertEqual(desc.testnet, True)
        self.assertEqual(desc.m_path, None)

    def test_parse_empty_descriptor(self):
        desc = Descriptor.parse("", True)
        self.assertIsNone(desc)

    def test_parse_descriptor_replace_h(self):
        desc = Descriptor.parse("wpkh([00000001/84h/1h/0']tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0)", True)
        self.assertIsNotNone(desc)
        self.assertEqual(desc.origin_path, "/84'/1'/0'")

    def test_serialize_descriptor_with_origin(self):
        descriptor = "wpkh([00000001/84'/1'/0']tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0)#mz20k55p"
        desc = Descriptor.parse(descriptor, True)
        self.assertEqual(desc.serialize(), descriptor)

    def test_serialize_descriptor_without_origin(self):
        descriptor = "wpkh(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0)#ac0p4yhq"
        desc = Descriptor.parse(descriptor, True)
        self.assertEqual(desc.serialize(), descriptor)

    def test_serialize_descriptor_with_key_at_end_with_origin(self):
        descriptor = "wpkh([00000001/84'/1'/0'/0/0]0297dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c7)#rh7p6vk2"
        desc = Descriptor.parse(descriptor, True)
        self.assertEqual(desc.serialize(), descriptor)

    def test_checksums(self):
        with self.subTest(msg='Valid checksum'):
            self.assertIsNotNone(Descriptor.parse("sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#ggrsrxfy"))
            self.assertIsNotNone(Descriptor.parse("sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjg09x5t"))
            self.assertIsNotNone(Descriptor.parse("sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))"))
            self.assertIsNotNone(Descriptor.parse("sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))"))
        with self.subTest(msg="Empty Checksum"):
            self.assertIsNone(Descriptor.parse("sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#"))
            self.assertIsNone(Descriptor.parse("sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#"))
        with self.subTest(msg="Too long Checksum"):
            self.assertIsNone(Descriptor.parse("sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#ggrsrxfyq"))
            self.assertIsNone(Descriptor.parse("sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjg09x5tq"))
        with self.subTest(msg="Too Short Checksum"):
            self.assertIsNone(Descriptor.parse("sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#ggrsrxf"))
            self.assertIsNone(Descriptor.parse("sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjg09x5"))
        with self.subTest(msg="Error in Payload"):
            self.assertIsNone(Descriptor.parse("sh(multi(3,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#ggrsrxfy"))
            self.assertIsNone(Descriptor.parse("sh(multi(3,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjg09x5t"))
        with self.subTest(msg="Error in Checksum"):
            self.assertIsNone(Descriptor.parse("sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#ggssrxfy"))
            self.assertIsNone(Descriptor.parse("sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjq09x4t"))

if __name__ == "__main__":
    unittest.main()
