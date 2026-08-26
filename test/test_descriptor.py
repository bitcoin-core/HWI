#! /usr/bin/env python3

from hwilib.commands import displayaddress
from hwilib.descriptor import (
    MiniscriptDescriptor,
    parse_descriptor,
    MultisigDescriptor,
    SHDescriptor,
    TRDescriptor,
    PKHDescriptor,
    WPKHDescriptor,
    WSHDescriptor,
)
from hwilib.common import AddressType
from hwilib.errors import BadArgumentError, InvalidPolicyError

import re
import unittest

class TestDescriptor(unittest.TestCase):
    def test_segwit_miniscript_policy(self):
        key_0 = "[6738736c/48'/0'/0'/2']xpub6FC1fXFP1GXLX5TKtcjHGT4q89SDRehkQLtbKJ2PzWcvbBHtyDsJPLtpLtkGqYNYZdVVAjRQ5kug9CsapegmmeRutpP7PW4u4wVF9JfkDhw"
        key_1 = "[b2b1f0cf/48'/0'/0'/2']xpub6EWhjpPa6FqrcaPBuGBZRJVjzGJ1ZsMygRF26RwN932Vfkn1gyCiTbECVitBjRCkexEvetLdiqzTcYimmzYxyR1BZ79KNevgt61PDcukmC7"
        multipath = "<0;1>/*"
        descriptor = (
            f"wsh(and_v(v:pk({key_0}/{multipath}),"
            f"or_d(pk({key_1}/{multipath}),older(12960))))"
        )
        parsed = parse_descriptor(descriptor)
        self.assertIsInstance(parsed, WSHDescriptor)
        self.assertIsInstance(parsed.subdescriptors[0], MiniscriptDescriptor)
        self.assertEqual(parsed.to_string_no_checksum(hardened_char="'"), descriptor)
        self.assertEqual(
            parsed.get_bip388_template(),
            "wsh(and_v(v:pk(@0/<0;1>/*),or_d(pk(@1/<0;1>/*),older(12960))))",
        )
        self.assertEqual(
            [provider.get_bip388_key_info() for provider in parsed.get_pubkey_providers()],
            [key_0, key_1],
        )

    def test_invalid_segwit_miniscript(self):
        key = "[6738736c/48'/0'/0'/2']xpub6FC1fXFP1GXLX5TKtcjHGT4q89SDRehkQLtbKJ2PzWcvbBHtyDsJPLtpLtkGqYNYZdVVAjRQ5kug9CsapegmmeRutpP7PW4u4wVF9JfkDhw"
        multipath = "<0;1>/*"
        with self.assertRaisesRegex(ValueError, "Unknown Miniscript fragment: unknown"):
            parse_descriptor(f"wsh(unknown({key}/{multipath}))")
        with self.assertRaisesRegex(ValueError, "Unknown Miniscript fragment: Pk"):
            parse_descriptor(f"wsh(Pk({key}/{multipath}))")
        with self.assertRaisesRegex(ValueError, "Unknown Miniscript wrapper: x"):
            parse_descriptor(f"wsh(x:pk({key}/{multipath}))")
        with self.assertRaisesRegex(ValueError, "Invalid Miniscript expression"):
            parse_descriptor(f"wsh(and_v(v:pk({key}/{multipath}),older(1)")
        with self.assertRaisesRegex(ValueError, "takes exactly one number"):
            parse_descriptor("wsh(older(1,2))")
        with self.assertRaisesRegex(ValueError, "argument must be a number"):
            parse_descriptor("wsh(older(-1))")
        with self.assertRaisesRegex(ValueError, "character hex string"):
            parse_descriptor("wsh(sha256(abcd))")
        with self.assertRaisesRegex(ValueError, "threshold must be between"):
            parse_descriptor(f"wsh(and_v(v:pk({key}/{multipath}),multi(2,{key}/{multipath})))")
        with self.assertRaisesRegex(ValueError, "only allowed in tapscript"):
            parse_descriptor(f"wsh(and_v(v:pk({key}/{multipath}),multi_a(1,{key}/{multipath})))")
        with self.assertRaisesRegex(ValueError, "Empty argument"):
            parse_descriptor("wsh(and_v(,older(1)))")

        # A non-ranged key parses, but is not a valid BIP 388 policy.
        non_ranged = parse_descriptor(f"wsh(and_v(v:pk({key}),older(1)))")
        with self.assertRaisesRegex(InvalidPolicyError, "ranged"):
            non_ranged.get_bip388_template()

        # Segwit v0 limits multi() to 20 keys.
        keys = ",".join([f"{key}/{multipath}"] * 21)
        with self.assertRaisesRegex(ValueError, "at most 20 keys"):
            parse_descriptor(f"wsh(and_v(v:pk({key}/{multipath}),multi(1,{keys})))")

    def test_tapscript_miniscript_policy(self):
        key_0 = "[6738736c/48'/0'/0'/2']xpub6FC1fXFP1GXLX5TKtcjHGT4q89SDRehkQLtbKJ2PzWcvbBHtyDsJPLtpLtkGqYNYZdVVAjRQ5kug9CsapegmmeRutpP7PW4u4wVF9JfkDhw"
        key_1 = "[b2b1f0cf/48'/0'/0'/2']xpub6EWhjpPa6FqrcaPBuGBZRJVjzGJ1ZsMygRF26RwN932Vfkn1gyCiTbECVitBjRCkexEvetLdiqzTcYimmzYxyR1BZ79KNevgt61PDcukmC7"
        recovery_key = "[6738736c/86'/0'/0']xpub6CryUDWPS28eR2cDyojB8G354izmx294BdjeSvH469Ty3o2E6Tq5VjBJCn8rWBgesvTJnyXNAJ3QpLFGuNwqFXNt3gn612raffLWfdHNkYL"
        multipath = "<0;1>/*"
        descriptor = (
            f"tr({recovery_key}/{multipath},{{"
            f"multi_a(2,{key_0}/{multipath},{key_1}/{multipath}),"
            f"{{andor(pk({key_0}/{multipath}),older(1000),1),"
            f"thresh(2,pk({key_1}/{multipath}),s:pk({recovery_key}/{multipath}),"
            f"snl:sha256(6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333))}}}})"
        )
        parsed = parse_descriptor(descriptor)
        self.assertIsInstance(parsed, TRDescriptor)
        for subdescriptor in parsed.subdescriptors:
            self.assertIsInstance(subdescriptor, MiniscriptDescriptor)
        self.assertEqual(parsed.to_string_no_checksum(hardened_char="'"), descriptor)
        self.assertEqual(
            parsed.get_bip388_template(),
            "tr(@0/<0;1>/*,{multi_a(2,@1/<0;1>/*,@2/<0;1>/*),"
            "{andor(pk(@1/<0;1>/*),older(1000),1),"
            "thresh(2,pk(@2/<0;1>/*),s:pk(@0/<0;1>/*),"
            "snl:sha256(6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333))}})",
        )
        self.assertEqual(
            [provider.get_bip388_key_info() for provider in parsed.get_pubkey_providers()],
            [recovery_key, key_0, key_1],
        )

    def test_invalid_tapscript_miniscript(self):
        key = "[6738736c/86'/0'/0']xpub6CryUDWPS28eR2cDyojB8G354izmx294BdjeSvH469Ty3o2E6Tq5VjBJCn8rWBgesvTJnyXNAJ3QpLFGuNwqFXNt3gn612raffLWfdHNkYL"
        multipath = "<0;1>/*"
        with self.assertRaisesRegex(ValueError, "Unknown Miniscript fragment: unknown"):
            parse_descriptor(f"tr({key}/{multipath},unknown({key}/{multipath}))")
        with self.assertRaisesRegex(ValueError, "Unknown Miniscript fragment: Pk"):
            parse_descriptor(f"tr({key}/{multipath},Pk({key}/{multipath}))")
        with self.assertRaisesRegex(ValueError, "Invalid Miniscript expression"):
            parse_descriptor(f"tr({key}/{multipath},12345)")
        with self.assertRaisesRegex(ValueError, "Unknown Miniscript wrapper: x"):
            parse_descriptor(f"tr({key}/{multipath},x:pk({key}/{multipath}))")
        with self.assertRaisesRegex(ValueError, "only allowed in Segwit v0"):
            parse_descriptor(f"tr({key}/{multipath},multi(1,{key}/{multipath}))")
        with self.assertRaisesRegex(ValueError, "threshold must be between"):
            parse_descriptor(f"tr({key}/{multipath},multi_a(3,{key}/{multipath},{key}/{multipath}))")
        with self.assertRaisesRegex(ValueError, "Mismatched multipath"):
            parse_descriptor(f"tr({key}/{multipath},pk({key}/<0;1;2>/*))")
        with self.assertRaisesRegex(ValueError, "Invalid Miniscript expression"):
            parse_descriptor(f"tr({key}/{multipath},)")

        non_ranged = parse_descriptor(f"tr({key}/{multipath},and_v(v:pk({key}),older(1)))")
        with self.assertRaisesRegex(InvalidPolicyError, "ranged"):
            non_ranged.get_bip388_template()

        xonly = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
        keys = ",".join([xonly] * 1000)
        with self.assertRaisesRegex(ValueError, "at most 999 keys"):
            parse_descriptor(f"tr({key}/{multipath},multi_a(1,{keys}))")

    def test_bip379_tapscript_corpus(self):
        expressions = [
            "andor(and_b(multi_a(2,A,B,C),aj:multi_a(2,D,E,F)),multi_a(2,G,I,J),multi_a(2,K,L,M))",
            "thresh(1,or_d(multi_a(2,A,B,C),pk(D)),s:pk(E),s:pk(F))",
            "and_v(and_v(or_c(multi_a(2,A,B,C),v:multi_a(2,D,E,F)),v:after(1)),after(500000001))",
            "andor(pk(A),older(4194305),pk(B))",
            "and_n(pk(A),pk(B))",
            "and_b(after(1),a:or_d(or_i(c:pk_h(A),0),multi_a(2,B,C,D)))",
            "and_b(after(1),a:and_b(after(1),ac:pk_k(A)))",
            "and_b(after(1),a:and_b(c:pk_h(A),an:after(500000001)))",
            "and_v(or_c(sha256(926a54995ca48600920a19bf7bc502ca5f2f7d07e6f804c4f00ebf0325084dbc),v:after(1)),1)",
            "u:pk(A)",
            "l:pk(A)",
            "pkh(A)",
            "hash160(4355a46b19d348dc2f57c046f8ef63d4538ebb93)",
            "ripemd160(4355a46b19d348dc2f57c046f8ef63d4538ebb93)",
            "hash256(926a54995ca48600920a19bf7bc502ca5f2f7d07e6f804c4f00ebf0325084dbc)",
        ]
        internal_key = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
        for expression in expressions:
            substituted = re.sub(
                r"(?<![0-9a-zA-Z_])([A-Z])(?![0-9a-zA-Z_])",
                lambda match: format(0xf9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce03600 + ord(match.group(1)), "064x"),
                expression,
            )
            descriptor = f"tr({internal_key},{substituted})"
            self.assertEqual(parse_descriptor(descriptor).to_string_no_checksum(), descriptor)

    def test_bip388_taproot_miniscript_vector(self):
        key_0 = "[6738736c/48'/0'/0'/100']xpub6FC1fXFP1GXQpyRFfSE1vzzySqs3Vg63bzimYLeqtNUYbzA87kMNTcuy9ubr7MmavGRjW2FRYHP4WGKjwutbf1ghgkUW9H7e3ceaPLRcVwa"
        key_1 = "xpub6Fc2TRaCWNgfT49nRGG2G78d1dPnjhW66gEXi7oYZML7qEFN8e21b2DLDipTZZnfV6V7ivrMkvh4VbnHY2ChHTS9qM3XVLJiAgcfagYQk6K"
        key_2 = "xpub6GxHB9kRdFfTqYka8tgtX9Gh3Td3A9XS8uakUGVcJ9NGZ1uLrGZrRVr67DjpMNCHprZmVmceFTY4X4wWfksy8nVwPiNvzJ5pjLxzPtpnfEM"
        key_3 = "xpub6GjFUVVYewLj5no5uoNKCWuyWhQ1rKGvV8DgXBG9Uc6DvAKxt2dhrj1EZFrTNB5qxAoBkVW3wF8uCS3q1ri9fueAa6y7heFTcf27Q4gyeh6"
        descriptor = parse_descriptor(
            f"tr({key_0}/<0;1>/*,{{sortedmulti_a(1,{key_0}/<2;3>/*,{key_1}/<0;1>/*),"
            f"or_b(pk({key_2}/<0;1>/*),s:pk({key_3}/<0;1>/*))}})"
        )
        self.assertEqual(
            descriptor.get_bip388_template(),
            "tr(@0/<0;1>/*,{sortedmulti_a(1,@0/<2;3>/*,@1/<0;1>/*),"
            "or_b(pk(@2/<0;1>/*),s:pk(@3/<0;1>/*))})",
        )
        self.assertEqual(
            [provider.get_bip388_key_info() for provider in descriptor.get_pubkey_providers()],
            [key_0, key_1, key_2, key_3],
        )

    def test_taproot_script_tree_requires_registration(self):
        key = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
        descriptor = f"tr({key},pk({key}))"
        with self.assertRaisesRegex(BadArgumentError, "registered BIP 388 policy"):
            displayaddress(object(), desc=descriptor)

    def test_musig_requires_registration(self):
        key_0 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
        key_1 = "03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659"
        with self.assertRaisesRegex(BadArgumentError, "registered BIP 388 policy"):
            displayaddress(object(), desc=f"tr(musig({key_0},{key_1}))")

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

    def test_parse_invalid_key_expressions(self):
        xpub = "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B"
        with self.assertRaisesRegex(ValueError, "Invalid ranged derivation path"):
            parse_descriptor(f"wpkh({xpub}/0*)")
        with self.assertRaisesRegex(ValueError, "Empty key expression"):
            parse_descriptor(f"wsh(multi(1,{xpub}/0/*,,{xpub}/1/*))")
        with self.assertRaisesRegex(ValueError, "Trailing comma"):
            parse_descriptor(f"wsh(multi(1,{xpub}/0/*,))")

    def test_bip388_key_deduplication(self):
        key = "[6738736c/48'/0'/0'/2']xpub6FC1fXFP1GXLX5TKtcjHGT4q89SDRehkQLtbKJ2PzWcvbBHtyDsJPLtpLtkGqYNYZdVVAjRQ5kug9CsapegmmeRutpP7PW4u4wVF9JfkDhw"
        other = "[b2b1f0cf/48'/0'/0'/2']xpub6EWhjpPa6FqrcaPBuGBZRJVjzGJ1ZsMygRF26RwN932Vfkn1gyCiTbECVitBjRCkexEvetLdiqzTcYimmzYxyR1BZ79KNevgt61PDcukmC7"
        descriptor = parse_descriptor(f"wsh(multi(2,{key}/<0;1>/*,{other}/<0;1>/*,{key}/<2;3>/*))")
        self.assertEqual(
            descriptor.get_bip388_template(),
            "wsh(multi(2,@0/<0;1>/*,@1/<0;1>/*,@0/<2;3>/*))",
        )
        self.assertEqual(
            [provider.get_bip388_key_info() for provider in descriptor.get_pubkey_providers()],
            [key, other],
        )

    def test_parse_invalid_musig(self):
        key_0 = "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B"
        key_1 = "tpubDFHiBJDeNvqPWNJbzzxqDVXmJZoNn2GEtoVcFhMjXipQiorGUmps3e5ieDGbRrBPTFTh9TXEKJCwbAGW9uZnfrVPbMxxbFohuFzfT6VThty"
        with self.assertRaisesRegex(ValueError, "at least two participants"):
            parse_descriptor(f"tr(musig({key_0}))")
        with self.assertRaisesRegex(ValueError, "Empty key expression"):
            parse_descriptor(f"tr(musig({key_0},,{key_1}))")
        with self.assertRaisesRegex(ValueError, "Trailing comma"):
            parse_descriptor(f"tr(musig({key_0},{key_1},))")
        with self.assertRaisesRegex(ValueError, "cannot be nested"):
            parse_descriptor(f"tr(musig(musig({key_0},{key_1}),{key_1}))")
        with self.assertRaisesRegex(ValueError, "Invalid ranged derivation path"):
            parse_descriptor(f"tr(musig({key_0},{key_1})/0*)")

    def test_parse_musig_bip390(self):
        # Test vectors from BIP 390
        hex_1 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
        hex_2 = "03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659"
        hex_3 = "023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66"
        xpub_a = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
        xpub_b = "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"
        valid = [
            f"tr(musig({hex_1},{hex_2},{hex_3}))",
            f"tr(musig({xpub_a}/1,{xpub_a}/1)/2)",
            # Participants may be ranged when the aggregate key is not
            f"tr(musig({xpub_a}/*,{xpub_b}/*))",
        ]
        for descriptor in valid:
            self.assertEqual(parse_descriptor(descriptor).to_string_no_checksum(), descriptor)

        # Derivation happens on the participant keys when the aggregate key has no path
        self.assertEqual(
            parse_descriptor(f"tr(musig({xpub_a}/*,{xpub_b}/*))").derive(3).to_string_no_checksum(),
            f"tr(musig({xpub_a}/3,{xpub_b}/3))",
        )

        with self.assertRaisesRegex(ValueError, "only allowed in tr"):
            parse_descriptor(f"pk(musig({hex_1},{hex_2},{hex_3}))")
        with self.assertRaisesRegex(ValueError, "only allowed in tr"):
            parse_descriptor(f"pkh(musig({hex_1},{hex_2},{hex_3}))")
        with self.assertRaisesRegex(ValueError, "only allowed in tr"):
            parse_descriptor(f"wpkh(musig({hex_1},{hex_2},{hex_3}))")
        with self.assertRaisesRegex(ValueError, "only allowed in tr"):
            parse_descriptor(f"wsh(pk(musig({hex_1},{hex_2},{hex_3})))")
        with self.assertRaisesRegex(ValueError, "Unknown Miniscript fragment: musig"):
            parse_descriptor(f"wsh(musig({hex_1},{hex_2},{hex_3}))")
        with self.assertRaisesRegex(ValueError, "extended public key participants"):
            parse_descriptor(f"tr(musig({hex_1},{hex_2},{hex_3})/0/0)")
        with self.assertRaisesRegex(ValueError, "cannot be ranged or multipath"):
            parse_descriptor(f"tr(musig({xpub_a}/*,{xpub_b})/0/*)")
        with self.assertRaisesRegex(ValueError, "cannot be ranged or multipath"):
            parse_descriptor(f"tr(musig({xpub_a}/<0;1>,{xpub_b})/<2;3>)")
        with self.assertRaisesRegex(ValueError, "hardened derivation steps"):
            parse_descriptor(f"tr(musig({xpub_a},{xpub_b})/0h/*)")
        with self.assertRaises(ValueError):
            parse_descriptor(f"tr(musig({xpub_a},{xpub_b})/0/*h)")

        # BIP 388 does not allow derivation before aggregation
        with self.assertRaisesRegex(InvalidPolicyError, "follow musig"):
            parse_descriptor(f"tr(musig({xpub_a}/1,{xpub_b}/1)/<0;1>/*)").get_bip388_template()

    def test_musig_tapscript_key(self):
        key_0 = "[6738736c/48'/0'/0'/2']xpub6FC1fXFP1GXLX5TKtcjHGT4q89SDRehkQLtbKJ2PzWcvbBHtyDsJPLtpLtkGqYNYZdVVAjRQ5kug9CsapegmmeRutpP7PW4u4wVF9JfkDhw"
        key_1 = "[b2b1f0cf/48'/0'/0'/2']xpub6EWhjpPa6FqrcaPBuGBZRJVjzGJ1ZsMygRF26RwN932Vfkn1gyCiTbECVitBjRCkexEvetLdiqzTcYimmzYxyR1BZ79KNevgt61PDcukmC7"
        internal_key = "[6738736c/86'/0'/0']xpub6CryUDWPS28eR2cDyojB8G354izmx294BdjeSvH469Ty3o2E6Tq5VjBJCn8rWBgesvTJnyXNAJ3QpLFGuNwqFXNt3gn612raffLWfdHNkYL"
        descriptor = (
            f"tr({internal_key}/<0;1>/*,"
            f"and_v(v:pk(musig({key_0},{key_1})/<0;1>/*),older(12960)))"
        )
        parsed = parse_descriptor(descriptor)
        self.assertEqual(parsed.to_string_no_checksum(hardened_char="'"), descriptor)
        self.assertEqual(
            parsed.get_bip388_template(),
            "tr(@0/<0;1>/*,and_v(v:pk(musig(@1,@2)/<0;1>/*),older(12960)))",
        )
        self.assertEqual(
            [provider.get_bip388_key_info() for provider in parsed.get_pubkey_providers()],
            [internal_key, key_0, key_1],
        )

    def test_bip388_musig_tapscript_vector(self):
        key_0 = "[6738736c/48'/0'/0'/100']xpub6FC1fXFP1GXQpyRFfSE1vzzySqs3Vg63bzimYLeqtNUYbzA87kMNTcuy9ubr7MmavGRjW2FRYHP4WGKjwutbf1ghgkUW9H7e3ceaPLRcVwa"
        key_1 = "[b2b1f0cf/44'/0'/0'/100']xpub6EYajCJHe2CK53RLVXrN14uWoEttZgrRSaRztujsXg7yRhGtHmLBt9ot9Pd5ugfwWEu6eWyJYKSshyvZFKDXiNbBcoK42KRZbxwjRQpm5Js"
        key_2 = "[a666a867/44'/0'/0'/100']xpub6Dgsze3ujLi1EiHoCtHFMS9VLS1UheVqxrHGfP7sBJ2DBfChEUHV4MDwmxAXR2ayeytpwm3zJEU3H3pjCR6q6U5sP2p2qzAD71x9z5QShK2"
        descriptor = parse_descriptor(
            f"tr(musig({key_0},{key_1},{key_2})/<0;1>/*,"
            f"{{and_v(v:pk(musig({key_0},{key_1})/<0;1>/*),older(12960)),"
            f"{{and_v(v:pk(musig({key_0},{key_2})/<0;1>/*),older(12960)),"
            f"and_v(v:pk(musig({key_1},{key_2})/<0;1>/*),older(12960))}}}})"
        )
        self.assertEqual(
            descriptor.get_bip388_template(),
            "tr(musig(@0,@1,@2)/<0;1>/*,"
            "{and_v(v:pk(musig(@0,@1)/<0;1>/*),older(12960)),"
            "{and_v(v:pk(musig(@0,@2)/<0;1>/*),older(12960)),"
            "and_v(v:pk(musig(@1,@2)/<0;1>/*),older(12960))}})",
        )
        self.assertEqual(
            [provider.get_bip388_key_info() for provider in descriptor.get_pubkey_providers()],
            [key_0, key_1, key_2],
        )

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
        # The same key is used in all four leaves, so it shares one BIP 388 key index
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].expr_index, 1)
        self.assertEqual(desc.subdescriptors[1].pubkeys[0].expr_index, 1)
        self.assertEqual(desc.subdescriptors[2].pubkeys[0].expr_index, 1)
        self.assertEqual(desc.subdescriptors[3].pubkeys[0].expr_index, 1)
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
        musig_descriptor = "tr(musig([6738736c/48'/0'/0'/2']xpub6FC1fXFP1GXLX5TKtcjHGT4q89SDRehkQLtbKJ2PzWcvbBHtyDsJPLtpLtkGqYNYZdVVAjRQ5kug9CsapegmmeRutpP7PW4u4wVF9JfkDhw,[b2b1f0cf/48'/0'/0'/2']xpub6EWhjpPa6FqrcaPBuGBZRJVjzGJ1ZsMygRF26RwN932Vfkn1gyCiTbECVitBjRCkexEvetLdiqzTcYimmzYxyR1BZ79KNevgt61PDcukmC7)/<0;1>/*)"
        check(
            musig_descriptor,
            ["[6738736c/48'/0'/0'/2']xpub6FC1fXFP1GXLX5TKtcjHGT4q89SDRehkQLtbKJ2PzWcvbBHtyDsJPLtpLtkGqYNYZdVVAjRQ5kug9CsapegmmeRutpP7PW4u4wVF9JfkDhw", "[b2b1f0cf/48'/0'/0'/2']xpub6EWhjpPa6FqrcaPBuGBZRJVjzGJ1ZsMygRF26RwN932Vfkn1gyCiTbECVitBjRCkexEvetLdiqzTcYimmzYxyR1BZ79KNevgt61PDcukmC7"],
            "tr(musig(@0,@1)/<0;1>/*)"
        )
        self.assertEqual(
            parse_descriptor(musig_descriptor).derive(7, multipath_index=1).to_string_no_checksum(hardened_char="'"),
            "tr(musig([6738736c/48'/0'/0'/2']xpub6FC1fXFP1GXLX5TKtcjHGT4q89SDRehkQLtbKJ2PzWcvbBHtyDsJPLtpLtkGqYNYZdVVAjRQ5kug9CsapegmmeRutpP7PW4u4wVF9JfkDhw,[b2b1f0cf/48'/0'/0'/2']xpub6EWhjpPa6FqrcaPBuGBZRJVjzGJ1ZsMygRF26RwN932Vfkn1gyCiTbECVitBjRCkexEvetLdiqzTcYimmzYxyR1BZ79KNevgt61PDcukmC7)/1/7)",
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
