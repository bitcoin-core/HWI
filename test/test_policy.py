#!/usr/bin/env python3

import unittest

from hwilib.descriptor import AddChecksum
from hwilib.errors import BadArgumentError
from hwilib.policy import BIP388Policy, _validate_template


XPUB_A = "tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT"
XPUB_B = "tpubDDoFYQF4zAhrW8LRtCxePR8bJsAh5SXU6PwPNi2oRfeh67qhmxZawJ4m3V76P8AYSEueKmwvNyiSPAGYtynGfzJNvTHyzj2FJTbp729jmYM"

# Canonical test vectors from BIP388 version 1.1.0:
# https://github.com/bitcoin/bips/blob/master/bip-0388.mediawiki#test-vectors
BIP44_KEY = "[6738736c/44'/0'/0']xpub6Br37sWxruYfT8ASpCjVHKGwgdnYFEn98DwiN76i2oyY6fgH1LAPmmDcF46xjxJr22gw4jmVjTE2E3URMnRPEPYyo1zoPSUba563ESMXCeb"
BIP49_KEY = "[6738736c/49'/0'/1']xpub6Bex1CHWGXNNwGVKHLqNC7kcV348FxkCxpZXyCWp1k27kin8sRPayjZUKDjyQeZzGUdyeAj2emoW5zStFFUAHRgd5w8iVVbLgZ7PmjAKAm9"
BIP84_KEY = "[6738736c/84'/0'/2']xpub6CRQzb8u9dmMcq5XAwwRn9gcoYCjndJkhKgD11WKzbVGd932UmrExWFxCAvRnDN3ez6ZujLmMvmLBaSWdfWVn75L83Qxu1qSX4fJNrJg2Gt"
BIP86_KEY = "[6738736c/86'/0'/0']xpub6CryUDWPS28eR2cDyojB8G354izmx294BdjeSvH469Ty3o2E6Tq5VjBJCn8rWBgesvTJnyXNAJ3QpLFGuNwqFXNt3gn612raffLWfdHNkYL"
BIP48_KEY_0 = "[6738736c/48'/0'/0'/2']xpub6FC1fXFP1GXLX5TKtcjHGT4q89SDRehkQLtbKJ2PzWcvbBHtyDsJPLtpLtkGqYNYZdVVAjRQ5kug9CsapegmmeRutpP7PW4u4wVF9JfkDhw"
BIP48_KEY_1 = "[b2b1f0cf/48'/0'/0'/2']xpub6EWhjpPa6FqrcaPBuGBZRJVjzGJ1ZsMygRF26RwN932Vfkn1gyCiTbECVitBjRCkexEvetLdiqzTcYimmzYxyR1BZ79KNevgt61PDcukmC7"
POLICY_KEY_0 = "[6738736c/48'/0'/0'/100']xpub6FC1fXFP1GXQpyRFfSE1vzzySqs3Vg63bzimYLeqtNUYbzA87kMNTcuy9ubr7MmavGRjW2FRYHP4WGKjwutbf1ghgkUW9H7e3ceaPLRcVwa"
POLICY_KEY_1 = "[b2b1f0cf/44'/0'/0'/100']xpub6EYajCJHe2CK53RLVXrN14uWoEttZgrRSaRztujsXg7yRhGtHmLBt9ot9Pd5ugfwWEu6eWyJYKSshyvZFKDXiNbBcoK42KRZbxwjRQpm5Js"
POLICY_KEY_2 = "[a666a867/44'/0'/0'/100']xpub6Dgsze3ujLi1EiHoCtHFMS9VLS1UheVqxrHGfP7sBJ2DBfChEUHV4MDwmxAXR2ayeytpwm3zJEU3H3pjCR6q6U5sP2p2qzAD71x9z5QShK2"
POLICY_KEY_3 = "[bb641298/44'/0'/0'/100']xpub6Dz8PHFmXkYkykQ83ySkruky567XtJb9N69uXScJZqweYiQn6FyieajdiyjCvWzRZ2GoLHMRE1cwDfuJZ6461YvNRGVBJNnLA35cZrQKSRJ"
TAPROOT_KEY_1 = "xpub6Fc2TRaCWNgfT49nRGG2G78d1dPnjhW66gEXi7oYZML7qEFN8e21b2DLDipTZZnfV6V7ivrMkvh4VbnHY2ChHTS9qM3XVLJiAgcfagYQk6K"
TAPROOT_KEY_2 = "xpub6GxHB9kRdFfTqYka8tgtX9Gh3Td3A9XS8uakUGVcJ9NGZ1uLrGZrRVr67DjpMNCHprZmVmceFTY4X4wWfksy8nVwPiNvzJ5pjLxzPtpnfEM"
TAPROOT_KEY_3 = "xpub6GjFUVVYewLj5no5uoNKCWuyWhQ1rKGvV8DgXBG9Uc6DvAKxt2dhrj1EZFrTNB5qxAoBkVW3wF8uCS3q1ri9fueAa6y7heFTcf27Q4gyeh6"
NON_PLACEHOLDER_XPUB = "xpub6AHA9hZDN11k2ijHMeS5QqHx2KP9aMBRhTDqANMnwVtdyw2TDYRmF8PjpvwUFcL1Et8Hj59S3gTSMcUQ5gAqTz3Wd8EsMTmF3DChhqPQBnU"
RECEIVE_CHANGE_DERIVATION = "/<0;1>/*"
ALTERNATE_DERIVATION = "/<2;3>/*"
OVERLAPPING_DERIVATION = "/<1;2>/*"


class TestBIP388Policy(unittest.TestCase):
    def test_bip388_valid_policy_vectors(self) -> None:
        musig_3_of_3 = f"musig({POLICY_KEY_0},{POLICY_KEY_1},{POLICY_KEY_2})"
        musig_0_1 = f"musig({POLICY_KEY_0},{POLICY_KEY_1})"
        musig_0_2 = f"musig({POLICY_KEY_0},{POLICY_KEY_2})"
        musig_1_2 = f"musig({POLICY_KEY_1},{POLICY_KEY_2})"

        valid_policies = [
            (
                "BIP-44, first account",
                "pkh(@0/**)",
                [BIP44_KEY],
                f"pkh({BIP44_KEY}{RECEIVE_CHANGE_DERIVATION})",
            ),
            (
                "BIP-49, second account",
                "sh(wpkh(@0/**))",
                [BIP49_KEY],
                f"sh(wpkh({BIP49_KEY}{RECEIVE_CHANGE_DERIVATION}))",
            ),
            (
                "BIP-84, third account",
                "wpkh(@0/**)",
                [BIP84_KEY],
                f"wpkh({BIP84_KEY}{RECEIVE_CHANGE_DERIVATION})",
            ),
            (
                "BIP-86, first account",
                "tr(@0/**)",
                [BIP86_KEY],
                f"tr({BIP86_KEY}{RECEIVE_CHANGE_DERIVATION})",
            ),
            (
                "BIP-48 P2WSH multisig",
                "wsh(sortedmulti(2,@0/**,@1/**))",
                [BIP48_KEY_0, BIP48_KEY_1],
                f"wsh(sortedmulti(2,{BIP48_KEY_0}{RECEIVE_CHANGE_DERIVATION},{BIP48_KEY_1}{RECEIVE_CHANGE_DERIVATION}))",
            ),
            (
                "Miniscript 3-of-3 degrading to 2-of-3",
                "wsh(thresh(3,pk(@0/**),s:pk(@1/**),s:pk(@2/**),sln:older(12960)))",
                [POLICY_KEY_0, POLICY_KEY_1, POLICY_KEY_2],
                f"wsh(thresh(3,pk({POLICY_KEY_0}{RECEIVE_CHANGE_DERIVATION}),s:pk({POLICY_KEY_1}{RECEIVE_CHANGE_DERIVATION}),s:pk({POLICY_KEY_2}{RECEIVE_CHANGE_DERIVATION}),sln:older(12960)))",
            ),
            (
                "Miniscript automatic inheritance",
                "wsh(or_d(pk(@0/**),and_v(v:multi(2,@1/**,@2/**,@3/**),older(65535))))",
                [POLICY_KEY_0, POLICY_KEY_1, POLICY_KEY_2, POLICY_KEY_3],
                f"wsh(or_d(pk({POLICY_KEY_0}{RECEIVE_CHANGE_DERIVATION}),and_v(v:multi(2,{POLICY_KEY_1}{RECEIVE_CHANGE_DERIVATION},{POLICY_KEY_2}{RECEIVE_CHANGE_DERIVATION},{POLICY_KEY_3}{RECEIVE_CHANGE_DERIVATION}),older(65535))))",
            ),
            (
                "Taproot sortedmulti_a and miniscript leaves",
                "tr(@0/**,{sortedmulti_a(1,@0/<2;3>/*,@1/**),or_b(pk(@2/**),s:pk(@3/**))})",
                [POLICY_KEY_0, TAPROOT_KEY_1, TAPROOT_KEY_2, TAPROOT_KEY_3],
                f"tr({POLICY_KEY_0}{RECEIVE_CHANGE_DERIVATION},{{sortedmulti_a(1,{POLICY_KEY_0}{ALTERNATE_DERIVATION},{TAPROOT_KEY_1}{RECEIVE_CHANGE_DERIVATION}),or_b(pk({TAPROOT_KEY_2}{RECEIVE_CHANGE_DERIVATION}),s:pk({TAPROOT_KEY_3}{RECEIVE_CHANGE_DERIVATION}))}})",
            ),
            (
                "Taproot MuSig2 with recovery paths",
                "tr(musig(@0,@1,@2)/**,{and_v(v:pk(musig(@0,@1)/**),older(12960)),{and_v(v:pk(musig(@0,@2)/**),older(12960)),and_v(v:pk(musig(@1,@2)/**),older(12960))}})",
                [POLICY_KEY_0, POLICY_KEY_1, POLICY_KEY_2],
                f"tr({musig_3_of_3}{RECEIVE_CHANGE_DERIVATION},{{and_v(v:pk({musig_0_1}{RECEIVE_CHANGE_DERIVATION}),older(12960)),{{and_v(v:pk({musig_0_2}{RECEIVE_CHANGE_DERIVATION}),older(12960)),and_v(v:pk({musig_1_2}{RECEIVE_CHANGE_DERIVATION}),older(12960))}}}})",
            ),
        ]

        for name, descriptor_template, keys_info, descriptor in valid_policies:
            with self.subTest(name=name):
                policy = BIP388Policy.from_descriptor(name, descriptor)
                self.assertEqual(policy.descriptor_template, descriptor_template)
                self.assertEqual(policy.keys_info, keys_info)

    def test_bip388_invalid_policy_vectors(self) -> None:
        invalid_templates = [
            ("Key placeholder with no path", "pkh(@0)", 1),
            ("Key placeholder with an explicit path", "pkh(@0/0/**)", 1),
            ("Key placeholders out of order", "sh(multi(1,@1/**,@0/**))", 2),
            ("Skipped key placeholder", "sh(multi(1,@0/**,@2/**))", 3),
            ("Repeated key path", "sh(multi(1,@0/**,@0/**))", 1),
            (
                "Non-disjoint multipath expressions",
                "sh(multi(1,@0/<0;1>/*,@0/<1;2>/*))",
                1,
            ),
            (
                "Non-placeholder key",
                f"sh(multi(1,@0/**,{NON_PLACEHOLDER_XPUB}{RECEIVE_CHANGE_DERIVATION}))",
                1,
            ),
            ("Multipath cardinality greater than two", "pkh(@0/<0;1;2>/*)", 1),
            ("Derivation before MuSig2 aggregation", "tr(musig(@0/**,@1/**))", 2),
        ]

        for name, descriptor_template, key_count in invalid_templates:
            with self.subTest(name=name):
                with self.assertRaises(BadArgumentError):
                    _validate_template(descriptor_template, key_count)

    def test_single_key_descriptor(self) -> None:
        descriptor = f"wpkh([f5acc2fd/84h/1h/0h]{XPUB_A}{RECEIVE_CHANGE_DERIVATION})"
        policy = BIP388Policy.from_descriptor("single", AddChecksum(descriptor))

        self.assertEqual(policy.name, "single")
        self.assertEqual(policy.descriptor_template, "wpkh(@0/**)")
        self.assertEqual(
            policy.keys_info,
            [f"[f5acc2fd/84'/1'/0']{XPUB_A}"],
        )
        self.assertIsNone(policy.registration)

    def test_musig_descriptor(self) -> None:
        descriptor = (
            f"tr(musig([f5acc2fd/87h/1h/0h]{XPUB_A},"
            f"[4c00739d/87h/1h/0h]{XPUB_B}){RECEIVE_CHANGE_DERIVATION})"
        )
        policy = BIP388Policy.from_descriptor("musig", descriptor, "00" * 32)

        self.assertEqual(policy.descriptor_template, "tr(musig(@0,@1)/**)")
        self.assertEqual(len(policy.keys_info), 2)
        self.assertEqual(policy.registration, "00" * 32)

    def test_reused_key_with_disjoint_branches(self) -> None:
        descriptor = (
            f"wsh(or_b(pk([f5acc2fd/84h/1h/0h]{XPUB_A}{RECEIVE_CHANGE_DERIVATION}),"
            f"s:pk([f5acc2fd/84h/1h/0h]{XPUB_A}{ALTERNATE_DERIVATION})))"
        )
        policy = BIP388Policy.from_descriptor("branches", descriptor)

        self.assertEqual(len(policy.keys_info), 1)
        self.assertEqual(
            policy.descriptor_template,
            "wsh(or_b(pk(@0/**),s:pk(@0/<2;3>/*)))",
        )

    def test_rejects_non_combined_descriptor(self) -> None:
        with self.assertRaisesRegex(BadArgumentError, "Every BIP388 key placeholder"):
            BIP388Policy.from_descriptor(
                "receive only",
                f"wpkh([f5acc2fd/84h/1h/0h]{XPUB_A}/0/*)",
            )

    def test_rejects_bad_checksum(self) -> None:
        with self.assertRaisesRegex(BadArgumentError, "checksum does not match"):
            BIP388Policy.from_descriptor(
                "bad checksum",
                f"wpkh([f5acc2fd/84h/1h/0h]{XPUB_A}{RECEIVE_CHANGE_DERIVATION})#aaaaaaaa",
            )

    def test_rejects_overlapping_key_reuse(self) -> None:
        descriptor = (
            f"wsh(or_b(pk([f5acc2fd/84h/1h/0h]{XPUB_A}{RECEIVE_CHANGE_DERIVATION}),"
            f"s:pk([f5acc2fd/84h/1h/0h]{XPUB_A}{OVERLAPPING_DERIVATION})))"
        )
        with self.assertRaisesRegex(BadArgumentError, "overlapping derivation"):
            BIP388Policy.from_descriptor("overlap", descriptor)


if __name__ == "__main__":
    unittest.main()
