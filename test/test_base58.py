#! /usr/bin/env python3

"""Reference tests for base58"""

from binascii import unhexlify
from typing import List, Tuple
import unittest
import hwilib._base58 as base58

# Taken from Bitcoin Core
# https://github.com/bitcoin/bitcoin/blob/master/src/test/data/base58_encode_decode.json
TEST_VECTORS: List[Tuple[str, str]] = [
    ("", ""),
    ("61", "2g"),
    ("626262", "a3gV"),
    ("636363", "aPEr"),
    ("73696d706c792061206c6f6e6720737472696e67", "2cFupjhnEsSn59qHXstmK2ffpLv2"),
    ("00eb15231dfceb60925886b67d065299925915aeb172c06647", "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L"),
    ("516b6fcd0f", "ABnLTmg"),
    ("bf4f89001e670274dd", "3SEo3LWLoPntC"),
    ("572e4794", "3EFU7m"),
    ("ecac89cad93923c02321", "EJDM8drfXA6uyA"),
    ("10c8511e", "Rt5zm"),
    ("00000000000000000000", "1111111111"),
    ("000111d38e5fc9071ffcd20b4a763cc9ae4f252bb4e48fd66a835e252ada93ff480d6dd43dc62a641155a5",
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"),
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "1cWB5HCBdLjAuqGGReWE3R3CguuwSjw6RHn39s2yuDRTS5NsBgNiFpWgAnEx6VQi8csexkgYw3mdYrMHr8x9i7aEwP8kZ7vccXWqKDvGv3u1GxFKPuAkn8JCPPGDMf3vMMnbzm6Nh9zh1gcNsMvH3ZNLmP5fSG6DGbbi2tuwMWPthr4boWwCxf7ewSgNQeacyozhKDDQQ1qL5fQFUW52QKUZDZ5fw3KXNQJMcNTcaB723LchjeKun7MuGW5qyCBZYzA1KjofN1gYBV3NqyhQJ3Ns746GNuf9N2pQPmHz4xpnSrrfCvy6TVVz5d4PdrjeshsWQwpZsZGzvbdAdN8MKV5QsBDY")
]

# Test vectors for encode_check and decode_check
TEST_VECTORS_CHECK: List[Tuple[str, str]] = [
    ("", "3QJmnh"),
    ("61", "C2dGTwc"),
    ("626262", "4jF5uERJAK"),
    ("636363", "4mT4krqUYJ"),
    ("73696d706c792061206c6f6e6720737472696e67", "BXF1HuEUCqeVzZdrKeJjG74rjeXxqJ7dW"),
    ("00eb15231dfceb60925886b67d065299925915aeb172c06647", "13REmUhe2ckUKy1FvM7AMCdtyYq831yxM3QeyEu4"),
    ("516b6fcd0f", "237LSrY9NUUas"),
    ("bf4f89001e670274dd", "GwDDDeduj1jpykc27e"),
    ("572e4794", "FamExfqCeza"),
    ("ecac89cad93923c02321", "2W1Yd5Zu6WGyKVtHGMrH"),
    ("10c8511e", "3op3iuGMmhs"),
    ("00000000000000000000", "111111111146Momb"),
    ("000111d38e5fc9071ffcd20b4a763cc9ae4f252bb4e48fd66a835e252ada93ff480d6dd43dc62a641155a5", "17mxz9b2TuLnDf6XyQrHjAc3UvMoEg7YzRsJkBd4VwNpFh8a1StKmCe5WtAW27Y"),
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "151KWPPBRzdWPr1ASeu172gVgLf1YfUp6VJyk6K9t4cLqYtFHcMa2iX8S3NJEprUcW7W5LvaPRpz7UG7puBj5STE3nKhCGt5eckYq7mMn5nT7oTTic2BAX6zDdqrmGCnkszQkzkz8e5QLGDjf7KeQgtEDm4UER6DMSdBjFQVa6cHrrJn9myVyyhUrsVnfUk2WmNFZvkWv3Tnvzo2cJ1xW62XDfUgYz1pd97eUGGPuXvDFfLsBVd1dfdUhPwxW7pMPgdWHTmg5uqKGFF6vE4xXpAqZTbTxRZjCDdTn68c2wrcxApm8hq3JX65Hix7VtcD13FF8b7BzBtwjXq1ze6NMjKgUcqpGV5XA5"),
]

class TestBase58(unittest.TestCase):
    """Unit test class for base58 encoding and decoding."""

    def test_decoding(self):
        """Test base58 decoding"""

        for pair in TEST_VECTORS:
            decoded: bytes = base58.decode(pair[1])
            self.assertEqual(decoded, unhexlify(pair[0]))

    def test_encoding(self):
        """Test base58 encoding"""

        for pair in TEST_VECTORS:
            encoded: str = base58.encode(unhexlify(pair[0]))
            self.assertEqual(encoded, pair[1])

    def test_check_decoding(self):
        """Test base58 check decoding"""

        for pair in TEST_VECTORS_CHECK:
            decoded: bytes = base58.decode_check(pair[1])
            self.assertEqual(decoded, unhexlify(pair[0]))

    def test_check_encoding(self):
        """Test base58 check encoding"""

        for pair in TEST_VECTORS_CHECK:
            encoded: str = base58.encode_check(unhexlify(pair[0]))
            self.assertEqual(encoded, pair[1])

if __name__ == "__main__":
    unittest.main()
