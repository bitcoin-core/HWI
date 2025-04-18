"""
Test PKCS11 Token Support
************************

This module tests the PKCS11 token support implementation.
"""

import os
import unittest
from unittest.mock import patch, MagicMock
from typing import Dict, Any

from hwilib.devices.pkcs11 import PKCS11Client, enumerate
from hwilib.common import Chain
from hwilib.psbt import PSBT
from hwilib.key import ExtendedKey

class TestPKCS11Client(unittest.TestCase):
    """Test the PKCS11 client implementation."""

    def setUp(self):
        """Set up test environment."""
        self.path = "/path/to/pkcs11/library.so"
        self.password = "test123"
        self.chain = Chain.MAIN
        self.expert = False

        # Mock PKCS11 library
        self.mock_lib = MagicMock()
        self.mock_token = MagicMock()
        self.mock_session = MagicMock()
        self.mock_master_key = MagicMock()

        # Set up mock return values
        self.mock_lib.get_token.return_value = self.mock_token
        self.mock_token.open.return_value = self.mock_session
        self.mock_session.get_key.return_value = self.mock_master_key
        self.mock_master_key.get_attribute.return_value = b'\x06\x05\x2b\x81\x04\x00\x0a'  # secp256k1 OID

    @patch('hwilib.devices.pkcs11.pkcs11')
    def test_initialization(self, mock_pkcs11):
        """Test PKCS11 client initialization."""
        mock_pkcs11.lib.return_value = self.mock_lib

        client = PKCS11Client(self.path, self.password, self.expert, self.chain)
        
        # Verify initialization
        self.assertEqual(client.path, self.path)
        self.assertEqual(client.password, self.password)
        self.assertEqual(client.chain, self.chain)
        self.assertEqual(client.expert, self.expert)

    @patch('hwilib.devices.pkcs11.pkcs11')
    def test_get_pubkey_at_path(self, mock_pkcs11):
        """Test getting public key at BIP32 path."""
        mock_pkcs11.lib.return_value = self.mock_lib
        
        # Mock key attributes
        self.mock_session.get_key.return_value = MagicMock(
            get_attribute=lambda x: b'test_pubkey' if x == 'EC_POINT' else b'test_chaincode'
        )

        client = PKCS11Client(self.path, self.password, self.expert, self.chain)
        result = client.get_pubkey_at_path("m/44'/0'/0'/0/0")

        self.assertIsInstance(result, ExtendedKey)
        self.assertEqual(result.key_data, b'test_pubkey')

    @patch('hwilib.devices.pkcs11.pkcs11')
    def test_sign_tx(self, mock_pkcs11):
        """Test transaction signing."""
        mock_pkcs11.lib.return_value = self.mock_lib
        
        # Create a mock PSBT
        psbt = PSBT()
        psbt.inputs = [MagicMock(
            hd_keypaths={b'test_pubkey': MagicMock(fingerprint=b'\x00\x01\x02\x03', path="m/44'/0'/0'/0/0")},
            sighash=b'test_sighash',
            partial_sigs={}
        )]

        # Mock master fingerprint
        self.mock_master_key.get_attribute.return_value = b'\x00\x01\x02\x03'

        client = PKCS11Client(self.path, self.password, self.expert, self.chain)
        result = client.sign_tx(psbt)

        self.assertIsInstance(result, PSBT)
        self.assertIn(b'test_pubkey', result.inputs[0].partial_sigs)

    @patch('hwilib.devices.pkcs11.pkcs11')
    def test_sign_message(self, mock_pkcs11):
        """Test message signing."""
        mock_pkcs11.lib.return_value = self.mock_lib
        
        # Mock signature
        self.mock_session.get_key.return_value = MagicMock(
            sign=lambda x, mechanism: b'test_signature'
        )

        client = PKCS11Client(self.path, self.password, self.expert, self.chain)
        result = client.sign_message("test message", "m/44'/0'/0'/0/0")

        self.assertEqual(result, "746573745f7369676e6174757265")  # hex of 'test_signature'

    @patch('hwilib.devices.pkcs11.pkcs11')
    def test_get_master_fingerprint(self, mock_pkcs11):
        """Test getting master key fingerprint."""
        mock_pkcs11.lib.return_value = self.mock_lib
        
        # Mock public key
        self.mock_master_key.get_attribute.return_value = b'test_pubkey'

        client = PKCS11Client(self.path, self.password, self.expert, self.chain)
        result = client.get_master_fingerprint()

        self.assertIsInstance(result, bytes)
        self.assertEqual(len(result), 4)

    @patch('hwilib.devices.pkcs11.pkcs11')
    def test_enumerate(self, mock_pkcs11):
        """Test device enumeration."""
        mock_pkcs11.lib.return_value = self.mock_lib
        self.mock_lib.get_tokens.return_value = [MagicMock(label='Bitcoin')]

        result = enumerate(self.password, self.expert, self.chain)

        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['type'], 'pkcs11')
        self.assertEqual(result[0]['model'], 'PKCS#11 Token')
        self.assertEqual(result[0]['label'], 'Bitcoin')

    @patch('hwilib.devices.pkcs11.pkcs11')
    def test_close(self, mock_pkcs11):
        """Test closing the session."""
        mock_pkcs11.lib.return_value = self.mock_lib

        client = PKCS11Client(self.path, self.password, self.expert, self.chain)
        client.close()

        self.mock_session.close.assert_called_once()

if __name__ == '__main__':
    unittest.main() 