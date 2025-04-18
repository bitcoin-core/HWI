"""
PKCS#11 Token Support
********************

This module implements support for PKCS#11 tokens (HSMs) with secp256k1 curve support.
"""

import logging
import os
import platform
import struct
from typing import Dict, List, Optional, Set, Tuple, Union, Any

import pkcs11
from pkcs11 import Mechanism, ObjectClass, KeyType, Attribute

from ..hwwclient import HardwareWalletClient
from ..common import AddressType, Chain
from ..key import ExtendedKey, parse_path
from ..psbt import PSBT
from ..errors import (
    BadArgumentError,
    DeviceConnectionError,
    DeviceNotReadyError,
    UnavailableActionError,
)
from ..descriptor import MultisigDescriptor

# Constants for PKCS#11
PKCS11_LIB_PATH = os.environ.get('PKCS11_LIB_PATH', '')
TOKEN_LABEL = os.environ.get('PKCS11_TOKEN_LABEL', 'Bitcoin')
MASTER_KEY_LABEL = 'MASTER_KEY'

# Windows-specific paths
if platform.system() == 'Windows':
    DEFAULT_PKCS11_PATHS = [
        r'C:\Windows\System32\*.dll',  # System PKCS#11 libraries
        r'C:\Program Files\*.dll',     # Program Files PKCS#11 libraries
        r'C:\Program Files (x86)\*.dll' # 32-bit Program Files PKCS#11 libraries
    ]
else:
    DEFAULT_PKCS11_PATHS = [
        '/usr/lib/*.so',           # System libraries
        '/usr/local/lib/*.so',     # Local libraries
        '/usr/lib/x86_64-linux-gnu/*.so',  # Debian/Ubuntu
        '/usr/lib64/*.so',         # Fedora/RHEL
    ]

class PKCS11Client(HardwareWalletClient):
    """Create a client for a PKCS#11 token that has already been opened."""

    def __init__(self, path: str, password: Optional[str] = None, expert: bool = False, chain: Chain = Chain.MAIN) -> None:
        """
        Initialize the PKCS#11 client.

        :param path: Path to the PKCS#11 library
        :param password: The PIN/password to use with the token
        :param expert: Whether to return additional information intended for experts
        :param chain: The chain to use (mainnet/testnet)
        """
        super(PKCS11Client, self).__init__(path, password, expert, chain)
        
        if not path:
            # Try to find the PKCS#11 library
            for pattern in DEFAULT_PKCS11_PATHS:
                try:
                    import glob
                    libs = glob.glob(pattern)
                    if libs:
                        path = libs[0]
                        break
                except:
                    continue
            
            if not path:
                raise DeviceConnectionError("PKCS#11 library path not specified and no default library found")
            
        try:
            # Initialize PKCS#11 library
            self.lib = pkcs11.lib(path)
            self.token = self.lib.get_token(token_label=TOKEN_LABEL)
            self.session = self.token.open(user_pin=password)
            
            # Find the master key
            self.master_key = self.session.get_key(
                object_class=ObjectClass.PRIVATE_KEY,
                key_type=KeyType.EC,
                label=MASTER_KEY_LABEL
            )
            
            # Verify secp256k1 curve support
            curve = self.master_key.get_attribute(Attribute.EC_PARAMS)
            if curve != b'\x06\x05\x2b\x81\x04\x00\x0a':  # OID for secp256k1
                raise DeviceNotReadyError("Token does not support secp256k1 curve")
                
        except Exception as e:
            raise DeviceConnectionError(f"Failed to connect to PKCS#11 token: {str(e)}")

    def get_pubkey_at_path(self, bip32_path: str) -> ExtendedKey:
        """
        Get the public key at the BIP32 derivation path.

        :param bip32_path: The BIP32 derivation path
        :return: The extended public key
        """
        try:
            # Parse BIP32 path
            path = parse_path(bip32_path)
            
            # Get the key at this path
            key = self.session.get_key(
                object_class=ObjectClass.PRIVATE_KEY,
                key_type=KeyType.EC,
                label=f"KEY_{bip32_path}"
            )
            
            # Get public key attributes
            pubkey = key.get_attribute(Attribute.EC_POINT)
            chain_code = key.get_attribute(Attribute.EC_PARAMS)
            
            # Create ExtendedKey
            return ExtendedKey(
                version=ExtendedKey.MAINNET_PUBLIC if self.chain == Chain.MAIN else ExtendedKey.TESTNET_PUBLIC,
                depth=len(path),
                parent_fingerprint=self.get_master_fingerprint(),
                child_num=path[-1] if path else 0,
                chain_code=chain_code,
                key_data=pubkey
            )
        except Exception as e:
            raise BadArgumentError(f"Failed to get public key at path {bip32_path}: {str(e)}")

    def sign_tx(self, psbt: PSBT) -> PSBT:
        """
        Sign a PSBT using the PKCS#11 token.

        :param psbt: The PSBT to sign
        :return: The signed PSBT
        """
        try:
            # Get master fingerprint
            master_fp = self.get_master_fingerprint()
            
            # For each input that needs signing
            for input_num, psbt_in in enumerate(psbt.inputs):
                # Check if this input needs our signature
                for pubkey, origin in psbt_in.hd_keypaths.items():
                    if origin.fingerprint == master_fp:
                        # Get the key for this path
                        key = self.session.get_key(
                            object_class=ObjectClass.PRIVATE_KEY,
                            key_type=KeyType.EC,
                            label=f"KEY_{origin.path}"
                        )
                        
                        # Sign the input
                        signature = key.sign(
                            psbt_in.sighash,
                            mechanism=Mechanism.ECDSA
                        )
                        
                        # Add signature to PSBT
                        psbt_in.partial_sigs[pubkey] = signature + b'\x01'  # SIGHASH_ALL
            
            return psbt
        except Exception as e:
            raise BadArgumentError(f"Failed to sign transaction: {str(e)}")

    def sign_message(self, message: Union[str, bytes], keypath: str) -> str:
        """
        Sign a message using the key at the specified path.

        :param message: The message to sign
        :param keypath: The BIP32 path of the key to sign with
        :return: The signature in base64 format
        """
        try:
            # Get the key
            key = self.session.get_key(
                object_class=ObjectClass.PRIVATE_KEY,
                key_type=KeyType.EC,
                label=f"KEY_{keypath}"
            )
            
            # Sign the message
            signature = key.sign(
                message if isinstance(message, bytes) else message.encode(),
                mechanism=Mechanism.ECDSA
            )
            
            return signature.hex()
        except Exception as e:
            raise BadArgumentError(f"Failed to sign message: {str(e)}")

    def get_master_fingerprint(self) -> bytes:
        """
        Get the master key's fingerprint.

        :return: The master key fingerprint
        """
        try:
            # Get the master public key
            pubkey = self.master_key.get_attribute(Attribute.EC_POINT)
            
            # Calculate fingerprint (first 4 bytes of hash160)
            from hashlib import sha256, ripemd160
            h = ripemd160.new(sha256(pubkey).digest()).digest()
            return h[:4]
        except Exception as e:
            raise DeviceNotReadyError(f"Failed to get master fingerprint: {str(e)}")

    def close(self) -> None:
        """Close the PKCS#11 session."""
        try:
            self.session.close()
        except:
            pass

def enumerate(password: Optional[str] = None, expert: bool = False, chain: Chain = Chain.MAIN, allow_emulators: bool = False) -> List[Dict[str, Any]]:
    """
    Enumerate all connected PKCS#11 tokens.

    :param password: The PIN/password to use with the token
    :param expert: Whether to return additional information intended for experts
    :param chain: The chain to use (mainnet/testnet)
    :param allow_emulators: Whether to allow emulator devices
    :return: A list of dictionaries describing the found tokens
    """
    result = []
    
    # Try all possible PKCS#11 library paths
    paths_to_try = [PKCS11_LIB_PATH] if PKCS11_LIB_PATH else []
    paths_to_try.extend(DEFAULT_PKCS11_PATHS)
    
    for path_pattern in paths_to_try:
        try:
            import glob
            for path in glob.glob(path_pattern):
                try:
                    # Try to load the PKCS#11 library
                    lib = pkcs11.lib(path)
                    
                    # Get all tokens
                    for token in lib.get_tokens():
                        if token.label == TOKEN_LABEL:
                            result.append({
                                'type': 'pkcs11',
                                'path': path,
                                'model': 'PKCS#11 Token',
                                'label': token.label,
                                'expert': expert,
                                'chain': chain,
                            })
                except Exception as e:
                    logging.debug(f"Failed to load PKCS#11 library at {path}: {str(e)}")
                    continue
        except Exception as e:
            logging.debug(f"Failed to glob path pattern {path_pattern}: {str(e)}")
            continue
    
    return result 