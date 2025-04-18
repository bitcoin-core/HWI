"""
Devices
*******

This module contains all of the device implementations.
Each device implementation is a subclass of :class:`~hwilib.hwwclient.HardwareWalletClient`.
"""

from .trezor import TrezorClient
from .ledger import LedgerClient
from .keepkey import KeepkeyClient
from .jade import JadeClient
from .coldcard import ColdcardClient
from .digitalbitbox import DigitalbitboxClient
from .bitbox02 import Bitbox02Client
from .pkcs11 import PKCS11Client

__all__ = [
    'trezor',
    'ledger',
    'keepkey',
    'jade',
    'coldcard',
    'digitalbitbox',
    'bitbox02',
    'pkcs11',
]
