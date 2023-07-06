# Copyright 2019 Shift Cryptosecurity AG
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
""" Library to interact with a BitBox02 device. """

from __future__ import print_function
import sys

__version__ = "6.2.0"

if sys.version_info.major != 3 or sys.version_info.minor < 6:
    print(
        "Python version is {}.{}, but 3.6+ is required by this script.".format(
            sys.version_info.major, sys.version_info.minor
        ),
        file=sys.stderr,
    )
    sys.exit(1)

try:
    import hid

    hid.device  # pylint: disable=pointless-statement
except AttributeError:
    print(
        "Unable to reference hid.device; maybe hid package is masking "
        "hidapi? Try:\n\t$ pip3 uninstall hid",
        file=sys.stderr,
    )
    sys.exit(1)

# pylint: disable=wrong-import-position
from .bitbox02 import (
    btc_sign_needs_prevtxs,
    Backup,
    BitBox02,
    BTCInputType,
    BTCOutputExternal,
    BTCOutputInternal,
    BTCOutputType,
    BTCPrevTxInputType,
    BTCPrevTxOutputType,
    DuplicateEntryException,
    hww,
    btc,
    cardano,
    common,
    eth,
    system,
)
from .bootloader import Bootloader
