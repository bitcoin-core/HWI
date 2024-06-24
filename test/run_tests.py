#! /usr/bin/env python3

import argparse
import sys
import unittest

from test_base58 import TestBase58
from test_bech32 import TestSegwitAddress
from test_bip32 import TestBIP32
from test_coldcard import coldcard_test_suite
from test_descriptor import TestDescriptor
from test_device import Bitcoind
from test_psbt import TestPSBT
from test_trezor import trezor_test_suite
from test_ledger import ledger_test_suite
from test_digitalbitbox import digitalbitbox_test_suite
from test_keepkey import keepkey_test_suite
from test_jade import jade_test_suite
from test_bitbox02 import bitbox02_test_suite
from test_udevrules import TestUdevRulesInstaller

parser = argparse.ArgumentParser(description='Setup the testing environment and run automated tests')
trezor_group = parser.add_mutually_exclusive_group()
trezor_group.add_argument('--no-trezor-1', dest='trezor_1', help='Do not run Trezor test with emulator', action='store_false')
trezor_group.add_argument('--trezor-1', dest='trezor_1', help='Run Trezor test with emulator', action='store_true')

trezor_t_group = parser.add_mutually_exclusive_group()
trezor_t_group.add_argument('--no-trezor-t', dest='trezor_t', help='Do not run Trezor T test with emulator', action='store_false')
trezor_t_group.add_argument('--trezor-t', dest='trezor_t', help='Run Trezor T test with emulator', action='store_true')

coldcard_group = parser.add_mutually_exclusive_group()
coldcard_group.add_argument('--no-coldcard', dest='coldcard', help='Do not run Coldcard test with simulator', action='store_false')
coldcard_group.add_argument('--coldcard', dest='coldcard', help='Run Coldcard test with simulator', action='store_true')

ledger_group = parser.add_mutually_exclusive_group()
ledger_group.add_argument('--no-ledger', dest='ledger', help='Do not run Ledger test with emulator', action='store_false')
ledger_group.add_argument('--ledger', dest='ledger', help='Run Ledger test with emulator', action='store_true')

ledger_legacy_group = parser.add_mutually_exclusive_group()
ledger_legacy_group.add_argument('--no-ledger-legacy', dest='ledger_legacy', help='Do not run Ledger App legacy test with emulator', action='store_false')
ledger_legacy_group.add_argument('--ledger-legacy', dest='ledger_legacy', help='Run Ledger App legacy test with emulator', action='store_true')

keepkey_group = parser.add_mutually_exclusive_group()
keepkey_group.add_argument('--no-keepkey', dest='keepkey', help='Do not run Keepkey test with emulator', action='store_false')
keepkey_group.add_argument('--keepkey', dest='keepkey', help='Run Keepkey test with emulator', action='store_true')

jade_group = parser.add_mutually_exclusive_group()
jade_group.add_argument('--no-jade', dest='jade', help='Do not run Jade test with emulator', action='store_false')
jade_group.add_argument('--jade', dest='jade', help='Run Jade test with emulator', action='store_true')

dbb_group = parser.add_mutually_exclusive_group()
dbb_group.add_argument('--no_bitbox01', dest='bitbox01', help='Do not run Digital Bitbox test with simulator', action='store_false')
dbb_group.add_argument('--bitbox01', dest='bitbox01', help='Run Digital Bitbox test with simulator', action='store_true')

dbb_group = parser.add_mutually_exclusive_group()
dbb_group.add_argument('--no_bitbox02', dest='bitbox02', help='Do not run BitBox02 test with simulator', action='store_false')
dbb_group.add_argument('--bitbox02', dest='bitbox02', help='Run BitBox02 test with simulator', action='store_true')

parser.add_argument('--trezor-1-path', dest='trezor_1_path', help='Path to Trezor 1 emulator', default='work/trezor-firmware/legacy/firmware/trezor.elf')
parser.add_argument('--trezor-t-path', dest='trezor_t_path', help='Path to Trezor T emulator', default='work/trezor-firmware/core/emu.sh')
parser.add_argument('--coldcard-path', dest='coldcard_path', help='Path to Coldcar simulator', default='work/firmware/unix/headless.py')
parser.add_argument('--keepkey-path', dest='keepkey_path', help='Path to Keepkey emulator', default='work/keepkey-firmware/bin/kkemu')
parser.add_argument('--bitbox01-path', dest='bitbox01_path', help='Path to Digital Bitbox simulator', default='work/mcu/build/bin/simulator')
parser.add_argument('--ledger-path', dest='ledger_path', help='Path to Ledger emulator', default='work/speculos/speculos.py')
parser.add_argument('--jade-path', dest='jade_path', help='Path to Jade qemu emulator', default='work/jade/simulator')
parser.add_argument('--bitbox02-path', dest='bitbox02_path', help='Path to BitBox02 simulator', default='work/bitbox02-firmware/build-build/bin/simulator')

parser.add_argument('--all', help='Run tests on all existing simulators', default=False, action='store_true')
parser.add_argument('--bitcoind', help='Path to bitcoind', default='work/bitcoin/src/bitcoind')
parser.add_argument('--interface', help='Which interface to send commands over', choices=['library', 'cli', 'bindist', 'stdin'], default='library')

parser.add_argument("--device-only", help="Only run device tests", action="store_true")

parser.set_defaults(trezor_1=None, trezor_t=None, coldcard=None, keepkey=None, bitbox01=None, ledger=None, ledger_legacy=None, jade=None, bitbox02=None)

args = parser.parse_args()

# Run tests
success = True
suite = unittest.TestSuite()
if not args.device_only:
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestDescriptor))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestSegwitAddress))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestPSBT))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestBase58))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestBIP32))
    if sys.platform.startswith("linux"):
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestUdevRulesInstaller))
    success = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite).wasSuccessful()

if args.all:
    # Default all true unless overridden
    args.trezor_1 = True if args.trezor_1 is None else args.trezor_1
    args.trezor_t = True if args.trezor_t is None else args.trezor_t
    args.coldcard = True if args.coldcard is None else args.coldcard
    args.keepkey = True if args.keepkey is None else args.keepkey
    args.bitbox01 = True if args.bitbox01 is None else args.bitbox01
    args.ledger = True if args.ledger is None else args.ledger
    args.ledger_legacy = True if args.ledger_legacy is None else args.ledger_legacy
    args.jade = True if args.jade is None else args.jade
    args.bitbox02 = True if args.bitbox02 is None else args.bitbox02
else:
    # Default all false unless overridden
    args.trezor_1 = False if args.trezor_1 is None else args.trezor_1
    args.trezor_t = False if args.trezor_t is None else args.trezor_t
    args.coldcard = False if args.coldcard is None else args.coldcard
    args.keepkey = False if args.keepkey is None else args.keepkey
    args.bitbox01 = False if args.bitbox01 is None else args.bitbox01
    args.ledger = False if args.ledger is None else args.ledger
    args.ledger_legacy = False if args.ledger_legacy is None else args.ledger_legacy
    args.jade = False if args.jade is None else args.jade
    args.bitbox02 = False if args.bitbox02 is None else args.bitbox02

if args.trezor_1 or args.trezor_t or args.coldcard or args.ledger or args.ledger_legacy or args.keepkey or args.bitbox01 or args.jade or args.bitbox02:
    # Start bitcoind
    bitcoind = Bitcoind.create(args.bitcoind)

    if success and args.bitbox01:
        success &= digitalbitbox_test_suite(args.bitbox01_path, bitcoind, args.interface)
    if success and args.coldcard:
        success &= coldcard_test_suite(args.coldcard_path, bitcoind, args.interface)
    if success and args.trezor_1:
        success &= trezor_test_suite(args.trezor_1_path, bitcoind, args.interface, '1')
    if success and args.trezor_t:
        success &= trezor_test_suite(args.trezor_t_path, bitcoind, args.interface, 't')
    if success and args.keepkey:
        success &= keepkey_test_suite(args.keepkey_path, bitcoind, args.interface)
    if success and args.ledger:
        success &= ledger_test_suite(args.ledger_path, bitcoind, args.interface, False)
    if success and args.ledger_legacy:
        success &= ledger_test_suite(args.ledger_path, bitcoind, args.interface, True)
    if success and args.jade:
        success &= jade_test_suite(args.jade_path, bitcoind, args.interface)
    if success and args.bitbox02:
        success &= bitbox02_test_suite(args.bitbox02_path, bitcoind, args.interface)

sys.exit(not success)
