#! /usr/bin/env python3

import argparse
import sys
import unittest

from test_base58 import TestBase58
from test_bech32 import TestSegwitAddress
from test_bip32 import TestBIP32
from test_coldcard import coldcard_test_suite
from test_descriptor import TestDescriptor
from test_device import start_bitcoind
from test_psbt import TestPSBT
from test_trezor import trezor_test_suite
from test_ledger import ledger_test_suite
from test_digitalbitbox import digitalbitbox_test_suite
from test_keepkey import keepkey_test_suite
from test_udevrules import TestUdevRulesInstaller

parser = argparse.ArgumentParser(description='Setup the testing environment and run automated tests')
trezor_group = parser.add_mutually_exclusive_group()
trezor_group.add_argument('--no-trezor', dest='trezor', help='Do not run Trezor test with emulator', action='store_false')
trezor_group.add_argument('--trezor', dest='trezor', help='Run Trezor test with emulator', action='store_true')

trezor_t_group = parser.add_mutually_exclusive_group()
trezor_t_group.add_argument('--no-trezor-t', dest='trezor_t', help='Do not run Trezor T test with emulator', action='store_false')
trezor_t_group.add_argument('--trezor-t', dest='trezor_t', help='Run Trezor T test with emulator', action='store_true')

coldcard_group = parser.add_mutually_exclusive_group()
coldcard_group.add_argument('--no-coldcard', dest='coldcard', help='Do not run Coldcard test with simulator', action='store_false')
coldcard_group.add_argument('--coldcard', dest='coldcard', help='Run Coldcard test with simulator', action='store_true')

ledger_group = parser.add_mutually_exclusive_group()
ledger_group.add_argument('--no-ledger', dest='ledger', help='Do not run Ledger test with emulator', action='store_false')
ledger_group.add_argument('--ledger', dest='ledger', help='Run Ledger test with emulator', action='store_true')

keepkey_group = parser.add_mutually_exclusive_group()
keepkey_group.add_argument('--no-keepkey', dest='keepkey', help='Do not run Keepkey test with emulator', action='store_false')
keepkey_group.add_argument('--keepkey', dest='keepkey', help='Run Keepkey test with emulator', action='store_true')

dbb_group = parser.add_mutually_exclusive_group()
dbb_group.add_argument('--no_bitbox', dest='bitbox', help='Do not run Digital Bitbox test with simulator', action='store_false')
dbb_group.add_argument('--bitbox', dest='bitbox', help='Run Digital Bitbox test with simulator', action='store_true')

parser.add_argument('--trezor-path', dest='trezor_path', help='Path to Trezor emulator', default='work/trezor-firmware/legacy/firmware/trezor.elf')
parser.add_argument('--trezor-t-path', dest='trezor_t_path', help='Path to Trezor T emulator', default='work/trezor-firmware/core/emu.sh')
parser.add_argument('--coldcard-path', dest='coldcard_path', help='Path to Coldcar simulator', default='work/firmware/unix/headless.py')
parser.add_argument('--keepkey-path', dest='keepkey_path', help='Path to Keepkey emulator', default='work/keepkey-firmware/bin/kkemu')
parser.add_argument('--bitbox-path', dest='bitbox_path', help='Path to Digital Bitbox simulator', default='work/mcu/build/bin/simulator')
parser.add_argument('--ledger-path', dest='ledger_path', help='Path to Ledger emulator', default='work/speculos/speculos.py')

parser.add_argument('--all', help='Run tests on all existing simulators', default=False, action='store_true')
parser.add_argument('--bitcoind', help='Path to bitcoind', default='work/bitcoin/src/bitcoind')
parser.add_argument('--interface', help='Which interface to send commands over', choices=['library', 'cli', 'bindist', 'stdin'], default='library')

parser.set_defaults(trezor=None, trezor_t=None, coldcard=None, keepkey=None, bitbox=None, ledger=None)
args = parser.parse_args()

# Run tests
success = True
suite = unittest.TestSuite()
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
    args.trezor = True if args.trezor is None else args.trezor
    args.trezor_t = True if args.trezor_t is None else args.trezor_t
    args.coldcard = True if args.coldcard is None else args.coldcard
    args.keepkey = True if args.keepkey is None else args.keepkey
    args.bitbox = True if args.bitbox is None else args.bitbox
    args.ledger = True if args.ledger is None else args.ledger
else:
    # Default all false unless overridden
    args.trezor = False if args.trezor is None else args.trezor
    args.trezor_t = False if args.trezor_t is None else args.trezor_t
    args.coldcard = False if args.coldcard is None else args.coldcard
    args.keepkey = False if args.keepkey is None else args.keepkey
    args.bitbox = False if args.bitbox is None else args.bitbox
    args.ledger = False if args.ledger is None else args.ledger

if args.trezor or args.trezor_t or args.coldcard or args.ledger or args.keepkey or args.bitbox:
    # Start bitcoind
    rpc, userpass = start_bitcoind(args.bitcoind)

    if success and args.bitbox:
        success &= digitalbitbox_test_suite(args.bitbox_path, rpc, userpass, args.interface)
    if success and args.coldcard:
        success &= coldcard_test_suite(args.coldcard_path, rpc, userpass, args.interface)
    if success and args.trezor:
        success &= trezor_test_suite(args.trezor_path, rpc, userpass, args.interface)
    if success and args.trezor_t:
        success &= trezor_test_suite(args.trezor_t_path, rpc, userpass, args.interface, True)
    if success and args.keepkey:
        success &= keepkey_test_suite(args.keepkey_path, rpc, userpass, args.interface)
    if success and args.ledger:
        success &= ledger_test_suite(args.ledger_path, rpc, userpass, args.interface)

sys.exit(not success)
