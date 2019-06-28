#! /usr/bin/env python3

import argparse
import sys
import unittest

from test_base58 import TestBase58
from test_bech32 import TestSegwitAddress
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

ledger_s_group = parser.add_mutually_exclusive_group()
ledger_s_group.add_argument('--ledger-s', help='Run physical Ledger Nano S tests.', action='store_true')

ledger_x_group = parser.add_mutually_exclusive_group()
ledger_x_group.add_argument('--ledger-x', help='Run physical Ledger Nano X tests.', action='store_true')

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

parser.add_argument('--all', help='Run tests on all existing simulators', default=False, action='store_true')
parser.add_argument('--bitcoind', help='Path to bitcoind', default='work/bitcoin/src/bitcoind')
parser.add_argument('--interface', help='Which interface to send commands over', choices=['library', 'cli', 'bindist', 'stdin'], default='library')

parser.set_defaults(trezor=False, trezor_t=False, coldcard=False, keepkey=False, bitbox=False)
args = parser.parse_args()

# Run tests
suite = unittest.TestSuite()
suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestDescriptor))
suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestSegwitAddress))
suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestPSBT))
suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestBase58))
if sys.platform.startswith("linux"):
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestUdevRulesInstaller))

if args.all:
    args.trezor = True
    args.trezor_t = True
    args.coldcard = True
    args.keepkey = True
    args.bitbox = True

if args.trezor or args.trezor_t or args.coldcard or args.ledger_s or args.ledger_x or args.keepkey or args.bitbox:
    # Start bitcoind
    rpc, userpass = start_bitcoind(args.bitcoind)

    if args.bitbox:
        suite.addTest(digitalbitbox_test_suite(args.bitbox_path, rpc, userpass, args.interface))
    if args.coldcard:
        suite.addTest(coldcard_test_suite(args.coldcard_path, rpc, userpass, args.interface))
    if args.trezor:
        suite.addTest(trezor_test_suite(args.trezor_path, rpc, userpass, args.interface))
    if args.trezor_t:
        suite.addTest(trezor_test_suite(args.trezor_t_path, rpc, userpass, args.interface, True))
    if args.keepkey:
        suite.addTest(keepkey_test_suite(args.keepkey_path, rpc, userpass, args.interface))
    if args.ledger_s:
        suite.addTest(ledger_test_suite("ledger_nano_s", rpc, userpass, args.interface))
    if args.ledger_x:
        suite.addTest(ledger_test_suite("ledger_nano_x", rpc, userpass, args.interface))

result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
sys.exit(not result.wasSuccessful())
