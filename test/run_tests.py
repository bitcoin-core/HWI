#! /usr/bin/env python3

import argparse
import subprocess
import sys
import unittest

from test_bech32 import TestSegwitAddress
from test_coldcard import coldcard_test_suite
from test_device import start_bitcoind
from test_psbt import TestPSBT
from test_trezor import trezor_test_suite
from test_ledger import ledger_test_suite
from test_digitalbitbox import digitalbitbox_test_suite
from test_keepkey import keepkey_test_suite

parser = argparse.ArgumentParser(description='Setup the testing environment and run automated tests')
trezor_group = parser.add_mutually_exclusive_group()
trezor_group.add_argument('--no_trezor', help='Do not run Trezor test with emulator', action='store_true')
trezor_group.add_argument('--trezor', help='Path to Trezor emulator.', default='work/trezor-mcu/firmware/trezor.elf')
coldcard_group = parser.add_mutually_exclusive_group()
coldcard_group.add_argument('--no_coldcard', help='Do not run Coldcard test with simulator', action='store_true')
coldcard_group.add_argument('--coldcard', help='Path to Coldcard simulator.', default='work/firmware/unix/headless.py')
ledger_group = parser.add_mutually_exclusive_group()
ledger_group.add_argument('--ledger', help='Run physical Ledger Nano S/X tests.', action='store_true')
keepkey_group = parser.add_mutually_exclusive_group()
keepkey_group.add_argument('--no_keepkey', help='Do not run Keepkey test with emulator', action='store_true')
keepkey_group.add_argument('--keepkey', help='Path to Keepkey emulator.', default='work/keepkey-firmware/bin/kkemu')

parser.add_argument('--digitalbitbox', help='Run physical Digital Bitbox tests.', action='store_true')
parser.add_argument('--bitcoind', help='Path to bitcoind.', default='work/bitcoin/src/bitcoind')
parser.add_argument('--password', '-p', help='Device password')
args = parser.parse_args()

# Run tests
suite = unittest.TestSuite()
suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestSegwitAddress))
suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestPSBT))

if not args.no_trezor or not args.no_coldcard or args.ledger or args.digitalbitbox:
    # Start bitcoind
    rpc, userpass = start_bitcoind(args.bitcoind)

if not args.no_trezor:
    suite.addTest(trezor_test_suite(args.trezor, rpc, userpass))
if not args.no_coldcard:
    suite.addTest(coldcard_test_suite(args.coldcard, rpc, userpass))
if args.ledger:
    suite.addTest(ledger_test_suite(rpc, userpass))
if args.digitalbitbox:
    if args.password:
        suite.addTest(digitalbitbox_test_suite(rpc, userpass, args.password))
    else:
        print('Cannot run Digital Bitbox test without --password set')
if not args.no_keepkey:
    suite.addTest(keepkey_test_suite(args.keepkey, rpc, userpass))
result = unittest.TextTestRunner(stream=sys.stdout).run(suite)
sys.exit(not result.wasSuccessful())
