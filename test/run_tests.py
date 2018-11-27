#! /usr/bin/env python3

import argparse
import multiprocessing
import os
import subprocess
import sys

parser = argparse.ArgumentParser(description='Setup the testing environment and run automated tests')
trezor_group = parser.add_mutually_exclusive_group()
trezor_group.add_argument('--no_trezor', help='Do not run Trezor test with emulator', action='store_true')
trezor_group.add_argument('--trezor', help='Path to Trezor emulator.', default='work/trezor-mcu/firmware/trezor.elf')
coldcard_group = parser.add_mutually_exclusive_group()
coldcard_group.add_argument('--no_coldcard', help='Do not run Coldcard test with simulator', action='store_true')
coldcard_group.add_argument('--coldcard', help='Path to Coldcard simulator.', default='work/firmware/unix/headless.py')
parser.add_argument('--bitcoind', help='Path to bitcoind.', default='work/bitcoin/src/bitcoind')
args = parser.parse_args()

# Run tests
subprocess.check_call(['python3', 'test_bech32.py'])
subprocess.check_call(['python3', 'test_psbt.py'])
if not args.no_trezor:
    subprocess.check_call(['python3', 'test_trezor.py', args.trezor, args.bitcoind])
if not args.no_coldcard:
    subprocess.check_call(['python3', 'test_coldcard.py', args.coldcard, args.bitcoind])
