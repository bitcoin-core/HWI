#! /usr/bin/env python3

import argparse
import atexit
import json
import logging
import os
import socket
import subprocess
import sys
import time
import unittest

from keepkeylib.transport_udp import UDPTransport
from keepkeylib.client import KeepKeyDebugClient
from test_device import DeviceTestCase, start_bitcoind, TestDeviceConnect, TestDisplayAddress, TestGetKeypool, TestSignTx

from hwilib.commands import process_commands

emulator_proc = None

def start_emulator():
    # Start the Keepkey emulator
    emulator_proc = subprocess.Popen([emulator])
    # Wait for emulator to be up
    # From https://github.com/trezor/trezor-mcu/blob/master/script/wait_for_emulator.py
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(('127.0.0.1', 21324))
    sock.settimeout(0)
    while True:
        try:
            sock.sendall(b"PINGPING")
            r = sock.recv(8)
            if r == b"PONGPONG":
                break
        except Exception:
            time.sleep(0.05)

    # Setup the emulator
    sim_dev = UDPTransport('127.0.0.1:21324')
    sim_dev.buffer = b'' # HACK to work around a bug in the keepkey library
    sim_dev_debug = UDPTransport('127.0.0.1:21325')
    sim_dev_debug.buffer = b'' # HACK to work around a bug in the keepkey library
    client = KeepKeyDebugClient(sim_dev)
    client.set_debuglink(sim_dev_debug)
    client.wipe_device()
    client.load_device_by_mnemonic(mnemonic='alcohol woman abuse must during monitor noble actual mixed trade anger aisle', pin='', passphrase_protection=False, label='test', language='english') # From Trezor device tests
    return client

def stop_emulator():
    if emulator_proc:
        emulator_proc.kill()

# Keepkey specific getxpub test because this requires device specific thing to set xprvs
class TestKeepkeyGetxpub(unittest.TestCase):
    def setUp(self):
        self.client = start_emulator()
    
    def test_getxpub(self):
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/bip32_vectors.json'), encoding='utf-8') as f:
            vectors = json.load(f)
        for vec in vectors:
            with self.subTest(vector=vec):
                # Setup with xprv
                self.client.wipe_device()
                self.client.load_device_by_xprv(xprv=vec['xprv'], pin='', passphrase_protection=False, label='test', language='english')

                # Test getmasterxpub
                gmxp_res = process_commands(['-t', 'keepkey', '-d', 'udp:127.0.0.1:21324', 'getmasterxpub'])
                self.assertEqual(gmxp_res['xpub'], vec['master_xpub'])

                # Test the path derivs
                for path_vec in vec['vectors']:
                    gxp_res = process_commands(['-t', 'keepkey', '-d', 'udp:127.0.0.1:21324', 'getxpub', path_vec['path']])
                    self.assertEqual(gxp_res['xpub'], path_vec['xpub'])

def keepkey_test_suite(emulator, rpc, userpass):
    # Redirect stderr to /dev/null as it's super spammy
    sys.stderr = open(os.devnull, 'w')

    # Device info for tests
    type = 'keepkey'
    path = 'udp:127.0.0.1:21324'
    fingerprint = '95d8f670'
    master_xpub = 'xpub6D1weXBcFAo8CqBbpP4TbH5sxQH8ZkqC5pDEvJ95rNNBZC9zrKmZP2fXMuve7ZRBe18pWQQsGg68jkq24mZchHwYENd8cCiSb71u3KD4AFH'

    # Generic Device tests
    suite = unittest.TestSuite()
    suite.addTest(DeviceTestCase.parameterize(TestDeviceConnect, rpc, userpass, type, path, fingerprint, master_xpub))
    suite.addTest(DeviceTestCase.parameterize(TestGetKeypool, rpc, userpass, type, path, fingerprint, master_xpub))
    suite.addTest(DeviceTestCase.parameterize(TestSignTx, rpc, userpass, type, path, fingerprint, master_xpub))
    suite.addTest(DeviceTestCase.parameterize(TestDisplayAddress, rpc, userpass, type, path, fingerprint, master_xpub))
    suite.addTest(TestKeepkeyGetxpub())
    return suite

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test Keepkey implementation')
    parser.add_argument('emulator', help='Path to the Keepkey emulator')
    parser.add_argument('bitcoind', help='Path to bitcoind binary')
    args = parser.parse_args()

    # Start bitcoind
    rpc, userpass = start_bitcoind(args.bitcoind)

    suite = keepkey_test_suite(args.emulator, rpc, userpass)
    unittest.TextTestRunner(stream=sys.stdout).run(suite)
