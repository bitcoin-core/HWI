#! /usr/bin/env python3

import argparse
import atexit
import json
import os
import socket
import subprocess
import sys
import time
import unittest

from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from trezorlib.transport import enumerate_devices
from trezorlib.transport.udp import UdpTransport
from trezorlib.debuglink import TrezorClientDebugLink, load_device_by_mnemonic, load_device_by_xprv
from trezorlib import device
from test_device import DeviceEmulator, DeviceTestCase, start_bitcoind, TestDeviceConnect, TestDisplayAddress, TestGetKeypool, TestSignTx

from hwilib.commands import process_commands

class TrezorEmulator(DeviceEmulator):
    def __init__(self, path):
        self.emulator_path = path
        self.emulator_proc = None

    def start(self):
        # Start the Trezor emulator
        self.emulator_proc = subprocess.Popen(['./' + os.path.basename(self.emulator_path)], cwd=os.path.dirname(self.emulator_path))
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
        for dev in enumerate_devices():
            # Find the udp transport, that's the emulator
            if isinstance(dev, UdpTransport):
                wirelink = dev
                break
        client = TrezorClientDebugLink(wirelink)
        device.wipe(client)
        load_device_by_mnemonic(client=client, mnemonic='alcohol woman abuse must during monitor noble actual mixed trade anger aisle', pin='', passphrase_protection=False, label='test') # From Trezor device tests
        return client

    def stop(self):
        self.emulator_proc.kill()
        self.emulator_proc.wait()

class TrezorTestCase(unittest.TestCase):
    def __init__(self, emulator, methodName='runTest'):
        super(TrezorTestCase, self).__init__(methodName)
        self.emulator = emulator

    @staticmethod
    def parameterize(testclass, emulator):
        testloader = unittest.TestLoader()
        testnames = testloader.getTestCaseNames(testclass)
        suite = unittest.TestSuite()
        for name in testnames:
            suite.addTest(testclass(emulator, name))
        return suite

    def __str__(self):
        return 'trezor: {}'.format(super().__str__())

    def __repr__(self):
        return 'trezor: {}'.format(super().__repr__())

# Trezor specific getxpub test because this requires device specific thing to set xprvs
class TestTrezorGetxpub(TrezorTestCase):
    def setUp(self):
        self.client = self.emulator.start()

    def tearDown(self):
        self.emulator.stop()

    def test_getxpub(self):
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/bip32_vectors.json'), encoding='utf-8') as f:
            vectors = json.load(f)
        for vec in vectors:
            with self.subTest(vector=vec):
                # Setup with xprv
                device.wipe(self.client)
                load_device_by_xprv(client=self.client, xprv=vec['xprv'], pin='', passphrase_protection=False, label='test', language='english')

                # Test getmasterxpub
                gmxp_res = process_commands(['-t', 'trezor', '-d', 'udp:127.0.0.1:21324', 'getmasterxpub'])
                self.assertEqual(gmxp_res['xpub'], vec['master_xpub'])

                # Test the path derivs
                for path_vec in vec['vectors']:
                    gxp_res = process_commands(['-t', 'trezor', '-d', 'udp:127.0.0.1:21324', 'getxpub', path_vec['path']])
                    self.assertEqual(gxp_res['xpub'], path_vec['xpub'])

def trezor_test_suite(emulator, rpc, userpass):
    # Redirect stderr to /dev/null as it's super spammy
    sys.stderr = open(os.devnull, 'w')

    # Device info for tests
    type = 'trezor'
    path = 'udp:127.0.0.1:21324'
    fingerprint = '95d8f670'
    master_xpub = 'xpub6D1weXBcFAo8CqBbpP4TbH5sxQH8ZkqC5pDEvJ95rNNBZC9zrKmZP2fXMuve7ZRBe18pWQQsGg68jkq24mZchHwYENd8cCiSb71u3KD4AFH'
    dev_emulator = TrezorEmulator(emulator)

    # Generic Device tests
    suite = unittest.TestSuite()
    suite.addTest(DeviceTestCase.parameterize(TestDeviceConnect, rpc, userpass, type, path, fingerprint, master_xpub, emulator=dev_emulator))
    suite.addTest(DeviceTestCase.parameterize(TestGetKeypool, rpc, userpass, type, path, fingerprint, master_xpub, emulator=dev_emulator))
    suite.addTest(DeviceTestCase.parameterize(TestSignTx, rpc, userpass, type, path, fingerprint, master_xpub, emulator=dev_emulator))
    suite.addTest(DeviceTestCase.parameterize(TestDisplayAddress, rpc, userpass, type, path, fingerprint, master_xpub, emulator=dev_emulator))
    suite.addTest(TrezorTestCase.parameterize(TestTrezorGetxpub, emulator=dev_emulator))
    return suite

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test Trezor implementation')
    parser.add_argument('emulator', help='Path to the Trezor emulator')
    parser.add_argument('bitcoind', help='Path to bitcoind binary')
    args = parser.parse_args()

    # Start bitcoind
    rpc, userpass = start_bitcoind(args.bitcoind)

    suite = trezor_test_suite(args.emulator, rpc, userpass)
    unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
