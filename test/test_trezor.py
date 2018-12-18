#! /usr/bin/env python3

import argparse
import atexit
import json
import os
import socket
import subprocess
import time
import unittest

from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from trezorlib.transport import enumerate_devices
from trezorlib.transport.udp import UdpTransport
from trezorlib.debuglink import TrezorClientDebugLink, load_device_by_mnemonic, load_device_by_xprv
from trezorlib import device
from test_device import DeviceTestCase, start_bitcoind, TestDeviceConnect, TestDisplayAddress, TestGetKeypool, TestSignTx

from hwilib.commands import process_commands

def trezor_test_suite(emulator, rpc, userpass):
    # Start the Trezor emulator
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
    # Cleanup
    def cleanup_emulator():
        emulator_proc.kill()
    atexit.register(cleanup_emulator)

    # Setup the emulator
    for dev in enumerate_devices():
        # Find the udp transport, that's the emulator
        if isinstance(dev, UdpTransport):
            wirelink = dev
            break
    client = TrezorClientDebugLink(wirelink)
    device.wipe(client)
    load_device_by_mnemonic(client=client, mnemonic='alcohol woman abuse must during monitor noble actual mixed trade anger aisle', pin='', passphrase_protection=False, label='test') # From Trezor device tests

    class TrezorTestCase(unittest.TestCase):
        def __init__(self, client, methodName='runTest'):
            super(TrezorTestCase, self).__init__(methodName)
            self.client = client

        @staticmethod
        def parameterize(testclass, client):
            testloader = unittest.TestLoader()
            testnames = testloader.getTestCaseNames(testclass)
            suite = unittest.TestSuite()
            for name in testnames:
                suite.addTest(testclass(client, name))
            return suite

    # Trezor specific getxpub test because this requires device specific thing to set xprvs
    class TestTrezorGetxpub(TrezorTestCase):
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

    # Generic Device tests
    suite = unittest.TestSuite()
    suite.addTest(DeviceTestCase.parameterize(TestDeviceConnect, rpc, userpass, 'trezor', 'udp:127.0.0.1:21324', '95d8f670', 'xpub6D1weXBcFAo8CqBbpP4TbH5sxQH8ZkqC5pDEvJ95rNNBZC9zrKmZP2fXMuve7ZRBe18pWQQsGg68jkq24mZchHwYENd8cCiSb71u3KD4AFH'))
    suite.addTest(DeviceTestCase.parameterize(TestGetKeypool, rpc, userpass, 'trezor', 'udp:127.0.0.1:21324', '95d8f670', 'xpub6D1weXBcFAo8CqBbpP4TbH5sxQH8ZkqC5pDEvJ95rNNBZC9zrKmZP2fXMuve7ZRBe18pWQQsGg68jkq24mZchHwYENd8cCiSb71u3KD4AFH'))
    suite.addTest(DeviceTestCase.parameterize(TestSignTx, rpc, userpass, 'trezor', 'udp:127.0.0.1:21324', '95d8f670', 'xpub6D1weXBcFAo8CqBbpP4TbH5sxQH8ZkqC5pDEvJ95rNNBZC9zrKmZP2fXMuve7ZRBe18pWQQsGg68jkq24mZchHwYENd8cCiSb71u3KD4AFH'))
    suite.addTest(DeviceTestCase.parameterize(TestDisplayAddress, rpc, userpass, 'trezor', 'udp:127.0.0.1:21324', '95d8f670', 'xpub6D1weXBcFAo8CqBbpP4TbH5sxQH8ZkqC5pDEvJ95rNNBZC9zrKmZP2fXMuve7ZRBe18pWQQsGg68jkq24mZchHwYENd8cCiSb71u3KD4AFH'))
    suite.addTest(TrezorTestCase.parameterize(TestTrezorGetxpub, client))
    return suite

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test Trezor implementation')
    parser.add_argument('emulator', help='Path to the Trezor emulator')
    parser.add_argument('bitcoind', help='Path to bitcoind binary')
    args = parser.parse_args()

    # Start bitcoind
    rpc, userpass = start_bitcoind(args.bitcoind)

    suite = trezor_test_suite(args.emulator, rpc, userpass)
    unittest.TextTestRunner().run(suite)
