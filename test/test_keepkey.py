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
from keepkeylib import messages_pb2 as messages
from test_device import DeviceEmulator, DeviceTestCase, start_bitcoind, TestDeviceConnect, TestDisplayAddress, TestGetKeypool, TestSignMessage, TestSignTx

from hwilib.cli import process_commands
from hwilib.devices.keepkey import KeepkeyClient

from types import MethodType

def pin_matrix(self, code=None):
    if self.pin:
        pin = self.debug.encode_pin(self.pin)
    else:
        pin = self.debug.read_pin_encoded()
    return messages.PinMatrixAck(pin=pin)

class KeepkeyEmulator(DeviceEmulator):
    def __init__(self, emulator_path):
        self.emulator_proc = None
        self.emulator_path = emulator_path

    def start(self):
        # Start the Keepkey emulator
        self.emulator_proc = subprocess.Popen(['./' + os.path.basename(self.emulator_path)], cwd=os.path.dirname(self.emulator_path), stdout=subprocess.DEVNULL)
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

        # Redirect stdout to /dev/null as the keepkey lib kind of spammy
        sys.stdout = open(os.devnull, 'w')

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

    def stop(self):
        self.emulator_proc.kill()
        self.emulator_proc.wait()
        # Redirect stdout back to stdout
        sys.stdout = sys.__stdout__

class KeepkeyTestCase(unittest.TestCase):
    def __init__(self, emulator, methodName='runTest'):
        super(KeepkeyTestCase, self).__init__(methodName)
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
        return 'keepkey: {}'.format(super().__str__())

    def __repr__(self):
        return 'keepkey: {}'.format(super().__repr__())

# Keepkey specific getxpub test because this requires device specific thing to set xprvs
class TestKeepkeyGetxpub(KeepkeyTestCase):
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
                self.client.wipe_device()
                self.client.load_device_by_xprv(xprv=vec['xprv'], pin='', passphrase_protection=False, label='test', language='english')

                # Test getmasterxpub
                gmxp_res = process_commands(['-t', 'keepkey', '-d', 'udp:127.0.0.1:21324', 'getmasterxpub'])
                self.assertEqual(gmxp_res['xpub'], vec['master_xpub'])

                # Test the path derivs
                for path_vec in vec['vectors']:
                    gxp_res = process_commands(['-t', 'keepkey', '-d', 'udp:127.0.0.1:21324', 'getxpub', path_vec['path']])
                    self.assertEqual(gxp_res['xpub'], path_vec['xpub'])

# Trezor specific management (setup, wipe, restore, backup, promptpin, sendpin) command tests
class TestKeepkeyManCommands(KeepkeyTestCase):
    def setUp(self):
        self.client = self.emulator.start()
        self.dev_args = ['-t', 'keepkey', '-d', 'udp:127.0.0.1:21324']

    def tearDown(self):
        self.emulator.stop()

    def test_setup_wipe(self):
        # Device is init, setup should fail
        result = process_commands(self.dev_args + ['setup'])
        self.assertEquals(result['code'], -10)
        self.assertEquals(result['error'], 'Device is already initialized. Use wipe first and try again')

        # Wipe
        result = process_commands(self.dev_args + ['wipe'])
        self.assertTrue(result['success'])

        # Setup
        k_client = KeepkeyClient('udp:127.0.0.1:21324', 'test')
        k_client.client.callback_PinMatrixRequest = MethodType(pin_matrix, k_client.client)
        k_client.client.pin = '1234'
        result = k_client.setup_device()
        self.assertTrue(result['success'])

        # Make sure device is init, setup should fail
        result = process_commands(self.dev_args + ['setup'])
        self.assertEquals(result['code'], -10)
        self.assertEquals(result['error'], 'Device is already initialized. Use wipe first and try again')

    def test_backup(self):
        result = process_commands(self.dev_args + ['backup'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['error'], 'The Keepkey does not support creating a backup via software')
        self.assertEqual(result['code'], -9)

    def test_pins(self):
        # There's no PIN
        result = process_commands(self.dev_args + ['--debug', 'promptpin'])
        self.assertEqual(result['error'], 'This device does not need a PIN')
        self.assertEqual(result['code'], -11)
        result = process_commands(self.dev_args + ['sendpin', '1234'])
        self.assertEqual(result['error'], 'This device does not need a PIN')
        self.assertEqual(result['code'], -11)

        # Set a PIN
        self.client.wipe_device()
        self.client.load_device_by_mnemonic(mnemonic='alcohol woman abuse must during monitor noble actual mixed trade anger aisle', pin='1234', passphrase_protection=False, label='test', language='english')
        self.client.call(messages.ClearSession())
        result = process_commands(self.dev_args + ['promptpin'])
        self.assertTrue(result['success'])

        # Invalid pin
        result = process_commands(self.dev_args + ['sendpin', 'notnum'])
        self.assertEqual(result['error'], 'Non-numeric PIN provided')
        self.assertEqual(result['code'], -7)

        result = process_commands(self.dev_args + ['sendpin', '00000'])
        self.assertFalse(result['success'])

        # Make sure we get a needs pin message
        result = process_commands(self.dev_args + ['getxpub', 'm/0h'])
        self.assertEqual(result['code'], -12)
        self.assertEqual(result['error'], 'Keepkey is locked. Unlock by using \'promptpin\' and then \'sendpin\'.')

        # Prompt pin
        self.client.call(messages.ClearSession())
        result = process_commands(self.dev_args + ['promptpin'])
        self.assertTrue(result['success'])

        # Send the PIN
        pin = self.client.debug.encode_pin('1234')
        result = process_commands(self.dev_args + ['sendpin', pin])
        self.assertTrue(result['success'])

        # Sending PIN after unlock
        result = process_commands(self.dev_args + ['promptpin'])
        self.assertEqual(result['error'], 'The PIN has already been sent to this device')
        self.assertEqual(result['code'], -11)
        result = process_commands(self.dev_args + ['sendpin', '1234'])
        self.assertEqual(result['error'], 'The PIN has already been sent to this device')
        self.assertEqual(result['code'], -11)

def keepkey_test_suite(emulator, rpc, userpass):
    # Redirect stderr to /dev/null as it's super spammy
    sys.stderr = open(os.devnull, 'w')

    # Device info for tests
    type = 'keepkey'
    path = 'udp:127.0.0.1:21324'
    fingerprint = '95d8f670'
    master_xpub = 'xpub6D1weXBcFAo8CqBbpP4TbH5sxQH8ZkqC5pDEvJ95rNNBZC9zrKmZP2fXMuve7ZRBe18pWQQsGg68jkq24mZchHwYENd8cCiSb71u3KD4AFH'
    dev_emulator = KeepkeyEmulator(emulator)

    # Generic Device tests
    suite = unittest.TestSuite()
    suite.addTest(DeviceTestCase.parameterize(TestDeviceConnect, rpc, userpass, type, path, fingerprint, master_xpub, emulator=dev_emulator))
    suite.addTest(DeviceTestCase.parameterize(TestGetKeypool, rpc, userpass, type, path, fingerprint, master_xpub, emulator=dev_emulator))
    suite.addTest(DeviceTestCase.parameterize(TestSignTx, rpc, userpass, type, path, fingerprint, master_xpub, emulator=dev_emulator))
    suite.addTest(DeviceTestCase.parameterize(TestDisplayAddress, rpc, userpass, type, path, fingerprint, master_xpub, emulator=dev_emulator))
    suite.addTest(DeviceTestCase.parameterize(TestSignMessage, rpc, userpass, type, path, fingerprint, master_xpub, emulator=dev_emulator))
    suite.addTest(KeepkeyTestCase.parameterize(TestKeepkeyGetxpub, emulator=dev_emulator))
    suite.addTest(KeepkeyTestCase.parameterize(TestKeepkeyManCommands, emulator=dev_emulator))
    return suite

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test Keepkey implementation')
    parser.add_argument('emulator', help='Path to the Keepkey emulator')
    parser.add_argument('bitcoind', help='Path to bitcoind binary')
    args = parser.parse_args()

    # Start bitcoind
    rpc, userpass = start_bitcoind(args.bitcoind)

    suite = keepkey_test_suite(args.emulator, rpc, userpass)
    unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
