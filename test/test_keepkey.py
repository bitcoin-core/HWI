#! /usr/bin/env python3

import argparse
import atexit
import json
import os
import shlex
import socket
import subprocess
import sys
import time
import unittest

from hwilib.devices.trezorlib.transport.udp import UdpTransport
from hwilib.devices.trezorlib.debuglink import TrezorClientDebugLink, load_device_by_mnemonic
from hwilib.devices.trezorlib import device, messages
from test_device import DeviceEmulator, DeviceTestCase, start_bitcoind, TestDeviceConnect, TestDisplayAddress, TestGetKeypool, TestGetDescriptors, TestSignMessage, TestSignTx

from hwilib._cli import process_commands
from hwilib.devices.keepkey import (
    KeepkeyClient,
    KeepkeyDebugLinkState,
    KeepkeyFeatures,
    KeepkeyResetDevice,
)
from types import MethodType

def get_pin(self, code=None):
    if self.pin:
        return self.debuglink.encode_pin(self.pin)
    else:
        return self.debuglink.read_pin_encoded()

class KeepkeyEmulator(DeviceEmulator):
    def __init__(self, path):
        self.emulator_path = path
        self.emulator_proc = None
        self.keepkey_log = None
        try:
            os.unlink('keepkey-emulator.stdout')
        except FileNotFoundError:
            pass

    def start(self):
        self.keepkey_log = open('keepkey-emulator.stdout', 'a')
        # Start the Keepkey emulator
        self.emulator_proc = subprocess.Popen(['./' + os.path.basename(self.emulator_path)], cwd=os.path.dirname(self.emulator_path), stdout=self.keepkey_log)
        # Wait for emulator to be up
        # From https://github.com/trezor/trezor-firmware/blob/master/legacy/script/wait_for_emulator.py
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
        wirelink = UdpTransport.enumerate()[0]
        client = TrezorClientDebugLink(wirelink)
        client.vendors = ("keepkey.com")
        client.minimum_versions = {"K1-14AM": (0, 0, 0)}
        client.map_type_to_class_override[KeepkeyFeatures.MESSAGE_WIRE_TYPE] = KeepkeyFeatures
        client.map_type_to_class_override[KeepkeyResetDevice.MESSAGE_WIRE_TYPE] = KeepkeyResetDevice
        client.debug.map_type_to_class_override[KeepkeyDebugLinkState.MESSAGE_WIRE_TYPE] = KeepkeyDebugLinkState
        client.init_device()
        device.wipe(client)
        load_device_by_mnemonic(client=client, mnemonic='alcohol woman abuse must during monitor noble actual mixed trade anger aisle', pin='', passphrase_protection=False, label='test') # From Trezor device tests
        atexit.register(self.stop)
        return client

    def stop(self):
        self.emulator_proc.terminate()
        self.emulator_proc.wait()

        # Clean up emulator image
        emulator_img = os.path.dirname(self.emulator_path) + "/emulator.img"
        if os.path.isfile(emulator_img):
            os.unlink(emulator_img)

        if self.keepkey_log is not None:
            self.keepkey_log.close()

        atexit.unregister(self.stop)

class KeepkeyTestCase(unittest.TestCase):
    def __init__(self, emulator, interface='library', methodName='runTest'):
        super(KeepkeyTestCase, self).__init__(methodName)
        self.emulator = emulator
        self.interface = interface

    @staticmethod
    def parameterize(testclass, emulator, interface='library'):
        testloader = unittest.TestLoader()
        testnames = testloader.getTestCaseNames(testclass)
        suite = unittest.TestSuite()
        for name in testnames:
            suite.addTest(testclass(emulator, interface, name))
        return suite

    def do_command(self, args):
        cli_args = []
        for arg in args:
            cli_args.append(shlex.quote(arg))
        if self.interface == 'cli':
            proc = subprocess.Popen(['hwi ' + ' '.join(cli_args)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=True)
            result = proc.communicate()
            return json.loads(result[0].decode())
        elif self.interface == 'bindist':
            proc = subprocess.Popen(['../dist/hwi ' + ' '.join(cli_args)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=True)
            result = proc.communicate()
            return json.loads(result[0].decode())
        elif self.interface == 'stdin':
            input_str = '\n'.join(args) + '\n'
            proc = subprocess.Popen(['hwi', '--stdin'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            result = proc.communicate(input_str.encode())
            return json.loads(result[0].decode())
        else:
            return process_commands(args)

    def __str__(self):
        return 'keepkey: {}'.format(super().__str__())

    def __repr__(self):
        return 'keepkey: {}'.format(super().__repr__())

    def setUp(self):
        self.client = self.emulator.start()

    def tearDown(self):
        self.emulator.stop()

# Keepkey specific getxpub test because this requires device specific thing to set xprvs
class TestKeepkeyGetxpub(KeepkeyTestCase):
    def test_getxpub(self):
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/bip32_vectors.json'), encoding='utf-8') as f:
            vectors = json.load(f)
        for vec in vectors:
            with self.subTest(vector=vec):
                # Setup with mnemonic
                device.wipe(self.client)
                load_device_by_mnemonic(client=self.client, mnemonic=vec['mnemonic'], pin='', passphrase_protection=False, label='test', language='english')

                # Test getmasterxpub
                gmxp_res = self.do_command(['-t', 'keepkey', '-d', 'udp:127.0.0.1:21324', 'getmasterxpub', "--addr-type", "legacy"])
                self.assertEqual(gmxp_res['xpub'], vec['master_xpub'])

                # Test the path derivs
                for path_vec in vec['vectors']:
                    gxp_res = self.do_command(['-t', 'keepkey', '-d', 'udp:127.0.0.1:21324', 'getxpub', path_vec['path']])
                    self.assertEqual(gxp_res['xpub'], path_vec['xpub'])

    def test_expert_getxpub(self):
        result = self.do_command(['-t', 'keepkey', '-d', 'udp:127.0.0.1:21324', '--expert', 'getxpub', 'm/44h/0h/0h/3'])
        self.assertEqual(result['xpub'], 'xpub6FMafWAi3n3ET2rU5yQr16UhRD1Zx4dELmcEw3NaYeBaNnipcr2zjzYp1sNdwR3aTN37hxAqRWQ13AWUZr6L9jc617mU6EvgYXyBjXrEhgr')
        self.assertFalse(result['testnet'])
        self.assertFalse(result['private'])
        self.assertEqual(result['depth'], 4)
        self.assertEqual(result['parent_fingerprint'], 'f7e318db')
        self.assertEqual(result['child_num'], 3)
        self.assertEqual(result['chaincode'], '95a7fb33c4f0896f66045cd7f45ed49a9e72372d2aed204ad0149c39b7b17905')
        self.assertEqual(result['pubkey'], '022e6d9c18e5a837e802fb09abe00f787c8ccb0fc489c6ec5dc2613d930efd7eae')

# Keepkey specific management (setup, wipe, restore, backup, promptpin, sendpin) command tests
class TestKeepkeyManCommands(KeepkeyTestCase):
    def setUp(self):
        self.client = self.emulator.start()
        self.dev_args = ['-t', 'keepkey', '-d', 'udp:127.0.0.1:21324']

    def test_setup_wipe(self):
        # Device is init, setup should fail
        result = self.do_command(self.dev_args + ['-i', 'setup'])
        self.assertEquals(result['code'], -10)
        self.assertEquals(result['error'], 'Device is already initialized. Use wipe first and try again')

        # Wipe
        result = self.do_command(self.dev_args + ['wipe'])
        self.assertTrue(result['success'])

        # Setup
        t_client = KeepkeyClient('udp:127.0.0.1:21324', 'test')
        t_client.client.ui.get_pin = MethodType(get_pin, t_client.client.ui)
        t_client.client.ui.pin = '1234'
        result = t_client.setup_device()
        self.assertTrue(result)

        # Make sure device is init, setup should fail
        result = self.do_command(self.dev_args + ['-i', 'setup'])
        self.assertEquals(result['code'], -10)
        self.assertEquals(result['error'], 'Device is already initialized. Use wipe first and try again')

    def test_backup(self):
        result = self.do_command(self.dev_args + ['backup'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['error'], 'The Keepkey does not support creating a backup via software')
        self.assertEqual(result['code'], -9)

    def test_pins(self):
        # There's no PIN
        result = self.do_command(self.dev_args + ['--debug', 'promptpin'])
        self.assertEqual(result['error'], 'This device does not need a PIN')
        self.assertEqual(result['code'], -11)
        result = self.do_command(self.dev_args + ['sendpin', '1234'])
        self.assertEqual(result['error'], 'This device does not need a PIN')
        self.assertEqual(result['code'], -11)
        result = self.do_command(self.dev_args + ['enumerate'])
        for dev in result:
            if dev['type'] == 'trezor' and dev['path'] == 'udp:127.0.0.1:21324':
                self.assertFalse(dev['needs_pin_sent'])

        # Set a PIN
        device.wipe(self.client)
        load_device_by_mnemonic(client=self.client, mnemonic='alcohol woman abuse must during monitor noble actual mixed trade anger aisle', pin='1234', passphrase_protection=False, label='test')
        self.client.call(messages.LockDevice())
        result = self.do_command(self.dev_args + ['enumerate'])
        for dev in result:
            if dev['type'] == 'trezor' and dev['path'] == 'udp:127.0.0.1:21324':
                self.assertTrue(dev['needs_pin_sent'])
        result = self.do_command(self.dev_args + ['promptpin'])
        self.assertTrue(result['success'])

        # Invalid pins
        result = self.do_command(self.dev_args + ['sendpin', 'notnum'])
        self.assertEqual(result['error'], 'Non-numeric PIN provided')
        self.assertEqual(result['code'], -7)

        result = self.do_command(self.dev_args + ['sendpin', '00000'])
        self.assertFalse(result["success"])

        # Make sure we get a needs pin message
        result = self.do_command(self.dev_args + ['getxpub', 'm/0h'])
        self.assertEqual(result['code'], -12)
        self.assertEqual(result['error'], 'Keepkey is locked. Unlock by using \'promptpin\' and then \'sendpin\'.')

        # Prompt pin
        self.client.call(messages.LockDevice())
        result = self.do_command(self.dev_args + ['promptpin'])
        self.assertTrue(result['success'])

        # Send the PIN
        self.client.open()
        pin = self.client.debug.encode_pin('1234')
        result = self.do_command(self.dev_args + ['sendpin', pin])
        self.assertTrue(result['success'])

        result = self.do_command(self.dev_args + ['enumerate'])
        for dev in result:
            if dev['type'] == 'trezor' and dev['path'] == 'udp:127.0.0.1:21324':
                self.assertFalse(dev['needs_pin_sent'])

        # Sending PIN after unlock
        result = self.do_command(self.dev_args + ['promptpin'])
        self.assertEqual(result['error'], 'The PIN has already been sent to this device')
        self.assertEqual(result['code'], -11)
        result = self.do_command(self.dev_args + ['sendpin', '1234'])
        self.assertEqual(result['error'], 'The PIN has already been sent to this device')
        self.assertEqual(result['code'], -11)

    def test_passphrase(self):
        # Enable passphrase
        self.do_command(self.dev_args + ['togglepassphrase'])

        # A passphrase will need to be sent
        result = self.do_command(self.dev_args + ['enumerate'])
        for dev in result:
            if dev['type'] == 'keepkey' and dev['path'] == 'udp:127.0.0.1:21324':
                self.assertTrue(dev['needs_passphrase_sent'])
        result = self.do_command(self.dev_args + ['-p', 'pass', 'enumerate'])
        for dev in result:
            if dev['type'] == 'keepkey' and dev['path'] == 'udp:127.0.0.1:21324':
                self.assertFalse(dev['needs_passphrase_sent'])
                fpr = dev['fingerprint']
        # A different passphrase will change the fingerprint
        result = self.do_command(self.dev_args + ['-p', 'pass2', 'enumerate'])
        for dev in result:
            if dev['type'] == 'keepkey' and dev['path'] == 'udp:127.0.0.1:21324':
                self.assertFalse(dev['needs_passphrase_sent'])
                self.assertNotEqual(dev['fingerprint'], fpr)

        # Clearing the session and starting a new one with a new passphrase should change the passphrase
        self.client.call(messages.LockDevice())
        result = self.do_command(self.dev_args + ['-p', 'pass3', 'enumerate'])
        for dev in result:
            if dev['type'] == 'keepkey' and dev['path'] == 'udp:127.0.0.1:21324':
                self.assertFalse(dev['needs_passphrase_sent'])
                self.assertNotEqual(dev['fingerprint'], fpr)

        # Disable passphrase
        self.do_command(self.dev_args + ['togglepassphrase'])

        # There's no passphrase
        result = self.do_command(self.dev_args + ['enumerate'])
        for dev in result:
            if dev['type'] == 'keepkey' and dev['path'] == 'udp:127.0.0.1:21324':
                self.assertFalse(dev['needs_passphrase_sent'])
                self.assertEquals(dev['fingerprint'], '95d8f670')
        # Setting a passphrase won't change the fingerprint
        result = self.do_command(self.dev_args + ['-p', 'pass', 'enumerate'])
        for dev in result:
            if dev['type'] == 'keepkey' and dev['path'] == 'udp:127.0.0.1:21324':
                self.assertFalse(dev['needs_passphrase_sent'])
                self.assertEquals(dev['fingerprint'], '95d8f670')

def keepkey_test_suite(emulator, rpc, userpass, interface):
    # Redirect stderr to /dev/null as it's super spammy
    sys.stderr = open(os.devnull, 'w')

    # Device info for tests
    type = 'keepkey'
    full_type = 'keepkey'
    path = 'udp:127.0.0.1:21324'
    fingerprint = '95d8f670'
    master_xpub = 'xpub6D1weXBcFAo8CqBbpP4TbH5sxQH8ZkqC5pDEvJ95rNNBZC9zrKmZP2fXMuve7ZRBe18pWQQsGg68jkq24mZchHwYENd8cCiSb71u3KD4AFH'
    dev_emulator = KeepkeyEmulator(emulator)

    # Generic Device tests
    suite = unittest.TestSuite()
    suite.addTest(DeviceTestCase.parameterize(TestDeviceConnect, rpc, userpass, type, full_type, path, fingerprint, master_xpub, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestDeviceConnect, rpc, userpass, 'keepkey_simulator', full_type, path, fingerprint, master_xpub, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestGetDescriptors, rpc, userpass, type, full_type, path, fingerprint, master_xpub, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestGetKeypool, rpc, userpass, type, full_type, path, fingerprint, master_xpub, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestSignTx, rpc, userpass, type, full_type, path, fingerprint, master_xpub, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestDisplayAddress, rpc, userpass, type, full_type, path, fingerprint, master_xpub, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestSignMessage, rpc, userpass, type, full_type, path, fingerprint, master_xpub, emulator=dev_emulator, interface=interface))
    suite.addTest(KeepkeyTestCase.parameterize(TestKeepkeyGetxpub, emulator=dev_emulator, interface=interface))
    suite.addTest(KeepkeyTestCase.parameterize(TestKeepkeyManCommands, emulator=dev_emulator, interface=interface))

    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
    sys.stderr = sys.__stderr__
    return result.wasSuccessful()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test Keepkey implementation')
    parser.add_argument('emulator', help='Path to the Keepkey emulator')
    parser.add_argument('bitcoind', help='Path to bitcoind binary')
    parser.add_argument('--interface', help='Which interface to send commands over', choices=['library', 'cli', 'bindist'], default='library')
    args = parser.parse_args()

    # Start bitcoind
    rpc, userpass = start_bitcoind(args.bitcoind)

    sys.exit(not keepkey_test_suite(args.emulator, rpc, userpass, args.interface))
