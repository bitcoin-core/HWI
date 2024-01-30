#! /usr/bin/env python3

import argparse
import atexit
import json
import os
import shlex
import signal
import socket
import subprocess
import sys
import time
import unittest

from hwilib.devices.trezorlib.transport.udp import UdpTransport
from hwilib.devices.trezorlib.debuglink import TrezorClientDebugLink, load_device_by_mnemonic
from hwilib.devices.trezorlib import device
from hwilib.devices.onekey import retrieval_version, ensure_model, ONEKEY_LEGACY
from test_device import (
    Bitcoind,
    DeviceEmulator,
    DeviceTestCase,
    TestDeviceConnect,
    TestGetKeypool,
    TestGetDescriptors,
    TestDisplayAddress,
    TestSignMessage,
    TestSignTx,
)

from hwilib._cli import process_commands

from types import MethodType

ONEKEY_MODELS = {'1', 't'}

def get_pin(self, code=None):
    if self.pin:
        return self.debuglink.encode_pin(self.pin)
    else:
        return self.debuglink.read_pin_encoded()

DEFAULT_UDP_PORT = 54935

class OnkeyEmulator(DeviceEmulator):
    def __init__(self, path, model):
        assert model in ONEKEY_MODELS
        self.emulator_path = path
        self.emulator_proc = None
        self.model = model
        self.emulator_log = None
        try:
            os.unlink('onekey-{}-emulator.stdout'.format(self.model))
        except FileNotFoundError:
            pass
        self.type = f"onekey_{model}"
        self.path = "udp:127.0.0.1:54935"
        self.fingerprint = '95d8f670'
        self.master_xpub = "tpubDCknDegFqAdP4V2AhHhs635DPe8N1aTjfKE9m2UFbdej8zmeNbtqDzK59SxnsYSRSx5uS3AujbwgANUiAk4oHmDNUKoGGkWWUY6c48WgjEx"
        self.password = ""
        self.supports_ms_display = True
        self.supports_xpub_ms_display = True
        self.supports_unsorted_ms = True
        self.supports_taproot = True
        self.strict_bip48 = True
        self.include_xpubs = False
        self.supports_device_multiple_multisig = True

    def start(self):
        super().start()
        self.emulator_log = open('onekey-{}-emulator.stdout'.format(self.model), 'a')
        # Start the Onekey emulator
        self.emulator_proc = subprocess.Popen(['./' + os.path.basename(self.emulator_path)], cwd=os.path.dirname(self.emulator_path), stdout=self.emulator_log, env={'SDL_VIDEODRIVER': 'dummy', 'PYOPT': '0'}, shell=True, preexec_fn=os.setsid)
        # Wait for emulator to be up
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(('127.0.0.1', DEFAULT_UDP_PORT))
        sock.settimeout(0)
        while True:
            try:
                time.sleep(1)
                sock.sendall(b"PINGPING")
                r = sock.recv(8)
                if r == b"PONGPONG":
                    break
            except Exception:
                time.sleep(1)
        # Setup the emulator
        wirelink = UdpTransport.enumerate("127.0.0.1:54935")[0]
        client = TrezorClientDebugLink(wirelink, model=ONEKEY_LEGACY)
        client.retrieval_version = MethodType(retrieval_version, client)
        client.ensure_model = MethodType(ensure_model, client)
        client.init_device()
        device.wipe(client)
        load_device_by_mnemonic(client=client, mnemonic='alcohol woman abuse must during monitor noble actual mixed trade anger aisle', pin='', passphrase_protection=False, label='test') # From Trezor device tests
        atexit.register(self.stop)
        return client

    def stop(self):
        super().stop()
        if self.emulator_proc.poll() is None:
            os.killpg(os.getpgid(self.emulator_proc.pid), signal.SIGTERM)
            os.waitpid(self.emulator_proc.pid, 0)

        # Clean up emulator image
        if self.model == 't':
            emulator_img = "/var/tmp/onekey.flash"
        else:  # self.model == '1'
            emulator_img = os.path.dirname(self.emulator_path) + "/emulator.img"

        if os.path.isfile(emulator_img):
            os.unlink(emulator_img)

        if self.emulator_log is not None:
            self.emulator_log.close()
            self.emulator_log = None

        # Wait a second for everything to be cleaned up before going to the next test
        time.sleep(1)

        atexit.unregister(self.stop)

class OnekeyTestCase(unittest.TestCase):
    def __init__(self, emulator, interface='library', methodName='runTest'):
        super(OnekeyTestCase, self).__init__(methodName)
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
        return 'onekey_{}: {}'.format(self.emulator.model, super().__str__())

    def __repr__(self):
        return 'onekey_{}: {}'.format(self.emulator.model, super().__repr__())

    def setUp(self):
        self.client = self.emulator.start()

    def tearDown(self):
        self.emulator.stop()

# OneKey specific getxpub test because this requires device specific thing to set xprvs
class TestOnekeyGetxpub(OnekeyTestCase):
    def test_getxpub(self):
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/bip32_vectors.json'), encoding='utf-8') as f:
            vectors = json.load(f)
        for vec in vectors:
            with self.subTest(vector=vec):
                # Setup with mnemonic
                device.wipe(self.client)
                load_device_by_mnemonic(client=self.client, mnemonic=vec['mnemonic'], pin='', passphrase_protection=False, label='test', language='english')

                # Test getmasterxpub
                gmxp_res = self.do_command(['-t', 'onekey', '-d', "udp:127.0.0.1:54935", 'getmasterxpub', "--addr-type", "legacy"])
                self.assertEqual(gmxp_res['xpub'], vec['master_xpub'])

                # Test the path derivs
                for path_vec in vec['vectors']:
                    gxp_res = self.do_command(['-t', 'onekey', '-d', "udp:127.0.0.1:54935", 'getxpub', path_vec['path']])
                    self.assertEqual(gxp_res['xpub'], path_vec['xpub'])

    def test_expert_getxpub(self):
        result = self.do_command(['-t', 'onekey', '-d', "udp:127.0.0.1:54935", '--expert', 'getxpub', 'm/44h/0h/0h/3'])
        self.assertEqual(result['xpub'], 'xpub6FMafWAi3n3ET2rU5yQr16UhRD1Zx4dELmcEw3NaYeBaNnipcr2zjzYp1sNdwR3aTN37hxAqRWQ13AWUZr6L9jc617mU6EvgYXyBjXrEhgr')
        self.assertFalse(result['testnet'])
        self.assertFalse(result['private'])
        self.assertEqual(result['depth'], 4)
        self.assertEqual(result['parent_fingerprint'], 'f7e318db')
        self.assertEqual(result['child_num'], 3)
        self.assertEqual(result['chaincode'], '95a7fb33c4f0896f66045cd7f45ed49a9e72372d2aed204ad0149c39b7b17905')
        self.assertEqual(result['pubkey'], '022e6d9c18e5a837e802fb09abe00f787c8ccb0fc489c6ec5dc2613d930efd7eae')

class TestOnekeyLabel(OnekeyTestCase):
    def setUp(self):
        self.client = self.emulator.start()
        self.dev_args = ['-t', 'onekey', '-d', "udp:127.0.0.1:54935"]

    def test_label(self):
        result = self.do_command(self.dev_args + ['enumerate'])
        for dev in result:
            if dev['type'] == 'onekey' and dev['path'] == "udp:127.0.0.1:54935":
                self.assertEqual(dev['label'], 'test')
                break
        else:
            self.fail("Did not enumerate device")

def onekey_test_suite(emulator, bitcoind, interface, model):
    assert model in ONEKEY_MODELS
    # Redirect stderr to /dev/null as it's super spammy
    sys.stderr = open(os.devnull, 'w')

    dev_emulator = OnkeyEmulator(emulator, model)
    signtx_cases = [
        (["legacy"], ["legacy"], False, True),
        (["segwit"], ["segwit"], False, True),
        (["tap"], [], False, True),
        (["legacy", "segwit"], ["legacy", "segwit"], False, True),
        (["legacy", "segwit", "tap"], ["legacy", "segwit"], False, True),
    ]
    # Generic Device tests
    suite = unittest.TestSuite()
    suite.addTest(DeviceTestCase.parameterize(TestDeviceConnect, bitcoind, emulator=dev_emulator, interface=interface, detect_type="onekey"))
    suite.addTest(DeviceTestCase.parameterize(TestDeviceConnect, bitcoind, emulator=dev_emulator, interface=interface, detect_type=f"onekey_{model}_simulator"))
    suite.addTest(DeviceTestCase.parameterize(TestGetDescriptors, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestGetKeypool, bitcoind, emulator=dev_emulator, interface=interface))
    if model == 't':
        suite.addTest(DeviceTestCase.parameterize(TestSignTx, bitcoind, emulator=dev_emulator, interface=interface, signtx_cases=signtx_cases))
        suite.addTest(DeviceTestCase.parameterize(TestDisplayAddress, bitcoind, emulator=dev_emulator, interface=interface))
        suite.addTest(DeviceTestCase.parameterize(TestSignMessage, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(OnekeyTestCase.parameterize(TestOnekeyLabel, emulator=dev_emulator, interface=interface))
    suite.addTest(OnekeyTestCase.parameterize(TestOnekeyGetxpub, emulator=dev_emulator, interface=interface))
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
    sys.stderr = sys.__stderr__
    return result.wasSuccessful()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test Onekey implementation')
    parser.add_argument('emulator', help='Path to the Onekey emulator')
    parser.add_argument('bitcoind', help='Path to bitcoind binary')
    parser.add_argument('--interface', help='Which interface to send commands over', choices=['library', 'cli', 'bindist'], default='library')
    group = parser.add_argument_group()
    group.add_argument('--model_1', help='The emulator is for the Onekey legacy', action='store_const', const='1', dest='model')
    group.add_argument('--model_t', help='The emulator is for the Onekey Touch', action='store_const', const='t', dest='model')
    args = parser.parse_args()

    # Start bitcoind
    bitcoind = Bitcoind.create(args.bitcoind)

    sys.exit(not onekey_test_suite(args.emulator, bitcoind, args.interface, args.model))
