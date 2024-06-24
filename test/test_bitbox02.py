#! /usr/bin/env python3

import atexit
import os
import subprocess
import time
import unittest
import sys
import argparse

from hwilib.devices.bitbox02 import Bitbox02Client

from test_device import (
    DeviceEmulator,
    DeviceTestCase,
    TestDeviceConnect,
    TestDisplayAddress,
    TestGetKeypool,
    TestGetDescriptors,
    TestSignTx,
)

# Class for emulator control
class BitBox02Emulator(DeviceEmulator):
    def __init__(self, simulator):
        self.simulator = simulator
        self.path = "127.0.0.1:15423"
        self.type = "bitbox02"
        self.fingerprint = "4c00739d"
        self.master_xpub = "tpubDDoFYQF4zAhrW8LRtCxePR8bJsAh5SXU6PwPNi2oRfeh67qhmxZawJ4m3V76P8AYSEueKmwvNyiSPAGYtynGfzJNvTHyzj2FJTbp729jmYM"
        self.password = None
        self.supports_ms_display = False
        self.supports_xpub_ms_display = False
        self.supports_unsorted_ms = False
        self.supports_taproot = False
        self.strict_bip48 = False
        self.include_xpubs = True
        self.supports_device_multiple_multisig = True

    def start(self):
        super().start()
        self.log = open('bitbox02-simulator.stderr', 'a')
        # Start the Bitbox02 simulator
        self.simulator_proc = subprocess.Popen(
            [
                './' + os.path.basename(self.simulator)
            ],
            cwd=os.path.dirname(self.simulator),
            stderr=self.log
        )
        time.sleep(1)

        self.setup_client = Bitbox02Client(self.path)
        self.setup_bb02 = self.setup_client.restore_device()
        self.setup_client.close()

        atexit.register(self.stop)

    def stop(self):
        super().stop()
        self.simulator_proc.terminate()
        self.simulator_proc.wait()
        self.log.close()
        atexit.unregister(self.stop)

class TestBitbox02GetXpub(DeviceTestCase):
    def test_getxpub(self):
        self.dev_args.remove('--chain')
        self.dev_args.remove('test')
        result = self.do_command(self.dev_args + ['--expert', 'getxpub', 'm/84h/0h/0h/3'])
        self.assertEqual(result['xpub'], 'xpub6F8W4c3nJf6vWyEQPW9rofRgKf9LUWrbLc6fh2GUgofxXzuMwNEXw9dUuAeHuNiu2MebTmLX1CY2wxN1pgUuQtsWa9x8QBk7J51nD86vann')
        self.assertFalse(result['testnet'])
        self.assertFalse(result['private'])
        self.assertEqual(result['depth'], 4)
        self.assertEqual(result['parent_fingerprint'], 'd934efde')
        self.assertEqual(result['child_num'], 3)
        self.assertEqual(result['chaincode'], '03b0d37df586659fb87145e1d28506e4e2d42777586568d61ecdf6c9e041a0a1')
        self.assertEqual(result['pubkey'], '03290b94a942a317c3846244f1eb6d67214326c8cfc6d940c823ace57ab818dbbd')

def bitbox02_test_suite(simulator, bitcoind, interface):
    dev_emulator = BitBox02Emulator(simulator)

    signtx_cases = [
        (["segwit"], [], False, False)
    ]

    # Generic Device tests
    suite = unittest.TestSuite()
    suite.addTest(DeviceTestCase.parameterize(TestDeviceConnect, bitcoind, emulator=dev_emulator, interface=interface, detect_type=dev_emulator.type, supports_legacy=False))
    suite.addTest(DeviceTestCase.parameterize(TestGetKeypool, bitcoind, emulator=dev_emulator, interface=interface, supports_legacy=False))
    suite.addTest(DeviceTestCase.parameterize(TestGetDescriptors, bitcoind, emulator=dev_emulator, interface=interface, supports_legacy=False))
    suite.addTest(DeviceTestCase.parameterize(TestSignTx, bitcoind, emulator=dev_emulator, interface=interface, signtx_cases=signtx_cases, supports_legacy=False))
    suite.addTest(DeviceTestCase.parameterize(TestDisplayAddress, bitcoind, emulator=dev_emulator, interface=interface, supports_legacy=False))
    # TestSignMessage is removed, since its only testcase is for legacy p2pkh, which is not supported by BitBox02
    # suite.addTest(DeviceTestCase.parameterize(TestSignMessage, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestBitbox02GetXpub, bitcoind, emulator=dev_emulator, interface=interface, supports_legacy=False))

    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
    return result.wasSuccessful()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test BitBox02 implementation')
    parser.add_argument('simulator', help='Path to simulator binary')
    parser.add_argument('bitcoind', help='Path to bitcoind binary')
    parser.add_argument('--interface', help='Which interface to send commands over', choices=['library', 'cli', 'bindist'], default='library')
    args = parser.parse_args()

    sys.exit(not bitbox02_test_suite(args.simulator, None, None))
