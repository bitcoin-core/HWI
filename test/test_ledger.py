#! /usr/bin/env python3

import argparse
import atexit
import os
import subprocess
import signal
import sys
import time
import unittest

from test_device import (
    Bitcoind,
    DeviceEmulator,
    DeviceTestCase,
    TestDeviceConnect,
    TestDisplayAddress,
    TestGetKeypool,
    TestGetDescriptors,
    TestSignMessage,
    TestSignTx,
)

from hwilib._cli import process_commands

class LedgerEmulator(DeviceEmulator):
    def __init__(self, path, legacy=False):
        self.emulator_path = path
        self.emulator_proc = None
        self.emulator_stderr = None
        self.emulator_stdout = None
        self.legacy = legacy
        try:
            os.unlink('ledger-emulator.stderr')
        except FileNotFoundError:
            pass
        self.type = "ledger"
        self.path = 'tcp:127.0.0.1:9999'
        self.fingerprint = 'f5acc2fd'
        self.master_xpub = 'tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT'
        self.password = ""
        self.supports_ms_display = False # Legacy does not multisig address display; tests not updated for new app
        self.supports_xpub_ms_display = False # Legacy does not multisig address display; tests not updated for new app
        self.supports_unsorted_ms = False # Legacy does not support unsorted multisig; tests not updated for new app
        self.supports_taproot = not legacy # Legacy does not support Taproot
        self.strict_bip48 = True
        self.include_xpubs = True
        self.supports_device_multiple_multisig = True

    def start(self):
        super().start()
        automation_path = os.path.abspath("data/speculos-automation.json")
        app_path = "./apps/nanos#btc#2.0#ce796c1b.elf" if self.legacy else "./apps/btc-test.elf"
        os.environ["SPECULOS_APPNAME"] = "Bitcoin Test:1.6.0" if self.legacy else "Bitcoin Test:2.1.0"

        self.emulator_stderr = open('ledger-emulator.stderr', 'a')
        # Start the emulator
        self.emulator_proc = subprocess.Popen(
            [
                'python3',
                './' + os.path.basename(self.emulator_path),
                '--display',
                'headless',
                '--automation',
                'file:{}'.format(automation_path),
                '--log-level',
                'automation:DEBUG',
                '--log-level',
                'seproxyhal:DEBUG',
                '--api-port',
                '0',
                '--model', 'nanos',
                app_path
            ],
            cwd=os.path.dirname(self.emulator_path),
            stderr=self.emulator_stderr,
            preexec_fn=os.setsid,
        )
        # Wait for simulator to be up
        while True:
            try:
                enum_res = process_commands(['enumerate'])
                found = False
                for dev in enum_res:
                    if dev['type'] == 'ledger' and 'error' not in dev:
                        found = True
                        break
                if found:
                    break
            except Exception as e:
                print(str(e))
                pass
            time.sleep(0.5)
        atexit.register(self.stop)

    def stop(self):
        super().stop()
        if self.emulator_proc.poll() is None:
            os.killpg(os.getpgid(self.emulator_proc.pid), signal.SIGTERM)
            os.waitpid(self.emulator_proc.pid, 0)
        if self.emulator_stderr is not None:
            self.emulator_stderr.close()
        if self.emulator_stdout is not None:
            self.emulator_stdout.close()
        atexit.unregister(self.stop)

# Ledger specific disabled command tests
class TestLedgerDisabledCommands(DeviceTestCase):
    def test_pin(self):
        result = self.do_command(self.dev_args + ['promptpin'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['error'], 'The Ledger Nano S and X do not need a PIN sent from the host')
        self.assertEqual(result['code'], -9)

        result = self.do_command(self.dev_args + ['sendpin', '1234'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['error'], 'The Ledger Nano S and X do not need a PIN sent from the host')
        self.assertEqual(result['code'], -9)

    def test_setup(self):
        result = self.do_command(self.dev_args + ['-i', 'setup'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['error'], 'The Ledger Nano S and X do not support software setup')
        self.assertEqual(result['code'], -9)

    def test_wipe(self):
        result = self.do_command(self.dev_args + ['wipe'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['error'], 'The Ledger Nano S and X do not support wiping via software')
        self.assertEqual(result['code'], -9)

    def test_restore(self):
        result = self.do_command(self.dev_args + ['-i', 'restore'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['error'], 'The Ledger Nano S and X do not support restoring via software')
        self.assertEqual(result['code'], -9)

    def test_backup(self):
        result = self.do_command(self.dev_args + ['backup'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['error'], 'The Ledger Nano S and X do not support creating a backup via software')
        self.assertEqual(result['code'], -9)

class TestLedgerGetXpub(DeviceTestCase):
    def test_getxpub(self):
        result = self.do_command(self.dev_args + ['--expert', 'getxpub', 'm/44h/1h/0h/0/3'])
        self.assertEqual(result['xpub'], "tpubDHcN44A4UHqdR5iJduo8FWiWtJNcY7MPUEe1Dmpo4sv1R93k6mrWxAVNmjFAsW4e9gC14yTfkHFzBTQUjnkdijZVLmmiJdueMgLPczBRBSL")
        self.assertTrue(result['testnet'])
        self.assertFalse(result['private'])
        self.assertEqual(result['depth'], 5)
        self.assertEqual(result['parent_fingerprint'], "f7ed8b7e")
        self.assertEqual(result['child_num'], 3)
        self.assertEqual(result['chaincode'], "1067f2a53975faf7ac265be505c1c50ef80a0dcbe1f53f50497c5618e8888dbd")
        self.assertEqual(result['pubkey'], "035879ca173a9c1b3f300ec587fb4cc6d54d618e30584e425c1b53b98828708f1d")

def ledger_test_suite(emulator, bitcoind, interface, legacy=False):
    dev_emulator = LedgerEmulator(emulator, legacy)

    signtx_cases = [
        (["legacy"], ["legacy"], True, legacy),
        (["segwit"], ["segwit"], True, legacy),
    ]
    if not legacy:
        signtx_cases.extend([
            (["tap"], [], True, legacy),
            (["legacy", "segwit"], ["legacy", "segwit"], True, legacy),
            (["legacy", "segwit", "tap"], ["legacy", "segwit"], True, legacy),
        ])

    # Generic Device tests
    suite = unittest.TestSuite()
    suite.addTest(DeviceTestCase.parameterize(TestLedgerDisabledCommands, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestLedgerGetXpub, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestDeviceConnect, bitcoind, emulator=dev_emulator, interface=interface, detect_type=dev_emulator.type))
    suite.addTest(DeviceTestCase.parameterize(TestGetDescriptors, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestGetKeypool, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestDisplayAddress, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestSignMessage, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestSignTx, bitcoind, emulator=dev_emulator, interface=interface, signtx_cases=signtx_cases))

    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
    return result.wasSuccessful()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test Ledger implementation')
    parser.add_argument('emulator', help='Path to the ledger emulator')
    parser.add_argument('bitcoind', help='Path to bitcoind binary')
    parser.add_argument('--interface', help='Which interface to send commands over', choices=['library', 'cli', 'bindist'], default='library')
    parser.add_argument("--legacy", action="store_true", help="Use the v1 app and test the legacy API")

    args = parser.parse_args()

    # Start bitcoind
    bitcoind = Bitcoind.create(args.bitcoind)

    sys.exit(not ledger_test_suite(args.emulator, bitcoind, args.interface, args.legacy))
