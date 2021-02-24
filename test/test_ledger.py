#! /usr/bin/env python3

import argparse
import atexit
import os
import subprocess
import signal
import sys
import time
import unittest

from test_device import DeviceEmulator, DeviceTestCase, start_bitcoind, TestDeviceConnect, TestDisplayAddress, TestGetKeypool, TestGetDescriptors, TestSignMessage, TestSignTx

from hwilib._cli import process_commands

class LedgerEmulator(DeviceEmulator):
    def __init__(self, path):
        self.emulator_path = path
        self.emulator_proc = None
        self.emulator_stderr = None
        self.emulator_stdout = None
        try:
            os.unlink('ledger-emulator.stderr')
        except FileNotFoundError:
            pass

    def start(self):
        automation_path = os.path.abspath("data/speculos-automation.json")

        self.emulator_stderr = open('ledger-emulator.stderr', 'a')
        # Start the emulator
        self.emulator_proc = subprocess.Popen(['python3', './' + os.path.basename(self.emulator_path), '--display', 'headless', '--automation', 'file:{}'.format(automation_path), '--log-level', 'automation:DEBUG', '--log-level', 'seproxyhal:DEBUG', './apps/btc.elf'], cwd=os.path.dirname(self.emulator_path), stderr=self.emulator_stderr, preexec_fn=os.setsid)
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

    def stop(self):
        if self.emulator_proc.poll() is None:
            os.killpg(os.getpgid(self.emulator_proc.pid), signal.SIGTERM)
            os.waitpid(self.emulator_proc.pid, 0)
        if self.emulator_stderr is not None:
            self.emulator_stderr.close()
        if self.emulator_stdout is not None:
            self.emulator_stdout.close()

def ledger_test_suite(emulator, rpc, userpass, interface):

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
        def setUp(self):
            self.dev_args.remove("--chain")
            self.dev_args.remove("test")

        def test_getxpub(self):
            result = self.do_command(self.dev_args + ['--expert', 'getxpub', 'm/44h/0h/0h/3'])
            self.assertEqual(result['xpub'], 'xpub6DqTtMuqBiBsSPb5UxB1qgJ3ViXuhoyZYhw3zTK4MywLB6psioW4PN1SAbhxVVirKQojnTBsjG5gXiiueRBgWmUuN43dpbMSgMCQHVqx2bR')
            self.assertFalse(result['testnet'])
            self.assertFalse(result['private'])
            self.assertEqual(result['depth'], 4)
            self.assertEqual(result['parent_fingerprint'], '2930ce56')
            self.assertEqual(result['child_num'], 3)
            self.assertEqual(result['chaincode'], 'a3cd503ab3ffd3c31610a84307f141528c7e9b8416e10980ced60d1868b463e2')
            self.assertEqual(result['pubkey'], '03d5edb7c091b5577e1e2e6493b34e602b02547518222e26472cfab1745bb5977d')

    device_model = 'ledger_nano_s_simulator'
    path = 'tcp:127.0.0.1:9999'
    master_xpub = 'xpub6Cak8u8nU1evR4eMoz5UX12bU9Ws5RjEgq2Kq1RKZrsEQF6Cvecoyr19ZYRikWoJo16SXeft5fhkzbXcmuPfCzQKKB9RDPWT8XnUM62ieB9'
    fingerprint = 'f5acc2fd'
    dev_emulator = LedgerEmulator(emulator)
    dev_emulator.start()
    atexit.register(dev_emulator.stop)

    # Generic Device tests
    suite = unittest.TestSuite()
    suite.addTest(DeviceTestCase.parameterize(TestLedgerDisabledCommands, rpc, userpass, device_model, 'ledger', path, fingerprint, master_xpub, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestLedgerGetXpub, rpc, userpass, device_model, 'ledger', path, fingerprint, master_xpub, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestDeviceConnect, rpc, userpass, device_model, 'ledger', path, fingerprint, master_xpub, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestGetDescriptors, rpc, userpass, device_model, 'ledger', path, fingerprint, master_xpub, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestGetKeypool, rpc, userpass, device_model, 'ledger', path, fingerprint, master_xpub, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestDisplayAddress, rpc, userpass, device_model, 'ledger', path, fingerprint, master_xpub, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestSignMessage, rpc, userpass, device_model, 'ledger', path, fingerprint, master_xpub, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestSignTx, rpc, userpass, device_model, 'ledger', path, fingerprint, master_xpub, interface=interface))

    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
    dev_emulator.stop()
    atexit.unregister(dev_emulator.stop)
    return result.wasSuccessful()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test Ledger implementation')
    parser.add_argument('emulator', help='Path to the ledger emulator')
    parser.add_argument('bitcoind', help='Path to bitcoind binary')
    parser.add_argument('--interface', help='Which interface to send commands over', choices=['library', 'cli', 'bindist'], default='library')

    args = parser.parse_args()

    # Start bitcoind
    rpc, userpass = start_bitcoind(args.bitcoind)

    sys.exit(not ledger_test_suite(args.emulator, rpc, userpass, args.interface))
