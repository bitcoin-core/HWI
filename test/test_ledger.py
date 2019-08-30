#! /usr/bin/env python3

import argparse
import atexit
import json
import os
import socket
import subprocess
import time
import unittest

from authproxy import AuthServiceProxy, JSONRPCException
from test_device import DeviceTestCase, start_bitcoind, TestDeviceConnect, TestDisplayAddress, TestGetKeypool, TestSignMessage, TestSignTx

from hwilib.cli import process_commands

def ledger_test_suite(device_model, rpc, userpass, interface):
    # Look for real ledger using HWI API(self-referential, but no other way)
    enum_res = process_commands(['enumerate'])
    path = None
    master_xpub = None
    fingerprint = None
    for device in enum_res:
        if device['type'] == 'ledger':
            fingerprint = device['fingerprint']
            path = device['path']
            master_xpub = process_commands(['-f', fingerprint, 'getmasterxpub'])['xpub']
            break
    assert(path is not None and master_xpub is not None and fingerprint is not None)

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

    # Generic Device tests
    suite = unittest.TestSuite()
    suite.addTest(DeviceTestCase.parameterize(TestLedgerDisabledCommands, rpc, userpass, device_model, 'ledger', path, fingerprint, master_xpub, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestDeviceConnect, rpc, userpass, device_model, 'ledger', path, fingerprint, master_xpub, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestDeviceConnect, rpc, userpass, device_model, 'ledger', path, fingerprint, master_xpub, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestGetKeypool, rpc, userpass, device_model, 'ledger', path, fingerprint, master_xpub, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestSignTx, rpc, userpass, device_model, 'ledger', path, fingerprint, master_xpub, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestDisplayAddress, rpc, userpass, device_model, 'ledger', path, fingerprint, master_xpub, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestSignMessage, rpc, userpass, device_model, 'ledger', path, fingerprint, master_xpub, interface=interface))
    return suite

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test Ledger implementation on physical device')
    parser.add_argument('bitcoind', help='Path to bitcoind binary')
    parser.add_argument('device_model', help='Device model', choices=['ledger_nano_s', 'ledger_nano_x'])
    parser.add_argument('--interface', help='Which interface to send commands over', choices=['library', 'cli', 'bindist'], default='library')

    args = parser.parse_args()

    # Start bitcoind
    rpc, userpass = start_bitcoind(args.bitcoind)

    suite = ledger_test_suite(args.device_model, rpc, userpass, args.interface)
    unittest.TextTestRunner(verbosity=2).run(suite)
