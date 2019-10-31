#! /usr/bin/env python3

import argparse
import atexit
import json
import os
import subprocess
import time
import unittest

from test_device import DeviceTestCase, start_bitcoind, TestDeviceConnect, TestGetKeypool, TestGetDescriptors, TestSignTx, TestSignMessage

from hwilib.devices.digitalbitbox import BitboxSimulator, send_plain, send_encrypt

def digitalbitbox_test_suite(simulator, rpc, userpass, interface):
    # Start the Digital bitbox simulator
    simulator_proc = subprocess.Popen(['./' + os.path.basename(simulator), '../../tests/sd_files/'], cwd=os.path.dirname(simulator), stderr=subprocess.DEVNULL)
    # Wait for simulator to be up
    while True:
        try:
            dev = BitboxSimulator('127.0.0.1', 35345)
            reply = send_plain(b'{"password":"0000"}', dev)
            if 'error' not in reply:
                break
        except:
            pass
        time.sleep(0.5)
    # Cleanup

    def cleanup_simulator():
        simulator_proc.terminate()
        simulator_proc.wait()
    atexit.register(cleanup_simulator)

    # Set password and load from backup
    send_encrypt(json.dumps({"seed": {"source": "backup", "filename": "test_backup.pdf", "key": "key"}}), '0000', dev)

    # params
    type = 'digitalbitbox'
    full_type = 'digitalbitbox'
    path = 'udp:127.0.0.1:35345'
    fingerprint = 'a31b978a'
    master_xpub = 'xpub6BsWJiRvbzQJg3J6tgUKmHWYbHJSj41EjAAje6LuDwnYLqLiNSWK4N7rCXwiUmNJTBrKL8AEH3LBzhJdgdxoy4T9aMPLCWAa6eWKGCFjQhq'

    # DigitalBitbox specific management command tests
    class TestDBBManCommands(DeviceTestCase):
        def test_restore(self):
            result = self.do_command(self.dev_args + ['-i', 'restore'])
            self.assertIn('error', result)
            self.assertIn('code', result)
            self.assertEqual(result['error'], 'The Digital Bitbox does not support restoring via software')
            self.assertEqual(result['code'], -9)

        def test_pin(self):
            result = self.do_command(self.dev_args + ['promptpin'])
            self.assertIn('error', result)
            self.assertIn('code', result)
            self.assertEqual(result['error'], 'The Digital Bitbox does not need a PIN sent from the host')
            self.assertEqual(result['code'], -9)

            result = self.do_command(self.dev_args + ['sendpin', '1234'])
            self.assertIn('error', result)
            self.assertIn('code', result)
            self.assertEqual(result['error'], 'The Digital Bitbox does not need a PIN sent from the host')
            self.assertEqual(result['code'], -9)

        def test_display(self):
            result = self.do_command(self.dev_args + ['displayaddress', '--path', 'm/0h'])
            self.assertIn('error', result)
            self.assertIn('code', result)
            self.assertEqual(result['error'], 'The Digital Bitbox does not have a screen to display addresses on')
            self.assertEqual(result['code'], -9)

        def test_setup_wipe(self):
            # Device is init, setup should fail
            result = self.do_command(self.dev_args + ['-i', 'setup', '--label', 'setup_test', '--backup_passphrase', 'testpass'])
            self.assertEquals(result['code'], -10)
            self.assertEquals(result['error'], 'Device is already initialized. Use wipe first and try again')

            # Wipe
            result = self.do_command(self.dev_args + ['wipe'])
            self.assertTrue(result['success'])

            # Check arguments
            result = self.do_command(self.dev_args + ['-i', 'setup', '--label', 'setup_test'])
            self.assertEquals(result['code'], -7)
            self.assertEquals(result['error'], 'The label and backup passphrase for a new Digital Bitbox wallet must be specified and cannot be empty')
            result = self.do_command(self.dev_args + ['-i', 'setup', '--backup_passphrase', 'testpass'])
            self.assertEquals(result['code'], -7)
            self.assertEquals(result['error'], 'The label and backup passphrase for a new Digital Bitbox wallet must be specified and cannot be empty')

            # Setup
            result = self.do_command(self.dev_args + ['-i', 'setup', '--label', 'setup_test', '--backup_passphrase', 'testpass'])
            self.assertTrue(result['success'])

            # Reset back to original
            result = self.do_command(self.dev_args + ['wipe'])
            self.assertTrue(result['success'])
            send_plain(b'{"password":"0000"}', dev)
            send_encrypt(json.dumps({"seed": {"source": "backup", "filename": "test_backup.pdf", "key": "key"}}), '0000', dev)

            # Make sure device is init, setup should fail
            result = self.do_command(self.dev_args + ['-i', 'setup', '--label', 'setup_test', '--backup_passphrase', 'testpass'])
            self.assertEquals(result['code'], -10)
            self.assertEquals(result['error'], 'Device is already initialized. Use wipe first and try again')

        def test_backup(self):
            # Check arguments
            result = self.do_command(self.dev_args + ['backup', '--label', 'backup_test'])
            self.assertEquals(result['code'], -7)
            self.assertEquals(result['error'], 'The label and backup passphrase for a Digital Bitbox backup must be specified and cannot be empty')
            result = self.do_command(self.dev_args + ['backup', '--backup_passphrase', 'key'])
            self.assertEquals(result['code'], -7)
            self.assertEquals(result['error'], 'The label and backup passphrase for a Digital Bitbox backup must be specified and cannot be empty')

            # Wipe
            result = self.do_command(self.dev_args + ['wipe'])
            self.assertTrue(result['success'])

            # Setup
            result = self.do_command(self.dev_args + ['-i', 'setup', '--label', 'backup_test', '--backup_passphrase', 'testpass'])
            self.assertTrue(result['success'])

            # make the backup
            result = self.do_command(self.dev_args + ['backup', '--label', 'backup_test_backup', '--backup_passphrase', 'testpass'])
            self.assertTrue(result['success'])

    # Generic Device tests
    suite = unittest.TestSuite()
    suite.addTest(DeviceTestCase.parameterize(TestDBBManCommands, rpc, userpass, type, full_type, path, fingerprint, master_xpub, '0000', interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestDeviceConnect, rpc, userpass, type, full_type, path, fingerprint, master_xpub, '0000', interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestDeviceConnect, rpc, userpass, 'digitalbitbox_01_simulator', full_type, path, fingerprint, master_xpub, '0000', interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestGetDescriptors, rpc, userpass, type, full_type, path, fingerprint, master_xpub, '0000', interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestGetKeypool, rpc, userpass, type, full_type, path, fingerprint, master_xpub, '0000', interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestSignTx, rpc, userpass, type, full_type, path, fingerprint, master_xpub, '0000', interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestSignMessage, rpc, userpass, type, full_type, path, fingerprint, master_xpub, '0000', interface=interface))
    return suite

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test Digital Bitbox implementation')
    parser.add_argument('simulator', help='Path to simulator binary')
    parser.add_argument('bitcoind', help='Path to bitcoind binary')
    parser.add_argument('--interface', help='Which interface to send commands over', choices=['library', 'cli', 'bindist'], default='library')
    args = parser.parse_args()

    # Start bitcoind
    rpc, userpass = start_bitcoind(args.bitcoind)

    suite = digitalbitbox_test_suite(args.simulator, rpc, userpass, args.interface)
    unittest.TextTestRunner(verbosity=2).run(suite)
