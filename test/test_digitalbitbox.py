#! /usr/bin/env python3

import argparse
import atexit
import json
import os
import subprocess
import sys
import time
import unittest

from test_device import (
    Bitcoind,
    DeviceEmulator,
    DeviceTestCase,
    TestDeviceConnect,
    TestGetKeypool,
    TestGetDescriptors,
    TestSignTx,
)

from hwilib.devices.digitalbitbox import BitboxSimulator, send_plain, send_encrypt

class BitBox01Emulator(DeviceEmulator):
    def __init__(self, simulator):
        try:
            os.unlink('bitbox-emulator.stderr')
        except FileNotFoundError:
            pass
        self.simulator = simulator
        self.bitbox_log = None
        self.simulator_proc = None
        self.type = 'digitalbitbox'
        self.path = 'udp:127.0.0.1:35345'
        self.fingerprint = 'a31b978a'
        self.master_xpub = "tpubDCjZ76WbqdyGWi7NaFLuhWL8GX7NK5gCGB7ApynxUHGkgvBVCtpXX1i6Uj88rL9WKM7vimN8QZRjowSX4g2uPxjnuie1Kg7XK8pvNGZznQi"
        self.password = "0000"
        self.supports_ms_display = False
        self.supports_xpub_ms_display = False
        self.supports_unsorted_ms = False
        self.supports_taproot = False
        self.strict_bip48 = False
        self.include_xpubs = False
        self.supports_device_multiple_multisig = True

    def start(self):
        super().start()
        self.bitbox_log = open('bitbox-emulator.stderr', 'a')
        # Start the Digital bitbox simulator
        self.simulator_proc = subprocess.Popen(
            [
                './' + os.path.basename(self.simulator),
                '../../tests/sd_files/'
            ],
            cwd=os.path.dirname(self.simulator),
            stderr=self.bitbox_log
        )
        # Wait for simulator to be up
        while True:
            try:
                self.dev = BitboxSimulator('127.0.0.1', 35345)
                reply = send_plain(b'{"password":"0000"}', self.dev)
                if 'error' not in reply:
                    break
            except Exception:
                pass
            time.sleep(0.5)

        # Set password and load from backup
        send_encrypt(json.dumps({"seed": {"source": "backup", "filename": "test_backup.pdf", "key": "key"}}), '0000', self.dev)

        atexit.register(self.stop)

    def stop(self):
        super().stop()
        self.simulator_proc.terminate()
        self.simulator_proc.wait()
        self.bitbox_log.close()
        atexit.unregister(self.stop)

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
        send_plain(b'{"password":"0000"}', self.emulator.dev)
        send_encrypt(json.dumps({"seed": {"source": "backup", "filename": "test_backup.pdf", "key": "key"}}), '0000', self.emulator.dev)

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

class TestBitboxGetXpub(DeviceTestCase):
    def test_getxpub(self):
        self.dev_args.remove('--chain')
        self.dev_args.remove('test')
        result = self.do_command(self.dev_args + ['--expert', 'getxpub', 'm/44h/0h/0h/3'])
        self.assertEqual(result['xpub'], 'xpub6Du9e5Cz1NZWz3dvsvM21tsj4xEdbAb7AcbysFL42Y3yr8PLMnsaxhetHxurTpX5Rp5RbnFFwP1wct8K3gErCUSwcxFhxThsMBSxdmkhTNf')
        self.assertFalse(result['testnet'])
        self.assertFalse(result['private'])
        self.assertEqual(result['depth'], 4)
        self.assertEqual(result['parent_fingerprint'], '31d5e5ea')
        self.assertEqual(result['child_num'], 3)
        self.assertEqual(result['chaincode'], '7062818c752f878bf96ca668f77630452c3fa033b7415eed3ff568e04ada8104')
        self.assertEqual(result['pubkey'], '029078c9ad8421afd958d7bc054a0952874923e2586fc9375604f0479a354ea193')

def digitalbitbox_test_suite(simulator, bitcoind, interface):
    dev_emulator = BitBox01Emulator(simulator)

    signtx_cases = [
        (["legacy"], ["legacy"], True, True),
        (["segwit"], ["segwit"], True, True),
        (["legacy", "segwit"], ["legacy", "segwit"], True, True),
    ]

    # Generic Device tests
    suite = unittest.TestSuite()
    suite.addTest(DeviceTestCase.parameterize(TestDBBManCommands, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestBitboxGetXpub, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestDeviceConnect, bitcoind, emulator=dev_emulator, interface=interface, detect_type="digitalbitbox"))
    suite.addTest(DeviceTestCase.parameterize(TestDeviceConnect, bitcoind, emulator=dev_emulator, interface=interface, detect_type="digitalbitbox_01_simulator"))
    suite.addTest(DeviceTestCase.parameterize(TestGetDescriptors, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestGetKeypool, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestSignTx, bitcoind, emulator=dev_emulator, interface=interface, signtx_cases=signtx_cases))

    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
    return result.wasSuccessful()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test Digital Bitbox implementation')
    parser.add_argument('simulator', help='Path to simulator binary')
    parser.add_argument('bitcoind', help='Path to bitcoind binary')
    parser.add_argument('--interface', help='Which interface to send commands over', choices=['library', 'cli', 'bindist'], default='library')
    args = parser.parse_args()

    # Start bitcoind
    bitcoind = Bitcoind.create(args.bitcoind)

    sys.exit(not digitalbitbox_test_suite(args.simulator, bitcoind, args.interface))
