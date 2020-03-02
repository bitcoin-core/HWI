#! /usr/bin/env python3

import argparse
import json
import os
import subprocess
import signal
import socket
import time
import unittest

from test_device import DeviceEmulator, DeviceTestCase, start_bitcoind, TestDeviceConnect, TestDisplayAddress, TestGetKeypool, TestGetDescriptors, TestSignMessage, TestSignTx
from threading import Thread

from hwilib.cli import process_commands

SCREEN_TEXT_SOCKET = '/tmp/ledger-screen.sock'
KEYBOARD_PORT = 1235


class ScreenTextThread(Thread):
    def get_screen_text(self, use_timeout=False):
        if use_timeout:
            self.sock.settimeout(5)
        else:
            self.sock.settimeout(None)
        data_str = self.sock.recv(200)
        if len(data_str) == 0:
            return ''
        data = json.loads(data_str.decode())

        text = ''
        if data['y'] == 12: # Upper line
            text = data['text']
            text += self.get_screen_text() # Get next line
        elif data['y'] == 26 or data['y'] == 28: # lower line or single line
            text = data['text']
        return text

    def run(self):
        self.running = True
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        while True:
            try:
                self.sock.bind(SCREEN_TEXT_SOCKET)
                break
            except:
                os.remove(SCREEN_TEXT_SOCKET)

        self.key_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.key_sock.connect(('127.0.0.1', KEYBOARD_PORT))

        seen_msg_hash = False
        while True:
            try:
                text = self.get_screen_text(False)
                break
            except:
                continue
        while self.running:
            just_wait = False
            if text.startswith('Address') or text.startswith('Message hash') or text.startswith("Reviewoutput") or text.startswith("Amount") or text.startswith("Fees") or text == 'Confirmtransaction':
                time.sleep(0.05)
                self.key_sock.send(b'Rr')
                if text.startswith('Message hash'):
                    seen_msg_hash = True
            elif text == 'Approve' or text.startswith('Accept'):
                time.sleep(0.05)
                self.key_sock.send(b'LRlr')
            elif text == 'Signmessage':
                time.sleep(0.05)
                if seen_msg_hash:
                    self.key_sock.send(b'LRlr')
                    seen_msg_hash = False
                else:
                    self.key_sock.send(b'Rr')
            elif text == 'Cancel' or text == 'Reject':
                time.sleep(0.05)
                self.key_sock.send(b'Ll')
            else:
                # For everything else, do nothing and wait for next text
                just_wait = True

            try:
                if just_wait:
                    # Main screen, don't do anything
                    new_text = self.get_screen_text(False)
                else:
                    # Try to fetch the next text
                    # If it times out, maybe our input didn't make it, so try processing text again
                    new_text = self.get_screen_text(True)
                text = new_text
            except:
                continue

        self.sock.close()

    def stop(self):
        self.running = False
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()
        self.key_sock.close()
        os.remove(SCREEN_TEXT_SOCKET)

class LedgerEmulator(DeviceEmulator):
    def __init__(self, path):
        self.emulator_path = path
        self.emulator_proc = None

    def start(self):
        # Start the emulator
        self.emulator_proc = subprocess.Popen(['python3', './' + os.path.basename(self.emulator_path), '--display', 'headless', '--button-port', '1235', './apps/btc.elf'], cwd=os.path.dirname(self.emulator_path), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
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

        self.kp_thread = ScreenTextThread()
        self.kp_thread.start()

    def stop(self):
        self.kp_thread.stop()
        os.killpg(os.getpgid(self.emulator_proc.pid), signal.SIGTERM)
        os.waitpid(self.emulator_proc.pid, 0)
        self.kp_thread.join()

def ledger_test_suite(emulator, rpc, userpass, interface, signtx=False):

    # Ledger specific disabled command tests
    class TestLedgerDisabledCommands(DeviceTestCase):
        def setUp(self):
            self.emulator.start()

        def tearDown(self):
            self.emulator.stop()

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
            self.emulator.start()

        def tearDown(self):
            self.emulator.stop()

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

    # Generic Device tests
    suite = unittest.TestSuite()
    suite.addTest(DeviceTestCase.parameterize(TestLedgerDisabledCommands, rpc, userpass, device_model, 'ledger', path, fingerprint, master_xpub, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestLedgerGetXpub, rpc, userpass, device_model, 'ledger', path, fingerprint, master_xpub, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestDeviceConnect, rpc, userpass, device_model, 'ledger', path, fingerprint, master_xpub, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestGetDescriptors, rpc, userpass, device_model, 'ledger', path, fingerprint, master_xpub, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestGetKeypool, rpc, userpass, device_model, 'ledger', path, fingerprint, master_xpub, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestDisplayAddress, rpc, userpass, device_model, 'ledger', path, fingerprint, master_xpub, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestSignMessage, rpc, userpass, device_model, 'ledger', path, fingerprint, master_xpub, emulator=dev_emulator, interface=interface))
    if signtx:
        suite.addTest(DeviceTestCase.parameterize(TestSignTx, rpc, userpass, device_model, 'ledger', path, fingerprint, master_xpub, emulator=dev_emulator, interface=interface))
    return suite

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test Ledger implementation')
    parser.add_argument('emulator', help='Path to the ledger emulator')
    parser.add_argument('bitcoind', help='Path to bitcoind binary')
    parser.add_argument('--interface', help='Which interface to send commands over', choices=['library', 'cli', 'bindist'], default='library')
    parser.add_argument('--signtx', help='Run the transaction signing tests too', action='store_true')

    args = parser.parse_args()

    # Start bitcoind
    rpc, userpass = start_bitcoind(args.bitcoind)

    suite = ledger_test_suite(args.emulator, rpc, userpass, args.interface, args.signtx)
    unittest.TextTestRunner(verbosity=2).run(suite)
