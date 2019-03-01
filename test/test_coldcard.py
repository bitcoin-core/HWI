#! /usr/bin/env python3

import argparse
import atexit
import os
import subprocess
import time
import unittest

from hwilib.cli import process_commands
from hwilib.devices.ckcc.protocol import CCProtocolPacker
from hwilib.devices.ckcc.client import ColdcardDevice
from test_device import DeviceTestCase, start_bitcoind, TestDeviceConnect, TestDisplayAddress, TestGetKeypool, TestSignMessage, TestSignTx

def coldcard_test_suite(simulator, rpc, userpass, interface):
    # Start the Coldcard simulator
    simulator_proc = subprocess.Popen(['python3', os.path.basename(simulator)], cwd=os.path.dirname(simulator), stdout=subprocess.DEVNULL)
    # Wait for simulator to be up
    while True:
        enum_res = process_commands(['enumerate'])
        if len(enum_res) > 0 and 'error' not in enum_res[0]:
            break
        time.sleep(0.5)
    # Cleanup
    def cleanup_simulator():
        dev = ColdcardDevice(sn='/tmp/ckcc-simulator.sock')
        resp = dev.send_recv(CCProtocolPacker.logout())
    atexit.register(cleanup_simulator)

    # Coldcard specific management command tests
    class TestColdcardManCommands(DeviceTestCase):
        def test_setup(self):
            result = self.do_command(self.dev_args + ['setup'])
            self.assertIn('error', result)
            self.assertIn('code', result)
            self.assertEqual(result['error'], 'The Coldcard does not support software setup')
            self.assertEqual(result['code'], -9)

        def test_wipe(self):
            result = self.do_command(self.dev_args + ['wipe'])
            self.assertIn('error', result)
            self.assertIn('code', result)
            self.assertEqual(result['error'], 'The Coldcard does not support wiping via software')
            self.assertEqual(result['code'], -9)

        def test_restore(self):
            result = self.do_command(self.dev_args + ['restore'])
            self.assertIn('error', result)
            self.assertIn('code', result)
            self.assertEqual(result['error'], 'The Coldcard does not support restoring via software')
            self.assertEqual(result['code'], -9)

        def test_backup(self):
            result = self.do_command(self.dev_args + ['backup'])
            self.assertTrue(result['success'])
            self.assertIn('The backup has been written to', result['message'])

        def test_pin(self):
            result = self.do_command(self.dev_args + ['promptpin'])
            self.assertIn('error', result)
            self.assertIn('code', result)
            self.assertEqual(result['error'], 'The Coldcard does not need a PIN sent from the host')
            self.assertEqual(result['code'], -9)

            result = self.do_command(self.dev_args + ['sendpin', '1234'])
            self.assertIn('error', result)
            self.assertIn('code', result)
            self.assertEqual(result['error'], 'The Coldcard does not need a PIN sent from the host')
            self.assertEqual(result['code'], -9)

    # Generic device tests
    suite = unittest.TestSuite()
    suite.addTest(DeviceTestCase.parameterize(TestColdcardManCommands, rpc, userpass, 'coldcard', '/tmp/ckcc-simulator.sock', '0f056943', '', interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestDeviceConnect, rpc, userpass, 'coldcard', '/tmp/ckcc-simulator.sock', '0f056943', 'tpubDDpWvmUrPZrhSPmUzCMBHffvC3HyMAPnWDSAQNBTnj1iZeJa7BZQEttFiP4DS4GCcXQHezdXhn86Hj6LHX5EDstXPWrMaSneRWM8yUf6NFd', interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestGetKeypool, rpc, userpass, 'coldcard', '/tmp/ckcc-simulator.sock', '0f056943', 'tpubDDpWvmUrPZrhSPmUzCMBHffvC3HyMAPnWDSAQNBTnj1iZeJa7BZQEttFiP4DS4GCcXQHezdXhn86Hj6LHX5EDstXPWrMaSneRWM8yUf6NFd', interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestDisplayAddress, rpc, userpass, 'coldcard', '/tmp/ckcc-simulator.sock', '0f056943', 'tpubDDpWvmUrPZrhSPmUzCMBHffvC3HyMAPnWDSAQNBTnj1iZeJa7BZQEttFiP4DS4GCcXQHezdXhn86Hj6LHX5EDstXPWrMaSneRWM8yUf6NFd', interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestSignMessage, rpc, userpass, 'coldcard', '/tmp/ckcc-simulator.sock', '0f056943', 'tpubDDpWvmUrPZrhSPmUzCMBHffvC3HyMAPnWDSAQNBTnj1iZeJa7BZQEttFiP4DS4GCcXQHezdXhn86Hj6LHX5EDstXPWrMaSneRWM8yUf6NFd', interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestSignTx, rpc, userpass, 'coldcard', '/tmp/ckcc-simulator.sock', '0f056943', 'tpubDDpWvmUrPZrhSPmUzCMBHffvC3HyMAPnWDSAQNBTnj1iZeJa7BZQEttFiP4DS4GCcXQHezdXhn86Hj6LHX5EDstXPWrMaSneRWM8yUf6NFd', interface=interface))
    return suite

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test Coldcard implementation')
    parser.add_argument('simulator', help='Path to the Coldcard simulator')
    parser.add_argument('bitcoind', help='Path to bitcoind binary')
    parser.add_argument('--interface', help='Which interface to send commands over', choices=['library', 'cli'], default='library')
    args = parser.parse_args()

    # Start bitcoind
    rpc, userpass = start_bitcoind(args.bitcoind)

    suite = coldcard_test_suite(args.simulator, rpc, userpass, args.interface)
    unittest.TextTestRunner(verbosity=2).run(suite)
