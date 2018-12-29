#! /usr/bin/env python3

import argparse
import atexit
import os
import subprocess
import time
import unittest

from hwilib.commands import process_commands
from ckcc.protocol import CCProtocolPacker
from ckcc.client import ColdcardDevice
from test_device import DeviceTestCase, start_bitcoind, TestDeviceConnect, TestDisplayAddress, TestGetKeypool, TestSignTx

def coldcard_test_suite(simulator, rpc, userpass):
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

    # Coldcard specific setup and wipe tests
    class TestColdcardSetupWipe(DeviceTestCase):
        def test_setup(self):
            result = process_commands(self.dev_args + ['setup'])
            self.assertIn('error', result)
            self.assertIn('code', result)
            self.assertEqual(result['error'], 'The Coldcard does not support software setup')
            self.assertEqual(result['code'], -9)

        def test_wipe(self):
            result = process_commands(self.dev_args + ['wipe'])
            self.assertIn('error', result)
            self.assertIn('code', result)
            self.assertEqual(result['error'], 'The Coldcard does not support wiping via software')
            self.assertEqual(result['code'], -9)

    # Generic device tests
    suite = unittest.TestSuite()
    suite.addTest(DeviceTestCase.parameterize(TestColdcardSetupWipe, rpc, userpass, 'coldcard', '/tmp/ckcc-simulator.sock', '0f056943', ''))
    suite.addTest(DeviceTestCase.parameterize(TestDeviceConnect, rpc, userpass, 'coldcard', '/tmp/ckcc-simulator.sock', '0f056943', 'tpubDDpWvmUrPZrhSPmUzCMBHffvC3HyMAPnWDSAQNBTnj1iZeJa7BZQEttFiP4DS4GCcXQHezdXhn86Hj6LHX5EDstXPWrMaSneRWM8yUf6NFd'))
    suite.addTest(DeviceTestCase.parameterize(TestGetKeypool, rpc, userpass, 'coldcard', '/tmp/ckcc-simulator.sock', '0f056943', 'tpubDDpWvmUrPZrhSPmUzCMBHffvC3HyMAPnWDSAQNBTnj1iZeJa7BZQEttFiP4DS4GCcXQHezdXhn86Hj6LHX5EDstXPWrMaSneRWM8yUf6NFd'))
    suite.addTest(DeviceTestCase.parameterize(TestDisplayAddress, rpc, userpass, 'coldcard', '/tmp/ckcc-simulator.sock', '0f056943', 'tpubDDpWvmUrPZrhSPmUzCMBHffvC3HyMAPnWDSAQNBTnj1iZeJa7BZQEttFiP4DS4GCcXQHezdXhn86Hj6LHX5EDstXPWrMaSneRWM8yUf6NFd'))
    # HACK: Skip this in headless simulator because it requires user input
    if not simulator.endswith('headless.py'):
        suite.addTest(DeviceTestCase.parameterize(TestSignTx, rpc, userpass, 'coldcard', '/tmp/ckcc-simulator.sock', '0f056943', 'tpubDDpWvmUrPZrhSPmUzCMBHffvC3HyMAPnWDSAQNBTnj1iZeJa7BZQEttFiP4DS4GCcXQHezdXhn86Hj6LHX5EDstXPWrMaSneRWM8yUf6NFd'))
    return suite

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test Coldcard implementation')
    parser.add_argument('simulator', help='Path to the Coldcard simulator')
    parser.add_argument('bitcoind', help='Path to bitcoind binary')
    args = parser.parse_args()

    # Start bitcoind
    rpc, userpass = start_bitcoind(args.bitcoind)

    suite = coldcard_test_suite(args.simulator, rpc, userpass)
    unittest.TextTestRunner().run(suite)
