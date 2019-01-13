#! /usr/bin/env python3

import argparse
import atexit
import json
import os
import subprocess
import time
import unittest

from test_device import DeviceTestCase, start_bitcoind, TestDeviceConnect, TestGetKeypool, TestSignTx, TestSignMessage

from hwilib.commands import process_commands
from hwilib.devices.digitalbitbox import BitboxSimulator, send_plain, send_encrypt

def digitalbitbox_test_suite(rpc, userpass, simulator):
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
        simulator_proc.kill()
        simulator_proc.wait()
    atexit.register(cleanup_simulator)

    # Set password and load from backup
    send_encrypt(json.dumps({"seed":{"source":"backup","filename":"test_backup.pdf","key":"key"}}), '0000', dev)

    # params
    type = 'digitalbitbox'
    path = 'udp:127.0.0.1:35345'
    fingerprint = 'a31b978a'
    master_xpub = 'xpub6BsWJiRvbzQJg3J6tgUKmHWYbHJSj41EjAAje6LuDwnYLqLiNSWK4N7rCXwiUmNJTBrKL8AEH3LBzhJdgdxoy4T9aMPLCWAa6eWKGCFjQhq'

    # Generic Device tests
    suite = unittest.TestSuite()
    suite.addTest(DeviceTestCase.parameterize(TestDeviceConnect, rpc, userpass, type, path, fingerprint, master_xpub, '0000'))
    suite.addTest(DeviceTestCase.parameterize(TestGetKeypool, rpc, userpass, type, path, fingerprint, master_xpub, '0000'))
    suite.addTest(DeviceTestCase.parameterize(TestSignTx, rpc, userpass, type, path, fingerprint, master_xpub, '0000'))
    suite.addTest(DeviceTestCase.parameterize(TestSignMessage, rpc, userpass, type, path, fingerprint, master_xpub, '0000'))
    return suite

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test Digital Bitbox implementation')
    parser.add_argument('simulator', help='Path to simulator binary')
    parser.add_argument('bitcoind', help='Path to bitcoind binary')
    args = parser.parse_args()

    # Start bitcoind
    rpc, userpass = start_bitcoind(args.bitcoind)

    suite = digitalbitbox_test_suite(rpc, userpass, args.simulator)
    unittest.TextTestRunner(verbosity=2).run(suite)
