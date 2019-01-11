#! /usr/bin/env python3

import argparse
import unittest

from test_device import DeviceTestCase, start_bitcoind, TestDeviceConnect, TestGetKeypool, TestSignTx, TestSignMessage

from hwilib.commands import process_commands

def digitalbitbox_test_suite(rpc, userpass, password):
    # Look for real Digital BitBox using HWI API(self-referential, but no other way)
    enum_res = process_commands(['-p', password, 'enumerate'])
    path = None
    master_xpub = None
    fingerprint = None
    for device in enum_res:
        if device['type'] == 'digitalbitbox':
            fingerprint = device['fingerprint']
            path = device['path']
            master_xpub = process_commands(['-f', fingerprint, '-p', password, 'getmasterxpub'])['xpub']
            break
    assert(path is not None and master_xpub is not None and fingerprint is not None)

    # Generic Device tests
    suite = unittest.TestSuite()
    suite.addTest(DeviceTestCase.parameterize(TestDeviceConnect, rpc, userpass, 'digitalbitbox', path, fingerprint, master_xpub, password))
    suite.addTest(DeviceTestCase.parameterize(TestGetKeypool, rpc, userpass, 'digitalbitbox', path, fingerprint, master_xpub, password))
    suite.addTest(DeviceTestCase.parameterize(TestSignTx, rpc, userpass, 'digitalbitbox', path, fingerprint, master_xpub, password))
    suite.addTest(DeviceTestCase.parameterize(TestSignMessage, rpc, userpass, 'digitalbitbox', path, fingerprint, master_xpub, password))
    return suite

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test Digital Bitbox implementation')
    parser.add_argument('bitcoind', help='Path to bitcoind binary')
    parser.add_argument('password', help='Device password')
    args = parser.parse_args()

    # Start bitcoind
    rpc, userpass = start_bitcoind(args.bitcoind)

    suite = digitalbitbox_test_suite(rpc, userpass, args.password)
    unittest.TextTestRunner().run(suite)
