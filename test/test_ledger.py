#! /usr/bin/env python3

import argparse
import atexit
import json
import os
import socket
import subprocess
import time
import unittest

from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from test_device import DeviceTestCase, start_bitcoind, TestDeviceConnect, TestDisplayAddress, TestGetKeypool, TestSignTx

from hwilib.commands import process_commands

def ledger_test_suite(rpc, userpass):
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

    # Generic Device tests
    suite = unittest.TestSuite()
    suite.addTest(DeviceTestCase.parameterize(TestDeviceConnect, rpc, userpass, 'ledger', path, fingerprint, master_xpub))
    suite.addTest(DeviceTestCase.parameterize(TestGetKeypool, rpc, userpass, 'ledger', path, fingerprint, master_xpub))
    suite.addTest(DeviceTestCase.parameterize(TestSignTx, rpc, userpass, 'ledger', path, fingerprint, master_xpub))
    suite.addTest(DeviceTestCase.parameterize(TestDisplayAddress, rpc, userpass, 'ledger', path, fingerprint, master_xpub))
    return suite

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test Ledger implementation')
    parser.add_argument('bitcoind', help='Path to bitcoind binary')
    args = parser.parse_args()

    # Start bitcoind
    rpc, userpass = start_bitcoind(args.bitcoind)

    suite = ledger_test_suite(rpc, userpass)
    unittest.TextTestRunner(verbosity=2).run(suite)
