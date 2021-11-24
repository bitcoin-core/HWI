#! /usr/bin/env python3

import argparse
import atexit
import os
import subprocess
import logging
import signal
import sys
import time
import unittest

from test_device import DeviceEmulator, DeviceTestCase, start_bitcoind, TestDeviceConnect, TestDisplayAddress, TestGetKeypool, TestGetDescriptors, TestSignMessage, TestSignTx
from hwilib.devices.jadepy.jade import JadeAPI

USE_SIMULATOR = True
JADE_PATH = 'tcp:127.0.0.1:2222' if USE_SIMULATOR else '/dev/ttyUSB0'
JADE_MODEL = 'jade_simulator' if USE_SIMULATOR else 'jade'
TEST_SEED = bytes.fromhex('b90e532426d0dc20fffe01037048c018e940300038b165c211915c672e07762c')

LOGGING = None  # logging.INFO

# Enable jade logging
if LOGGING:
    logger = logging.getLogger('jade')
    logger.setLevel(LOGGING)
    device_logger = logging.getLogger('jade-device')
    device_logger.setLevel(LOGGING)

class JadeEmulator(DeviceEmulator):
    def __init__(self, jade_qemu_emulator_path):
        self.emulator_path = jade_qemu_emulator_path
        self.emulator_proc = None

    def start(self):
        if USE_SIMULATOR:
            # Start the qemu emulator
            print('Starting Jade emulator at:', self.emulator_path)
            self.emulator_proc = subprocess.Popen(
                [
                    './qemu-system-xtensa',
                    '-nographic',
                    '-machine', 'esp32',
                    '-m', '4M',
                    '-drive', 'file=flash_image.bin,if=mtd,format=raw',
                    '-nic', 'user,model=open_eth,id=lo0,hostfwd=tcp:0.0.0.0:2222-:2222',
                    '-drive', 'file=qemu_efuse.bin,if=none,format=raw,id=efuse',
                    '-global', 'driver=nvram.esp32.efuse,property=drive,value=efuse',
                    '-serial', 'pty'
                ],
                cwd=self.emulator_path, preexec_fn=os.setsid)
            time.sleep(5)

            # Wait for emulator to be up
            while True:
                time.sleep(1)
                try:
                    # Try to connect and set the test seed
                    with JadeAPI.create_serial(JADE_PATH, timeout=5) as jade:
                        if jade.set_seed(TEST_SEED, temporary_wallet=True):
                            print('Emulator started and test seed set')
                            break

                except Exception as e:
                    print(str(e))

    def stop(self):
        if USE_SIMULATOR:
            print('Stopping Jade emulator')
            if self.emulator_proc.poll() is None:
                os.killpg(os.getpgid(self.emulator_proc.pid), signal.SIGTERM)
                os.waitpid(self.emulator_proc.pid, 0)

def jade_test_suite(emulator, rpc, userpass, interface):

    # Jade specific disabled command tests
    class TestJadeDisabledCommands(DeviceTestCase):
        def test_pin(self):
            result = self.do_command(self.dev_args + ['promptpin'])
            self.assertIn('error', result)
            self.assertIn('code', result)
            self.assertEqual(result['error'], 'Blockstream Jade does not need a PIN sent from the host')
            self.assertEqual(result['code'], -9)

            result = self.do_command(self.dev_args + ['sendpin', '1234'])
            self.assertIn('error', result)
            self.assertIn('code', result)
            self.assertEqual(result['error'], 'Blockstream Jade does not need a PIN sent from the host')
            self.assertEqual(result['code'], -9)

        def test_setup(self):
            result = self.do_command(self.dev_args + ['-i', 'setup'])
            self.assertIn('error', result)
            self.assertIn('code', result)
            self.assertEqual(result['error'], 'Blockstream Jade does not support software setup')
            self.assertEqual(result['code'], -9)

        def test_wipe(self):
            result = self.do_command(self.dev_args + ['wipe'])
            self.assertIn('error', result)
            self.assertIn('code', result)
            self.assertEqual(result['error'], 'Blockstream Jade does not support wiping via software')
            self.assertEqual(result['code'], -9)

        def test_restore(self):
            result = self.do_command(self.dev_args + ['-i', 'restore'])
            self.assertIn('error', result)
            self.assertIn('code', result)
            self.assertEqual(result['error'], 'Blockstream Jade does not support restoring via software')
            self.assertEqual(result['code'], -9)

        def test_backup(self):
            result = self.do_command(self.dev_args + ['backup'])
            self.assertIn('error', result)
            self.assertIn('code', result)
            self.assertEqual(result['error'], 'Blockstream Jade does not support creating a backup via software')
            self.assertEqual(result['code'], -9)

    class TestJadeGetXpub(DeviceTestCase):
        def setUp(self):
            self.dev_args.remove("--chain")
            self.dev_args.remove("test")

        def test_getexpertxpub(self):
            result = self.do_command(self.dev_args + ['--expert', 'getxpub', 'm/44h/0h/0h/3'])
            self.assertEqual(result['xpub'], 'xpub6EZPQwwr93eGRt5uAN8fqNpLWtgoWM4Cn96Y7XERhRBaXus5FjuTpgGBWuvuAXp1PhYBfp7h7C7HPyuRvCyyc6wBAK7PC1Z1JVEGBnrZUXi')
            self.assertFalse(result['testnet'])
            self.assertFalse(result['private'])
            self.assertEqual(result['depth'], 4)
            self.assertEqual(result['parent_fingerprint'], '8b878d56')
            self.assertEqual(result['child_num'], 3)
            self.assertEqual(result['chaincode'], '7f6e61a651f74388da6a741be38aaf223e849ab5a677220dee113c34c51028b3')
            self.assertEqual(result['pubkey'], '03f99c7114dd0418434585410e11648ec202817dcba5551d7a5ab1d3f93a2aad2e')

    # Because Jade has some restrictions about what multisigs it supports, we run
    # explicit multisig-address tests, rather than using the standard/provided ones.
    class TestJadeGetMultisigAddresses(DeviceTestCase):
        def test_getp2sh(self):
            descriptor_param = '--desc=sh(multi(2,[1273da33/44/0h/0h]tpubDDCNstnPhbdd4vwbw5UWK3vRQSF1WXQkvBHpNXpKJAkwFYjwu735EH3GVf53qwbWimzewDUv68MUmRDgYtQ1AU8FRCPkazfuaBp7LaEaohG/3/1/11/12,[e3ebcc79/3h/1h/1]tpubDDExQpZg2tziZ7ACSBCYsY3rYxAZtTRBgWwioRLYqgNBguH6rMHN1D8epTxUQUB5kM5nxkEtr2SNic6PJLPubcGMR6S2fmDZTzL9dHpU7ka/1/3/4/5))'
            result = self.do_command(self.dev_args + ['displayaddress', descriptor_param])
            self.assertEqual(result['address'], '2N2K6xGHeEYNaKEHZSBVy33g2GfUdFwJr2A')

        def test_getp2wsh(self):
            descriptor_param = '--desc=wsh(multi(2,[b5281696/3]tpubECMbgHMZm4QymrFbuEntaWbSsaaKvJVpoR6rhVwxGUrT9qf6WLfC88piWYVsQDV86PUKx3QsXYiCqugWX1oz8ekucUdFUdupuNCgjf17EYK/0/37,[e3ebcc79/3h/2h/1]tpubDD8fpYqWy6DEvbqdj9CVWptA3gd3xqarNN6wCAjfDs1sFnd8zfb9SeDzRAXA3S4eeeYvo2sz6mbyS3KaXuDe5PcWy94PqShTpBjiJN198A6/0/37,[1273da33/1]tpubD8PzcLmm1rVeUpEjmd2kQD6a9DXy6dwVVgE14mrh1zc6L98nmNqmDaApAbEcbrJ1iPBpo2gnEniSpVXHgovU8ecWwfHVP113DK2bWEMPpEs/0/37))'
            result = self.do_command(self.dev_args + ['displayaddress', descriptor_param])
            self.assertEqual(result['address'], 'tb1qd4zy3l2dckqwjartdq2aj53x2xgesvg530x5569z4lzfrueuhjmsrtcdfp')

        def test_getp2shwsh(self):
            descriptor_param = '--desc=sh(wsh(multi(2,[b5281696/3]tpubECMbgHMZm4QymrFbuEntaWbSsaaKvJVpoR6rhVwxGUrT9qf6WLfC88piWYVsQDV86PUKx3QsXYiCqugWX1oz8ekucUdFUdupuNCgjf17EYK/13,[e3ebcc79/3h/2h/1]tpubDD8fpYqWy6DEvbqdj9CVWptA3gd3xqarNN6wCAjfDs1sFnd8zfb9SeDzRAXA3S4eeeYvo2sz6mbyS3KaXuDe5PcWy94PqShTpBjiJN198A6/13,[1273da33/1]tpubD8PzcLmm1rVeUpEjmd2kQD6a9DXy6dwVVgE14mrh1zc6L98nmNqmDaApAbEcbrJ1iPBpo2gnEniSpVXHgovU8ecWwfHVP113DK2bWEMPpEs/13)))'
            result = self.do_command(self.dev_args + ['displayaddress', descriptor_param])
            self.assertEqual(result['address'], '2NFgE1k4EpyiBTN4SBkGamFU9E1DwLLajLo')

        # NOTE: these ones are used by the sign-tx tests - using them here gets
        # them 'registered' on the Jade hw - This is not mandatory but means in
        # sign-tx we should be using them to auto-validate the change outputs.
        SIGN_TX_MULTI_DESCRIPTOR = 'multi(2,[1273da33/48h/1h/2h/0h]tpubDE5KhdeLh956ERiopzHRskaJ3huWXLUPKiQUSkR3R3nTsr4SQfVVU6DbA9E66BZYwTk87hwE7wn1175WqBzMsbkFErGt3ATJm2xaisCPUmn/0/1,[1273da33/48h/1h/0h/0h]tpubDEAjmvwVDj4aNW8D1KX39VmMW1ZUX8BNgVEyD6tUVshZYCJQvbp9LSqvihiJa4tGZUisf6XpyZHg76dDBxNZLHTf6xYwgbio4Xnj6i21JgN/0/1,[1273da33/48h/1h/1h/0h]tpubDERHGgfviqDnoRSykG1YBBfhFbgNPuTeWvjwJBXM36d5wzFwkQpWFXHC76XW99hMgd1NkR6A3rRHM93Njqdx2X3KoUebekokUPsAvmeC4NE/0/1)'

        def test_get_signing_p2sh(self):
            descriptor_param = '--desc=sh({})'.format(TestJadeGetMultisigAddresses.SIGN_TX_MULTI_DESCRIPTOR)
            result = self.do_command(self.dev_args + ['displayaddress', descriptor_param])
            self.assertEqual(result['address'], '2N4v6yct4NHy7FLex1wgwksLG97dXSTEs9x', result)

        def test_get_signing_p2wsh(self):
            descriptor_param = '--desc=wsh({})'.format(TestJadeGetMultisigAddresses.SIGN_TX_MULTI_DESCRIPTOR)
            result = self.do_command(self.dev_args + ['displayaddress', descriptor_param])
            self.assertEqual(result['address'], 'tb1qxjxvxk69yedt49u2djh8mu9lsmw6tf4n2pwuqend5tjlqrumuq2skh7qzc', result)

        def test_get_signing_p2shwsh(self):
            descriptor_param = '--desc=sh(wsh({}))'.format(TestJadeGetMultisigAddresses.SIGN_TX_MULTI_DESCRIPTOR)
            result = self.do_command(self.dev_args + ['displayaddress', descriptor_param])
            self.assertEqual(result['address'], '2N6wdpQsBUvT3nAp8hGaXEFpfvzerqaHFVC', result)

    full_type = 'jade'
    device_model = JADE_MODEL
    path = JADE_PATH
    master_xpub = 'xpub6CYWf8Kf1MXHij4KJjjtkNgQxJufSmAoyrmGuiGWvjXHSpak638GrmgWZqiem339nuHf2xuCmEVmmnXDmskEjB7QdZGW2HdiBUnoEAwV1q2'
    fingerprint = '1273da33'
    dev_emulator = JadeEmulator(emulator)
    dev_emulator.start()
    atexit.register(dev_emulator.stop)

    # Generic Device tests
    suite = unittest.TestSuite()
    suite.addTest(DeviceTestCase.parameterize(TestJadeDisabledCommands, rpc, userpass, device_model, full_type, path, fingerprint, master_xpub, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestDeviceConnect, rpc, userpass, device_model, full_type, path, fingerprint, master_xpub, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestJadeGetXpub, rpc, userpass, device_model, full_type, path, fingerprint, master_xpub, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestGetDescriptors, rpc, userpass, device_model, full_type, path, fingerprint, master_xpub, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestGetKeypool, rpc, userpass, device_model, full_type, path, fingerprint, master_xpub, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestDisplayAddress, rpc, userpass, device_model, full_type, path, fingerprint, master_xpub, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestJadeGetMultisigAddresses, rpc, userpass, device_model, full_type, path, fingerprint, master_xpub, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestSignMessage, rpc, userpass, device_model, full_type, path, fingerprint, master_xpub, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestSignTx, rpc, userpass, device_model, full_type, path, fingerprint, master_xpub, interface=interface))

    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
    dev_emulator.stop()
    atexit.unregister(dev_emulator.stop)
    return result.wasSuccessful()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test Jade implementation')
    parser.add_argument('emulator', help='Docker image name of the jade emulator')
    parser.add_argument('bitcoind', help='Path to bitcoind binary')
    parser.add_argument('--interface', help='Which interface to send commands over', choices=['library', 'cli', 'bindist'], default='library')

    args = parser.parse_args()

    # Start bitcoind
    rpc, userpass = start_bitcoind(args.bitcoind)

    sys.exit(not jade_test_suite(args.emulator, rpc, userpass, args.interface))
