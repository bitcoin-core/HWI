#! /usr/bin/env python3

import atexit
import os
import shutil
import subprocess
import tempfile
import time
import unittest

from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from hwilib.commands import process_commands
from hwilib.serializations import PSBT

# Class for emulator control
class DeviceEmulator():
    def start(self):
        pass
    def stop(self):
        pass

def start_bitcoind(bitcoind_path):
    datadir = tempfile.mkdtemp()
    bitcoind_proc = subprocess.Popen([bitcoind_path, '-regtest', '-datadir=' + datadir, '-noprinttoconsole'])
    def cleanup_bitcoind():
        bitcoind_proc.kill()
        shutil.rmtree(datadir)
    atexit.register(cleanup_bitcoind)
    # Wait for cookie file to be created
    while not os.path.exists(datadir + '/regtest/.cookie'):
        time.sleep(0.5)
    # Read .cookie file to get user and pass
    with open(datadir + '/regtest/.cookie') as f:
        userpass = f.readline().lstrip().rstrip()
    rpc = AuthServiceProxy('http://{}@127.0.0.1:18443'.format(userpass))

    # Wait for bitcoind to be ready
    ready = False
    while not ready:
        try:
            rpc.getblockchaininfo()
            ready = True
        except JSONRPCException as e:
            time.sleep(0.5)
            pass

    # Make sure there are blocks and coins available
    rpc.generatetoaddress(101, rpc.getnewaddress())
    return (rpc, userpass)

class DeviceTestCase(unittest.TestCase):
    def __init__(self, rpc, rpc_userpass, type, path, fingerprint, master_xpub, password = '', emulator=None, methodName='runTest'):
        super(DeviceTestCase, self).__init__(methodName)
        self.rpc = rpc
        self.rpc_userpass = rpc_userpass
        self.type = type
        self.path = path
        self.fingerprint = fingerprint
        self.master_xpub = master_xpub
        self.password = password
        self.dev_args = ['-t', self.type, '-d', self.path]
        if emulator:
            self.emulator = emulator
        else:
            self.emulator = DeviceEmulator()
        if password:
            self.dev_args.extend(['-p', password])

    @staticmethod
    def parameterize(testclass, rpc, rpc_userpass, type, path, fingerprint, master_xpub, password = '', emulator=None):
        testloader = unittest.TestLoader()
        testnames = testloader.getTestCaseNames(testclass)
        suite = unittest.TestSuite()
        for name in testnames:
            suite.addTest(testclass(rpc, rpc_userpass, type, path, fingerprint, master_xpub, password, emulator, name))
        return suite

    def __str__(self):
        return '{}: {}'.format(self.type, super().__str__())

    def __repr__(self):
        return '{}: {}'.format(self.type, super().__repr__())

class TestDeviceConnect(DeviceTestCase):
    def setUp(self):
        self.emulator.start()

    def tearDown(self):
        self.emulator.stop()

    def test_enumerate(self):
        enum_res = process_commands(['-p', self.password, 'enumerate'])
        found = False
        for device in enum_res:
            if device['type'] == self.type and device['path'] == self.path and device['fingerprint'] == self.fingerprint:
                self.assertNotIn('error', device)
                found = True
        self.assertTrue(found)

    def test_no_type(self):
        gmxp_res = process_commands(['getmasterxpub'])
        self.assertIn('error', gmxp_res)
        self.assertEqual(gmxp_res['error'], 'You must specify a device type or fingerprint for all commands except enumerate')
        self.assertIn('code', gmxp_res)
        self.assertEqual(gmxp_res['code'], -1)

    def test_path_type(self):
        gmxp_res = process_commands(['-t', self.type, '-d', self.path, '-p', self.password, 'getmasterxpub'])
        self.assertEqual(gmxp_res['xpub'], self.master_xpub)

    def test_fingerprint_autodetect(self):
        gmxp_res = process_commands(['-f', self.fingerprint, '-p', self.password, 'getmasterxpub'])
        self.assertEqual(gmxp_res['xpub'], self.master_xpub)

    def test_type_only_autodetech(self):
        gmxp_res = process_commands(['-t', self.type, '-p', self.password, 'getmasterxpub'])
        self.assertEqual(gmxp_res['xpub'], self.master_xpub)

class TestGetKeypool(DeviceTestCase):
    def setUp(self):
        self.rpc = AuthServiceProxy('http://{}@127.0.0.1:18443'.format(self.rpc_userpass))
        if '{}_test'.format(self.type) not in self.rpc.listwallets():
            self.rpc.createwallet('{}_test'.format(self.type), True)
        self.wrpc = AuthServiceProxy('http://{}@127.0.0.1:18443/wallet/{}_test'.format(self.rpc_userpass, self.type))
        self.wpk_rpc = AuthServiceProxy('http://{}@127.0.0.1:18443/wallet/'.format(self.rpc_userpass))
        if '--testnet' not in self.dev_args:
            self.dev_args.append('--testnet')
        self.emulator.start()

    def tearDown(self):
        self.emulator.stop()

    def test_getkeypool_bad_args(self):
        result = process_commands(self.dev_args + ['getkeypool', '--sh_wpkh', '--wpkh', '0', '20'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['code'], -7)

    def test_getkeypool(self):
        non_keypool_desc = process_commands(self.dev_args + ['getkeypool', '0', '20'])
        import_result = self.wpk_rpc.importmulti(non_keypool_desc)
        self.assertTrue(import_result[0]['success'])

        keypool_desc = process_commands(self.dev_args + ['getkeypool', '--keypool', '0', '20'])
        import_result = self.wpk_rpc.importmulti(keypool_desc)
        self.assertFalse(import_result[0]['success'])

        import_result = self.wrpc.importmulti(keypool_desc)
        self.assertTrue(import_result[0]['success'])
        for i in range(0, 21):
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getnewaddress())
            self.assertEqual(addr_info['hdkeypath'], "m/44'/1'/0'/0/{}".format(i))

        keypool_desc = process_commands(self.dev_args + ['getkeypool', '--keypool', '--internal', '0', '20'])
        import_result = self.wrpc.importmulti(keypool_desc)
        self.assertTrue(import_result[0]['success'])
        for i in range(0, 21):
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getrawchangeaddress())
            self.assertEqual(addr_info['hdkeypath'], "m/44'/1'/0'/1/{}".format(i))

        keypool_desc = process_commands(self.dev_args + ['getkeypool', '--keypool', '--sh_wpkh', '0', '20'])
        import_result = self.wrpc.importmulti(keypool_desc)
        self.assertTrue(import_result[0]['success'])
        for i in range(0, 21):
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getnewaddress())
            self.assertEqual(addr_info['hdkeypath'], "m/49'/1'/0'/0/{}".format(i))
        keypool_desc = process_commands(self.dev_args + ['getkeypool', '--keypool', '--sh_wpkh', '--internal', '0', '20'])
        import_result = self.wrpc.importmulti(keypool_desc)
        self.assertTrue(import_result[0]['success'])
        for i in range(0, 21):
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getrawchangeaddress())
            self.assertEqual(addr_info['hdkeypath'], "m/49'/1'/0'/1/{}".format(i))

        keypool_desc = process_commands(self.dev_args + ['getkeypool', '--keypool', '--wpkh', '0', '20'])
        import_result = self.wrpc.importmulti(keypool_desc)
        self.assertTrue(import_result[0]['success'])
        for i in range(0, 21):
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getnewaddress())
            self.assertEqual(addr_info['hdkeypath'], "m/84'/1'/0'/0/{}".format(i))
        keypool_desc = process_commands(self.dev_args + ['getkeypool', '--keypool', '--wpkh', '--internal', '0', '20'])
        import_result = self.wrpc.importmulti(keypool_desc)
        self.assertTrue(import_result[0]['success'])
        for i in range(0, 21):
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getrawchangeaddress())
            self.assertEqual(addr_info['hdkeypath'], "m/84'/1'/0'/1/{}".format(i))

        keypool_desc = process_commands(self.dev_args + ['getkeypool', '--keypool', '--sh_wpkh', '--account', '3', '0', '20'])
        import_result = self.wrpc.importmulti(keypool_desc)
        self.assertTrue(import_result[0]['success'])
        for i in range(0, 21):
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getnewaddress())
            self.assertEqual(addr_info['hdkeypath'], "m/49'/1'/3'/0/{}".format(i))
        keypool_desc = process_commands(self.dev_args + ['getkeypool', '--keypool', '--sh_wpkh', '--internal', '--account', '3', '0', '20'])
        import_result = self.wrpc.importmulti(keypool_desc)
        self.assertTrue(import_result[0]['success'])
        for i in range(0, 21):
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getrawchangeaddress())
            self.assertEqual(addr_info['hdkeypath'], "m/49'/1'/3'/1/{}".format(i))
        keypool_desc = process_commands(self.dev_args + ['getkeypool', '--keypool', '--wpkh', '--account', '3', '0', '20'])
        import_result = self.wrpc.importmulti(keypool_desc)
        self.assertTrue(import_result[0]['success'])
        for i in range(0, 21):
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getnewaddress())
            self.assertEqual(addr_info['hdkeypath'], "m/84'/1'/3'/0/{}".format(i))
        keypool_desc = process_commands(self.dev_args + ['getkeypool', '--keypool', '--wpkh', '--internal', '--account', '3', '0', '20'])
        import_result = self.wrpc.importmulti(keypool_desc)
        self.assertTrue(import_result[0]['success'])
        for i in range(0, 21):
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getrawchangeaddress())
            self.assertEqual(addr_info['hdkeypath'], "m/84'/1'/3'/1/{}".format(i))

        keypool_desc = process_commands(self.dev_args + ['getkeypool', '--keypool', '--path', 'm/0h/0h/4h/*', '0', '20'])
        import_result = self.wrpc.importmulti(keypool_desc)
        self.assertTrue(import_result[0]['success'])
        for i in range(0, 21):
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getnewaddress())
            self.assertEqual(addr_info['hdkeypath'], "m/0'/0'/4'/{}".format(i))

        keypool_desc = process_commands(self.dev_args + ['getkeypool', '--keypool', '--path', '/0h/0h/4h/*', '0', '20'])
        self.assertEqual(keypool_desc['error'], 'Path must start with m/')
        self.assertEqual(keypool_desc['code'], -7)
        keypool_desc = process_commands(self.dev_args + ['getkeypool', '--keypool', '--path', 'm/0h/0h/4h/', '0', '20'])
        self.assertEqual(keypool_desc['error'], 'Path must end with /*')
        self.assertEqual(keypool_desc['code'], -7)

class TestSignTx(DeviceTestCase):
    def setUp(self):
        self.rpc = AuthServiceProxy('http://{}@127.0.0.1:18443'.format(self.rpc_userpass))
        if '{}_test'.format(self.type) not in self.rpc.listwallets():
            self.rpc.createwallet('{}_test'.format(self.type), True)
        self.wrpc = AuthServiceProxy('http://{}@127.0.0.1:18443/wallet/{}_test'.format(self.rpc_userpass, self.type))
        self.wpk_rpc = AuthServiceProxy('http://{}@127.0.0.1:18443/wallet/'.format(self.rpc_userpass))
        if '--testnet' not in self.dev_args:
            self.dev_args.append('--testnet')
        self.emulator.start()

    def tearDown(self):
        self.emulator.stop()

    def _generate_and_finalize(self, unknown_inputs, psbt):
        if not unknown_inputs:
            # Just do the normal signing process to test "all inputs" case
            sign_res = process_commands(self.dev_args + ['signtx', psbt['psbt']])
            finalize_res = self.wrpc.finalizepsbt(sign_res['psbt'])
        else:
            # Sign only input one on first pass
            # then rest on second pass to test ability to successfully
            # ignore inputs that are not its own. Then combine both
            # signing passes to ensure they are actually properly being
            # partially signed at each step.
            first_psbt = PSBT()
            first_psbt.deserialize(psbt['psbt'])
            second_psbt = PSBT()
            second_psbt.deserialize(psbt['psbt'])


            # Blank master fingerprint to make hww fail to sign
            # Single input PSBTs will be fully signed by first signer
            for psbt_input in first_psbt.inputs[1:]:
                for pubkey, path in psbt_input.hd_keypaths.items():
                    psbt_input.hd_keypaths[pubkey] = (0,)+path[1:]
            for pubkey, path in second_psbt.inputs[0].hd_keypaths.items():
                    second_psbt.inputs[0].hd_keypaths[pubkey] = (0,)+path[1:]

            single_input = len(first_psbt.inputs) == 1

            # Process the psbts
            first_psbt = first_psbt.serialize()
            second_psbt = second_psbt.serialize()

            # First will always have something to sign
            first_sign_res = process_commands(self.dev_args + ['signtx', first_psbt])
            self.assertTrue(single_input == self.wrpc.finalizepsbt(first_sign_res['psbt'])['complete'])
            # Second may have nothing to sign (1 input case)
            # and also may throw an error(e.g., ColdCard)
            second_sign_res = process_commands(self.dev_args + ['signtx', second_psbt])
            if 'psbt' in second_sign_res:
                self.assertTrue(not self.wrpc.finalizepsbt(second_sign_res['psbt'])['complete'])
                combined_psbt = self.wrpc.combinepsbt([first_sign_res['psbt'], second_sign_res['psbt']])

            else:
                self.assertTrue('error' in second_sign_res)
                combined_psbt = first_sign_res['psbt']

            finalize_res = self.wrpc.finalizepsbt(combined_psbt)
            self.assertTrue(finalize_res['complete'])
            self.assertTrue(self.wrpc.testmempoolaccept([finalize_res['hex']])[0]["allowed"])
        return finalize_res['hex']

    def _test_signtx(self, input_type, multisig):
        # Import some keys to the watch only wallet and send coins to them
        keypool_desc = process_commands(self.dev_args + ['getkeypool', '--keypool', '--sh_wpkh', '30', '40'])
        import_result = self.wrpc.importmulti(keypool_desc)
        self.assertTrue(import_result[0]['success'])
        keypool_desc = process_commands(self.dev_args + ['getkeypool', '--keypool', '--sh_wpkh', '--internal', '30', '40'])
        import_result = self.wrpc.importmulti(keypool_desc)
        self.assertTrue(import_result[0]['success'])
        sh_wpkh_addr = self.wrpc.getnewaddress('', 'p2sh-segwit')
        wpkh_addr = self.wrpc.getnewaddress('', 'bech32')
        pkh_addr = self.wrpc.getnewaddress('', 'legacy')
        self.wrpc.importaddress(wpkh_addr)
        self.wrpc.importaddress(pkh_addr)

        # pubkeys to construct 2-of-3 multisig descriptors for import
        sh_wpkh_info = self.wrpc.getaddressinfo(sh_wpkh_addr)
        wpkh_info = self.wrpc.getaddressinfo(wpkh_addr)
        pkh_info = self.wrpc.getaddressinfo(pkh_addr)

        # Get origin info/key pair so wallet doesn't forget how to
        # sign with keys post-import
        pubkeys = [sh_wpkh_info['desc'][8:-2],\
                wpkh_info['desc'][5:-1],\
                pkh_info['desc'][4:-1]]

        sh_multi_desc = {'desc':'sh(multi(2,'+pubkeys[0]+','+pubkeys[1]+','+pubkeys[2]+'))', "timestamp":"now", "label":"shmulti"}
        sh_wsh_multi_desc = {'desc':'sh(wsh(multi(2,'+pubkeys[0]+','+pubkeys[1]+','+pubkeys[2]+')))', "timestamp":"now", "label":"shwshmulti"}
        # re-order pubkeys to allow import without "already have private keys" error
        wsh_multi_desc = {'desc':'wsh(multi(2,'+pubkeys[2]+','+pubkeys[1]+','+pubkeys[0]+'))', "timestamp":"now", "label":"wshmulti"}
        multi_result = self.wrpc.importmulti([sh_multi_desc, sh_wsh_multi_desc, wsh_multi_desc])
        self.assertTrue(multi_result[0]['success'])
        self.assertTrue(multi_result[1]['success'])
        self.assertTrue(multi_result[2]['success'])

        sh_multi_addr = self.wrpc.getaddressesbylabel("shmulti").popitem()[0]
        sh_wsh_multi_addr = self.wrpc.getaddressesbylabel("shwshmulti").popitem()[0]
        wsh_multi_addr = self.wrpc.getaddressesbylabel("wshmulti").popitem()[0]

        send_amount = 2
        number_inputs = 0
        # Single-sig
        if input_type == 'segwit' or input_type == 'all':
            self.wpk_rpc.sendtoaddress(sh_wpkh_addr, send_amount)
            self.wpk_rpc.sendtoaddress(wpkh_addr, send_amount)
            number_inputs += 2
        if input_type == 'legacy' or input_type == 'all':
            self.wpk_rpc.sendtoaddress(pkh_addr, send_amount)
            number_inputs += 1
        # Now do segwit/legacy multisig
        if multisig:
            if input_type == 'legacy' or input_type == 'all':
                self.wpk_rpc.sendtoaddress(sh_multi_addr, send_amount)
                number_inputs += 1
            if input_type == 'segwit' or input_type == 'all':
                self.wpk_rpc.sendtoaddress(wsh_multi_addr, send_amount)
                self.wpk_rpc.sendtoaddress(sh_wsh_multi_addr, send_amount)
                number_inputs += 2

        self.wpk_rpc.generatetoaddress(6, self.wpk_rpc.getnewaddress())

        # Spend different amounts, requiring 1 to 3 inputs
        for i in range(number_inputs):
            # Create a psbt spending the above
            if i == number_inputs-1:
                self.assertTrue((i+1)*send_amount == self.wrpc.getbalance("*", 0, True))
            psbt = self.wrpc.walletcreatefundedpsbt([], [{self.wpk_rpc.getnewaddress():(i+1)*send_amount}], 0, {'includeWatching': True, 'subtractFeeFromOutputs': [0]}, True)

            # Sign with unknown inputs in two steps
            self._generate_and_finalize(True, psbt)
            # Sign all inputs all at once
            final_tx = self._generate_and_finalize(False, psbt)

        # Send off final tx to sweep the wallet
        self.wrpc.sendrawtransaction(final_tx)

    # Test wrapper to avoid mixed-inputs signing for Ledger
    def test_signtx(self):
        supports_mixed = {'coldcard', 'trezor', 'digitalbitbox', 'keepkey'}
        supports_multisig = {'ledger', 'trezor', 'digitalbitbox', 'keepkey'}
        if self.type not in supports_mixed:
            self._test_signtx("legacy", self.type in supports_multisig)
            self._test_signtx("segwit", self.type in supports_multisig)
        else:
            self._test_signtx("all", self.type in supports_multisig)

class TestDisplayAddress(DeviceTestCase):
    def setUp(self):
        self.emulator.start()

    def tearDown(self):
        self.emulator.stop()

    def test_display_address_bad_args(self):
        result = process_commands(self.dev_args + ['displayaddress', '--sh_wpkh', '--wpkh', 'm/49h/1h/0h/0/0'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['code'], -7)

    def test_display_address(self):
        process_commands(self.dev_args + ['displayaddress', 'm/44h/1h/0h/0/0'])
        process_commands(self.dev_args + ['displayaddress', '--sh_wpkh', 'm/49h/1h/0h/0/0'])
        process_commands(self.dev_args + ['displayaddress', '--wpkh', 'm/84h/1h/0h/0/0'])

class TestSignMessage(DeviceTestCase):
    def setUp(self):
        self.emulator.start()

    def tearDown(self):
        self.emulator.stop()

    def test_sign_msg(self):
        process_commands(self.dev_args + ['signmessage', 'Message signing test', 'm/44h/1h/0h/0/0'])
