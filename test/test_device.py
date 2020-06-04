#! /usr/bin/env python3

import atexit
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import time
import unittest

from authproxy import AuthServiceProxy, JSONRPCException
from hwilib.base58 import xpub_to_pub_hex
from hwilib.cli import process_commands
from hwilib.serializations import PSBT

# Class for emulator control
class DeviceEmulator():
    def start(self):
        pass

    def stop(self):
        pass

def start_bitcoind(bitcoind_path):
    datadir = tempfile.mkdtemp()
    bitcoind_proc = subprocess.Popen([bitcoind_path, '-regtest', '-datadir=' + datadir, '-noprinttoconsole', '-fallbackfee=0.0002'])

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
        except JSONRPCException:
            time.sleep(0.5)
            pass

    # Make sure there are blocks and coins available
    rpc.generatetoaddress(101, rpc.getnewaddress())
    return (rpc, userpass)

class DeviceTestCase(unittest.TestCase):
    def __init__(self, rpc, rpc_userpass, type, full_type, path, fingerprint, master_xpub, password='', emulator=None, interface='library', methodName='runTest'):
        super(DeviceTestCase, self).__init__(methodName)
        self.rpc = rpc
        self.rpc_userpass = rpc_userpass
        self.type = type
        self.full_type = full_type
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
        self.interface = interface

    @staticmethod
    def parameterize(testclass, rpc, rpc_userpass, type, full_type, path, fingerprint, master_xpub, password='', interface='library', emulator=None):
        testloader = unittest.TestLoader()
        testnames = testloader.getTestCaseNames(testclass)
        suite = unittest.TestSuite()
        for name in testnames:
            suite.addTest(testclass(rpc, rpc_userpass, type, full_type, path, fingerprint, master_xpub, password, emulator, interface, name))
        return suite

    def do_command(self, args):
        cli_args = []
        for arg in args:
            cli_args.append(shlex.quote(arg))
        if self.interface == 'cli':
            proc = subprocess.Popen(['hwi ' + ' '.join(cli_args)], stdout=subprocess.PIPE, shell=True)
            result = proc.communicate()
            return json.loads(result[0].decode())
        elif self.interface == 'bindist':
            proc = subprocess.Popen(['../dist/hwi ' + ' '.join(cli_args)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=True)
            result = proc.communicate()
            return json.loads(result[0].decode())
        elif self.interface == 'stdin':
            input_str = '\n'.join(args) + '\n'
            proc = subprocess.Popen(['hwi', '--stdin'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            result = proc.communicate(input_str.encode())
            return json.loads(result[0].decode())
        else:
            return process_commands(args)

    def get_password_args(self):
        if self.password:
            return ['-p', self.password]
        return []

    def __str__(self):
        return '{}: {}'.format(self.full_type, super().__str__())

    def __repr__(self):
        return '{}: {}'.format(self.full_type, super().__repr__())

    def setUp(self):
        self.emulator.start()

    def tearDown(self):
        self.emulator.stop()

class TestDeviceConnect(DeviceTestCase):
    def test_enumerate(self):
        enum_res = self.do_command(self.get_password_args() + ['enumerate'])
        found = False
        for device in enum_res:
            if (device['type'] == self.type or device['model'] == self.type) and device['path'] == self.path and device['fingerprint'] == self.fingerprint:
                self.assertIn('type', device)
                self.assertIn('model', device)
                self.assertIn('path', device)
                self.assertIn('needs_pin_sent', device)
                self.assertIn('needs_passphrase_sent', device)
                self.assertNotIn('error', device)
                self.assertNotIn('code', device)
                found = True
        self.assertTrue(found)

    def test_no_type(self):
        gmxp_res = self.do_command(['getmasterxpub'])
        self.assertIn('error', gmxp_res)
        self.assertEqual(gmxp_res['error'], 'You must specify a device type or fingerprint for all commands except enumerate')
        self.assertIn('code', gmxp_res)
        self.assertEqual(gmxp_res['code'], -1)

    def test_path_type(self):
        gmxp_res = self.do_command(self.get_password_args() + ['-t', self.type, '-d', self.path, 'getmasterxpub'])
        self.assertEqual(gmxp_res['xpub'], self.master_xpub)

    def test_fingerprint_autodetect(self):
        gmxp_res = self.do_command(self.get_password_args() + ['-f', self.fingerprint, 'getmasterxpub'])
        self.assertEqual(gmxp_res['xpub'], self.master_xpub)

        # Nonexistent fingerprint
        gmxp_res = self.do_command(self.get_password_args() + ['-f', '0000ffff', 'getmasterxpub'])
        self.assertEqual(gmxp_res['error'], 'Could not find device with specified fingerprint')
        self.assertEqual(gmxp_res['code'], -3)

    def test_type_only_autodetect(self):
        gmxp_res = self.do_command(self.get_password_args() + ['-t', self.type, 'getmasterxpub'])
        self.assertEqual(gmxp_res['xpub'], self.master_xpub)

        # Unknown device type
        gmxp_res = self.do_command(['-t', 'fakedev', '-d', 'fakepath', 'getmasterxpub'])
        self.assertEqual(gmxp_res['error'], 'Unknown device type specified')
        self.assertEqual(gmxp_res['code'], -4)

class TestGetKeypool(DeviceTestCase):
    def setUp(self):
        self.rpc = AuthServiceProxy('http://{}@127.0.0.1:18443'.format(self.rpc_userpass))
        if '{}_test'.format(self.full_type) not in self.rpc.listwallets():
            self.rpc.createwallet('{}_test'.format(self.full_type), True)
        self.wrpc = AuthServiceProxy('http://{}@127.0.0.1:18443/wallet/{}_test'.format(self.rpc_userpass, self.full_type))
        self.wpk_rpc = AuthServiceProxy('http://{}@127.0.0.1:18443/wallet/'.format(self.rpc_userpass))
        if '--testnet' not in self.dev_args:
            self.dev_args.append('--testnet')
        self.emulator.start()

    def test_getkeypool(self):
        non_keypool_desc = self.do_command(self.dev_args + ['getkeypool', '--nokeypool', '0', '20'])
        import_result = self.wpk_rpc.importmulti(non_keypool_desc)
        self.assertTrue(import_result[0]['success'])

        pkh_keypool_desc = self.do_command(self.dev_args + ['getkeypool', '0', '20'])
        import_result = self.wpk_rpc.importmulti(pkh_keypool_desc)
        self.assertFalse(import_result[0]['success'])

        import_result = self.wrpc.importmulti(pkh_keypool_desc)
        self.assertTrue(import_result[0]['success'])
        for i in range(0, 21):
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getnewaddress())
            self.assertEqual(addr_info['hdkeypath'], "m/44'/1'/0'/0/{}".format(i))
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getrawchangeaddress())
            self.assertEqual(addr_info['hdkeypath'], "m/44'/1'/0'/1/{}".format(i))

        shwpkh_keypool_desc = self.do_command(self.dev_args + ['getkeypool', '--sh_wpkh', '0', '20'])
        import_result = self.wrpc.importmulti(shwpkh_keypool_desc)
        self.assertTrue(import_result[0]['success'])
        for i in range(0, 21):
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getnewaddress('', 'p2sh-segwit'))
            self.assertEqual(addr_info['hdkeypath'], "m/49'/1'/0'/0/{}".format(i))
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getrawchangeaddress('p2sh-segwit'))
            self.assertEqual(addr_info['hdkeypath'], "m/49'/1'/0'/1/{}".format(i))

        wpkh_keypool_desc = self.do_command(self.dev_args + ['getkeypool', '--wpkh', '0', '20'])
        import_result = self.wrpc.importmulti(wpkh_keypool_desc)
        self.assertTrue(import_result[0]['success'])
        for i in range(0, 21):
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getnewaddress())
            self.assertEqual(addr_info['hdkeypath'], "m/84'/1'/0'/0/{}".format(i))
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getrawchangeaddress())
            self.assertEqual(addr_info['hdkeypath'], "m/84'/1'/0'/1/{}".format(i))

        # Test that `--all` option gives the "concatenation" of previous three calls
        all_keypool_desc = self.do_command(self.dev_args + ['getkeypool', '--all', '0', '20'])
        self.assertEqual(all_keypool_desc, pkh_keypool_desc + wpkh_keypool_desc + shwpkh_keypool_desc)

        keypool_desc = self.do_command(self.dev_args + ['getkeypool', '--sh_wpkh', '--account', '3', '0', '20'])
        import_result = self.wrpc.importmulti(keypool_desc)
        self.assertTrue(import_result[0]['success'])
        for i in range(0, 21):
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getnewaddress('', 'p2sh-segwit'))
            self.assertEqual(addr_info['hdkeypath'], "m/49'/1'/3'/0/{}".format(i))
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getrawchangeaddress('p2sh-segwit'))
            self.assertEqual(addr_info['hdkeypath'], "m/49'/1'/3'/1/{}".format(i))
        keypool_desc = self.do_command(self.dev_args + ['getkeypool', '--wpkh', '--account', '3', '0', '20'])
        import_result = self.wrpc.importmulti(keypool_desc)
        self.assertTrue(import_result[0]['success'])
        for i in range(0, 21):
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getnewaddress())
            self.assertEqual(addr_info['hdkeypath'], "m/84'/1'/3'/0/{}".format(i))
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getrawchangeaddress())
            self.assertEqual(addr_info['hdkeypath'], "m/84'/1'/3'/1/{}".format(i))

        keypool_desc = self.do_command(self.dev_args + ['getkeypool', '--path', 'm/0h/0h/4h/*', '0', '20'])
        import_result = self.wrpc.importmulti(keypool_desc)
        self.assertTrue(import_result[0]['success'])
        for i in range(0, 21):
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getnewaddress())
            self.assertEqual(addr_info['hdkeypath'], "m/0'/0'/4'/{}".format(i))

        keypool_desc = self.do_command(self.dev_args + ['getkeypool', '--path', '/0h/0h/4h/*', '0', '20'])
        self.assertEqual(keypool_desc['error'], 'Path must start with m/')
        self.assertEqual(keypool_desc['code'], -7)
        keypool_desc = self.do_command(self.dev_args + ['getkeypool', '--path', 'm/0h/0h/4h/', '0', '20'])
        self.assertEqual(keypool_desc['error'], 'Path must end with /*')
        self.assertEqual(keypool_desc['code'], -7)

class TestGetDescriptors(DeviceTestCase):
    def setUp(self):
        self.rpc = AuthServiceProxy('http://{}@127.0.0.1:18443'.format(self.rpc_userpass))
        if '--testnet' not in self.dev_args:
            self.dev_args.append('--testnet')
        self.emulator.start()

    def tearDown(self):
        self.emulator.stop()

    def test_getdescriptors(self):
        descriptors = self.do_command(self.dev_args + ['getdescriptors'])

        self.assertIn('receive', descriptors)
        self.assertIn('internal', descriptors)
        self.assertEqual(len(descriptors['receive']), 3)
        self.assertEqual(len(descriptors['internal']), 3)

        for descriptor in descriptors['receive']:
            info_result = self.rpc.getdescriptorinfo(descriptor)
            self.assertTrue(info_result['isrange'])
            self.assertTrue(info_result['issolvable'])

        for descriptor in descriptors['internal']:
            info_result = self.rpc.getdescriptorinfo(descriptor)
            self.assertTrue(info_result['isrange'])
            self.assertTrue(info_result['issolvable'])

class TestSignTx(DeviceTestCase):
    def setUp(self):
        self.rpc = AuthServiceProxy('http://{}@127.0.0.1:18443'.format(self.rpc_userpass))
        if '{}_test'.format(self.full_type) not in self.rpc.listwallets():
            self.rpc.createwallet('{}_test'.format(self.full_type), True)
        self.wrpc = AuthServiceProxy('http://{}@127.0.0.1:18443/wallet/{}_test'.format(self.rpc_userpass, self.full_type))
        self.wpk_rpc = AuthServiceProxy('http://{}@127.0.0.1:18443/wallet/'.format(self.rpc_userpass))
        if '--testnet' not in self.dev_args:
            self.dev_args.append('--testnet')
        self.emulator.start()

    def _generate_and_finalize(self, unknown_inputs, psbt):
        if not unknown_inputs:
            # Just do the normal signing process to test "all inputs" case
            sign_res = self.do_command(self.dev_args + ['signtx', psbt['psbt']])
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
                    psbt_input.hd_keypaths[pubkey] = (0,) + path[1:]
            for pubkey, path in second_psbt.inputs[0].hd_keypaths.items():
                second_psbt.inputs[0].hd_keypaths[pubkey] = (0,) + path[1:]

            single_input = len(first_psbt.inputs) == 1

            # Process the psbts
            first_psbt = first_psbt.serialize()
            second_psbt = second_psbt.serialize()

            # First will always have something to sign
            first_sign_res = self.do_command(self.dev_args + ['signtx', first_psbt])
            self.assertTrue(single_input == self.wrpc.finalizepsbt(first_sign_res['psbt'])['complete'])
            # Second may have nothing to sign (1 input case)
            # and also may throw an error(e.g., ColdCard)
            second_sign_res = self.do_command(self.dev_args + ['signtx', second_psbt])
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

    def _test_signtx(self, input_type, multisig, external):
        # Import some keys to the watch only wallet and send coins to them
        keypool_desc = self.do_command(self.dev_args + ['getkeypool', '--sh_wpkh', '30', '40'])
        import_result = self.wrpc.importmulti(keypool_desc)
        self.assertTrue(import_result[0]['success'])
        keypool_desc = self.do_command(self.dev_args + ['getkeypool', '--sh_wpkh', '--internal', '30', '40'])
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
        pubkeys = [sh_wpkh_info['desc'][8:-11],
                   wpkh_info['desc'][5:-10],
                   pkh_info['desc'][4:-10]]

        # Get the descriptors with their checksums
        sh_multi_desc = self.wrpc.getdescriptorinfo('sh(sortedmulti(2,' + pubkeys[0] + ',' + pubkeys[1] + ',' + pubkeys[2] + '))')['descriptor']
        sh_wsh_multi_desc = self.wrpc.getdescriptorinfo('sh(wsh(sortedmulti(2,' + pubkeys[0] + ',' + pubkeys[1] + ',' + pubkeys[2] + ')))')['descriptor']
        wsh_multi_desc = self.wrpc.getdescriptorinfo('wsh(sortedmulti(2,' + pubkeys[2] + ',' + pubkeys[1] + ',' + pubkeys[0] + '))')['descriptor']

        sh_multi_import = {'desc': sh_multi_desc, "timestamp": "now", "label": "shmulti"}
        sh_wsh_multi_import = {'desc': sh_wsh_multi_desc, "timestamp": "now", "label": "shwshmulti"}
        # re-order pubkeys to allow import without "already have private keys" error
        wsh_multi_import = {'desc': wsh_multi_desc, "timestamp": "now", "label": "wshmulti"}
        multi_result = self.wrpc.importmulti([sh_multi_import, sh_wsh_multi_import, wsh_multi_import])
        self.assertTrue(multi_result[0]['success'])
        self.assertTrue(multi_result[1]['success'])
        self.assertTrue(multi_result[2]['success'])

        sh_multi_addr = self.wrpc.getaddressesbylabel("shmulti").popitem()[0]
        sh_wsh_multi_addr = self.wrpc.getaddressesbylabel("shwshmulti").popitem()[0]
        wsh_multi_addr = self.wrpc.getaddressesbylabel("wshmulti").popitem()[0]

        in_amt = 3
        out_amt = in_amt // 3
        number_inputs = 0
        # Single-sig
        if input_type == 'segwit' or input_type == 'all':
            self.wpk_rpc.sendtoaddress(sh_wpkh_addr, in_amt)
            self.wpk_rpc.sendtoaddress(wpkh_addr, in_amt)
            number_inputs += 2
        if input_type == 'legacy' or input_type == 'all':
            self.wpk_rpc.sendtoaddress(pkh_addr, in_amt)
            number_inputs += 1
        # Now do segwit/legacy multisig
        if multisig:
            if input_type == 'legacy' or input_type == 'all':
                self.wpk_rpc.sendtoaddress(sh_multi_addr, in_amt)
                number_inputs += 1
            if input_type == 'segwit' or input_type == 'all':
                self.wpk_rpc.sendtoaddress(wsh_multi_addr, in_amt)
                self.wpk_rpc.sendtoaddress(sh_wsh_multi_addr, in_amt)
                number_inputs += 2

        self.wpk_rpc.generatetoaddress(6, self.wpk_rpc.getnewaddress())

        # Spend different amounts, requiring 1 to 3 inputs
        for i in range(number_inputs):
            # Create a psbt spending the above
            if i == number_inputs - 1:
                self.assertTrue((i + 1) * in_amt == self.wrpc.getbalance("*", 0, True))
            psbt = self.wrpc.walletcreatefundedpsbt([], [{self.wpk_rpc.getnewaddress('', 'legacy'): (i + 1) * out_amt}, {self.wpk_rpc.getnewaddress('', 'p2sh-segwit'): (i + 1) * out_amt}, {self.wpk_rpc.getnewaddress('', 'bech32'): (i + 1) * out_amt}], 0, {'includeWatching': True, 'subtractFeeFromOutputs': [0, 1, 2]}, True)

            if external:
                # Sign with unknown inputs in two steps
                self._generate_and_finalize(True, psbt)
            # Sign all inputs all at once
            final_tx = self._generate_and_finalize(False, psbt)

        # Send off final tx to sweep the wallet
        self.wrpc.sendrawtransaction(final_tx)

    # Test wrapper to avoid mixed-inputs signing for Ledger
    def test_signtx(self):
        supports_mixed = {'coldcard', 'trezor_1', 'digitalbitbox', 'keepkey'}
        supports_multisig = {'ledger', 'trezor_1', 'digitalbitbox', 'keepkey', 'coldcard', 'trezor_t'}
        supports_external = {'ledger', 'trezor_1', 'digitalbitbox', 'keepkey', 'coldcard'}
        if self.full_type not in supports_mixed:
            self._test_signtx("legacy", self.full_type in supports_multisig, self.full_type in supports_external)
            self._test_signtx("segwit", self.full_type in supports_multisig, self.full_type in supports_external)
        else:
            self._test_signtx("all", self.full_type in supports_multisig, self.full_type in supports_external)

    # Make a huge transaction which might cause some problems with different interfaces
    def test_big_tx(self):
        # make a huge transaction that is unrelated to the hardware wallet
        outputs = []
        num_inputs = 60
        for i in range(0, num_inputs):
            outputs.append({self.wpk_rpc.getnewaddress('', 'legacy'): 0.001})
        psbt = self.wpk_rpc.walletcreatefundedpsbt([], outputs, 0, {}, True)['psbt']
        psbt = self.wpk_rpc.walletprocesspsbt(psbt)['psbt']
        tx = self.wpk_rpc.finalizepsbt(psbt)['hex']
        txid = self.wpk_rpc.sendrawtransaction(tx)
        inputs = []
        for i in range(0, num_inputs):
            inputs.append({'txid': txid, 'vout': i})
        psbt = self.wpk_rpc.walletcreatefundedpsbt(inputs, [{self.wpk_rpc.getnewaddress('', 'legacy'): 0.001 * num_inputs}], 0, {'subtractFeeFromOutputs': [0]}, True)['psbt']
        # For cli, this should throw an exception
        try:
            result = self.do_command(self.dev_args + ['signtx', psbt])
            if self.interface == 'cli':
                self.fail('Big tx did not cause CLI to error')
            if self.type == 'coldcard':
                self.assertEqual(result['code'], -7)
            else:
                self.assertNotIn('code', result)
                self.assertNotIn('error', result)
        except OSError:
            if self.interface == 'cli':
                pass

class TestDisplayAddress(DeviceTestCase):
    def setUp(self):
        if '--testnet' not in self.dev_args:
            self.dev_args.append('--testnet')
        self.emulator.start()

    def test_display_address_bad_args(self):
        result = self.do_command(self.dev_args + ['displayaddress', '--sh_wpkh', '--wpkh', '--path', 'm/49h/1h/0h/0/0'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['code'], -7)

    def test_display_address_path(self):
        result = self.do_command(self.dev_args + ['displayaddress', '--path', 'm/44h/1h/0h/0/0'])
        self.assertNotIn('error', result)
        self.assertNotIn('code', result)
        self.assertIn('address', result)

        result = self.do_command(self.dev_args + ['displayaddress', '--sh_wpkh', '--path', 'm/49h/1h/0h/0/0'])
        self.assertNotIn('error', result)
        self.assertNotIn('code', result)
        self.assertIn('address', result)

        result = self.do_command(self.dev_args + ['displayaddress', '--wpkh', '--path', 'm/84h/1h/0h/0/0'])
        self.assertNotIn('error', result)
        self.assertNotIn('code', result)
        self.assertIn('address', result)

    def test_display_address_bad_path(self):
        result = self.do_command(self.dev_args + ['displayaddress', '--path', 'f'])
        self.assertEquals(result['code'], -7)

    def test_display_address_descriptor(self):
        account_xpub = self.do_command(self.dev_args + ['getxpub', 'm/84h/1h/0h'])['xpub']
        p2sh_segwit_account_xpub = self.do_command(self.dev_args + ['getxpub', 'm/49h/1h/0h'])['xpub']
        legacy_account_xpub = self.do_command(self.dev_args + ['getxpub', 'm/44h/1h/0h'])['xpub']

        # Native SegWit address using xpub:
        result = self.do_command(self.dev_args + ['displayaddress', '--desc', 'wpkh([' + self.fingerprint + '/84h/1h/0h]' + account_xpub + '/0/0)'])
        self.assertNotIn('error', result)
        self.assertNotIn('code', result)
        self.assertIn('address', result)

        # Native SegWit address using hex encoded pubkey:
        result = self.do_command(self.dev_args + ['displayaddress', '--desc', 'wpkh([' + self.fingerprint + '/84h/1h/0h]' + xpub_to_pub_hex(account_xpub) + '/0/0)'])
        self.assertNotIn('error', result)
        self.assertNotIn('code', result)
        self.assertIn('address', result)

        # P2SH wrapped SegWit address using xpub:
        result = self.do_command(self.dev_args + ['displayaddress', '--desc', 'sh(wpkh([' + self.fingerprint + '/49h/1h/0h]' + p2sh_segwit_account_xpub + '/0/0))'])
        self.assertNotIn('error', result)
        self.assertNotIn('code', result)
        self.assertIn('address', result)

        # Legacy address
        result = self.do_command(self.dev_args + ['displayaddress', '--desc', 'pkh([' + self.fingerprint + '/44h/1h/0h]' + legacy_account_xpub + '/0/0)'])
        self.assertNotIn('error', result)
        self.assertNotIn('code', result)
        self.assertIn('address', result)

        # Should check xpub
        result = self.do_command(self.dev_args + ['displayaddress', '--desc', 'wpkh([' + self.fingerprint + '/84h/1h/0h]' + "not_and_xpub" + '/0/0)'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['code'], -7)

        # Should check hex pub
        result = self.do_command(self.dev_args + ['displayaddress', '--desc', 'wpkh([' + self.fingerprint + '/84h/1h/0h]' + "not_and_xpub" + '/0/0)'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['code'], -7)

        # Should check fingerprint
        self.do_command(self.dev_args + ['displayaddress', '--desc', 'wpkh([00000000/84h/1h/0h]' + account_xpub + '/0/0)'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['code'], -7)

class TestSignMessage(DeviceTestCase):
    def test_sign_msg(self):
        self.do_command(self.dev_args + ['signmessage', '"Message signing test"', 'm/44h/1h/0h/0/0'])

    def test_bad_path(self):
        result = self.do_command(self.dev_args + ['signmessage', '"Message signing test"', 'f'])
        self.assertEquals(result['code'], -7)
