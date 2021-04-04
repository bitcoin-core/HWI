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
from hwilib._base58 import xpub_to_pub_hex, to_address, decode
from hwilib._cli import process_commands
from hwilib.descriptor import AddChecksum
from hwilib.key import KeyOriginInfo
from hwilib.psbt import PSBT

SUPPORTS_MS_DISPLAY = {'trezor_1', 'keepkey', 'coldcard', 'trezor_t'}
SUPPORTS_XPUB_MS_DISPLAY = {'trezor_1', 'trezor_t'}
SUPPORTS_UNSORTED_MS = {"trezor_1", "trezor_t"}
SUPPORTS_MIXED = {'coldcard', 'trezor_1', 'digitalbitbox', 'keepkey', 'trezor_t'}
SUPPORTS_MULTISIG = {'ledger', 'trezor_1', 'digitalbitbox', 'keepkey', 'coldcard', 'trezor_t'}
SUPPORTS_EXTERNAL = {'ledger', 'trezor_1', 'digitalbitbox', 'keepkey', 'coldcard', 'trezor_t'}
SUPPORTS_OP_RETURN = {'ledger', 'digitalbitbox', 'trezor_1', 'trezor_t', 'keepkey'}

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
    rpc.createwallet(wallet_name="supply")
    wrpc = AuthServiceProxy('http://{}@127.0.0.1:18443/wallet/supply'.format(userpass))
    wrpc.generatetoaddress(101, wrpc.getnewaddress())
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
        self.dev_args = ['-t', self.type, '-d', self.path, '--chain', 'test']
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
            args = [f'"{arg}"' for arg in args]
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

    def setup_wallets(self):
        wallet_name = '{}_{}_test'.format(self.full_type, self.id())
        self.rpc.createwallet(wallet_name=wallet_name, disable_private_keys=True, descriptors=True)
        self.wrpc = AuthServiceProxy('http://{}@127.0.0.1:18443/wallet/{}'.format(self.rpc_userpass, wallet_name))
        self.wpk_rpc = AuthServiceProxy('http://{}@127.0.0.1:18443/wallet/supply'.format(self.rpc_userpass))

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
        gmxp_res = self.do_command(['getmasterxpub', "--addr-type", "legacy"])
        self.assertIn('error', gmxp_res)
        self.assertEqual(gmxp_res['error'], 'You must specify a device type or fingerprint for all commands except enumerate')
        self.assertIn('code', gmxp_res)
        self.assertEqual(gmxp_res['code'], -1)

    def test_path_type(self):
        gmxp_res = self.do_command(self.get_password_args() + ['-t', self.type, '-d', self.path, 'getmasterxpub', "--addr-type", "legacy"])
        self.assertEqual(gmxp_res['xpub'], self.master_xpub)

    def test_fingerprint_autodetect(self):
        gmxp_res = self.do_command(self.get_password_args() + ['-f', self.fingerprint, 'getmasterxpub', "--addr-type", "legacy"])
        self.assertEqual(gmxp_res['xpub'], self.master_xpub)

        # Nonexistent fingerprint
        gmxp_res = self.do_command(self.get_password_args() + ['-f', '0000ffff', 'getmasterxpub', "--addr-type", "legacy"])
        self.assertEqual(gmxp_res['error'], 'Could not find device with specified fingerprint')
        self.assertEqual(gmxp_res['code'], -3)

    def test_type_only_autodetect(self):
        gmxp_res = self.do_command(self.get_password_args() + ['-t', self.type, 'getmasterxpub', "--addr-type", "legacy"])
        self.assertEqual(gmxp_res['xpub'], self.master_xpub)

        # Unknown device type
        gmxp_res = self.do_command(['-t', 'fakedev', '-d', 'fakepath', 'getmasterxpub', "--addr-type", "legacy"])
        self.assertEqual(gmxp_res['error'], 'Unknown device type specified')
        self.assertEqual(gmxp_res['code'], -4)

class TestGetKeypool(DeviceTestCase):
    def setUp(self):
        super().setUp()
        self.setup_wallets()

    def test_getkeypool(self):
        pkh_keypool_desc = self.do_command(self.dev_args + ['getkeypool', "--addr-type", "legacy", '0', '20'])
        import_result = self.wrpc.importdescriptors(pkh_keypool_desc)
        self.assertTrue(import_result[0]['success'])
        for _ in range(0, 21):
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getnewaddress('', 'legacy'))
            self.assertTrue(addr_info['hdkeypath'].startswith("m/44'/1'/0'/0/"))
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getrawchangeaddress('legacy'))
            self.assertTrue(addr_info['hdkeypath'].startswith("m/44'/1'/0'/1/"))

        shwpkh_keypool_desc = self.do_command(self.dev_args + ['getkeypool', "--addr-type", "sh_wit", '0', '20'])
        import_result = self.wrpc.importdescriptors(shwpkh_keypool_desc)
        self.assertTrue(import_result[0]['success'])
        for _ in range(0, 21):
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getnewaddress('', 'p2sh-segwit'))
            self.assertTrue(addr_info['hdkeypath'].startswith("m/49'/1'/0'/0/"))
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getrawchangeaddress('p2sh-segwit'))
            self.assertTrue(addr_info['hdkeypath'].startswith("m/49'/1'/0'/1/"))

        wpkh_keypool_desc = self.do_command(self.dev_args + ['getkeypool', '0', '20'])
        import_result = self.wrpc.importdescriptors(wpkh_keypool_desc)
        self.assertTrue(import_result[0]['success'])
        for _ in range(0, 21):
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getnewaddress('', 'bech32'))
            self.assertTrue(addr_info['hdkeypath'].startswith("m/84'/1'/0'/0/"))
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getrawchangeaddress('bech32'))
            self.assertTrue(addr_info['hdkeypath'].startswith("m/84'/1'/0'/1/"))

        # Test that `--all` option gives the "concatenation" of previous three calls
        all_keypool_desc = self.do_command(self.dev_args + ['getkeypool', '--all', '0', '20'])
        self.assertEqual(all_keypool_desc, pkh_keypool_desc + wpkh_keypool_desc + shwpkh_keypool_desc)

        keypool_desc = self.do_command(self.dev_args + ['getkeypool', "--addr-type", "sh_wit", '--account', '3', '0', '20'])
        import_result = self.wrpc.importdescriptors(keypool_desc)
        self.assertTrue(import_result[0]['success'])
        for _ in range(0, 21):
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getnewaddress('', 'p2sh-segwit'))
            self.assertTrue(addr_info['hdkeypath'].startswith("m/49'/1'/3'/0/"))
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getrawchangeaddress('p2sh-segwit'))
            self.assertTrue(addr_info['hdkeypath'].startswith("m/49'/1'/3'/1/"))
        keypool_desc = self.do_command(self.dev_args + ['getkeypool', '--account', '3', '0', '20'])
        import_result = self.wrpc.importdescriptors(keypool_desc)
        self.assertTrue(import_result[0]['success'])
        for _ in range(0, 21):
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getnewaddress('', 'bech32'))
            self.assertTrue(addr_info['hdkeypath'].startswith("m/84'/1'/3'/0/"))
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getrawchangeaddress('bech32'))
            self.assertTrue(addr_info['hdkeypath'].startswith("m/84'/1'/3'/1/"))

        keypool_desc = self.do_command(self.dev_args + ['getkeypool', '--path', 'm/0h/0h/4h/*', '0', '20'])
        import_result = self.wrpc.importdescriptors(keypool_desc)
        self.assertTrue(import_result[0]['success'])
        for _ in range(0, 21):
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getnewaddress('', 'bech32'))
            self.assertTrue(addr_info['hdkeypath'].startswith("m/0'/0'/4'/"))

        keypool_desc = self.do_command(self.dev_args + ['getkeypool', '--path', '/0h/0h/4h/*', '0', '20'])
        self.assertEqual(keypool_desc['error'], 'Path must start with m/')
        self.assertEqual(keypool_desc['code'], -7)
        keypool_desc = self.do_command(self.dev_args + ['getkeypool', '--path', 'm/0h/0h/4h/', '0', '20'])
        self.assertEqual(keypool_desc['error'], 'Path must end with /*')
        self.assertEqual(keypool_desc['code'], -7)

class TestGetDescriptors(DeviceTestCase):
    def tearDown(self):
        self.emulator.stop()

    def test_getdescriptors(self):
        descriptors = self.do_command(self.dev_args + ['getdescriptors'])

        self.assertIn('receive', descriptors)
        self.assertIn('internal', descriptors)
        self.assertEqual(len(descriptors['receive']), 3)
        self.assertEqual(len(descriptors['internal']), 3)

        for descriptor in descriptors['receive']:
            self.assertNotIn("'", descriptor)
            info_result = self.rpc.getdescriptorinfo(descriptor)
            self.assertTrue(info_result['isrange'])
            self.assertTrue(info_result['issolvable'])

        for descriptor in descriptors['internal']:
            self.assertNotIn("'", descriptor)
            info_result = self.rpc.getdescriptorinfo(descriptor)
            self.assertTrue(info_result['isrange'])
            self.assertTrue(info_result['issolvable'])

class TestSignTx(DeviceTestCase):
    def setUp(self):
        super().setUp()
        self.setup_wallets()

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
                    psbt_input.hd_keypaths[pubkey] = KeyOriginInfo(b"\x00\x00\x00\x00", path.path)
            for pubkey, path in second_psbt.inputs[0].hd_keypaths.items():
                second_psbt.inputs[0].hd_keypaths[pubkey] = KeyOriginInfo(b"\x00\x00\x00\x00", path.path)

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

    def _make_multisigs(self):
        def get_pubkeys(t):
            desc_pubkeys = []
            sorted_pubkeys = []
            for i in range(0, 3):
                path = "/48h/1h/{}h/{}h/0/0".format(i, t)
                origin = '{}{}'.format(self.fingerprint, path)
                xpub = self.do_command(self.dev_args + ["--expert", "getxpub", "m{}".format(path)])
                desc_pubkeys.append("[{}]{}".format(origin, xpub["pubkey"]))
                sorted_pubkeys.append(xpub["pubkey"])
            sorted_pubkeys.sort()
            return desc_pubkeys, sorted_pubkeys

        desc_pubkeys, sorted_pubkeys = get_pubkeys(0)
        sh_desc = AddChecksum("sh(sortedmulti(2,{},{},{}))".format(desc_pubkeys[0], desc_pubkeys[1], desc_pubkeys[2]))
        sh_ms_info = self.rpc.createmultisig(2, sorted_pubkeys, "legacy")
        self.assertEqual(self.rpc.deriveaddresses(sh_desc)[0], sh_ms_info["address"])

        # Trezor requires that each address type uses a different derivation path.
        # Other devices don't have this requirement, and in the tests involving multiple address types, Coldcard will fail.
        # So for those other devices, stick to the 0 path.
        desc_pubkeys, sorted_pubkeys = get_pubkeys(1) if self.full_type == "trezor_t" else get_pubkeys(0)
        sh_wsh_desc = AddChecksum("sh(wsh(sortedmulti(2,{},{},{})))".format(desc_pubkeys[1], desc_pubkeys[2], desc_pubkeys[0]))
        sh_wsh_ms_info = self.rpc.createmultisig(2, sorted_pubkeys, "p2sh-segwit")
        self.assertEqual(self.rpc.deriveaddresses(sh_wsh_desc)[0], sh_wsh_ms_info["address"])

        desc_pubkeys, sorted_pubkeys = get_pubkeys(2) if self.full_type == "trezor_t" else get_pubkeys(0)
        wsh_desc = AddChecksum("wsh(sortedmulti(2,{},{},{}))".format(desc_pubkeys[2], desc_pubkeys[1], desc_pubkeys[0]))
        wsh_ms_info = self.rpc.createmultisig(2, sorted_pubkeys, "bech32")
        self.assertEqual(self.rpc.deriveaddresses(wsh_desc)[0], wsh_ms_info["address"])

        return sh_desc, sh_ms_info["address"], sh_wsh_desc, sh_wsh_ms_info["address"], wsh_desc, wsh_ms_info["address"]

    def _test_signtx(self, input_type, multisig, external, op_return: bool):
        # Import some keys to the watch only wallet and send coins to them
        keypool_desc = self.do_command(self.dev_args + ['getkeypool', '--all', '30', '50'])
        import_result = self.wrpc.importdescriptors(keypool_desc)
        self.assertTrue(import_result[0]['success'])
        sh_wpkh_addr = self.wrpc.getnewaddress('', 'p2sh-segwit')
        wpkh_addr = self.wrpc.getnewaddress('', 'bech32')
        pkh_addr = self.wrpc.getnewaddress('', 'legacy')

        sh_multi_desc, sh_multi_addr, sh_wsh_multi_desc, sh_wsh_multi_addr, wsh_multi_desc, wsh_multi_addr = self._make_multisigs()

        sh_multi_import = {'desc': sh_multi_desc, "timestamp": "now", "label": "shmulti"}
        sh_wsh_multi_import = {'desc': sh_wsh_multi_desc, "timestamp": "now", "label": "shwshmulti"}
        wsh_multi_import = {'desc': wsh_multi_desc, "timestamp": "now", "label": "wshmulti"}
        multi_result = self.wrpc.importdescriptors([sh_multi_import, sh_wsh_multi_import, wsh_multi_import])
        self.assertTrue(multi_result[0]['success'])
        self.assertTrue(multi_result[1]['success'])
        self.assertTrue(multi_result[2]['success'])

        in_amt = 3
        out_amt = in_amt // 3 * 0.9
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
            change_addr = self.wrpc.getrawchangeaddress()
            if i == number_inputs - 1:
                self.assertEqual((i + 1) * in_amt, self.wrpc.getbalance("*", 0, True))
                change_addr = self.wpk_rpc.getrawchangeaddress()
            out_val = (i + 1) * out_amt
            outputs = [
                {self.wpk_rpc.getnewaddress('', 'legacy'): out_val},
                {self.wpk_rpc.getnewaddress('', 'p2sh-segwit'): out_val},
                {self.wpk_rpc.getnewaddress('', 'bech32'): out_val}
            ]
            if op_return:
                outputs.append({"data": "000102030405060708090a0b0c0d0e0f10111213141516171819101a1b1c1d1e1f"})
            psbt = self.wrpc.walletcreatefundedpsbt([], outputs, 0, {'includeWatching': True, "changePosition": 3, "changeAddress": change_addr}, True)

            if external:
                # Sign with unknown inputs in two steps
                self._generate_and_finalize(True, psbt)
            # Sign all inputs all at once
            final_tx = self._generate_and_finalize(False, psbt)

        # Send off final tx to sweep the wallet
        self.wrpc.sendrawtransaction(final_tx)

    # Test wrapper to avoid mixed-inputs signing for Ledger
    def test_signtx(self):
        multisig = self.full_type in SUPPORTS_MULTISIG
        external = self.full_type in SUPPORTS_EXTERNAL
        op_return = self.full_type in SUPPORTS_OP_RETURN
        with self.subTest(addrtype="legacy", multisig=multisig, external=external):
            self._test_signtx("legacy", multisig, external, op_return)
        with self.subTest(addrtype="segwit", multisig=multisig, external=external):
            self._test_signtx("segwit", multisig, external, op_return)
        if self.full_type in SUPPORTS_MIXED:
            with self.subTest(addrtype="all", multisig=multisig, external=external):
                self._test_signtx("all", multisig, external, op_return)

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
    def test_display_address_path(self):
        result = self.do_command(self.dev_args + ['displayaddress', "--addr-type", "legacy", '--path', 'm/44h/1h/0h/0/0'])
        self.assertNotIn('error', result)
        self.assertNotIn('code', result)
        self.assertIn('address', result)

        result = self.do_command(self.dev_args + ['displayaddress', "--addr-type", "sh_wit", '--path', 'm/49h/1h/0h/0/0'])
        self.assertNotIn('error', result)
        self.assertNotIn('code', result)
        self.assertIn('address', result)

        result = self.do_command(self.dev_args + ['displayaddress', "--addr-type", "wit", '--path', 'm/84h/1h/0h/0/0'])
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

    def _make_single_multisig(self, addrtype, sort, use_xpub):
        desc_pubkeys = []
        for i in range(0, 3):
            path = "/48h/1h/{}h/0h/0".format(i)
            if not use_xpub:
                path += "/0"
            origin = '{}{}'.format(self.fingerprint, path)
            xpub = self.do_command(self.dev_args + ["--expert", "getxpub", "m{}".format(path)])
            desc_pubkeys.append("[{}]{}{}".format(origin, xpub["xpub"] if use_xpub else xpub["pubkey"], "/0" if use_xpub else ""))

        desc_func = "sortedmulti" if sort else "multi"

        if addrtype == "pkh":
            desc = AddChecksum("sh({}(2,{},{},{}))".format(desc_func, desc_pubkeys[0], desc_pubkeys[1], desc_pubkeys[2]))
            addr = self.rpc.deriveaddresses(desc)[0]
        elif addrtype == "sh_wpkh":
            desc = AddChecksum("sh(wsh({}(2,{},{},{})))".format(desc_func, desc_pubkeys[1], desc_pubkeys[2], desc_pubkeys[0]))
            addr = self.rpc.deriveaddresses(desc)[0]
        elif addrtype == "wpkh":
            desc = AddChecksum("wsh({}(2,{},{},{}))".format(desc_func, desc_pubkeys[2], desc_pubkeys[1], desc_pubkeys[0]))
            addr = self.rpc.deriveaddresses(desc)[0]
        else:
            self.fail("Oops the test is broken")

        return addr, desc

    def test_display_address_multisig(self):
        if self.full_type not in SUPPORTS_MS_DISPLAY and self.full_type not in SUPPORTS_XPUB_MS_DISPLAY:
            raise unittest.SkipTest("{} does not support multisig display".format(self.full_type))

        for addrtype in ["pkh", "sh_wpkh", "wpkh"]:
            for sort in [True, False]:
                for derive in [True, False]:
                    with self.subTest(addrtype=addrtype):
                        if not sort and self.full_type not in SUPPORTS_UNSORTED_MS:
                            raise unittest.SkipTest("{} does not support unsorted multisigs".format(self.full_type))
                        if derive and self.full_type not in SUPPORTS_XPUB_MS_DISPLAY:
                            raise unittest.SkipTest("{} does not support multisig display with xpubs".format(self.full_type))

                        addr, desc = self._make_single_multisig(addrtype, sort, derive)

                        args = ['displayaddress', '--desc', desc]

                        result = self.do_command(self.dev_args + args)
                        self.assertNotIn('error', result)
                        self.assertNotIn('code', result)
                        self.assertIn('address', result)

                        if addrtype == "wpkh":
                            # removes prefix and checksum since regtest gives
                            # prefix `bcrt` on Bitcoin Core while wallets return testnet `tb` prefix
                            self.assertEqual(addr[4:58], result['address'][2:56])
                        else:
                            self.assertEqual(addr, result['address'])

class TestSignMessage(DeviceTestCase):
    def _check_sign_msg(self, msg):
        addr_path = "m/44h/1h/0h/0/0"
        sign_res = self.do_command(self.dev_args + ['signmessage', msg, addr_path])
        self.assertNotIn("error", sign_res)
        self.assertNotIn("code", sign_res)
        self.assertIn("signature", sign_res)
        sig = sign_res["signature"]

        addr = self.do_command(self.dev_args + ['displayaddress', "--addr-type", "legacy", '--path', addr_path])["address"]
        addr = to_address(decode(addr)[1:-4], b"\x6F")

        self.assertTrue(self.rpc.verifymessage(addr, sig, msg))

    def test_sign_msg(self):
        self._check_sign_msg("Message signing test")
        self._check_sign_msg("285") # Specific test case for Ledger shorter S

    def test_bad_path(self):
        result = self.do_command(self.dev_args + ['signmessage', "Message signing test", 'f'])
        self.assertEquals(result['code'], -7)
