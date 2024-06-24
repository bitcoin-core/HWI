#! /usr/bin/env python3

import atexit
import json
import os
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
import unittest

from typing import Dict

from authproxy import AuthServiceProxy, JSONRPCException
from hwilib._base58 import xpub_to_pub_hex, to_address, decode
from hwilib._cli import process_commands
from hwilib.descriptor import AddChecksum, parse_descriptor, PubkeyProvider
from hwilib.key import ExtendedKey, KeyOriginInfo
from hwilib.psbt import PSBT

# Class for emulator control
class DeviceEmulator():
    def __init__(self):
        self.type = None
        self.path = None
        self.fingerprint = None
        self.master_xpub = None
        self.password = None
        self.supports_ms_display = None
        self.supports_xpub_ms_display = None
        self.supports_unsorted_ms = None
        self.supports_taproot = None
        self.strict_bip48 = None
        self.include_xpubs = None
        self.supports_device_multiple_multisig = None

    def start(self):
        assert self.type is not None
        assert self.path is not None
        assert self.fingerprint is not None
        assert self.master_xpub is not None
        assert self.supports_ms_display is not None
        assert self.supports_xpub_ms_display is not None
        assert self.supports_unsorted_ms is not None
        assert self.strict_bip48 is not None
        assert self.include_xpubs is not None
        assert self.supports_device_multiple_multisig is not None

    def stop(self):
        pass

# Class for bitcoind control and RPC
class Bitcoind():
    def __init__(self, bitcoind_path):
        self.bitcoind_path = bitcoind_path
        self.datadir = tempfile.mkdtemp()
        self.rpc = None
        self.bitcoind_proc = None
        self.userpass = None

    def start(self):

        def get_free_port():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("", 0))
            s.listen(1)
            port = s.getsockname()[1]
            s.close()
            return port

        self.p2p_port = get_free_port()
        self.rpc_port = get_free_port()

        self.bitcoind_proc = subprocess.Popen(
            [
                self.bitcoind_path,
                "-regtest",
                f"-datadir={self.datadir}",
                "-noprinttoconsole",
                "-fallbackfee=0.0002",
                "-keypool=1",
                f"-port={self.p2p_port}",
                f"-rpcport={self.rpc_port}"
            ]
        )

        atexit.register(self.cleanup)

        # Wait for cookie file to be created
        cookie_path = os.path.join(self.datadir, "regtest", ".cookie")
        while not os.path.exists(cookie_path):
            time.sleep(0.5)
        # Read .cookie file to get user and pass
        with open(cookie_path) as f:
            self.userpass = f.readline().lstrip().rstrip()
        self.rpc_url = f"http://{self.userpass}@127.0.0.1:{self.rpc_port}"
        self.rpc = AuthServiceProxy(self.rpc_url)

        # Wait for bitcoind to be ready
        ready = False
        while not ready:
            try:
                self.rpc.getblockchaininfo()
                ready = True
            except JSONRPCException:
                time.sleep(0.5)
                pass

        # Make sure there are blocks and coins available
        self.rpc.createwallet(wallet_name="supply")
        self.wrpc = self.get_wallet_rpc("supply")
        self.wrpc.generatetoaddress(101, self.wrpc.getnewaddress())

    def get_wallet_rpc(self, wallet):
        url = self.rpc_url + f"/wallet/{wallet}"
        return AuthServiceProxy(url)

    def cleanup(self):
        if self.bitcoind_proc is not None and self.bitcoind_proc.poll() is None:
            self.bitcoind_proc.kill()
        shutil.rmtree(self.datadir)

    @staticmethod
    def create(*args, **kwargs):
        c = Bitcoind(*args, **kwargs)
        c.start()
        return c

class DeviceTestCase(unittest.TestCase):
    def __init__(self, bitcoind, emulator=None, interface='library', methodName='runTest', supports_legacy=True):
        super(DeviceTestCase, self).__init__(methodName)
        self.bitcoind = bitcoind
        self.rpc = bitcoind.rpc
        self.emulator = emulator
        self.supports_legacy = supports_legacy

        self.dev_args = ['-t', self.emulator.type, '-d', self.emulator.path, '--chain', 'test']
        if self.emulator.password is not None:
            self.dev_args.extend(['-p', self.emulator.password])

        self.interface = interface

    @staticmethod
    def parameterize(testclass, bitcoind, emulator, interface='library', *args, **kwargs):
        testloader = unittest.TestLoader()
        testnames = testloader.getTestCaseNames(testclass)
        suite = unittest.TestSuite()
        for name in testnames:
            suite.addTest(testclass(bitcoind, emulator, interface, name, *args, **kwargs))
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
            proc = subprocess.Popen(['../dist/hwi ' + ' '.join(cli_args)], stdout=subprocess.PIPE, shell=True)
            result = proc.communicate()
            return json.loads(result[0].decode())
        elif self.interface == 'stdin':
            args = [f'"{arg}"' for arg in args]
            input_str = '\n'.join(args) + '\n'
            proc = subprocess.Popen(['hwi', '--stdin'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            result = proc.communicate(input_str.encode())
            return json.loads(result[0].decode())
        else:
            return process_commands(args)

    def get_password_args(self):
        if self.emulator.password is not None:
            return ['-p', self.emulator.password]
        return []

    def __str__(self):
        return '{}: {}'.format(self.emulator.type, super().__str__())

    def __repr__(self):
        return '{}: {}'.format(self.emulator.type, super().__repr__())

    def setup_wallets(self):
        wallet_name = '{}_{}_test'.format(self.emulator.type, self.id())
        self.rpc.createwallet(wallet_name=wallet_name, disable_private_keys=True, descriptors=True)
        self.wrpc = self.bitcoind.get_wallet_rpc(wallet_name)
        self.wpk_rpc = self.bitcoind.get_wallet_rpc("supply")

    def setUp(self):
        self.emulator.start()

    def tearDown(self):
        self.emulator.stop()

class TestDeviceConnect(DeviceTestCase):
    def __init__(self, *args, detect_type, **kwargs):
        super(TestDeviceConnect, self).__init__(*args, **kwargs)
        self.detect_type = detect_type

    def test_enumerate(self):
        enum_res = self.do_command(self.get_password_args() + ["--emulators", "enumerate"])
        found = False
        for device in enum_res:
            if (device['type'] == self.detect_type or device['model'] == self.detect_type) and device['path'] == self.emulator.path and device['fingerprint'] == self.emulator.fingerprint:
                self.assertIn('type', device)
                self.assertIn('model', device)
                self.assertIn('path', device)
                self.assertIn('needs_pin_sent', device)
                self.assertIn('needs_passphrase_sent', device)
                self.assertNotIn('error', device)
                self.assertNotIn('code', device)
                found = True
        self.assertTrue(found)

    def test_no_emus(self):
        res = self.do_command(self.get_password_args() + ["enumerate"])
        self.assertEqual(len(res), 0)
        res = self.do_command(self.get_password_args() + ["-f", self.emulator.fingerprint, "--chain", "test", "getmasterxpub", "--addr-type", "legacy"])
        self.assertEqual(res['error'], 'Could not find device with specified fingerprint or type')
        self.assertEqual(res['code'], -3)
        res = self.do_command(self.get_password_args() + ["-t", self.detect_type, "--chain", "test", "getmasterxpub", "--addr-type", "legacy"])
        self.assertEqual(res['error'], 'Could not find device with specified fingerprint or type')
        self.assertEqual(res['code'], -3)

    def test_no_type(self):
        gmxp_res = self.do_command(["--chain", "test", "--emulators", "getmasterxpub", "--addr-type", "legacy"])
        self.assertIn('error', gmxp_res)
        self.assertEqual(gmxp_res['error'], 'You must specify a device type or fingerprint for all commands except enumerate')
        self.assertIn('code', gmxp_res)
        self.assertEqual(gmxp_res['code'], -1)

    def test_path_type(self):
        gmxp_res = self.do_command(self.get_password_args() + ["-t", self.detect_type, "-d", self.emulator.path, "--chain", "test", "--emulators", "getmasterxpub", "--addr-type", "legacy"])
        self.assertEqual(gmxp_res['xpub'], self.emulator.master_xpub)

    def test_fingerprint_autodetect(self):
        gmxp_res = self.do_command(self.get_password_args() + ["-f", self.emulator.fingerprint, "--chain", "test", "--emulators", "getmasterxpub", "--addr-type", "legacy"])
        self.assertEqual(gmxp_res['xpub'], self.emulator.master_xpub)

        # Nonexistent fingerprint
        gmxp_res = self.do_command(self.get_password_args() + ["-f", "0000ffff", "--chain", "test", "--emulators", "getmasterxpub", "--addr-type", "legacy"])
        self.assertEqual(gmxp_res['error'], 'Could not find device with specified fingerprint or type')
        self.assertEqual(gmxp_res['code'], -3)

    def test_type_only_autodetect(self):
        gmxp_res = self.do_command(self.get_password_args() + ["-t", self.detect_type, "--chain", "test", "--emulators", "getmasterxpub", "--addr-type", "legacy"])
        self.assertEqual(gmxp_res['xpub'], self.emulator.master_xpub)

        # Unknown device type
        gmxp_res = self.do_command(["-t", "fakedev", "-d", "fakepath", "--chain", "test", "--emulators", "getmasterxpub", "--addr-type", "legacy"])
        self.assertEqual(gmxp_res['error'], 'Unknown device type specified')
        self.assertEqual(gmxp_res['code'], -4)

class TestGetKeypool(DeviceTestCase):
    def setUp(self):
        super().setUp()
        self.setup_wallets()

    def test_getkeypool(self):

        getkeypool_args = [
            ("legacy", 44, "legacy"),
            ("wit", 84, "bech32"),
            ("sh_wit", 49, "p2sh-segwit"),
        ]
        if self.emulator.supports_taproot:
            getkeypool_args.append(("tap", 86, "bech32m"))

        descs = []
        for arg in getkeypool_args:
            with self.subTest(addrtype=arg[0]):
                desc = self.do_command(self.dev_args + ["getkeypool", "--addr-type", arg[0], "0", "20"])
                import_result = self.wrpc.importdescriptors(desc)
                self.assertTrue(import_result[0]["success"])
                for _ in range(0, 21):
                    addr_info = self.wrpc.getaddressinfo(self.wrpc.getnewaddress("", arg[2]))
                    self.assertTrue(addr_info["hdkeypath"].startswith(f"m/{arg[1]}h/1h/0h/0/"))
                    addr_info = self.wrpc.getaddressinfo(self.wrpc.getrawchangeaddress(arg[2]))
                    self.assertTrue(addr_info["hdkeypath"].startswith(f"m/{arg[1]}h/1h/0h/1/"))
                descs.extend(desc)

        # Test that `--all` option gives the "concatenation" of previous four calls
        all_keypool_desc = self.do_command(self.dev_args + ['getkeypool', '--all', '0', '20'])
        self.assertEqual(all_keypool_desc, descs)

        keypool_desc = self.do_command(self.dev_args + ['getkeypool', "--addr-type", "sh_wit", '--account', '3', '0', '20'])
        import_result = self.wrpc.importdescriptors(keypool_desc)
        self.assertTrue(import_result[0]['success'])
        for _ in range(0, 21):
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getnewaddress('', 'p2sh-segwit'))
            self.assertTrue(addr_info['hdkeypath'].startswith("m/49h/1h/3h/0/"))
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getrawchangeaddress('p2sh-segwit'))
            self.assertTrue(addr_info['hdkeypath'].startswith("m/49h/1h/3h/1/"))
        keypool_desc = self.do_command(self.dev_args + ['getkeypool', '--account', '3', '0', '20'])
        import_result = self.wrpc.importdescriptors(keypool_desc)
        self.assertTrue(import_result[0]['success'])
        for _ in range(0, 21):
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getnewaddress('', 'bech32'))
            self.assertTrue(addr_info['hdkeypath'].startswith("m/84h/1h/3h/0/"))
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getrawchangeaddress('bech32'))
            self.assertTrue(addr_info['hdkeypath'].startswith("m/84h/1h/3h/1/"))

        keypool_desc = self.do_command(self.dev_args + ['getkeypool', '--path', 'm/0h/0h/4h/*', '0', '20'])
        import_result = self.wrpc.importdescriptors(keypool_desc)
        self.assertTrue(import_result[0]['success'])
        for _ in range(0, 21):
            addr_info = self.wrpc.getaddressinfo(self.wrpc.getnewaddress('', 'bech32'))
            self.assertTrue(addr_info['hdkeypath'].startswith("m/0h/0h/4h/"))

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
        self.assertEqual(len(descriptors['receive']), 4 if self.emulator.supports_taproot else 3)
        self.assertEqual(len(descriptors['internal']), 4 if self.emulator.supports_taproot else 3)

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
    def __init__(self, *args, signtx_cases, **kwargs):
        super(TestSignTx, self).__init__(*args, **kwargs)
        self.signtx_cases = signtx_cases

    def setUp(self):
        super().setUp()
        self.setup_wallets()

    def _generate_and_finalize(self, unknown_inputs, psbt):
        if not self.emulator.supports_device_multiple_multisig:
            # We will need Core to sign so that the multisig is complete
            core_sign_res = self.wpk_rpc.walletprocesspsbt(psbt=psbt, finalize=False)
            psbt = core_sign_res["psbt"]

        if not unknown_inputs:
            # Just do the normal signing process to test "all inputs" case
            sign_res = self.do_command(self.dev_args + ['signtx', psbt])
            finalize_res = self.wrpc.finalizepsbt(sign_res['psbt'])
            self.assertTrue(sign_res["signed"])
            self.assertTrue(finalize_res["complete"])
        else:
            # Sign only input one on first pass
            # then rest on second pass to test ability to successfully
            # ignore inputs that are not its own. Then combine both
            # signing passes to ensure they are actually properly being
            # partially signed at each step.
            first_psbt = PSBT()
            first_psbt.deserialize(psbt)
            second_psbt = PSBT()
            second_psbt.deserialize(psbt)

            # Blank master fingerprint to make hww fail to sign
            # Single input PSBTs will be fully signed by first signer
            for psbt_input in first_psbt.inputs[1:]:
                for pubkey, path in psbt_input.hd_keypaths.items():
                    psbt_input.hd_keypaths[pubkey] = KeyOriginInfo(b"\x00\x00\x00\x01", path.path)
                for pubkey, (leaves, origin) in psbt_input.tap_bip32_paths.items():
                    psbt_input.tap_bip32_paths[pubkey] = (leaves, KeyOriginInfo(b"\x00\x00\x00\x01", origin.path))
            for pubkey, path in second_psbt.inputs[0].hd_keypaths.items():
                second_psbt.inputs[0].hd_keypaths[pubkey] = KeyOriginInfo(b"\x00\x00\x00\x01", path.path)
            for pubkey, (leaves, origin) in second_psbt.inputs[0].tap_bip32_paths.items():
                second_psbt.inputs[0].tap_bip32_paths[pubkey] = (leaves, KeyOriginInfo(b"\x00\x00\x00\x01", origin.path))

            single_input = len(first_psbt.inputs) == 1

            # Process the psbts
            first_psbt = first_psbt.serialize()
            second_psbt = second_psbt.serialize()

            # First will always have something to sign
            first_sign_res = self.do_command(self.dev_args + ['signtx', first_psbt])
            self.assertTrue(first_sign_res["signed"])
            self.assertTrue(single_input == self.wrpc.finalizepsbt(first_sign_res['psbt'])['complete'])
            # Second may have nothing to sign (1 input case)
            # and also may throw an error(e.g., ColdCard)
            second_sign_res = self.do_command(self.dev_args + ['signtx', second_psbt])
            if 'psbt' in second_sign_res:
                if single_input:
                    self.assertFalse(second_sign_res["signed"])
                else:
                    self.assertTrue(second_sign_res["signed"])
                self.assertTrue(not self.wrpc.finalizepsbt(second_sign_res['psbt'])['complete'])
                combined_psbt = self.wrpc.combinepsbt([first_sign_res['psbt'], second_sign_res['psbt']])

            else:
                self.assertTrue('error' in second_sign_res)
                combined_psbt = first_sign_res['psbt']

            finalize_res = self.wrpc.finalizepsbt(combined_psbt)
            self.assertTrue(finalize_res['complete'])
            self.assertTrue(self.wrpc.testmempoolaccept([finalize_res['hex']])[0]["allowed"])
        return finalize_res['hex']

    def _make_multisig(self, addrtype):
        if addrtype == "legacy":
            coin_type = 0
            desc_prefix = "sh("
            desc_suffix = ")"
        elif addrtype == "p2sh-segwit":
            coin_type = 1 if self.emulator.strict_bip48 else 0
            desc_prefix = "sh(wsh("
            desc_suffix = "))"
        elif addrtype == "bech32":
            coin_type = 2 if self.emulator.strict_bip48 else 0
            desc_prefix = "wsh("
            desc_suffix = ")"
        else:
            self.fail(f"Unknown address type {addrtype}")

        desc_pubkeys = []
        xpubs: Dict[bytes, KeyOriginInfo] = {}
        for account in range(0, 3 if self.emulator.supports_device_multiple_multisig else 1):
            path = f"/48h/1h/{account}h/{coin_type}h"
            origin = '{}{}'.format(self.emulator.fingerprint, path)
            xpub = self.do_command(self.dev_args + ["getxpub", "m{}".format(path)])
            desc_pubkeys.append("[{}]{}/0/0".format(origin, xpub["xpub"]))
            if self.emulator.include_xpubs:
                extkey = ExtendedKey.deserialize(xpub["xpub"])
                xpubs[extkey.serialize()] = KeyOriginInfo.from_string(origin)

        if not self.emulator.supports_device_multiple_multisig:
            # If the device does not support itself in the multisig more than once,
            # we need to fetch a key from Core, and use another key that will not be signed with
            counter_descs = self.wpk_rpc.listdescriptors()["descriptors"]
            desc = parse_descriptor(counter_descs[0]["desc"])
            pubkey_prov = None
            while pubkey_prov is None:
                if len(desc.pubkeys) > 0:
                    pubkey_prov = desc.pubkeys[0]
                else:
                    desc = desc.subdescriptors[0]
            assert pubkey_prov.extkey is not None
            assert pubkey_prov.origin is not None
            pubkey_prov.deriv_path = "/0/0"
            desc_pubkeys.append(pubkey_prov.to_string())
            if self.emulator.include_xpubs:
                xpubs[pubkey_prov.extkey.serialize()] = pubkey_prov.origin

            # A fixed key
            fixed_extkey = ExtendedKey.deserialize("tpubDCBWBScQPGv4Xk3JSbhw6wYYpayMjb2eAYyArpbSqQTbLDpphHGAetB6VQgVeftLML8vDSUEWcC2xDi3qJJ3YCDChJDvqVzpgoYSuT52MhJ")
            fixed_origin = KeyOriginInfo(b"\xde\xad\xbe\xef", [0x80000000])
            desc_pubkeys.append(PubkeyProvider(fixed_origin, fixed_extkey.to_string(), "/0/0").to_string())
            if self.emulator.include_xpubs:
                xpubs[fixed_extkey.serialize()] = fixed_origin

        desc = AddChecksum(f"{desc_prefix}sortedmulti(2,{desc_pubkeys[0]},{desc_pubkeys[1]},{desc_pubkeys[2]}){desc_suffix}")

        return desc, self.rpc.deriveaddresses(desc)[0], xpubs

    def _test_signtx(self, input_types, multisig_types, external, op_return: bool):
        # Import some keys to the watch only wallet and send coins to them
        keypool_desc = self.do_command(self.dev_args + ['getkeypool', '--all', '30', '50'])
        import_result = self.wrpc.importdescriptors(keypool_desc)
        self.assertTrue(import_result[0]['success'])
        sh_wpkh_addr = self.wrpc.getnewaddress('', 'p2sh-segwit')
        wpkh_addr = self.wrpc.getnewaddress('', 'bech32')
        pkh_addr = self.wrpc.getnewaddress('', 'legacy')
        tr_addr = None
        if "tap" in input_types:
            tr_addr = self.wrpc.getnewaddress("", "bech32m")

        in_amt = 1
        number_inputs = 0
        # Single-sig
        if "segwit" in input_types:
            self.wpk_rpc.sendtoaddress(sh_wpkh_addr, in_amt)
            self.wpk_rpc.sendtoaddress(wpkh_addr, in_amt)
            number_inputs += 2
        if "legacy" in input_types:
            self.wpk_rpc.sendtoaddress(pkh_addr, in_amt)
            number_inputs += 1
        if "tap" in input_types:
            assert tr_addr is not None
            self.wpk_rpc.sendtoaddress(tr_addr, in_amt)
            number_inputs += 1
        # Now do segwit/legacy multisig
        xpubs: Dict[bytes, KeyOriginInfo] = {}
        if "legacy" in multisig_types:
            sh_multi_desc, sh_multi_addr, sh_multi_xpubs = self._make_multisig("legacy")

            xpubs.update(sh_multi_xpubs)

            sh_multi_import = {'desc': sh_multi_desc, "timestamp": "now", "label": "shmulti"}
            multi_result = self.wrpc.importdescriptors([sh_multi_import])
            self.assertTrue(multi_result[0]['success'])

            self.wpk_rpc.sendtoaddress(sh_multi_addr, in_amt)
            number_inputs += 1
        if "segwit" in multisig_types:
            sh_wsh_multi_desc, sh_wsh_multi_addr, sh_wsh_xpubs = self._make_multisig("p2sh-segwit")
            wsh_multi_desc, wsh_multi_addr, wsh_xpubs = self._make_multisig("bech32")

            xpubs.update(sh_wsh_xpubs)
            xpubs.update(wsh_xpubs)

            sh_wsh_multi_import = {'desc': sh_wsh_multi_desc, "timestamp": "now", "label": "shwshmulti"}
            wsh_multi_import = {'desc': wsh_multi_desc, "timestamp": "now", "label": "wshmulti"}

            multi_result = self.wrpc.importdescriptors([sh_wsh_multi_import, wsh_multi_import])
            self.assertTrue(multi_result[0]['success'])
            self.assertTrue(multi_result[1]['success'])

            self.wpk_rpc.sendtoaddress(wsh_multi_addr, in_amt)
            self.wpk_rpc.sendtoaddress(sh_wsh_multi_addr, in_amt)
            number_inputs += 2

        self.wpk_rpc.generatetoaddress(6, self.wpk_rpc.getnewaddress())

        # Spend different amounts, with increasing number of inputs until the wallet is swept
        utxos = self.wrpc.listunspent()
        for i in range(1, number_inputs + 1):
            # Create a psbt spending the above
            change_addr = self.wpk_rpc.getrawchangeaddress()

            out_val = i / 4
            outputs = [
                {self.wpk_rpc.getnewaddress('', 'legacy'): out_val},
                {self.wpk_rpc.getnewaddress('', 'p2sh-segwit'): out_val},
                {self.wpk_rpc.getnewaddress('', 'bech32'): out_val}
            ]
            if self.emulator.supports_taproot:
                outputs.append({self.wpk_rpc.getnewaddress("", "bech32m"): out_val})
            if op_return:
                outputs.append({"data": "000102030405060708090a0b0c0d0e0f10111213141516171819101a1b1c1d1e1f"})
            psbt = self.wrpc.walletcreatefundedpsbt(
                utxos[:i],
                outputs,
                0,
                {
                    "includeWatching": True,
                    "changeAddress": change_addr,
                    "subtractFeeFromOutputs": [0, 1, 2],
                },
                True
            )["psbt"]

            # We need to modify the psbt to include our xpubs as Core does not include xpubs
            psbt_obj = PSBT()
            psbt_obj.deserialize(psbt)
            psbt_obj.xpub = xpubs
            psbt = psbt_obj.serialize()

            if external:
                # Sign with unknown inputs in two steps
                self._generate_and_finalize(True, psbt)
            # Sign all inputs all at once
            final_tx = self._generate_and_finalize(False, psbt)

        # Send off final tx to sweep the wallet
        self.wrpc.sendrawtransaction(final_tx)

    # Test wrapper to avoid mixed-inputs signing for Ledger
    def test_signtx(self):

        for addrtypes, multisig_types, external, op_return in self.signtx_cases:
            with self.subTest(addrtypes=addrtypes, multisig_types=multisig_types, external=external, op_return=op_return):
                self._test_signtx(addrtypes, multisig_types, external, op_return)

    # Make a huge transaction which might cause some problems with different interfaces
    def test_big_tx(self):
        # make a huge transaction
        addr_type = "legacy" if self.supports_legacy else "sh_wit"
        keypool_desc = self.do_command(self.dev_args + ["getkeypool", "--account", "10", "--addr-type", addr_type, "0", "100"])
        import_result = self.wrpc.importdescriptors(keypool_desc)
        self.assertTrue(import_result[0]['success'])
        outputs = []
        num_inputs = 60
        addr_type = "legacy" if self.supports_legacy else "p2sh-segwit"
        for i in range(0, num_inputs):
            outputs.append({self.wrpc.getnewaddress('', addr_type): 0.001})
        outputs.append({self.wrpc.getnewaddress("", addr_type): 10})
        psbt = self.wpk_rpc.walletcreatefundedpsbt([], outputs, 0, {}, True)['psbt']
        psbt = self.wpk_rpc.walletprocesspsbt(psbt)['psbt']
        tx = self.wpk_rpc.finalizepsbt(psbt)['hex']
        self.wpk_rpc.sendrawtransaction(tx)
        self.wpk_rpc.generatetoaddress(10, self.wpk_rpc.getnewaddress())
        inputs = self.wrpc.listunspent()
        psbt = self.wrpc.walletcreatefundedpsbt(inputs, [{self.wpk_rpc.getnewaddress('', addr_type): 0.001 * num_inputs}])['psbt']
        # For cli, this should throw an exception
        try:
            result = self.do_command(self.dev_args + ['signtx', psbt])
            if self.interface == 'cli':
                self.fail('Big tx did not cause CLI to error')
            else:
                self.assertNotIn('code', result)
                self.assertNotIn('error', result)
        except OSError:
            if self.interface == 'cli':
                pass

class TestDisplayAddress(DeviceTestCase):
    def test_display_address_path(self):
        result = self.do_command(self.dev_args + ['displayaddress', "--addr-type", "legacy", '--path', 'm/44h/1h/0h/0/0'])
        if self.supports_legacy:
            self.assertNotIn('error', result)
            self.assertNotIn('code', result)
            self.assertIn('address', result)
        else:
            self.assertIn('error', result)
            self.assertIn('code', result)
            self.assertEqual(result['code'], -9)

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
        self.assertEqual(result['code'], -7)

    def test_display_address_descriptor(self):
        account_xpub = self.do_command(self.dev_args + ['getxpub', 'm/84h/1h/0h'])['xpub']
        p2sh_segwit_account_xpub = self.do_command(self.dev_args + ['getxpub', 'm/49h/1h/0h'])['xpub']
        legacy_account_xpub = self.do_command(self.dev_args + ['getxpub', 'm/44h/1h/0h'])['xpub']

        # Native SegWit address using xpub:
        result = self.do_command(self.dev_args + ['displayaddress', '--desc', 'wpkh([' + self.emulator.fingerprint + '/84h/1h/0h]' + account_xpub + '/0/0)'])
        self.assertNotIn('error', result)
        self.assertNotIn('code', result)
        self.assertIn('address', result)

        # Native SegWit address using hex encoded pubkey:
        result = self.do_command(self.dev_args + ['displayaddress', '--desc', 'wpkh([' + self.emulator.fingerprint + '/84h/1h/0h]' + xpub_to_pub_hex(account_xpub) + '/0/0)'])
        self.assertNotIn('error', result)
        self.assertNotIn('code', result)
        self.assertIn('address', result)

        # P2SH wrapped SegWit address using xpub:
        result = self.do_command(self.dev_args + ['displayaddress', '--desc', 'sh(wpkh([' + self.emulator.fingerprint + '/49h/1h/0h]' + p2sh_segwit_account_xpub + '/0/0))'])
        self.assertNotIn('error', result)
        self.assertNotIn('code', result)
        self.assertIn('address', result)

        # Legacy address
        result = self.do_command(self.dev_args + ['displayaddress', '--desc', 'pkh([' + self.emulator.fingerprint + '/44h/1h/0h]' + legacy_account_xpub + '/0/0)'])
        if self.supports_legacy:
            self.assertNotIn('error', result)
            self.assertNotIn('code', result)
            self.assertIn('address', result)
        else:
            self.assertIn('error', result)
            self.assertIn('code', result)
            self.assertEqual(result['code'], -9)

        # Should check xpub
        result = self.do_command(self.dev_args + ['displayaddress', '--desc', 'wpkh([' + self.emulator.fingerprint + '/84h/1h/0h]' + "not_and_xpub" + '/0/0)'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['code'], -7)

        # Should check hex pub
        result = self.do_command(self.dev_args + ['displayaddress', '--desc', 'wpkh([' + self.emulator.fingerprint + '/84h/1h/0h]' + "not_and_xpub" + '/0/0)'])
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
            origin = '{}{}'.format(self.emulator.fingerprint, path)
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
        if not self.emulator.supports_ms_display and not self.emulator.supports_xpub_ms_display:
            raise unittest.SkipTest("{} does not support multisig display".format(self.emulator.type))

        for addrtype in ["pkh", "sh_wpkh", "wpkh"]:
            for sort in [True, False]:
                for derive in [True, False]:
                    with self.subTest(addrtype=addrtype):
                        if not sort and not self.emulator.supports_unsorted_ms:
                            raise unittest.SkipTest("{} does not support unsorted multisigs".format(self.emulator.type))
                        if derive and not self.emulator.supports_xpub_ms_display:
                            raise unittest.SkipTest("{} does not support multisig display with xpubs".format(self.emulator.type))

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
        self.assertEqual(result['code'], -7)
