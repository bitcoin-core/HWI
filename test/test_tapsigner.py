import os
import sys
import time
import glob
import signal
import atexit
import unittest
import argparse
import subprocess
from hwilib.common import hash160
from hwilib._cli import process_commands
from hwilib._base58 import to_address, xpub_to_pub_hex
from test_device import (
    Bitcoind,
    DeviceEmulator,
    DeviceTestCase,
    TestDeviceConnect,
    TestGetKeypool,
    TestGetDescriptors,
    TestSignTx,
)


def is_tapsigner_extra_installed():
    try:
        import cktap
        sys.stderr.write("cktap version %s" % cktap.__version__)
        return True
    except ImportError:
        return False


class TapsignerSimulator(DeviceEmulator):
    def __init__(self, simulator, setup_needed: bool = False):
        try:
            os.unlink("tapsigner-emulator.stdout")
        except FileNotFoundError:
            pass
        self.simulator = simulator
        self.tapsigner_log = None
        self.tapsigner_proc = None
        self.type = "tapsigner"
        self.path = "XDXKQ-W6VW6-GEQI3-ATSC2"
        self.fingerprint = "b633cab6"
        self.master_xpub = "tpubDC2Q4xK4XH72GLj1eKSzkfUGvZdf7i5a365vHjJLuD6XFUJhgsUDZQrE8bCKomGtqm7uKhMgiLMswiGzQN4U4fiTErfV7YCgAp7m1ShtMdU"
        self.password = "123456"
        self.supports_ms_display = False
        self.supports_xpub_ms_display = False
        self.supports_unsorted_ms = False
        self.supports_taproot = False
        self.strict_bip48 = False
        self.include_xpubs = False
        self.supports_device_multiple_multisig = True
        self.setup_needed = setup_needed

    def start(self):
        super().start()
        self.tapsigner_log = open("tapsigner-emulator.stdout", "a")
        # Start the Tapsigner simulator
        cmd_list = [
            "python3",
            os.path.basename(self.simulator),
            "--testnet",
            "emulate",
            "-t",  # t as tapsigner
        ]
        if self.setup_needed:
            cmd_list.append("-i")
        self.tapsigner_proc = subprocess.Popen(
            cmd_list,
            cwd=os.path.dirname(self.simulator),
            stdout=self.tapsigner_log,
            preexec_fn=os.setsid
        )
        # Wait for simulator to be up
        while True:
            try:
                enum_res = process_commands(["enumerate"])
                found = False
                for dev in enum_res:
                    if dev["type"] == "tapsigner":
                        found = True
                        break
                if found:
                    break
            except Exception:
                pass
            time.sleep(0.5)
        atexit.register(self.stop)

    def stop(self):
        super().stop()
        if self.tapsigner_proc.poll() is None:
            os.killpg(os.getpgid(self.tapsigner_proc.pid), signal.SIGTERM)
            os.waitpid(os.getpgid(self.tapsigner_proc.pid), 0)
        self.tapsigner_log.close()
        atexit.unregister(self.stop)


class TestTapsignerSetupCommand(DeviceTestCase):
    def test_setup(self):
        result = self.do_command(self.dev_args + ['-p', '123456', '-i', 'setup'])
        self.assertIn('success', result)
        self.assertTrue(result['success'])


# Tapsigner specific management command tests
class TestTapsignerManCommands(DeviceTestCase):
    def test_wipe(self):
        result = self.do_command(self.dev_args + ['wipe'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['error'], 'The Tapsigner does not support wiping via software')
        self.assertEqual(result['code'], -9)

    def test_backup(self):
        result = self.do_command(self.dev_args + ['-p', '123456', 'backup'])
        self.assertTrue(result['success'])
        for filename in glob.glob("backup-*.aes"):
            os.remove(filename)

    def test_pin(self):
        result = self.do_command(self.dev_args + ['promptpin'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['error'], 'The Tapsigner does not need a PIN sent from the host')
        self.assertEqual(result['code'], -9)

        result = self.do_command(self.dev_args + ['sendpin', '1234'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['error'], 'The Tapsigner does not need a PIN sent from the host')
        self.assertEqual(result['code'], -9)

class TestTapsignerGetXpub(DeviceTestCase):
    def test_getxpub(self):
        result = self.do_command(self.dev_args + ['-p', '123456', '--expert', 'getxpub', 'm/84h/0h/0h'])
        self.assertEqual(result['xpub'], 'tpubDC2Q4xK4XH72GaEJf2NWpspytdKgANWrYNfaN5CcLremZxeynDGqRzGRVNqHWyPPqLR9E6E6WxSsXiBntskkvXpiJMyN4DaNyfaJ7uzaUzj')
        self.assertTrue(result['testnet'])
        self.assertFalse(result['private'])
        self.assertEqual(result['depth'], 3)
        self.assertEqual(result['parent_fingerprint'], '00000000')
        self.assertEqual(result['child_num'], 2 ** 31)
        self.assertEqual(result['chaincode'], '40d3561481c82d1f9b1da7ff635c4f382e76efdfb818e35b10d63872f7c2691d')
        self.assertEqual(result['pubkey'], '030df106563eb9cce8bfd182ba563ff4acf5cfc78b6c7da8e2d8cd49151a78c567')

        result = self.do_command(self.dev_args + ['-p', '123456', '--expert', 'getxpub', 'm/84h/0h/0h/0/0'])
        self.assertEqual(result['xpub'], 'tpubDGzeN1gzhkF8yFPfjtCysCbbGhcB1UUmqbRurrHg9WzarPGGL6y5p2gC6cdqqHDexpaMGZ9wJ1ayWanNSpg3d67DKB2f2zxcW9GF5qJirQA')
        self.assertTrue(result['testnet'])
        self.assertFalse(result['private'])
        self.assertEqual(result['depth'], 5)
        self.assertEqual(result['parent_fingerprint'], 'a4245c33')
        self.assertEqual(result['child_num'], 0)
        self.assertEqual(result['chaincode'], 'b0245a7791f45f89629029dc3f32167dc5224293ca5380913fbc295097ba8ec5')
        self.assertEqual(result['pubkey'], '0274ff9026d3973433c903af8c407c51d23ad74a22a73f6f64041bd68287d6d2eb')


class TestTapsignerConnect(TestDeviceConnect):
    def test_path_type(self):
        gmxp_res = self.do_command(self.get_password_args() + ['-t', self.detect_type, '-d', self.emulator.path, "--chain", "test", 'getmasterxpub'])
        self.assertEqual(gmxp_res['xpub'], self.emulator.master_xpub)

        gmxp_res = self.do_command(self.get_password_args() + ['-t', self.detect_type, '-d', self.emulator.path, "--chain", "test", 'getmasterxpub', "--addr-type", "legacy"])
        self.assertEqual(gmxp_res['xpub'], "tpubDC2Q4xK4XH72HizcssdAYX8B84JCoMPM9tPUrbABoVCJfFnryWfb2nMvTyXYcc6j5hvnrLEtwoR8pCD6tu6jM4GyhwDtVPh6B6SMVvwNDZg")

        gmxp_res = self.do_command(self.get_password_args() + ['-t', self.detect_type, '-d', self.emulator.path, "--chain", "test", 'getmasterxpub', "--addr-type", "sh_wit"])
        self.assertEqual(gmxp_res['xpub'], "tpubDC2Q4xK4XH72GKRyafide6kNpsYjgEx3tbLt7RwXGcJzZbacsuZdnKQyvqx4JVpNnpTm3zsPqn6P5mDKJhqiouerBCSkcaw5CDL9DNxUQnt")

    def test_fingerprint_autodetect(self):
        gmxp_res = self.do_command(self.get_password_args() + ['-f', self.emulator.fingerprint, "--chain", "test", 'getmasterxpub'])
        self.assertEqual(gmxp_res['xpub'], self.emulator.master_xpub)

        # Nonexistent fingerprint
        gmxp_res = self.do_command(self.get_password_args() + ['-f', '0000ffff', "--chain", "test", 'getmasterxpub'])
        self.assertEqual(gmxp_res['error'], 'Could not find device with specified fingerprint')
        self.assertEqual(gmxp_res['code'], -3)

    def test_type_only_autodetect(self):
        gmxp_res = self.do_command(self.get_password_args() + ['-t', self.detect_type, "--chain", "test", 'getmasterxpub'])
        self.assertEqual(gmxp_res['xpub'], self.emulator.master_xpub)

        # Unknown device type
        gmxp_res = self.do_command(['-t', 'fakedev', '-d', 'fakepath', "--chain", "test", 'getmasterxpub'])
        self.assertEqual(gmxp_res['error'], 'Unknown device type specified')
        self.assertEqual(gmxp_res['code'], -4)


class TestTapsignerDisplayAddress(DeviceTestCase):
    def test_display_address_path(self):
        result = self.do_command(self.dev_args + ['displayaddress', "--addr-type", "legacy", '--path', 'm/44h/1h/0h/0/0'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result["error"], "The Tapsigner does not have a screen to display addresses on")
        self.assertEqual(result["code"], -9)


class TestTapsignerSignMessage(DeviceTestCase):
    def _check_sign_msg(self, msg):
        addr_path = "m/44h/1h/0h/0/0"
        xpub = self.do_command(self.dev_args + ['getxpub', addr_path])["xpub"]
        pubkey_hex = xpub_to_pub_hex(xpub)
        h160 = hash160(bytes.fromhex(pubkey_hex))
        addr = to_address(h160, b"\x6f")
        sign_res = self.do_command(self.dev_args + ['signmessage', msg, addr_path])
        self.assertNotIn("error", sign_res)
        self.assertNotIn("code", sign_res)
        self.assertIn("signature", sign_res)
        sig = sign_res["signature"]

        self.assertTrue(self.rpc.verifymessage(addr, sig, msg))

    def test_sign_msg(self):
        self._check_sign_msg("Message signing test")
        self._check_sign_msg("285") # Specific test case for Ledger shorter S

    def test_bad_path(self):
        result = self.do_command(self.dev_args + ['signmessage', "Message signing test", 'f'])
        self.assertEquals(result['code'], -7)
        result = self.do_command(self.dev_args + ['signmessage', "Message signing test", "m/44h/1h/0h/0/0/0"])
        self.assertEquals(result['code'], -7)
        self.assertEquals(result['error'], 'Length of subpath 0/0/0 is greater than 2')


def tapsigner_test_suite(simulator, bitcoind, interface):
    if not is_tapsigner_extra_installed():
        sys.stderr.write("Tapsigner extras not installed. Run `poetry install -E tapsigner` or "
                         "`pip3 install .[tapsigner]` to install Tapsigner extras\n")
        return True
    if interface.lower() == "bindist":
        sys.stderr.write("Tapsigner is not part of binary HWI distribution.\n")
        return True

    dev_emulator = TapsignerSimulator(simulator)
    dev_emulator_fresh = TapsignerSimulator(simulator, setup_needed=True)

    signtx_cases = [
        (["legacy"], ["legacy"], True, True),
        (["segwit"], ["segwit"], True, True),
        (["legacy", "segwit"], ["legacy", "segwit"], True, True),
    ]

    # Generic device tests
    suite = unittest.TestSuite()
    suite.addTest(DeviceTestCase.parameterize(TestTapsignerSetupCommand, bitcoind, emulator=dev_emulator_fresh, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestTapsignerManCommands, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestTapsignerGetXpub, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestTapsignerConnect, bitcoind, emulator=dev_emulator, interface=interface, detect_type="tapsigner"))
    suite.addTest(DeviceTestCase.parameterize(TestGetDescriptors, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestGetKeypool, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestTapsignerDisplayAddress, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestTapsignerSignMessage, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestSignTx, bitcoind, emulator=dev_emulator, interface=interface, signtx_cases=signtx_cases))

    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
    return result.wasSuccessful()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test Tapsigner implementation')
    parser.add_argument('simulator', help='Path to the Tapsigner simulator')
    parser.add_argument('bitcoind', help='Path to bitcoind binary')
    parser.add_argument('--interface', help='Which interface to send commands over', choices=['library', 'cli', 'bindist'], default='library')
    args = parser.parse_args()

    # Start bitcoind
    bitcoind = Bitcoind.create(args.bitcoind)

    sys.exit(not tapsigner_test_suite(args.simulator, bitcoind, args.interface))
