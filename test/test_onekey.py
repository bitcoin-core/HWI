#! /usr/bin/env python3

import argparse
import atexit
import json
import os
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from hwilib._cli import process_commands
from hwilib.devices import onekey
from hwilib.devices.trezorlib import device
from hwilib.devices.trezorlib import models as trezor_models
from hwilib.devices.trezorlib.debuglink import load_device_by_mnemonic
from hwilib.devices.trezorlib.transport.udp import UdpTransport
try:
    import test_device
except ModuleNotFoundError:
    from test import test_device


class _DictTransport:
    def __init__(self, raw_device):
        self.device = raw_device


class _RawUsbDevice:
    def __init__(self, vendor_id=0x1209, product_id=0x53C0, product="", manufacturer=""):
        self._vendor_id = vendor_id
        self._product_id = product_id
        self._product = product
        self._manufacturer = manufacturer

    def getVendorID(self):
        return self._vendor_id

    def getProductID(self):
        return self._product_id

    def getProduct(self):
        return self._product

    def getManufacturer(self):
        return self._manufacturer


class _FailingRawUsbDevice(_RawUsbDevice):
    def getProduct(self):
        raise RuntimeError("device query failed")


class _EnumerateTransport(_DictTransport):
    def __init__(self, raw_device, path="hid:onekey"):
        super().__init__(raw_device)
        self._path = path

    def get_path(self):
        return self._path


class _FakeFeatures:
    def __init__(
        self,
        model="1",
        onekey_device_type=None,
        pin_protection=True,
        unlocked=False,
        passphrase_protection=False,
        initialized=True,
        label="OneKey",
        vendor="OneKey",
    ):
        self.model = model
        self.onekey_device_type = onekey_device_type
        self.pin_protection = pin_protection
        self.unlocked = unlocked
        self.passphrase_protection = passphrase_protection
        self.initialized = initialized
        self.label = label
        self.vendor = vendor


class _FakeInnerClient:
    def __init__(self, features):
        self.features = features

    def refresh_features(self):
        return None


class _FakeOnekeyClient:
    def __init__(self, features):
        self.client = _FakeInnerClient(features)

    def get_master_fingerprint(self):
        return bytes.fromhex("f23f9fd2")

    def close(self):
        return None


class TestOnekeyHelpers(unittest.TestCase):
    def test_contains_onekey_marker(self):
        self.assertTrue(onekey._contains_onekey_marker("OneKey Pro"))
        self.assertTrue(onekey._contains_onekey_marker(b"ONEKEY Mini"))
        self.assertFalse(onekey._contains_onekey_marker("Other Wallet"))
        self.assertFalse(onekey._contains_onekey_marker(None))

    def test_get_usb_id(self):
        dict_device = _DictTransport({"vendor_id": 0x1209, "product_id": 0x53C0})
        self.assertEqual(onekey._get_usb_id(dict_device), (0x1209, 0x53C0))

        raw_device = _RawUsbDevice(vendor_id=0x1209, product_id=0x4F4A)
        self.assertEqual(onekey._get_usb_id(_DictTransport(raw_device)), (0x1209, 0x4F4A))

        self.assertIsNone(onekey._get_usb_id(object()))

    def test_is_onekey_device(self):
        self.assertTrue(onekey._is_onekey_device((0x1209, 0x4F4A), "", ""))
        self.assertTrue(onekey._is_onekey_device((0x1209, 0x53C1), "Wallet", "Vendor"))
        self.assertTrue(onekey._is_onekey_device((0x1209, 0x53C0), "OneKey Touch", "Unknown"))
        self.assertTrue(onekey._is_onekey_device((0x1209, 0x53C0), "Wallet", "OneKey"))
        self.assertFalse(onekey._is_onekey_device((0x0001, 0x0002), "Wallet", "Vendor"))

    def test_is_onekey_transport_with_dict_device(self):
        one_key_dict = _DictTransport({"product_string": "OneKey Pro", "manufacturer_string": "Unknown"})
        self.assertTrue(onekey._is_onekey_transport(one_key_dict, (0x1209, 0x53C0)))

        one_key_manufacturer = _DictTransport({"product_string": "Wallet", "manufacturer_string": "OneKey"})
        self.assertTrue(onekey._is_onekey_transport(one_key_manufacturer, (0x1209, 0x53C0)))

        exclusive_id = _DictTransport({"product_string": "Wallet", "manufacturer_string": "Vendor"})
        self.assertTrue(onekey._is_onekey_transport(exclusive_id, (0x1209, 0x4F4A)))

        not_onekey = _DictTransport({"product_string": "Wallet", "manufacturer_string": "Vendor"})
        self.assertFalse(onekey._is_onekey_transport(not_onekey, (0x1209, 0x53C0)))

    def test_is_onekey_transport_with_webusb_device(self):
        raw_device = _RawUsbDevice(product="OneKey Touch", manufacturer="Unknown")
        self.assertTrue(onekey._is_onekey_transport(_DictTransport(raw_device), (0x1209, 0x53C0)))

        failing = _FailingRawUsbDevice(product="OneKey Touch", manufacturer="Unknown")
        self.assertFalse(onekey._is_onekey_transport(_DictTransport(failing), (0x1209, 0x53C0)))

    def test_locked_instructions_by_model(self):
        self.assertIn("sendpin", onekey._locked_instructions("1"))
        self.assertIn("sendpin", onekey._locked_instructions("classic1s"))
        self.assertNotIn("sendpin", onekey._locked_instructions("pro"))
        self.assertNotIn("sendpin", onekey._locked_instructions("touch"))


class TestOnekeyEnumerate(unittest.TestCase):
    def _run_enumerate_with_features(self, features, path="hid:onekey", allow_emulators=False):
        transport = _EnumerateTransport(
            {
                "vendor_id": 0x1209,
                "product_id": 0x53C0,
                "product_string": "OneKey",
                "manufacturer_string": "OneKey",
            },
            path=path,
        )
        emulators = [onekey.udp.UdpTransport(onekey.ONEKEY_SIMULATOR_PATH)] if allow_emulators else []

        with mock.patch.object(onekey.hid.HidTransport, "enumerate", return_value=[transport]), mock.patch.object(
            onekey.webusb.WebUsbTransport, "enumerate", return_value=[]
        ), mock.patch.object(
            onekey.udp.UdpTransport, "enumerate", return_value=emulators
        ), mock.patch.object(onekey, "OnekeyClient", return_value=_FakeOnekeyClient(features)):
            return onekey.enumerate(allow_emulators=allow_emulators)

    def test_enumerate_keeps_locked_classic_device(self):
        results = self._run_enumerate_with_features(_FakeFeatures(model="1", unlocked=False))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["type"], "onekey")
        self.assertEqual(results[0]["model"], "onekey_1")
        self.assertTrue(results[0]["needs_pin_sent"])
        self.assertIsNone(results[0]["fingerprint"])
        self.assertIn("warnings", results[0])
        self.assertIn("sendpin", results[0]["warnings"][0][0])

    def test_enumerate_keeps_locked_pro_device(self):
        results = self._run_enumerate_with_features(_FakeFeatures(model="pro", unlocked=False))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["model"], "onekey_pro")
        self.assertTrue(results[0]["needs_pin_sent"])
        self.assertIsNone(results[0]["fingerprint"])
        self.assertIn("warnings", results[0])
        self.assertNotIn("sendpin", results[0]["warnings"][0][0])

    def test_enumerate_sets_fingerprint_when_unlocked(self):
        results = self._run_enumerate_with_features(_FakeFeatures(model="pro", unlocked=True))

        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]["needs_pin_sent"])
        self.assertEqual(results[0]["fingerprint"], "f23f9fd2")

    def test_enumerate_maps_core_model_fallback_to_pro(self):
        results = self._run_enumerate_with_features(_FakeFeatures(model="T", unlocked=True))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["model"], "onekey_pro")

    def test_enumerate_uses_onekey_device_type_for_simulator(self):
        cases = [
            (
                "pro",
                _FakeFeatures(
                    model="T",
                    onekey_device_type=onekey.messages.OneKeyDeviceType.PRO,
                    unlocked=True,
                ),
                "onekey_pro_simulator",
            ),
            (
                "classic1s",
                _FakeFeatures(
                    model="1",
                    onekey_device_type=onekey.messages.OneKeyDeviceType.CLASSIC1S,
                    unlocked=True,
                ),
                "onekey_classic1s_simulator",
            ),
            (
                "classicpure",
                _FakeFeatures(
                    model="1",
                    onekey_device_type=onekey.messages.OneKeyDeviceType.PURE,
                    unlocked=True,
                ),
                "onekey_classicpure_simulator",
            ),
        ]

        for name, features, expected_model in cases:
            with self.subTest(model=name), mock.patch.object(
                onekey.hid.HidTransport, "enumerate", return_value=[]
            ), mock.patch.object(
                onekey.webusb.WebUsbTransport, "enumerate", return_value=[]
            ), mock.patch.object(
                onekey.udp.UdpTransport,
                "enumerate",
                return_value=[onekey.udp.UdpTransport(onekey.ONEKEY_SIMULATOR_PATH)],
            ), mock.patch.object(onekey, "OnekeyClient", return_value=_FakeOnekeyClient(features)):
                results = onekey.enumerate(allow_emulators=True)

            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["path"], "udp:127.0.0.1:54935")
            self.assertEqual(results[0]["model"], expected_model)


class TestOnekeyClientCompat(unittest.TestCase):
    def test_refresh_features_accepts_onekey_vendor(self):
        cases = [
            (
                "pro",
                onekey.messages.Features(
                    vendor="onekey.so",
                    model="T",
                    major_version=2,
                    minor_version=99,
                    patch_version=99,
                    onekey_device_type=onekey.messages.OneKeyDeviceType.PRO,
                ),
                trezor_models.T2T1,
            ),
            (
                "classic1s",
                onekey.messages.Features(
                    vendor="onekey.so",
                    model="1",
                    major_version=1,
                    minor_version=8,
                    patch_version=0,
                    onekey_device_type=onekey.messages.OneKeyDeviceType.CLASSIC1S,
                ),
                trezor_models.T1B1,
            ),
            (
                "classicpure",
                onekey.messages.Features(
                    vendor="onekey.so",
                    model="1",
                    major_version=2,
                    minor_version=99,
                    patch_version=99,
                    onekey_device_type=onekey.messages.OneKeyDeviceType.PURE,
                ),
                trezor_models.T1B1,
            ),
        ]

        for name, features, expected_model in cases:
            with self.subTest(model=name):
                client = object.__new__(onekey.OneKeyTransportClient)
                client.model = None
                client.features = None
                client.version = (0, 0, 0)
                client.session_id = None
                client.check_firmware_version = lambda warn_only=True: None

                client._refresh_features(features)

                self.assertEqual(client.features, features)
                self.assertEqual(client.model, expected_model)
                self.assertEqual(
                    client.version,
                    (features.major_version, features.minor_version, features.patch_version),
                )

    def test_requires_serialized_signatures_for_legacy_models(self):
        client = object.__new__(onekey.OneKeyClient)

        client.client = mock.Mock()
        client.client.features = onekey.messages.Features(
            vendor="onekey.so",
            model="1",
            major_version=2,
            minor_version=99,
            patch_version=99,
            onekey_device_type=onekey.messages.OneKeyDeviceType.PURE,
        )
        self.assertTrue(client._requires_serialized_signatures())

        client.client.features = onekey.messages.Features(
            vendor="onekey.so",
            model="T",
            major_version=2,
            minor_version=99,
            patch_version=99,
            onekey_device_type=onekey.messages.OneKeyDeviceType.PRO,
        )
        self.assertFalse(client._requires_serialized_signatures())


class TestOnekeyDebugClientCompat(unittest.TestCase):
    def test_callback_button_acks_only_during_idle_auto_press(self):
        client = object.__new__(onekey.OneKeyDebugLinkClient)
        client._auto_press_depth = 1
        client._raw_write = mock.Mock()
        client._raw_read = mock.Mock(return_value="next-message")
        client.ui = mock.Mock()

        response = client._callback_button(
            onekey.messages.ButtonRequest(code=onekey.messages.ButtonRequestType.SignTx)
        )

        self.assertEqual(response, "next-message")
        client._raw_write.assert_called_once()
        ack = client._raw_write.call_args[0][0]
        self.assertIsInstance(ack, onekey.messages.ButtonAck)
        client.ui.button_request.assert_not_called()


class TestOnekeyLifecycleCompat(unittest.TestCase):
    def _make_client(self, simulator):
        client = object.__new__(onekey.OneKeyClient)
        client.simulator = simulator
        client.password = ""
        client._prepare_device = mock.Mock()

        ui = mock.Mock()
        original_get_pin = object()
        ui.get_pin = original_get_pin

        inner_client = mock.Mock()
        inner_client.ui = ui
        inner_client.features = _FakeFeatures(initialized=False)
        client.client = inner_client
        return client, ui, original_get_pin

    def test_setup_and_restore_preserve_simulator_pin_handler(self):
        cases = (
            ("setup_device", "reset", {"label": "simulator"}),
            ("restore_device", "recover", {"label": "simulator", "word_count": 12}),
        )
        for method_name, device_call_name, kwargs in cases:
            with self.subTest(method=method_name):
                client, ui, original_get_pin = self._make_client(simulator=True)
                with mock.patch.object(onekey.device, device_call_name, return_value=None) as device_call:
                    self.assertTrue(getattr(client, method_name)(**kwargs))

                client._prepare_device.assert_called_once()
                device_call.assert_called_once()
                self.assertIs(ui.get_pin, original_get_pin)

    def test_setup_and_restore_use_interactive_pin_for_hardware(self):
        cases = (
            ("setup_device", "reset", {"label": "hardware"}),
            ("restore_device", "recover", {"label": "hardware", "word_count": 12}),
        )
        for method_name, device_call_name, kwargs in cases:
            with self.subTest(method=method_name):
                client, ui, original_get_pin = self._make_client(simulator=False)
                with mock.patch.object(onekey.device, device_call_name, return_value=None) as device_call:
                    self.assertTrue(getattr(client, method_name)(**kwargs))

                client._prepare_device.assert_called_once()
                device_call.assert_called_once()
                self.assertIsNot(ui.get_pin, original_get_pin)
                self.assertIs(ui.get_pin.__self__, ui)
                self.assertIs(ui.get_pin.__func__, onekey.interactive_get_pin)


class TestOnekeyCommandFormatting(unittest.TestCase):
    def test_stdin_quotes_each_argument(self):
        class _FakeProcess:
            def __init__(self):
                self.payload = None

            def communicate(self, payload, timeout=None):
                self.payload = payload
                return (b"{}", b"")

        emulator = mock.Mock()
        emulator.model = "pro"
        case = _ONEKEY_TEST_TYPES["test_case"](emulator, interface="stdin")
        proc = _FakeProcess()

        with mock.patch.object(subprocess, "Popen", return_value=proc) as popen:
            result = case.do_command(["enumerate", "--device-type", "OneKey Pro"])

        self.assertEqual(result, {})
        self.assertEqual(proc.payload.decode(), '"enumerate"\n"--device-type"\n"OneKey Pro"\n')
        popen.assert_called_once_with(
            ["hwi", "--stdin"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )


ONEKEY_EMULATOR_PATH = "udp:127.0.0.1:54935"
ONEKEY_EMULATOR_HOST = ("127.0.0.1", 54935)
ONEKEY_TEST_MNEMONIC = "alcohol woman abuse must during monitor noble actual mixed trade anger aisle"
ONEKEY_PROCESS_TIMEOUT = 300
ONEKEY_MODELS = {"pro", "classic1s"}


class OneKeyEmulator(test_device.DeviceEmulator):
    def __init__(self, path, model="pro"):
        assert model in ONEKEY_MODELS
        self.model = model
        self.emulator_path = os.path.realpath(path)
        if self.model == "pro":
            self.emulator_cwd = os.path.realpath(
                os.path.join(os.path.dirname(self.emulator_path), "..", "..", "src")
            )
        else:
            self.emulator_cwd = os.path.dirname(self.emulator_path)
        self.emulator_proc = None
        self.emulator_log = None
        self.profile_dir = None
        self.debug_client = None
        self.type = "onekey"
        self.detect_type = f"onekey_{self.model}_simulator"
        self.path = ONEKEY_EMULATOR_PATH
        self.fingerprint = "95d8f670"
        self.master_xpub = "tpubDCknDegFqAdP4V2AhHhs635DPe8N1aTjfKE9m2UFbdej8zmeNbtqDzK59SxnsYSRSx5uS3AujbwgANUiAk4oHmDNUKoGGkWWUY6c48WgjEx"
        self.password = ""
        self.supports_ms_display = True
        self.supports_xpub_ms_display = True
        self.supports_unsorted_ms = True
        self.supports_taproot = True
        self.strict_bip48 = True
        self.include_xpubs = False
        self.supports_device_multiple_multisig = True
        self.supports_legacy = True

    def start(self):
        super().start()
        self.emulator_log = open(f"onekey-{self.model}-emulator.stdout", "a", encoding="utf-8")
        env = os.environ.copy()
        env["TREZOR_UDP_PORT"] = str(ONEKEY_EMULATOR_HOST[1])
        # OneKey firmware reads ONEKEY_UDP_PORT (not TREZOR_UDP_PORT)
        env["ONEKEY_UDP_PORT"] = str(ONEKEY_EMULATOR_HOST[1])
        env["SDL_AUDIODRIVER"] = "dummy"
        if self.model == "pro":
            # Pro emulator needs a real X display (SDL_VIDEODRIVER=dummy triggers
            # SDL_Init failure → SIGSEGV in __fatal_error).  In CI the install-sim
            # action starts Xvfb and exports DISPLAY=:99; locally any X display works.
            # Only fall back to dummy driver if no DISPLAY is available at all.
            if not env.get("DISPLAY"):
                env["SDL_VIDEODRIVER"] = "dummy"
            self.profile_dir = tempfile.TemporaryDirectory(prefix="onekey-pro-emulator-")
            env.update(
                {
                    "TREZOR_PROFILE_DIR": self.profile_dir.name,
                    "TREZOR_PROFILE": self.profile_dir.name,
                    "TREZOR_DISABLE_FADE": "1",
                    "TREZOR_DISABLE_ANIMATION": "1",
                }
            )
            # Match emu.sh: run binary directly without -m main; cwd is already core/src/
            command = [
                self.emulator_path,
                "-O0",
                "-X",
                "heapsize=20M",
            ]
        else:
            # classic1s SDL1 emulator works fine with the dummy driver.
            env["SDL_VIDEODRIVER"] = "dummy"
            command = ["./" + os.path.basename(self.emulator_path)]

        self.emulator_proc = subprocess.Popen(
            command,
            cwd=self.emulator_cwd,
            stdout=self.emulator_log,
            stderr=subprocess.STDOUT,
            env=env,
            start_new_session=True,
        )

        import signal

        def _ping_timeout_handler(signum, frame):
            raise TimeoutError("PINGPING timeout (30s via SIGALRM)")

        old_handler = signal.signal(signal.SIGALRM, _ping_timeout_handler)
        signal.alarm(30)  # hard 30-second deadline via OS signal
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0)
            sock.connect(ONEKEY_EMULATOR_HOST)
            while True:
                if self.emulator_proc.poll() is not None:
                    self.emulator_log.flush()
                    try:
                        with open(f"onekey-{self.model}-emulator.stdout", encoding="utf-8") as _f:
                            _log = _f.read()[-2000:]
                    except Exception:
                        _log = "(log unavailable)"
                    raise RuntimeError(
                        f"OneKey simulator failed with exit code {self.emulator_proc.poll()}\n"
                        f"--- emulator output (last 2000 chars) ---\n{_log}"
                    )
                try:
                    sock.sendall(b"PINGPING")
                    if sock.recv(8) == b"PONGPONG":
                        break
                except Exception:
                    time.sleep(0.05)
            sock.close()
        except TimeoutError:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
            self.emulator_log.flush()
            try:
                with open(f"onekey-{self.model}-emulator.stdout", encoding="utf-8") as _f:
                    _log = _f.read()[-2000:]
            except Exception:
                _log = "(log unavailable)"
            raise RuntimeError(
                f"OneKey simulator PINGPING timeout (30s via SIGALRM)\n"
                f"--- emulator output (last 2000 chars) ---\n{_log}"
            )
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

        wirelink = UdpTransport("127.0.0.1:54935")
        self.debug_client = onekey.OneKeyDebugLinkClient(wirelink)
        self.debug_client.init_device()
        device.wipe(self.debug_client)
        load_device_by_mnemonic(
            client=self.debug_client,
            mnemonic=ONEKEY_TEST_MNEMONIC,
            pin="",
            passphrase_protection=False,
            label="test",
        )
        detected_model = onekey._get_model(self.debug_client.features)
        self.detect_type = f"onekey_{detected_model}_simulator"
        atexit.register(self.stop)
        return self.debug_client

    def stop(self):
        super().stop()
        if self.debug_client is not None:
            self.debug_client.close()
            self.debug_client = None

        if self.emulator_proc is not None and self.emulator_proc.poll() is None:
            os.killpg(self.emulator_proc.pid, signal.SIGTERM)
            self.emulator_proc.wait()
        self.emulator_proc = None

        if self.emulator_log is not None:
            self.emulator_log.close()
            self.emulator_log = None

        if self.profile_dir is not None:
            self.profile_dir.cleanup()
            self.profile_dir = None

        if self.model == "classic1s":
            emulator_img = os.path.join(self.emulator_cwd, "emulator.img")
            if os.path.isfile(emulator_img):
                os.unlink(emulator_img)

        time.sleep(1)

        try:
            atexit.unregister(self.stop)
        except Exception:
            pass


class OneKeyTestCase(unittest.TestCase):
    def __init__(self, emulator, interface="library", methodName="runTest"):
        super().__init__(methodName)
        self.emulator = emulator
        self.interface = interface

    @staticmethod
    def parameterize(testclass, emulator, interface="library"):
        testloader = unittest.TestLoader()
        testnames = testloader.getTestCaseNames(testclass)
        suite = unittest.TestSuite()
        for name in testnames:
            suite.addTest(testclass(emulator, interface, name))
        return suite

    def do_command(self, args):
        cli_args = []
        for arg in args:
            cli_args.append(shlex.quote(arg))
        if self.interface == "cli":
            proc = subprocess.Popen(
                ["hwi " + " ".join(cli_args)],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                shell=True,
            )
            result = proc.communicate(timeout=ONEKEY_PROCESS_TIMEOUT)
            return json.loads(result[0].decode())
        elif self.interface == "bindist":
            proc = subprocess.Popen(
                ["../dist/hwi " + " ".join(cli_args)],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                shell=True,
            )
            result = proc.communicate(timeout=ONEKEY_PROCESS_TIMEOUT)
            return json.loads(result[0].decode())
        elif self.interface == "stdin":
            stdin_args = [f'"{arg}"' for arg in args]
            input_str = "\n".join(stdin_args) + "\n"
            proc = subprocess.Popen(
                ["hwi", "--stdin"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            result = proc.communicate(input_str.encode(), timeout=ONEKEY_PROCESS_TIMEOUT)
            return json.loads(result[0].decode())
        else:
            return process_commands(args)

    def __str__(self):
        return f"onekey_{self.emulator.model}: {super().__str__()}"

    def __repr__(self):
        return f"onekey_{self.emulator.model}: {super().__repr__()}"

    def setUp(self):
        self.client = self.emulator.start()

    def tearDown(self):
        self.emulator.stop()


class OneKeyDeviceTestCase(test_device.DeviceTestCase):
    def do_command(self, args):
        cli_args = []
        for arg in args:
            cli_args.append(shlex.quote(arg))
        if self.interface == "cli":
            proc = subprocess.Popen(
                ["hwi " + " ".join(cli_args)],
                stdout=subprocess.PIPE,
                shell=True,
            )
            result = proc.communicate(timeout=ONEKEY_PROCESS_TIMEOUT)
            return json.loads(result[0].decode())
        elif self.interface == "bindist":
            proc = subprocess.Popen(
                ["../dist/hwi " + " ".join(cli_args)],
                stdout=subprocess.PIPE,
                shell=True,
            )
            result = proc.communicate(timeout=ONEKEY_PROCESS_TIMEOUT)
            return json.loads(result[0].decode())
        elif self.interface == "stdin":
            stdin_args = [f'"{arg}"' for arg in args]
            input_str = "\n".join(stdin_args) + "\n"
            proc = subprocess.Popen(
                ["hwi", "--stdin"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
            )
            result = proc.communicate(input_str.encode(), timeout=ONEKEY_PROCESS_TIMEOUT)
            return json.loads(result[0].decode())
        else:
            return super().do_command(args)


class OneKeyDeviceConnect(test_device.TestDeviceConnect, OneKeyDeviceTestCase):
    def setUp(self):
        super().setUp()
        if self.detect_type == "__runtime_detect_type__":
            self.detect_type = self.emulator.detect_type


class OneKeyGetDescriptors(test_device.TestGetDescriptors, OneKeyDeviceTestCase):
    pass


class OneKeyGetKeypool(test_device.TestGetKeypool, OneKeyDeviceTestCase):
    pass


class OneKeySignTx(test_device.TestSignTx, OneKeyDeviceTestCase):
    def test_signtx(self):
        if self.emulator.model != "classic1s":
            return super().test_signtx()

        for index, (addrtypes, multisig_types, external, op_return) in enumerate(self.signtx_cases):
            with self.subTest(
                addrtypes=addrtypes,
                multisig_types=multisig_types,
                external=external,
                op_return=op_return,
            ):
                if index > 0:
                    # classic1s emulator 在连续大体量 signtx 回归里仍有状态/时序抖动，
                    # 子场景之间重启一次模拟器，避免前一轮签名残留影响后一轮 mixed multisig。
                    self.emulator.stop()
                    self.emulator.start()
                self._test_signtx(addrtypes, multisig_types, external, op_return)


class OneKeyDisplayAddress(test_device.TestDisplayAddress, OneKeyDeviceTestCase):
    pass


class OneKeySignMessage(test_device.TestSignMessage, OneKeyDeviceTestCase):
    pass


class TestOneKeyGetxpub(OneKeyTestCase):
    def test_getxpub(self):
        with open(
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "data/bip32_vectors.json"),
            encoding="utf-8",
        ) as f:
            vectors = json.load(f)
        # OneKey 模拟器明显慢于 Trezor/KeepKey，全量 24 组向量会让单个 CI job 超时。
        # 固定抽样首、中、尾三组助记词，仍覆盖不同 seed 下的整组路径派生。
        sample_indexes = sorted({0, len(vectors) // 2, len(vectors) - 1})
        for vec in [vectors[index] for index in sample_indexes]:
            with self.subTest(vector=vec):
                device.wipe(self.client)
                load_device_by_mnemonic(
                    client=self.client,
                    mnemonic=vec["mnemonic"],
                    pin="",
                    passphrase_protection=False,
                    label="test",
                    language="english",
                )

                gmxp_res = self.do_command(
                    [
                        "-t",
                        "onekey",
                        "-d",
                        ONEKEY_EMULATOR_PATH,
                        "--emulators",
                        "getmasterxpub",
                        "--addr-type",
                        "legacy",
                    ]
                )
                self.assertEqual(gmxp_res["xpub"], vec["master_xpub"])

                for path_vec in vec["vectors"]:
                    gxp_res = self.do_command(
                        [
                            "-t",
                            "onekey",
                            "-d",
                            ONEKEY_EMULATOR_PATH,
                            "--emulators",
                            "getxpub",
                            path_vec["path"],
                        ]
                    )
                    self.assertEqual(gxp_res["xpub"], path_vec["xpub"])


class TestOneKeyLabel(OneKeyTestCase):
    def setUp(self):
        self.client = self.emulator.start()
        self.dev_args = ["-t", "onekey", "-d", ONEKEY_EMULATOR_PATH]

    def test_label(self):
        result = self.do_command(self.dev_args + ["--emulators", "enumerate"])
        for dev in result:
            if dev["type"] == "onekey" and dev["path"] == ONEKEY_EMULATOR_PATH:
                self.assertEqual(dev["label"], "test")
                self.assertEqual(dev["model"], self.emulator.detect_type)
                break
        else:
            self.fail("Did not enumerate device")


_ONEKEY_TEST_TYPES = {
    "test_case": OneKeyTestCase,
    "device_connect": OneKeyDeviceConnect,
    "get_descriptors": OneKeyGetDescriptors,
    "get_keypool": OneKeyGetKeypool,
    "sign_tx": OneKeySignTx,
    "display_address": OneKeyDisplayAddress,
    "sign_message": OneKeySignMessage,
    "getxpub": TestOneKeyGetxpub,
    "label": TestOneKeyLabel,
}

# 避免 unittest 默认 discovery 把模拟器参数化测试当成普通 TestCase 实例化。
OneKeyTestCase = None
OneKeyDeviceTestCase = None
OneKeyDeviceConnect = None
OneKeyGetDescriptors = None
OneKeyGetKeypool = None
OneKeySignTx = None
OneKeyDisplayAddress = None
OneKeySignMessage = None
TestOneKeyGetxpub = None
TestOneKeyLabel = None


def onekey_test_suite(emulator, bitcoind, interface, model="pro"):
    original_stderr = sys.stderr
    devnull = open(os.devnull, "w")
    sys.stderr = devnull
    try:
        dev_emulator = OneKeyEmulator(emulator, model=model)
        signtx_cases = [
            (["legacy"], ["legacy"], False, True),
            (["segwit"], ["segwit"], False, True),
            (["tap"], [], False, True),
            (["legacy", "segwit"], ["legacy", "segwit"], False, True),
            (["legacy", "segwit", "tap"], ["legacy", "segwit"], False, True),
        ]

        suite = unittest.TestSuite()
        suite.addTest(
            test_device.DeviceTestCase.parameterize(
                _ONEKEY_TEST_TYPES["device_connect"],
                bitcoind,
                emulator=dev_emulator,
                interface=interface,
                detect_type="onekey",
            )
        )
        suite.addTest(
            test_device.DeviceTestCase.parameterize(
                _ONEKEY_TEST_TYPES["get_descriptors"],
                bitcoind,
                emulator=dev_emulator,
                interface=interface,
            )
        )
        suite.addTest(
            test_device.DeviceTestCase.parameterize(
                _ONEKEY_TEST_TYPES["get_keypool"],
                bitcoind,
                emulator=dev_emulator,
                interface=interface,
            )
        )
        suite.addTest(
            test_device.DeviceTestCase.parameterize(
                _ONEKEY_TEST_TYPES["sign_tx"],
                bitcoind,
                emulator=dev_emulator,
                interface=interface,
                signtx_cases=signtx_cases,
            )
        )
        suite.addTest(
            test_device.DeviceTestCase.parameterize(
                _ONEKEY_TEST_TYPES["display_address"],
                bitcoind,
                emulator=dev_emulator,
                interface=interface,
            )
        )
        suite.addTest(
            test_device.DeviceTestCase.parameterize(
                _ONEKEY_TEST_TYPES["sign_message"],
                bitcoind,
                emulator=dev_emulator,
                interface=interface,
            )
        )
        suite.addTest(
            _ONEKEY_TEST_TYPES["test_case"].parameterize(
                _ONEKEY_TEST_TYPES["label"],
                emulator=dev_emulator,
                interface=interface,
            )
        )
        suite.addTest(
            test_device.DeviceTestCase.parameterize(
                _ONEKEY_TEST_TYPES["device_connect"],
                bitcoind,
                emulator=dev_emulator,
                interface=interface,
                detect_type="__runtime_detect_type__",
            )
        )
        suite.addTest(
            _ONEKEY_TEST_TYPES["test_case"].parameterize(
                _ONEKEY_TEST_TYPES["getxpub"],
                emulator=dev_emulator,
                interface=interface,
            )
        )

        result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
        return result.wasSuccessful()
    finally:
        sys.stderr = original_stderr
        devnull.close()


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(TestOnekeyHelpers))
    suite.addTests(loader.loadTestsFromTestCase(TestOnekeyEnumerate))
    suite.addTests(loader.loadTestsFromTestCase(TestOnekeyClientCompat))
    suite.addTests(loader.loadTestsFromTestCase(TestOnekeyDebugClientCompat))
    suite.addTests(loader.loadTestsFromTestCase(TestOnekeyLifecycleCompat))
    suite.addTests(loader.loadTestsFromTestCase(TestOnekeyCommandFormatting))
    return suite


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test OneKey implementation")
    parser.add_argument("emulator", nargs="?", help="Path to the OneKey emulator")
    parser.add_argument("bitcoind", nargs="?", help="Path to bitcoind binary")
    parser.add_argument(
        "--model",
        help="Which OneKey emulator model to use",
        choices=sorted(ONEKEY_MODELS),
        default="pro",
    )
    parser.add_argument(
        "--interface",
        help="Which interface to send commands over",
        choices=["library", "cli", "bindist", "stdin"],
        default="library",
    )
    args = parser.parse_args()

    if args.emulator and args.bitcoind:
        bitcoind = test_device.Bitcoind.create(args.bitcoind)
        sys.exit(not onekey_test_suite(args.emulator, bitcoind, args.interface, model=args.model))

    unittest.main()
