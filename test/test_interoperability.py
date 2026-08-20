#! /usr/bin/env python3

import argparse
import sys
import unittest

from hwilib import _bech32 as bech32
from hwilib.descriptor import AddChecksum
from test_coldcard import ColdcardSimulator
from test_device import Bitcoind, DeviceTestCase
from test_ledger import LedgerEmulator


class TestMuSig2Interoperability(DeviceTestCase):
    def __init__(
        self,
        bitcoind,
        coldcard_edge,
        ledger,
        interface="library",
        methodName="runTest",
    ):
        self.devices = [coldcard_edge, ledger]
        super().__init__(bitcoind, coldcard_edge, interface, methodName)

    def setUp(self):
        for device in self.devices:
            device.start()
            self.addCleanup(device.stop)

        wallet_name = "interoperability_{}_test".format(self.id())
        self.rpc.createwallet(
            wallet_name=wallet_name,
            disable_private_keys=False,
            blank=True,
            descriptors=True,
        )
        self.wrpc = self.bitcoind.get_wallet_rpc(wallet_name)
        self.wpk_rpc = self.bitcoind.get_wallet_rpc("supply")
        self.wrpc.addhdkey()

    def tearDown(self):
        # Each simulator is stopped by the cleanup registered immediately after
        # it starts, including when a later simulator fails to start.
        pass

    def _device_args(self, device):
        args = ["-t", device.type, "-d", device.path, "--chain", "test"]
        if device.password is not None:
            args.extend(["-p", device.password])
        return args

    def _device_sign(self, device, registration, psbt):
        result = self.do_command(self._device_args(device) + [
            "signtx",
            "--registration", registration,
            psbt,
        ])
        self.assertNotIn("error", result)
        self.assertTrue(result["signed"])
        return result["psbt"]

    def test_coldcard_ledger_core(self):
        account_path = "m/87h/1h/0h"
        device_keys = []
        for device in self.devices:
            xpub = self.do_command(
                self._device_args(device) + ["getxpub", account_path]
            )["xpub"]
            device_keys.append(
                f"[{device.fingerprint}{account_path[1:]}]{xpub}"
            )

        core_info = self.wrpc.derivehdkey(path=account_path)
        core_key = core_info["origin"] + core_info["xpub"]
        descriptor = "tr(musig({})/<0;1>/*)".format(
            ",".join(device_keys + [core_key])
        )

        registrations = {}
        for device in self.devices:
            result = self.do_command(self._device_args(device) + [
                "registerdescriptor", "MuSigInterop", descriptor,
            ])
            self.assertNotIn("error", result)
            registrations[device] = result["registration"]

        imported = self.wrpc.importdescriptors([{
            "desc": AddChecksum(descriptor),
            "timestamp": "now",
            "active": True,
        }])
        self.assertTrue(imported[0]["success"])

        receive_address = self.wrpc.getnewaddress("", "bech32m")
        for device in self.devices:
            display = self.do_command(self._device_args(device) + [
                "displayaddress",
                "--index", "0",
                "--registration", registrations[device],
            ])
            self.assertNotIn("error", display)
            self.assertEqual(
                bech32.decode("tb", display["address"]),
                bech32.decode("bcrt", receive_address),
            )

        self.wpk_rpc.sendtoaddress(receive_address, 1)
        self.wpk_rpc.generatetoaddress(1, self.wpk_rpc.getnewaddress())
        psbt = self.wrpc.walletcreatefundedpsbt(
            [],
            [{self.wpk_rpc.getnewaddress("", "bech32m"): 0.5}],
            0,
            {"includeWatching": True},
            True,
        )["psbt"]
        self.assertEqual(self.rpc.decodepsbt(psbt)["psbt_version"], 2)
        nonce_psbts = [
            self._device_sign(device, registrations[device], psbt)
            for device in self.devices
        ]
        nonce_psbts.append(
            self.wrpc.walletprocesspsbt(psbt=psbt, finalize=False)["psbt"]
        )
        nonce_psbt = self.rpc.combinepsbt(nonce_psbts)
        decoded = self.rpc.decodepsbt(nonce_psbt)
        self.assertEqual(len(decoded["inputs"][0]["musig2_pubnonces"]), 3)

        partial_sig_psbts = [
            self._device_sign(device, registrations[device], nonce_psbt)
            for device in self.devices
        ]
        partial_sig_psbts.append(
            self.wrpc.walletprocesspsbt(
                psbt=nonce_psbt,
                finalize=False,
            )["psbt"]
        )
        signed_psbt = self.rpc.combinepsbt(partial_sig_psbts)
        decoded = self.rpc.decodepsbt(signed_psbt)
        self.assertEqual(
            len(decoded["inputs"][0]["musig2_partial_sigs"]),
            3,
        )

        finalized = self.rpc.finalizepsbt(signed_psbt)
        self.assertTrue(finalized["complete"])
        txid = self.rpc.sendrawtransaction(finalized["hex"])
        self.wpk_rpc.generatetoaddress(1, self.wpk_rpc.getnewaddress())
        self.assertGreaterEqual(self.wrpc.gettransaction(txid)["confirmations"], 1)


def interoperability_test_suite(
    coldcard_edge_path,
    ledger_path,
    bitcoind,
    interface,
):
    coldcard_edge = ColdcardSimulator(coldcard_edge_path, is_edge=True)
    ledger = LedgerEmulator(ledger_path)
    suite = unittest.TestSuite()
    suite.addTest(TestMuSig2Interoperability(
        bitcoind,
        coldcard_edge,
        ledger,
        interface,
        "test_coldcard_ledger_core",
    ))
    return unittest.TextTestRunner(
        stream=sys.stdout,
        verbosity=2,
    ).run(suite).wasSuccessful()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Test interoperability between hardware wallet devices"
    )
    parser.add_argument(
        "--coldcard-edge-path",
        default="work/firmware/unix/simulator.py",
        help="Path to the Coldcard Edge simulator",
    )
    parser.add_argument(
        "--ledger-path",
        default="work/speculos/speculos.py",
        help="Path to the Ledger emulator",
    )
    parser.add_argument(
        "--bitcoind",
        default="work/bitcoin/build/bin/bitcoind",
        help="Path to bitcoind",
    )
    parser.add_argument(
        "--interface",
        choices=["library", "cli", "bindist", "stdin"],
        default="library",
        help="Which interface to send commands over",
    )
    args = parser.parse_args()

    bitcoind = Bitcoind.create(args.bitcoind)
    success = interoperability_test_suite(
        args.coldcard_edge_path,
        args.ledger_path,
        bitcoind,
        args.interface,
    )
    sys.exit(not success)
