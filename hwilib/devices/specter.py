# Specter interaction script
import time
import socket
from typing import Dict, Optional, Union
from hwilib.common import Chain
from hwilib.key import ExtendedKey

from hwilib.psbt import PSBT
from hwilib.hwwclient import HardwareWalletClient
from hwilib.errors import (
    ActionCanceledError,
    BadArgumentError,
    DeviceBusyError,
    UnavailableActionError,
)
from hwilib._base58 import xpub_main_2_test
import hwilib._base58 as b58
from hwilib.descriptor import Descriptor
from binascii import b2a_base64
from typing import Dict, Optional, Union

import serial
import serial.tools.list_ports


class SpecterClient(HardwareWalletClient):

    # timeout large enough to handle xpub derivations
    TIMEOUT = 30

    def __init__(self, path: str, password: str = "", expert: bool = False) -> None:
        super().__init__(path, password, expert)
        self.simulator = ":" in path
        self.dev: Union[SpecterSimulator, SpecterUSBDevice]
        self.dev = SpecterSimulator(path) if self.simulator else SpecterUSBDevice(path)

    def query(self, data: str, timeout: Optional[float] = None) -> str:
        """Send a text-based query to the device and get back the response"""
        res = self.dev.query(data, timeout)
        if res == "error: User cancelled":
            raise ActionCanceledError("User didn't confirm action")
        elif res.startswith("error: Unknown command"):
            raise UnavailableActionError(res[7:])
        elif res.startswith("error: "):
            raise BadArgumentError(res[7:])
        return res

    def get_master_fingerprint_hex(self) -> str:
        return self.query("fingerprint", timeout=self.TIMEOUT)

    def get_pubkey_at_path(self, bip32_path: str) -> ExtendedKey:
        # this should be fast
        xpub = self.query("xpub %s" % bip32_path, timeout=self.TIMEOUT)
        # Specter returns xpub with a prefix
        # for a network currently selected on the device
        if self.chain == Chain.MAIN:
            xpub = xpub_test_2_main(xpub)
        else:
            xpub = xpub_main_2_test(xpub)
        return ExtendedKey.deserialize(xpub)

    def sign_tx(self, psbt: PSBT) -> PSBT:

        # this one can hang for quite some time
        response = self.query("sign %s" % psbt.serialize())
        signed_psbt = PSBT()
        signed_psbt.deserialize(response)
        # adding partial sigs to initial tx
        for i in range(len(psbt.inputs)):
            for k in signed_psbt.inputs[i].partial_sigs:
                psbt.inputs[i].partial_sigs[k] = signed_psbt.inputs[i].partial_sigs[k]
        return psbt

    def sign_message(self, message: Union[str, bytes], bip32_path: str) -> str:
        # convert message string to bytes
        if isinstance(message, str):
            msg = message.encode()
            # check if ascii - we only support ascii characters display
            try:
                msg.decode("ascii")
                fmt = "ascii"
            except UnicodeDecodeError:
                fmt = "base64"
            # with python >= 3.7 the above try/except should be:
            # fmt = "ascii" if msg.isascii() else "base64"
        else:
            msg = message
            fmt = "base64"

        # check if there is \r or \n in the message
        # in this case we need to encode to base64
        if b"\r" in msg or b"\n" in msg:
            fmt = "base64"
        # convert to base64 if necessary
        if fmt == "base64":
            msg = b2a_base64(msg).strip()
        return self.query(f"signmessage {bip32_path} {fmt}:{msg.decode()}")

    def display_address(
        self,
        bip32_path: str,
        p2sh_p2wpkh: bool,
        bech32: bool,
        redeem_script: Optional[str] = None,
        descriptor: Optional[Descriptor] = None,
    ) -> Dict[str, str]:
        script_type = "pkh" if redeem_script is None else "sh"
        if p2sh_p2wpkh:
            script_type = f"sh-w{script_type}"
        elif bech32:
            script_type = f"w{script_type}"
        # prepare a request of the form like
        # `showaddr sh-wsh m/1h/2h/3 descriptor`
        request = f"showaddr {script_type} {bip32_path}"
        if redeem_script is not None:
            request += f" {redeem_script}"
        address = self.query(request)
        return {"address": address}

    def close(self):
        pass

    # extra functions Specter supports ############

    def get_random(self, num_bytes: int = 32) -> bytes:
        "Return random bytes."
        if num_bytes < 0 or num_bytes > 10000:
            raise BadArgumentError("We can only get up to 10k bytes of random data")
        res = self.query("getrandom %d" % num_bytes)
        return bytes.fromhex(res)

    def import_wallet(self, name: str, descriptor: str):
        # TODO: implement and document
        pass


def enumerate(password: str = "", expert: bool = False, chain: Chain = Chain.MAIN):
    """
    Returns a list of detected Specter devices
    with their fingerprints and client's paths
    """
    results = []
    # find ports with micropython's VID
    ports = [
        port.device
        for port in serial.tools.list_ports.comports()
        if is_micropython(port)
    ]
    try:
        # check if there is a simulator on port 8789
        # and we can connect to it
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 8789))
        s.close()
        ports.append("127.0.0.1:8789")
    except Exception as e:
        print(e)

    for port in ports:
        # for every port try to get a fingerprint
        try:
            path = port
            data = {
                "type": "specter",
                "model": "specter-diy",
                "path": path,
                "needs_passphrase": False,
            }
            client = SpecterClient(path)
            data["fingerprint"] = client.get_master_fingerprint_hex()
            client.close()
            results.append(data)
        except Exception as e:
            print(e)
    return results


# Helper functions and base classes ##############


def xpub_test_2_main(xpub: str) -> str:
    data = b58.decode(xpub)
    main_data = b"\x04\x88\xb2\x1e" + data[4:-4]
    checksum = b58.hash256(main_data)[0:4]
    return b58.encode(main_data + checksum)


def is_micropython(port) -> bool:
    return "VID:PID=F055:" in port.hwid.upper()


class SpecterBase:
    """Class with common constants and command encoding"""

    EOL = b"\r\n"
    ACK = b"ACK"
    ACK_TIMOUT = 3

    def prepare_cmd(self, data):
        """
        Prepends command with 2*EOL and appends EOL at the end.
        Double EOL in the beginning makes sure all pending data
        will be cleaned up.
        """
        return self.EOL * 2 + data.encode("utf-8") + self.EOL


class SpecterUSBDevice(SpecterBase):
    """
    Base class for USB device.
    Implements a simple query command over serial
    """

    def __init__(self, path):
        self.ser = serial.Serial(baudrate=115200, timeout=30)
        self.ser.port = path

    def read_until(self, eol, timeout=None):
        t0 = time.time()
        res = b""
        while eol not in res:
            try:
                raw = self.ser.read(1)
                res += raw
            except Exception:
                time.sleep(0.01)
            if timeout is not None and time.time() > t0 + timeout:
                self.ser.close()
                raise DeviceBusyError("Timeout")
        return res

    def query(self, data, timeout=None):
        # non blocking
        self.ser.timeout = 0
        self.ser.open()
        self.ser.write(self.prepare_cmd(data))
        # first we should get ACK
        res = self.read_until(self.EOL, self.ACK_TIMOUT)[: -len(self.EOL)]
        # then we should get the data itself
        if res != self.ACK:
            self.ser.close()
            raise DeviceBusyError("Device didn't return ACK")
        res = self.read_until(self.EOL, timeout)[: -len(self.EOL)]
        self.ser.close()
        return res.decode()


class SpecterSimulator(SpecterBase):
    """
    Base class for the simulator.
    Implements a simple query command over tcp/ip socket
    """

    def __init__(self, path):
        arr = path.split(":")
        self.sock_settings = (arr[0], int(arr[1]))

    def read_until(self, s, eol, timeout=None):
        t0 = time.time()
        res = b""
        while eol not in res:
            try:
                raw = s.recv(1)
                res += raw
            except Exception:
                time.sleep(0.01)
            if timeout is not None and time.time() > t0 + timeout:
                s.close()
                raise DeviceBusyError("Timeout")
        return res

    def query(self, data, timeout=None):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(self.sock_settings)
        s.send(self.prepare_cmd(data))
        s.setblocking(False)
        # we will get ACK right away
        res = self.read_until(s, self.EOL, self.ACK_TIMOUT)[: -len(self.EOL)]
        if res != self.ACK:
            raise DeviceBusyError("Device didn't return ACK")
        # fetch with required timeout
        res = self.read_until(s, self.EOL, timeout)[: -len(self.EOL)]
        s.close()
        return res.decode()


###### test for communication ######

if __name__ == "__main__":
    import sys

    devices = enumerate()
    if len(devices) == 0:
        print("No devices found")
        sys.exit()
    inp = 0
    if len(devices) > 1:
        print("Found %d devices." % len(devices))
        for i, dev in enumerate(devices):
            print("[%d]" % i, dev)
        inp = int(raw_input("Enter the device number to use:"))
        if inp > len(devices):
            print("Meh... Screw you.")
            sys.exit()
    dev = SpecterClient(devices[inp]["path"])
    if len(sys.argv) == 1:
        mfp = dev.get_master_fingerprint_hex()
        derivation = "m/84h/0h/0h"
        xpub = dev.get_pubkey_at_path(derivation)["xpub"]
        print(f"Device fingerprint: {mfp}")
        print(f"Segwit xpub: {xpub}")
        print(f"Full key: [{mfp}{derivation[1:]}]{xpub}")
    else:
        if "-i" not in sys.argv:
            cmd = " ".join(sys.argv[1:])
            print("Running command:", cmd)
            print(dev.query(cmd))
        else:
            cmd = ""
            print("Interactive mode! Enter `quit` to exit.")
            while inp != "quit":
                cmd = input("Enter command to run: ")
                if cmd == "quit":
                    sys.exit(0)
                print(dev.query(cmd))
