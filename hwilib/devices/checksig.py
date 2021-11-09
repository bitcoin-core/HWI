import base64
from typing import Dict, Union

from hwilib.key import ExtendedKey

from ..errors import ActionCanceledError, DeviceConnectionError
from ..hwwclient import HardwareWalletClient
from hwilib.psbt import PSBT
from .checksiglib.ipc import ipc_connect, ipc_send_and_get_response
from .checksiglib.ipc_message import PING, SIGN_MESSAGE, SIGN_TX, XPUB, IpcMessage
from .checksiglib.settings import LISTEN_PORT, PORT_RANGE
from hwilib._base58 import xpub_main_2_test
from hwilib.common import Chain


class ChecksigClient(HardwareWalletClient):
    def __init__(self, path: str, password: str = "", expert: bool = False) -> None:
        super().__init__(path, password, expert)
        # Used to know where to connect for this device
        self.port = int(path.split(":")[1])

    # Segwit V0 only
    def sign_tx(self, psbt: PSBT) -> PSBT:

        sock = ipc_connect(self.port)

        if sock is None:
            raise DeviceConnectionError(
                "Unable to open a tcp socket with the CheckSig device"
            )

        serialized_psbt = psbt.serialize()
        data = serialized_psbt + "\n"
        msg = IpcMessage(SIGN_TX, data)

        resp = ipc_send_and_get_response(sock, msg)

        if resp is None:
            raise ActionCanceledError("CheckSig device did not sign tx")

        psbt = PSBT()
        psbt.deserialize(resp.get_raw_value())
        return psbt

    def sign_message(
        self, message: Union[str, bytes], bip32_path: str
    ) -> str:
        if isinstance(message, str):
            message = message.encode()
        sock = ipc_connect(self.port)

        if sock is None:
            raise DeviceConnectionError(
                "Unable to open a tcp socket with the CheckSig device"
            )

        message_b64 = base64.b64encode(message).decode("utf-8")
        data = message_b64 + "\n" + bip32_path
        msg = IpcMessage(SIGN_MESSAGE, data)

        resp = ipc_send_and_get_response(sock, msg)

        if resp is None:
            raise ActionCanceledError("CheckSig device did not sign message")

        return base64.b64decode(resp.get_raw_value()).decode()

    def close(self):
        pass

    def get_pubkey_at_path(self, bip32_path: str) -> ExtendedKey:
        sock = ipc_connect(self.port)

        if sock is None:
            raise DeviceConnectionError(
                "Unable to open a tcp socket with the checksig device"
            )

        data = bip32_path + "\n"
        msg = IpcMessage(XPUB, data)
        resp = ipc_send_and_get_response(sock, msg)
        if resp is None:
            raise ActionCanceledError("CheckSig device did not return pubkey at bip32_path")

        xpub = base64.b64decode(resp.get_raw_value()).decode("utf-8")

        if self.chain != Chain.MAIN:
            xpub = xpub_main_2_test(xpub)

        return ExtendedKey.deserialize(xpub)


def enumerate(password=""):
    results = []

    # Loop on the range port to check listening devices
    for i in range(PORT_RANGE):
        try:
            port = LISTEN_PORT + i
            sock = ipc_connect(port)

            if sock is None:
                continue

            ping_resp = ipc_send_and_get_response(sock, IpcMessage(PING, ""))
            if ping_resp is None:
                continue

            d_data = {
                "type": "checksig",
                "model": "checksig_hwi",
                "path": "127.0.0.1:" + str(port),
                "needs_pin_sent": False,
                "needs_passphrase_sent": False,
                "fingerprint": ping_resp.get_raw_value(),
            }
            results.append(d_data)

            sock.close()
        except Exception:
            continue

    return results
