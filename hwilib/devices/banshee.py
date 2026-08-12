"""
Banshee Devices
***************

Banshee is an open-source Bitcoin hardware wallet firmware for the LilyGo T-Display S3
(ESP32-S3). Communication is a newline-delimited text protocol over USB serial at 115200 baud.

Firmware and protocol documentation: https://github.com/CuseTheJuice/my-banshee-hardware-app
"""

from __future__ import annotations

import base64
import time
from typing import Any, Dict, List, Optional

import serial
from serial.tools import list_ports

from ..common import AddressType, Chain
from ..descriptor import MultisigDescriptor
from ..errors import (
    ActionCanceledError,
    DeviceConnectionError,
    DeviceNotReadyError,
    UnavailableActionError,
    common_err_msgs,
    handle_errors,
)
from ..hwwclient import HardwareWalletClient
from ..key import ExtendedKey, parse_path
from ..psbt import PSBT

BANSHEE_VID = 0x303A
BANSHEE_PID = 0xB05E
BANSHEE_DEVICE_IDS = [(BANSHEE_VID, BANSHEE_PID)]

BAUD = 115200
DEFAULT_TIMEOUT = 5
SIGN_TIMEOUT = 70


def _network_for_chain(chain: Chain) -> str:
    if chain in (Chain.TEST, Chain.SIGNET, Chain.REGTEST):
        return 'testnet'
    return 'mainnet'


class BansheeClient(HardwareWalletClient):
    def __init__(
        self,
        path: str,
        password: Optional[str] = None,
        expert: bool = False,
        chain: Chain = Chain.MAIN,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        super().__init__(path, password, expert, chain)
        self._timeout = timeout
        self._ser = serial.Serial(path, BAUD, timeout=timeout, write_timeout=timeout)
        self._ser.setRTS(False)
        self._ser.setDTR(False)
        self._network = _network_for_chain(chain)
        self._drain_banner()
        status = self._command('WALLET_STATUS')
        if 'ready=0' in status:
            raise DeviceNotReadyError(
                'Banshee wallet not initialized. Initialize the wallet on the device first.'
            )

    def close(self) -> None:
        if self._ser and self._ser.is_open:
            self._ser.close()

    def _drain_banner(self) -> None:
        deadline = time.time() + 2.0
        while time.time() < deadline:
            line = self._read_line(timeout=0.25)
            if not line:
                continue
            if line.startswith('OK READY'):
                return
            if line.startswith('OK ') or line.startswith('ERR '):
                return

    def _read_line(self, timeout: Optional[float] = None) -> str:
        old = self._ser.timeout
        if timeout is not None:
            self._ser.timeout = timeout
        try:
            line = self._ser.readline()
        finally:
            self._ser.timeout = old
        if not line:
            return ''
        return line.decode('utf-8', errors='replace').strip()

    def _command(self, cmd: str, timeout: Optional[float] = None) -> str:
        self._ser.write((cmd + '\n').encode('utf-8'))
        self._ser.flush()
        resp = self._read_line(timeout=timeout if timeout is not None else self._timeout)
        if resp.startswith('ERR '):
            raise DeviceConnectionError(resp[4:])
        if not resp.startswith('OK '):
            raise DeviceConnectionError(resp or 'invalid response')
        return resp[3:]

    def get_master_fingerprint(self) -> bytes:
        rest = self._command('GET_FINGERPRINT')
        if not rest.startswith('FINGERPRINT '):
            raise DeviceConnectionError(rest)
        return bytes.fromhex(rest.split(' ', 1)[1].strip())

    def get_pubkey_at_path(self, bip32_path: str) -> ExtendedKey:
        parse_path(bip32_path)
        path_str = bip32_path.replace("'", 'h')
        rest = self._command(f'GET_XPUB {self._network} {path_str}')
        if not rest.startswith('XPUB '):
            raise DeviceConnectionError(rest)
        xpub = ExtendedKey.deserialize(rest[5:].strip())
        if self.chain != Chain.MAIN:
            xpub.version = ExtendedKey.TESTNET_PUBLIC
        return xpub

    def sign_tx(self, tx: PSBT) -> PSBT:
        tx.convert_to_v0()
        b64 = base64.b64encode(tx.serialize()).decode('ascii')
        self._ser.write((f'SIGN_PSBT {self._network} {b64}\n').encode('utf-8'))
        self._ser.flush()
        resp = self._read_line(timeout=self._timeout)
        if resp.startswith('ERR '):
            raise DeviceConnectionError(resp[4:])
        if not resp.startswith('OK WAIT'):
            raise DeviceConnectionError(resp or 'invalid response')
        resp = self._read_line(timeout=SIGN_TIMEOUT)
        if resp.startswith('ERR timeout'):
            raise ActionCanceledError('Signing timed out on Banshee (press BOOT to confirm)')
        if resp.startswith('ERR '):
            raise DeviceConnectionError(resp[4:])
        if not resp.startswith('OK PSBT '):
            raise DeviceConnectionError(resp or 'invalid response')
        signed = PSBT()
        signed.deserialize(base64.b64decode(resp[8:].strip()))
        return signed

    def sign_message(self, message, bip32_path: str) -> str:
        raise UnavailableActionError('Banshee does not support message signing yet')

    def display_singlesig_address(self, bip32_path: str, addr_type: AddressType) -> str:
        raise UnavailableActionError('Banshee does not support address display via host yet')

    def display_multisig_address(self, addr_type: AddressType, multisig: MultisigDescriptor) -> str:
        raise UnavailableActionError('Banshee does not support multisig yet')

    def wipe_device(self) -> bool:
        raise UnavailableActionError('Erase the wallet on the device')

    def setup_device(self, label: str = '', passphrase: str = '') -> bool:
        raise UnavailableActionError('Initialize the wallet on the device')

    def restore_device(self, label: str = '', word_count: int = 24) -> bool:
        raise UnavailableActionError('Import the wallet on the device')

    def backup_device(self, label: str = '', passphrase: str = '') -> bool:
        raise UnavailableActionError('View the backup on the device display')

    def prompt_pin(self) -> bool:
        raise UnavailableActionError('Banshee does not use a host PIN')

    def send_pin(self, pin: str) -> bool:
        raise UnavailableActionError('Banshee does not use a host PIN')

    def toggle_passphrase(self) -> bool:
        raise UnavailableActionError('Banshee does not support passphrase from host')

    def can_sign_taproot(self) -> bool:
        return False


def enumerate(
    password: Optional[str] = None,
    expert: bool = False,
    chain: Chain = Chain.MAIN,
    allow_emulators: bool = False,
) -> List[Dict[str, Any]]:
    del password, expert, allow_emulators
    results: List[Dict[str, Any]] = []
    for dev in list_ports.comports():
        if (dev.vid, dev.pid) not in BANSHEE_DEVICE_IDS:
            continue
        d_data: Dict[str, Any] = {
            'type': 'banshee',
            'model': 'banshee',
            'path': dev.device,
            'needs_pin_sent': False,
            'needs_passphrase_sent': False,
        }
        with handle_errors(common_err_msgs['enumerate'], d_data):
            client = BansheeClient(dev.device, chain=chain, timeout=2)
            try:
                d_data['fingerprint'] = client.get_master_fingerprint().hex()
            finally:
                client.close()
        results.append(d_data)
    return results
