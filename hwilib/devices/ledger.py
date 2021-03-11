"""
Ledger Devices
**************
"""

from functools import wraps
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Union,
    Tuple,
)

from ..descriptor import MultisigDescriptor
from ..hwwclient import HardwareWalletClient
from ..errors import (
    ActionCanceledError,
    BadArgumentError,
    DeviceConnectionError,
    DeviceFailureError,
    UnavailableActionError,
    UnknownDeviceError,
    common_err_msgs,
    handle_errors,
)
from ..common import (
    AddressType,
    Chain,
    hash160,
)
from .btchip.bitcoinTransaction import bitcoinTransaction
from .btchip.btchip import btchip
from .btchip.btchipComm import (
    DongleServer,
    HIDDongleHIDAPI,
)
from .btchip.btchipException import BTChipException
from .btchip.btchipUtils import compress_public_key
import base64
import hid
import struct

from ..key import (
    ExtendedKey,
    parse_path,
)
from .._script import (
    is_p2sh,
    is_p2wpkh,
    is_p2wsh,
    is_witness,
)
from ..psbt import PSBT
from ..tx import (
    CTransaction,
)
import logging
import re

SIMULATOR_PATH = 'tcp:127.0.0.1:9999'

LEDGER_VENDOR_ID = 0x2c97
LEDGER_MODEL_IDS = {
    0x10: "ledger_nano_s",
    0x40: "ledger_nano_x"
}
LEDGER_LEGACY_PRODUCT_IDS = {
    0x0001: "ledger_nano_s",
    0x0004: "ledger_nano_x"
}

# minimal checking of string keypath
def check_keypath(key_path: str) -> bool:
    parts = re.split("/", key_path)
    if parts[0] != "m":
        return False
    # strip hardening chars
    for index in parts[1:]:
        index_int = re.sub('[hH\']', '', index)
        if not index_int.isdigit():
            return False
        if int(index_int) > 0x80000000:
            return False
    return True

bad_args = [
    0x6700, # BTCHIP_SW_INCORRECT_LENGTH
    0x6A80, # BTCHIP_SW_INCORRECT_DATA
    0x6B00, # BTCHIP_SW_INCORRECT_P1_P2
    0x6D00, # BTCHIP_SW_INS_NOT_SUPPORTED
]

cancels = [
    0x6982, # BTCHIP_SW_SECURITY_STATUS_NOT_SATISFIED
    0x6985, # BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED
]

def ledger_exception(f: Callable[..., Any]) -> Any:
    @wraps(f)
    def func(*args: Any, **kwargs: Any) -> Any:
        try:
            return f(*args, **kwargs)
        except ValueError as e:
            raise BadArgumentError(str(e))
        except BTChipException as e:
            if e.sw in bad_args:
                raise BadArgumentError('Bad argument')
            elif e.sw == 0x6F00: # BTCHIP_SW_TECHNICAL_PROBLEM
                raise DeviceFailureError(e.message)
            elif e.sw == 0x6FAA: # BTCHIP_SW_HALTED
                raise DeviceConnectionError('Device is asleep')
            elif e.sw in cancels:
                raise ActionCanceledError('{} canceled'.format(f.__name__))
            else:
                raise e
    return func

# This class extends the HardwareWalletClient for Ledger Nano S and Nano X specific things
class LedgerClient(HardwareWalletClient):

    def __init__(self, path: str, password: str = "", expert: bool = False) -> None:
        super(LedgerClient, self).__init__(path, password, expert)

        if path.startswith('tcp'):
            split_path = path.split(':')
            server = split_path[1]
            port = int(split_path[2])
            self.dongle = DongleServer(server, port, logging.getLogger().getEffectiveLevel() == logging.DEBUG)
        else:
            device = hid.device()
            device.open_path(path.encode())
            device.set_nonblocking(True)

            self.dongle = HIDDongleHIDAPI(device, True, logging.getLogger().getEffectiveLevel() == logging.DEBUG)

        self.app = btchip(self.dongle)

        if self.app.getAppName() not in ["Bitcoin", "Bitcoin Test", "app"]:
            raise UnknownDeviceError("Ledger is not in either the Bitcoin or Bitcoin Testnet app")

    @ledger_exception
    def get_pubkey_at_path(self, path: str) -> ExtendedKey:
        if not check_keypath(path):
            raise BadArgumentError("Invalid keypath")
        path = path[2:]
        path = path.replace('h', '\'')
        path = path.replace('H', '\'')
        # This call returns raw uncompressed pubkey, chaincode
        pubkey = self.app.getWalletPublicKey(path)
        int_path = parse_path(path)
        if len(path) > 0:
            parent_path = ""
            for ind in path.split("/")[:-1]:
                parent_path += ind + "/"
            parent_path = parent_path[:-1]

            # Get parent key fingerprint
            parent = self.app.getWalletPublicKey(parent_path)
            fpr = hash160(compress_public_key(parent["publicKey"]))[:4]

            child = int_path[-1]
        # Special case for m
        else:
            child = 0
            fpr = b"\x00\x00\x00\x00"

        xpub = ExtendedKey(
            version=ExtendedKey.MAINNET_PUBLIC if self.chain == Chain.MAIN else ExtendedKey.TESTNET_PUBLIC,
            depth=len(path.split("/")) if len(path) > 0 else 0,
            parent_fingerprint=fpr,
            child_num=child,
            chaincode=pubkey["chainCode"],
            privkey=None,
            pubkey=compress_public_key(pubkey["publicKey"]),
        )
        return xpub

    @ledger_exception
    def sign_tx(self, tx: PSBT) -> PSBT:
        """
        Sign a transaction with a Ledger device. Not all transactiosn can be signed by a Ledger.

        - Transactions containing both segwit and non-segwit inputs are not entirely supported; only the segwit inputs wil lbe signed in this case.
        """
        c_tx = CTransaction(tx.tx)
        tx_bytes = c_tx.serialize_with_witness()

        # Master key fingerprint
        master_fpr = hash160(compress_public_key(self.app.getWalletPublicKey('')["publicKey"]))[:4]
        # An entry per input, each with 0 to many keys to sign with
        all_signature_attempts: List[List[Tuple[str, bytes]]] = [[]] * len(c_tx.vin)

        # Get the app version to determine whether to use Trusted Input for segwit
        version = self.app.getFirmwareVersion()
        use_trusted_segwit = (version['major_version'] == 1 and version['minor_version'] >= 4) or version['major_version'] > 1

        # NOTE: We only support signing Segwit inputs, where we can skip over non-segwit
        # inputs, or non-segwit inputs, where *all* inputs are non-segwit. This is due
        # to Ledger's mutually exclusive signing steps for each type.
        segwit_inputs = []
        # Legacy style inputs
        legacy_inputs = []

        has_segwit = False
        has_legacy = False

        script_codes: List[bytes] = [b""] * len(c_tx.vin)

        # Detect changepath, (p2sh-)p2(w)pkh only
        change_path = ''
        for txout, i_num in zip(c_tx.vout, range(len(c_tx.vout))):
            # Find which wallet key could be change based on hdsplit: m/.../1/k
            # Wallets shouldn't be sending to change address as user action
            # otherwise this will get confused
            for pubkey, origin in tx.outputs[i_num].hd_keypaths.items():
                if origin.fingerprint == master_fpr and len(origin.path) > 1 and origin.path[-2] == 1:
                    # For possible matches, check if pubkey matches possible template
                    if hash160(pubkey) in txout.scriptPubKey or hash160(bytearray.fromhex("0014") + hash160(pubkey)) in txout.scriptPubKey:
                        change_path = ''
                        for index in origin.path:
                            change_path += str(index) + "/"
                        change_path = change_path[:-1]

        for txin, psbt_in, i_num in zip(c_tx.vin, tx.inputs, range(len(c_tx.vin))):

            seq_hex = txin.nSequence.to_bytes(4, byteorder="little").hex()

            scriptcode = b""
            utxo = None
            if psbt_in.witness_utxo:
                utxo = psbt_in.witness_utxo
            if psbt_in.non_witness_utxo:
                if txin.prevout.hash != psbt_in.non_witness_utxo.sha256:
                    raise BadArgumentError('Input {} has a non_witness_utxo with the wrong hash'.format(i_num))
                utxo = psbt_in.non_witness_utxo.vout[txin.prevout.n]
            if utxo is None:
                raise Exception("PSBT is missing input utxo information, cannot sign")
            scriptcode = utxo.scriptPubKey

            if is_p2sh(scriptcode):
                if len(psbt_in.redeem_script) == 0:
                    continue
                scriptcode = psbt_in.redeem_script

            is_wit, _, _ = is_witness(scriptcode)

            segwit_inputs.append({"value": txin.prevout.serialize() + struct.pack("<Q", utxo.nValue), "witness": True, "sequence": seq_hex})
            if is_wit:
                if is_p2wsh(scriptcode):
                    if len(psbt_in.witness_script) == 0:
                        continue
                    scriptcode = psbt_in.witness_script
                elif is_p2wpkh(scriptcode):
                    _, _, wit_prog = is_witness(scriptcode)
                    scriptcode = b"\x76\xa9\x14" + wit_prog + b"\x88\xac"
                else:
                    continue
                has_segwit = True
            else:
                # We only need legacy inputs in the case where all inputs are legacy, we check
                # later
                assert psbt_in.non_witness_utxo is not None
                ledger_prevtx = bitcoinTransaction(psbt_in.non_witness_utxo.serialize())
                legacy_inputs.append(self.app.getTrustedInput(ledger_prevtx, txin.prevout.n))
                legacy_inputs[-1]["sequence"] = seq_hex
                has_legacy = True

            if psbt_in.non_witness_utxo and use_trusted_segwit:
                ledger_prevtx = bitcoinTransaction(psbt_in.non_witness_utxo.serialize())
                segwit_inputs[-1].update(self.app.getTrustedInput(ledger_prevtx, txin.prevout.n))

            pubkeys = []
            signature_attempts = []

            # Save scriptcode for later signing
            script_codes[i_num] = scriptcode

            # Find which pubkeys could sign this input (should be all?)
            for pubkey in psbt_in.hd_keypaths.keys():
                if hash160(pubkey) in scriptcode or pubkey in scriptcode:
                    pubkeys.append(pubkey)

            # Figure out which keys in inputs are from our wallet
            for pubkey in pubkeys:
                keypath = psbt_in.hd_keypaths[pubkey]
                if master_fpr == keypath.fingerprint:
                    # Add the keypath strings
                    keypath_str = keypath.get_derivation_path()[2:] # Drop the leading m/
                    signature_attempts.append((keypath_str, pubkey))

            all_signature_attempts[i_num] = signature_attempts

        # Sign any segwit inputs
        if has_segwit:
            # Process them up front with all scriptcodes blank
            blank_script_code = bytearray()
            for i in range(len(segwit_inputs)):
                self.app.startUntrustedTransaction(i == 0, i, segwit_inputs, script_codes[i] if use_trusted_segwit else blank_script_code, c_tx.nVersion)

            # Number of unused fields for Nano S, only changepath and transaction in bytes req
            self.app.finalizeInput(b"DUMMY", -1, -1, change_path, tx_bytes)

            # For each input we control do segwit signature
            for i in range(len(segwit_inputs)):
                for signature_attempt in all_signature_attempts[i]:
                    self.app.startUntrustedTransaction(False, 0, [segwit_inputs[i]], script_codes[i], c_tx.nVersion)
                    tx.inputs[i].partial_sigs[signature_attempt[1]] = self.app.untrustedHashSign(signature_attempt[0], "", c_tx.nLockTime, 0x01)
        elif has_legacy:
            first_input = True
            # Legacy signing if all inputs are legacy
            for i in range(len(legacy_inputs)):
                for signature_attempt in all_signature_attempts[i]:
                    assert(tx.inputs[i].non_witness_utxo is not None)
                    self.app.startUntrustedTransaction(first_input, i, legacy_inputs, script_codes[i], c_tx.nVersion)
                    self.app.finalizeInput(b"DUMMY", -1, -1, change_path, tx_bytes)
                    tx.inputs[i].partial_sigs[signature_attempt[1]] = self.app.untrustedHashSign(signature_attempt[0], "", c_tx.nLockTime, 0x01)
                    first_input = False

        # Send PSBT back
        return tx

    @ledger_exception
    def sign_message(self, message: Union[str, bytes], keypath: str) -> str:
        if not check_keypath(keypath):
            raise BadArgumentError("Invalid keypath")
        if isinstance(message, str):
            message = bytearray(message, 'utf-8')
        else:
            message = bytearray(message)
        keypath = keypath[2:]
        # First display on screen what address you're signing for
        self.app.getWalletPublicKey(keypath, True)
        self.app.signMessagePrepare(keypath, message)
        signature = self.app.signMessageSign()

        # Make signature into standard bitcoin format
        rLength = signature[3]
        r = int.from_bytes(signature[4: 4 + rLength], byteorder="big", signed=True)
        s = int.from_bytes(signature[4 + rLength + 2:], byteorder="big", signed=True)

        sig = bytearray(chr(27 + 4 + (signature[0] & 0x01)), 'utf8') + r.to_bytes(32, byteorder="big", signed=False) + s.to_bytes(32, byteorder="big", signed=False)

        return base64.b64encode(sig).decode('utf-8')

    @ledger_exception
    def display_singlesig_address(
        self,
        keypath: str,
        addr_type: AddressType,
    ) -> str:
        if not check_keypath(keypath):
            raise BadArgumentError("Invalid keypath")
        p2sh_p2wpkh = addr_type == AddressType.SH_WIT
        bech32 = addr_type == AddressType.WIT
        output = self.app.getWalletPublicKey(keypath[2:], True, p2sh_p2wpkh or bech32, bech32)
        assert isinstance(output["address"], str)
        return output['address'][12:-2] # HACK: A bug in getWalletPublicKey results in the address being returned as the string "bytearray(b'<address>')". This extracts the actual address to work around this.

    @ledger_exception
    def display_multisig_address(
        self,
        addr_type: AddressType,
        multisig: MultisigDescriptor,
    ) -> str:
        raise BadArgumentError("The Ledger Nano S and X do not support P2SH address display")

    def setup_device(self, label: str = "", passphrase: str = "") -> bool:
        """
        The Coldcard does not support setup via software.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Ledger Nano S and X do not support software setup')

    def wipe_device(self) -> bool:
        """
        The Coldcard does not support wiping via software.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Ledger Nano S and X do not support wiping via software')

    def restore_device(self, label: str = "", word_count: int = 24) -> bool:
        """
        The Coldcard does not support restoring via software.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Ledger Nano S and X do not support restoring via software')

    def backup_device(self, label: str = "", passphrase: str = "") -> bool:
        """
        The Coldcard does not support backing up via software.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Ledger Nano S and X do not support creating a backup via software')

    def close(self) -> None:
        self.dongle.close()

    def prompt_pin(self) -> bool:
        """
        The Coldcard does not need a PIN sent from the host.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Ledger Nano S and X do not need a PIN sent from the host')

    def send_pin(self, pin: str) -> bool:
        """
        The Coldcard does not need a PIN sent from the host.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Ledger Nano S and X do not need a PIN sent from the host')

    def toggle_passphrase(self) -> bool:
        """
        The Coldcard does not support toggling passphrase from the host.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Ledger Nano S and X do not support toggling passphrase from the host')

def enumerate(password: str = '') -> List[Dict[str, Any]]:
    results = []
    devices = []
    devices.extend(hid.enumerate(LEDGER_VENDOR_ID, 0))
    devices.append({'path': SIMULATOR_PATH.encode(), 'interface_number': 0, 'product_id': 0x1000})

    for d in devices:
        if ('interface_number' in d and d['interface_number'] == 0
                or ('usage_page' in d and d['usage_page'] == 0xffa0)):
            d_data: Dict[str, Any] = {}

            path = d['path'].decode()
            d_data['type'] = 'ledger'
            model = d['product_id'] >> 8
            if model in LEDGER_MODEL_IDS.keys():
                d_data['model'] = LEDGER_MODEL_IDS[model]
            elif d['product_id'] in LEDGER_LEGACY_PRODUCT_IDS.keys():
                d_data['model'] = LEDGER_LEGACY_PRODUCT_IDS[d['product_id']]
            else:
                continue
            d_data['path'] = path

            if path == SIMULATOR_PATH:
                d_data['model'] += '_simulator'

            client = None
            with handle_errors(common_err_msgs["enumerate"], d_data):
                try:
                    client = LedgerClient(path, password)
                    d_data['fingerprint'] = client.get_master_fingerprint().hex()
                    d_data['needs_pin_sent'] = False
                    d_data['needs_passphrase_sent'] = False
                except BTChipException:
                    # Ignore simulator if there's an exception, means it isn't there
                    if path == SIMULATOR_PATH:
                        continue
                    else:
                        raise
                except UnknownDeviceError:
                    # This only happens if the ledger is not in the Bitcoin app, so skip it
                    continue

            if client:
                client.close()

            results.append(d_data)

    return results
