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
    Optional,
    Tuple,
    Union,
)

from ..descriptor import (
    MultisigDescriptor,
    PubkeyProvider,
)
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
)
from .ledger_bitcoin.client import (
    createClient,
    NewClient,
    LegacyClient,
    TransportClient,
)
from .ledger_bitcoin.client_legacy import DongleAdaptor
from .ledger_bitcoin.exception import NotSupportedError
from .ledger_bitcoin.wallet import (
    MultisigWallet,
    PolicyMapWallet,
)
from .ledger_bitcoin.btchip.btchipException import BTChipException
from .ledger_bitcoin.btchip.btchip import btchip

import base64
import builtins
import copy
import hid

from ..key import (
    ExtendedKey,
    get_bip44_purpose,
    get_bip44_chain,
    H_,
    is_standard_path,
    KeyOriginInfo,
    parse_path,
)
from .._script import (
    is_opreturn,
    is_p2pkh,
    is_p2sh,
    is_p2wpkh,
    is_p2wsh,
    is_witness,
    parse_multisig,
)
from ..psbt import PSBT
import logging
import re

SIMULATOR_PATH = 'tcp:127.0.0.1:9999'

LEDGER_VENDOR_ID = 0x2c97
LEDGER_MODEL_IDS = {
    0x10: "ledger_nano_s",
    0x40: "ledger_nano_x",
    0x50: "ledger_nano_s_plus"
}
LEDGER_LEGACY_PRODUCT_IDS = {
    0x0001: "ledger_nano_s",
    0x0004: "ledger_nano_x",
    0x0005: "ledger_nano_s_plus"
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

# The priority of address types we want for signing.
# We want to do Taproot first, then segwit, then legacy
# Higher number is lower priority so that sort does not require reversing.
signing_priority = {
    AddressType.TAP: 0,
    AddressType.WIT: 1,
    AddressType.SH_WIT: 2,
    AddressType.LEGACY: 3,
}

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

# This class extends the HardwareWalletClient for Ledger Nano S, Nano S Plus and Nano X specific things
class LedgerClient(HardwareWalletClient):

    def __init__(self, path: str, password: str = "", expert: bool = False, chain: Chain = Chain.MAIN) -> None:
        super(LedgerClient, self).__init__(path, password, expert, chain)

        is_debug = logging.getLogger().getEffectiveLevel() == logging.DEBUG

        try:
            if path.startswith('tcp'):
                split_path = path.split(':')
                server = split_path[1]
                port = int(split_path[2])
                self.transport_client = TransportClient(interface="tcp", server=server, port=port, debug=is_debug)
            else:
                self.transport_client = TransportClient(interface="hid", debug=is_debug, hid_path=path.encode())

            self.client = createClient(self.transport_client, chain=self.chain, debug=is_debug)
        except NotSupportedError as e:
            raise DeviceConnectionError(e.args[2])

    @ledger_exception
    def get_master_fingerprint(self) -> bytes:
        return self.client.get_master_fingerprint()

    @ledger_exception
    def get_pubkey_at_path(self, path: str) -> ExtendedKey:
        path = path.replace("h", "'")
        path = path.replace("H", "'")
        try:
            xpub_str = self.client.get_extended_pubkey(path=path, display=False)
        except NotSupportedError:
            # We will get not supported for non-standard paths
            # If so, try again but with display=True
            xpub_str = self.client.get_extended_pubkey(path=path, display=True)
        return ExtendedKey.deserialize(xpub_str)

    @ledger_exception
    def sign_tx(self, tx: PSBT) -> PSBT:
        """
        Sign a transaction with a Ledger device. Not all transactions can be signed by a Ledger.

        The scripts supported depend on the version of the Bitcoin Application installed on the Ledger.

        For application versions 1.x:

        - Transactions containing both segwit and non-segwit inputs are not entirely supported; only the segwit inputs will be signed in this case.

        For application versions 2.x:

        - Transactions containing OP_RETURN outputs are not supported.
        - Transactions containing multisig inputs involving the device more than once and also have Taproot outputs are currently not supported.
        - Only keys derived with standard BIP 44, 49, 84, and 86 derivation paths are supported.
        - Multisigs must only contain this device a single time. This is a limitation of the firmware.
        """
        master_fp = self.get_master_fingerprint()

        def legacy_sign_tx() -> PSBT:
            client = self.client
            if not isinstance(client, LegacyClient):
                client = LegacyClient(self.transport_client, self.chain)
            wallet = PolicyMapWallet("", "wpkh(@0)", [""])
            legacy_input_sigs = client.sign_psbt(tx, wallet, None)

            for idx, sigs in legacy_input_sigs.items():
                psbt_in = tx.inputs[idx]
                psbt_in.partial_sigs.update(sigs)
            return tx

        if isinstance(self.client, LegacyClient):
            return legacy_sign_tx()

        # Make a deepcopy of this psbt. We will need to modify it to get signing to work,
        # which will affect the caller's detection for whether signing occured.
        psbt2 = copy.deepcopy(tx)
        if tx.version != 2:
            psbt2.convert_to_v2()

        # Figure out which wallets are signing
        wallets: Dict[bytes, Tuple[int, AddressType, PolicyMapWallet, Optional[bytes]]] = {}
        pubkeys: Dict[int, bytes] = {}
        retry_legacy = False
        for input_num, psbt_in in builtins.enumerate(psbt2.inputs):
            utxo = None
            scriptcode = b""
            if psbt_in.witness_utxo:
                utxo = psbt_in.witness_utxo
            if psbt_in.non_witness_utxo:
                if psbt_in.prev_txid != psbt_in.non_witness_utxo.hash:
                    raise BadArgumentError(f"Input {input_num} has a non_witness_utxo with the wrong hash")
                assert psbt_in.prev_out is not None
                utxo = psbt_in.non_witness_utxo.vout[psbt_in.prev_out]
                psbt_in.witness_utxo = utxo # Make sure that all inputs have witness_utxo too as signing mixed will fail
            if utxo is None:
                continue
            scriptcode = utxo.scriptPubKey

            p2sh = False
            if is_p2sh(scriptcode):
                if len(psbt_in.redeem_script) == 0:
                    continue
                scriptcode = psbt_in.redeem_script
                p2sh = True

            is_wit, wit_ver, _ = is_witness(scriptcode)

            script_addrtype = AddressType.LEGACY
            if is_wit:
                if p2sh:
                    if wit_ver == 0:
                        script_addrtype = AddressType.SH_WIT
                    else:
                        raise BadArgumentError("Cannot have witness v1+ in p2sh")
                else:
                    if wit_ver == 0:
                        script_addrtype = AddressType.WIT
                    elif wit_ver == 1:
                        script_addrtype = AddressType.TAP
                    else:
                        continue

            # Check if P2WSH
            if is_p2wsh(scriptcode):
                if len(psbt_in.witness_script) == 0:
                    continue
                scriptcode = psbt_in.witness_script

            multisig = parse_multisig(scriptcode)
            if multisig is not None:
                k, ms_pubkeys = multisig

                # Figure out the parent xpubs
                key_exprs: List[str] = []
                ok = True
                our_keys = 0
                for pub in ms_pubkeys:
                    if pub in psbt_in.hd_keypaths:
                        pk_origin = psbt_in.hd_keypaths[pub]
                        if pk_origin.fingerprint == master_fp:
                            our_keys += 1
                            pubkeys[input_num] = pub
                        for xpub_bytes, xpub_origin in psbt2.xpub.items():
                            xpub = ExtendedKey.from_bytes(xpub_bytes)
                            if (xpub_origin.fingerprint == pk_origin.fingerprint) and (xpub_origin.path == pk_origin.path[:len(xpub_origin.path)]):
                                key_exprs.append(PubkeyProvider(xpub_origin, xpub.to_string(), "/**").to_string())
                                break
                        else:
                            # No xpub, Ledger will not accept this multisig
                            ok = False
                    else:
                        # No origin info, Ledger will not accept this multisig
                        ok = False

                if not ok:
                    retry_legacy = True
                    continue

                if our_keys != 1:
                    # Ledger does not allow having more than one key per multisig
                    retry_legacy = True
                    continue

                # Make and register the MultisigWallet
                msw = MultisigWallet(f"{k} of {len(key_exprs)} Multisig", script_addrtype, k, key_exprs)
                msw_id = msw.id
                if msw_id not in wallets:
                    _, registered_hmac = self.client.register_wallet(msw)
                    wallets[msw_id] = (
                        signing_priority[script_addrtype],
                        script_addrtype,
                        msw,
                        registered_hmac,
                    )
            else:
                def process_origin(origin: KeyOriginInfo) -> None:
                    if not is_standard_path(origin.path, script_addrtype, self.chain):
                        # TODO: Deal with non-default wallets
                        return
                    policy = self._get_singlesig_default_wallet_policy(script_addrtype, origin.path[2])
                    wallets[policy.id] = (
                        signing_priority[script_addrtype],
                        script_addrtype,
                        self._get_singlesig_default_wallet_policy(script_addrtype, origin.path[2]),
                        None, # Wallet hmac
                    )

                for key, origin in psbt_in.hd_keypaths.items():
                    if origin.fingerprint == master_fp:
                        if not multisig:
                            process_origin(origin)
                        pubkeys[input_num] = key

                for key, (leaf_hashes, origin) in psbt_in.tap_bip32_paths.items():
                    # TODO: Support script path signing
                    if key == psbt_in.tap_internal_key and origin.fingerprint == master_fp:
                        process_origin(origin)
                        pubkeys[input_num] = key

        # For each wallet, sign
        for _, (_, addrtype, wallet, wallet_hmac) in sorted(wallets.items(), key=lambda y: y[1][0]):
            if addrtype == AddressType.LEGACY:
                # We need to remove witness_utxo for legacy inputs when signing with legacy otherwise signing will fail
                for psbt_in in psbt2.inputs:
                    utxo = None
                    if psbt_in.witness_utxo:
                        utxo = psbt_in.witness_utxo
                    if utxo is None:
                        continue
                    is_wit, _, _ = is_witness(utxo.scriptPubKey)
                    if not is_wit:
                        psbt_in.witness_utxo = None

            input_sigs = self.client.sign_psbt(psbt2, wallet, wallet_hmac)

            for idx, sig in input_sigs.items():
                psbt_in = psbt2.inputs[idx]

                utxo = None
                if psbt_in.witness_utxo:
                    utxo = psbt_in.witness_utxo
                if psbt_in.non_witness_utxo:
                    if psbt_in.prev_txid != psbt_in.non_witness_utxo.hash:
                        raise BadArgumentError(f"Input {input_num} has a non_witness_utxo with the wrong hash")
                    assert psbt_in.prev_out is not None
                    utxo = psbt_in.non_witness_utxo.vout[psbt_in.prev_out]
                assert utxo is not None

                is_wit, wit_ver, _ = utxo.is_witness()

                if is_wit and wit_ver >= 1:
                    # TODO: Deal with script path signatures
                    # For now, assume key path signature
                    psbt_in.tap_key_sig = sig
                else:
                    pubkey = pubkeys[idx]
                    psbt_in.partial_sigs[pubkey] = sig

        # Extract the sigs from psbt2 and put them into tx
        for sig_in, psbt_in in zip(psbt2.inputs, tx.inputs):
            psbt_in.partial_sigs.update(sig_in.partial_sigs)
            psbt_in.tap_script_sigs.update(sig_in.tap_script_sigs)
            if len(sig_in.tap_key_sig) != 0 and len(psbt_in.tap_key_sig) == 0:
                psbt_in.tap_key_sig = sig_in.tap_key_sig

        # There are some situations where we want to retry with the legacy protocol
        # So do that if we should.
        if retry_legacy:
            # But the legacy protocol only supports legacy and segwit v0, so only retry if those are the only outputs types
            for output in tx.outputs:
                if not (
                    is_opreturn(output.script)
                    or is_p2sh(output.script)
                    or is_p2pkh(output.script)
                    or is_p2wpkh(output.script)
                    or is_p2wsh(output.script)
                ):
                    break
            else:
                return legacy_sign_tx()

        return tx

    @ledger_exception
    def sign_message(self, message: Union[str, bytes], keypath: str) -> str:
        app = btchip(DongleAdaptor(self.transport_client))

        if not check_keypath(keypath):
            raise BadArgumentError("Invalid keypath")
        if isinstance(message, str):
            message = bytearray(message, 'utf-8')
        else:
            message = bytearray(message)
        keypath = keypath[2:]
        # First display on screen what address you're signing for
        app.getWalletPublicKey(keypath, True)
        app.signMessagePrepare(keypath, message)
        signature = app.signMessageSign()

        # Make signature into standard bitcoin format
        rLength = signature[3]
        r = int.from_bytes(signature[4: 4 + rLength], byteorder="big", signed=True)
        s = int.from_bytes(signature[4 + rLength + 2:], byteorder="big", signed=True)

        sig = bytearray(chr(27 + 4 + (signature[0] & 0x01)), 'utf8') + r.to_bytes(32, byteorder="big", signed=False) + s.to_bytes(32, byteorder="big", signed=False)

        return base64.b64encode(sig).decode('utf-8')

    def _get_singlesig_default_wallet_policy(self, addr_type: AddressType, account: int) -> PolicyMapWallet:
        if addr_type == AddressType.LEGACY:
            template = "pkh(@0)"
        elif addr_type == AddressType.WIT:
            template = "wpkh(@0)"
        elif addr_type == AddressType.SH_WIT:
            template = "sh(wpkh(@0))"
        elif addr_type == AddressType.TAP:
            template = "tr(@0)"
        else:
            BadArgumentError("Unknown address type")

        path = [H_(get_bip44_purpose(addr_type)), H_(get_bip44_chain(self.chain)), H_(account)]

        # Build a PubkeyProvider for the key we're going to use
        origin = KeyOriginInfo(self.get_master_fingerprint(), path)
        pk_prov = PubkeyProvider(origin, self.get_pubkey_at_path(f"m{origin._path_string()}").to_string(), "/**")
        key_str = pk_prov.to_string()

        # Make the Wallet object
        return PolicyMapWallet(name="", policy_map=template, keys_info=[key_str])

    @ledger_exception
    def display_singlesig_address(
        self,
        keypath: str,
        addr_type: AddressType,
    ) -> str:
        path = parse_path(keypath)

        if isinstance(self.client, LegacyClient):
            if addr_type == AddressType.LEGACY:
                template = "pkh(@0)"
            elif addr_type == AddressType.WIT:
                template = "wpkh(@0)"
            elif addr_type == AddressType.SH_WIT:
                template = "sh(wpkh(@0))"
            elif addr_type == AddressType.TAP:
                BadArgumentError("Taproot is not supported by this version of the Bitcoin App")
            else:
                BadArgumentError("Unknown address type")

            origin = KeyOriginInfo(self.get_master_fingerprint(), path)
            wallet = PolicyMapWallet(name="", policy_map=template, keys_info=[f"[{origin.to_string()}]"])
        else:
            if not is_standard_path(path, addr_type, self.chain):
                raise BadArgumentError("Ledger requires BIP 44 standard paths")

            wallet = self._get_singlesig_default_wallet_policy(addr_type, path[2])

        return self.client.get_wallet_address(wallet, None, path[-2], path[-1], True)

    @ledger_exception
    def display_multisig_address(
        self,
        addr_type: AddressType,
        multisig: MultisigDescriptor,
    ) -> str:
        raise BadArgumentError("The Ledger Nano S and X do not support P2(W)SH address display")

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
        self.client.stop()

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

    @ledger_exception
    def can_sign_taproot(self) -> bool:
        """
        Ledgers support Taproot if the Bitcoin App version greater than 2.0.0.

        :returns: True if Bitcoin App version is greater than or equal to 2.0.0. False otherwise.
        """
        return isinstance(self.client, NewClient)


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
            d_data['label'] = None
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
                except (BTChipException, ConnectionRefusedError):
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
