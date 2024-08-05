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
from .ledger_bitcoin.client_base import ApduException
from .ledger_bitcoin.exception import NotSupportedError
from .ledger_bitcoin.wallet import (
    MultisigWallet,
    WalletPolicy,
)
from .ledger_bitcoin.btchip.btchipException import BTChipException

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
    is_p2sh,
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
    0x50: "ledger_nano_s_plus",
    0x60: "ledger_stax",
    0x70: "ledger_flex"
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

# The priority of address types we want for signing.
# We want to do Taproot first, then segwit, then legacy
# Higher number is lower priority so that sort does not require reversing.
signing_priority = {
    AddressType.TAP: 0,
    AddressType.WIT: 1,
    AddressType.SH_WIT: 2,
    AddressType.LEGACY: 3,
}

def handle_chip_exception(e: Union[BTChipException, ApduException], func_name: str) -> bool:
    if e.sw in bad_args:
        raise BadArgumentError('Bad argument')
    elif e.sw == 0x6F00: # BTCHIP_SW_TECHNICAL_PROBLEM
        raise DeviceFailureError(e.message)
    elif e.sw == 0x6FAA: # BTCHIP_SW_HALTED
        raise DeviceConnectionError('Device is asleep')
    elif e.sw in cancels:
        raise ActionCanceledError('{} canceled'.format(func_name))
    else:
        raise e

def ledger_exception(f: Callable[..., Any]) -> Any:
    @wraps(f)
    def func(*args: Any, **kwargs: Any) -> Any:
        try:
            return f(*args, **kwargs)
        except ValueError as e:
            raise BadArgumentError(str(e))
        except BTChipException as e:
            handle_chip_exception(e, f.__name__)
        except ApduException as e:
            e.message = e.data.decode("utf-8")
            handle_chip_exception(e, f.__name__)
    return func

# This class extends the HardwareWalletClient for Ledger Nano S and Nano X specific things
class LedgerClient(HardwareWalletClient):

    def __init__(self, path: str, password: Optional[str] = None, expert: bool = False, chain: Chain = Chain.MAIN) -> None:
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

        For application versions 1.x and 2.0.x:

        - Transactions containing both segwit and non-segwit inputs are not entirely supported; only the segwit inputs will be signed in this case.

        For application versions 2.1.x and above:

        - Only keys derived with standard BIP 44, 49, 84, and 86 derivation paths are supported for single signature addresses.
        """
        master_fp = self.get_master_fingerprint()

        def legacy_sign_tx() -> PSBT:
            client = self.client
            if not isinstance(client, LegacyClient):
                client = LegacyClient(self.transport_client, self.chain)
            wallet = WalletPolicy("", "wpkh(@0/**)", [""])
            legacy_input_sigs = client.sign_psbt(tx, wallet, None)

            for idx, pubkey, sig in legacy_input_sigs:
                psbt_in = tx.inputs[idx]
                psbt_in.partial_sigs[pubkey] = sig
            return tx

        if isinstance(self.client, LegacyClient):
            return legacy_sign_tx()

        # Make a deepcopy of this psbt. We will need to modify it to get signing to work,
        # which will affect the caller's detection for whether signing occured.
        psbt2 = copy.deepcopy(tx)
        if tx.version != 2:
            psbt2.convert_to_v2()

        # Figure out which wallets are signing
        wallets: Dict[bytes, Tuple[int, AddressType, WalletPolicy, Optional[bytes]]] = {}
        pubkeys: Dict[int, bytes] = {}
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
                                key_exprs.append(PubkeyProvider(xpub_origin, xpub.to_string(), None).to_string(hardened_char="'"))
                                break
                        else:
                            # No xpub, Ledger will not accept this multisig
                            ok = False

                if not ok:
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

            for idx, pubkey, sig in input_sigs:
                psbt_in = psbt2.inputs[idx]

                utxo = None
                if psbt_in.witness_utxo:
                    utxo = psbt_in.witness_utxo
                if psbt_in.non_witness_utxo:
                    assert psbt_in.prev_out is not None
                    utxo = psbt_in.non_witness_utxo.vout[psbt_in.prev_out]
                assert utxo is not None

                is_wit, wit_ver, _ = utxo.is_witness()

                if is_wit and wit_ver >= 1:
                    # TODO: Deal with script path signatures
                    # For now, assume key path signature
                    psbt_in.tap_key_sig = sig
                else:
                    psbt_in.partial_sigs[pubkey] = sig

        # Extract the sigs from psbt2 and put them into tx
        for sig_in, psbt_in in zip(psbt2.inputs, tx.inputs):
            psbt_in.partial_sigs.update(sig_in.partial_sigs)
            psbt_in.tap_script_sigs.update(sig_in.tap_script_sigs)
            if len(sig_in.tap_key_sig) != 0 and len(psbt_in.tap_key_sig) == 0:
                psbt_in.tap_key_sig = sig_in.tap_key_sig

        return tx

    @ledger_exception
    def sign_message(self, message: Union[str, bytes], keypath: str) -> str:
        if not check_keypath(keypath):
            raise ValueError("Invalid keypath")

        # Ledger requires the character "'" for hardened derivations since version 2.0.0
        keypath = keypath.replace("h", "'")

        return self.client.sign_message(message, keypath)

    def _get_singlesig_default_wallet_policy(self, addr_type: AddressType, account: int) -> WalletPolicy:
        if addr_type == AddressType.LEGACY:
            template = "pkh(@0/**)"
        elif addr_type == AddressType.WIT:
            template = "wpkh(@0/**)"
        elif addr_type == AddressType.SH_WIT:
            template = "sh(wpkh(@0/**))"
        elif addr_type == AddressType.TAP:
            template = "tr(@0/**)"
        else:
            BadArgumentError("Unknown address type")

        path = [H_(get_bip44_purpose(addr_type)), H_(get_bip44_chain(self.chain)), H_(account)]

        # Build a PubkeyProvider for the key we're going to use
        origin = KeyOriginInfo(self.get_master_fingerprint(), path)
        pk_prov = PubkeyProvider(origin, self.get_pubkey_at_path(f"m{origin._path_string()}").to_string(), None)
        key_str = pk_prov.to_string(hardened_char="'")

        # Make the Wallet object
        return WalletPolicy(name="", descriptor_template=template, keys_info=[key_str])

    @ledger_exception
    def display_singlesig_address(
        self,
        keypath: str,
        addr_type: AddressType,
    ) -> str:
        path = parse_path(keypath)

        if isinstance(self.client, LegacyClient):
            if addr_type == AddressType.LEGACY:
                template = "pkh(@0/**)"
            elif addr_type == AddressType.WIT:
                template = "wpkh(@0/**)"
            elif addr_type == AddressType.SH_WIT:
                template = "sh(wpkh(@0/**))"
            elif addr_type == AddressType.TAP:
                BadArgumentError("Taproot is not supported by this version of the Bitcoin App")
            else:
                BadArgumentError("Unknown address type")

            origin = KeyOriginInfo(self.get_master_fingerprint(), path)
            wallet = WalletPolicy(name="", descriptor_template=template, keys_info=["[{}]".format(origin.to_string(hardened_char="'"))])
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
        if isinstance(self.client, LegacyClient):
            raise BadArgumentError("Displaying multisignature addresses is not supported by this version of the Bitcoin App")

        def is_valid_der_path(path: Optional[str]) -> bool:
            if path is None:
                return False
            path_parts = path.split("/")
            return len(path_parts) == 3 and path_parts[1] in ["0", "1"] and path_parts[2].isdigit() and 0 <= int(path_parts[2]) <= 0x7fffffff

        if any(not is_valid_der_path(pk.deriv_path) for pk in multisig.pubkeys):
            raise BadArgumentError("Ledger Bitcoin app requires derivation paths ending with /0/* or /1/* for multisig")

        if not (all(pk.deriv_path == multisig.pubkeys[0].deriv_path for pk in multisig.pubkeys)):
            raise BadArgumentError("Ledger Bitcoin app requires all derivation paths to end with /0/*, or all with /1/* for multisig")

        if any(pk.origin is not None and len(pk.origin.path) > 4 for pk in multisig.pubkeys):
            raise BadArgumentError("Ledger Bitcoin app requires extended keys with derivation length at most 4")

        def format_key_info(pubkey: PubkeyProvider) -> str:
            assert pubkey.origin is not None and pubkey.extkey is not None
            hardened_char = "'"
            return f"[{pubkey.origin.to_string(hardened_char=hardened_char)}]{pubkey.extkey.to_string()}"

        keys_info = [format_key_info(pk) for pk in multisig.pubkeys]

        multisig_wallet = MultisigWallet(f"{multisig.thresh} of {len(keys_info)} Multisig", addr_type, multisig.thresh, keys_info=keys_info, sorted=multisig.is_sorted)
        _, registered_hmac = self.client.register_wallet(multisig_wallet)

        assert multisig.pubkeys[0].deriv_path is not None  # already checked above with is_valid_der_path
        change = 0 if multisig.pubkeys[0].deriv_path[:3] == "/0/" else 1
        address_index = int(multisig.pubkeys[0].deriv_path.split("/")[2])

        return self.client.get_wallet_address(multisig_wallet, registered_hmac, change, address_index, True)

    def setup_device(self, label: str = "", passphrase: str = "") -> bool:
        """
        Ledgers do not support setup via software.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Ledger Nano S and X do not support software setup')

    def wipe_device(self) -> bool:
        """
        Ledgers do not support wiping via software.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Ledger Nano S and X do not support wiping via software')

    def restore_device(self, label: str = "", word_count: int = 24) -> bool:
        """
        Ledgers do not support restoring via software.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Ledger Nano S and X do not support restoring via software')

    def backup_device(self, label: str = "", passphrase: str = "") -> bool:
        """
        Ledgers do not support backing up via software.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Ledger Nano S and X do not support creating a backup via software')

    def close(self) -> None:
        self.client.stop()

    def prompt_pin(self) -> bool:
        """
        Ledgers do not need a PIN sent from the host.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Ledger Nano S and X do not need a PIN sent from the host')

    def send_pin(self, pin: str) -> bool:
        """
        Ledgers do not need a PIN sent from the host.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Ledger Nano S and X do not need a PIN sent from the host')

    def toggle_passphrase(self) -> bool:
        """
        Ledgers do not support toggling passphrase from the host.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Ledger Nano S and X do not support toggling passphrase from the host')

    @ledger_exception
    def can_sign_taproot(self) -> bool:
        """
        Ledgers support Taproot if the Bitcoin App version greater than 2.0.0; support here is for versions 2.1.0 and above.

        :returns: True if Bitcoin App version is greater than or equal to 2.1.0, and not the "Legacy" release. False otherwise.
        """
        return isinstance(self.client, NewClient)


def enumerate(password: Optional[str] = None, expert: bool = False, chain: Chain = Chain.MAIN, allow_emulators: bool = False) -> List[Dict[str, Any]]:
    results = []
    devices = []
    devices.extend(hid.enumerate(LEDGER_VENDOR_ID, 0))
    if allow_emulators:
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
