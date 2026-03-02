"""
Cypherock X1
************
"""

from typing import (
    Any,
    Dict,
    List,
    Optional,
    Union
)

from .cypherock_sdk.app_btc import BtcApp
from .cypherock_sdk.app_btc.operations import GetPublicKeyParams, GetXpubsParams, SignTxnParams
from .cypherock_sdk.app_btc.operations.types import SignTxnInputData, SignTxnOutputData, SignTxnTxnData
from .cypherock_sdk.app_manager import ManagerApp
from .cypherock_sdk.hw_hid import get_available_devices, DeviceConnection
from .cypherock_sdk.interfaces import IDevice

from .. import _base58 as base58
from ..common import AddressType, Chain, hash256
from ..descriptor import MultisigDescriptor
from ..errors import BadArgumentError, DeviceConnectionError, UnavailableActionError
from ..hwwclient import HardwareWalletClient
from ..key import ExtendedKey, is_standard_path, parse_path
from ..psbt import PSBT
from .._script import is_p2sh, is_p2wsh, is_witness, parse_multisig
from .._serialize import ser_uint256

py_enumerate = enumerate # Need to use the enumerate built-in but there's another function already named that


def convert_xpub_to_standard(xpub: str, chain: Chain = Chain.MAIN) -> str:
    """Convert any xpub format to standard xpub format."""
    decoded = base58.decode(xpub)

    if chain == Chain.MAIN:
        standard_version = ExtendedKey.MAINNET_PUBLIC
    else:
        standard_version = ExtendedKey.TESTNET_PUBLIC

    decoded_with_standard_version = standard_version + decoded[4:-4]
    checksum = hash256(decoded_with_standard_version)[:4]
    standard_xpub = base58.encode(decoded_with_standard_version + checksum)

    return standard_xpub

class CypherockClient(HardwareWalletClient):
    """
    The `CypherockClient` is a `HardwareWalletClient` for interacting with Cypherock X1 devices.
    """

    def __init__(self, path: str, password: Optional[str] = None, expert: bool = False, chain: Chain = Chain.MAIN) -> None:
        super(CypherockClient, self).__init__(path, password, expert, chain)

        all_devices = get_available_devices()
        for device in all_devices:
            if device["path"] == path:
                self.device: IDevice = device
                break
        else:
            raise DeviceConnectionError(f"Device not found: {path}")

        try:
            self.connection = DeviceConnection.connect(self.device)
            self.manager_app = ManagerApp.create(self.connection)
            self.btc_app = BtcApp.create(self.connection)
        except Exception as e:
            raise DeviceConnectionError(f"Failed to connect to Cypherock X1: {e}")

    def get_master_fingerprint(self) -> bytes:
        return bytes.fromhex(self.device["fingerprint"])

    def get_pubkey_at_path(self, path: str) -> ExtendedKey:
        """
        Get the public key at the BIP 32 derivation path.
        The Cypherock X1 only supports BIP 32 derivation paths of at least depth 3.

        :param path: The BIP 32 derivation path
        :return: The extended public key
        """
        parsed_path = parse_path(path)
        if len(parsed_path) < 3:
            raise BadArgumentError(f"The Cypherock X1 only supports BIP 32 derivation paths of at least depth 3, but {path} has depth {len(parsed_path)}")

        wallet_id = self.select_wallet()
        params = GetXpubsParams(wallet_id=wallet_id, derivation_paths=[{"path": parsed_path[0:3]}])
        response = self.btc_app.get_xpubs(params)
        standard_xpub = convert_xpub_to_standard(response.xpubs[0])
        return ExtendedKey.deserialize(standard_xpub).derive_pub_path(parsed_path[3:])

    def sign_tx(self, tx: PSBT) -> PSBT:
        """
        Sign a transaction with the Cypherock X1.
        :param tx: The transaction to sign
        :return: The signed transaction

        :note: It only supports legacy singlesig transactions for now.
        """
        master_fp = self.get_master_fingerprint()

        # Determine derivation path from first input
        derivation_path = None
        for psbt_in in tx.inputs:
            for _, keypath in psbt_in.hd_keypaths.items():
                if keypath.fingerprint == master_fp and len(keypath.path) >= 3:
                    # Extract purpose/coin/account (first 3 elements, hardened)
                    derivation_path = keypath.path[:3]
                    break
            if derivation_path:
                break

        if not derivation_path:
            raise ValueError("Could not determine derivation path from PSBT")

        script_addrtype = None
        txn_inputs = []
        for i, psbt_in in py_enumerate(tx.inputs):
            # Get previous txid and output index
            prev_txid = ser_uint256(tx.tx.vin[i].prevout.hash)
            prev_index = tx.tx.vin[i].prevout.n

            # Get previous transaction
            if psbt_in.non_witness_utxo:
                prev_tx = psbt_in.non_witness_utxo
                if prev_index >= len(prev_tx.vout):
                    raise ValueError(f"Invalid prev_index {prev_index} for input {i}, length of vout is {len(prev_tx.vout)}")
                prev_txn_bytes = prev_tx.serialize()
                prev_out = prev_tx.vout[prev_index]
            else:
                raise ValueError(f"Input {i} missing full previous transaction data")

            # Get value and script_pub_key from previous output
            value = prev_out.nValue
            script_pub_key = prev_out.scriptPubKey
            sequence = psbt_in.sequence

            p2sh = False
            if is_p2sh(script_pub_key):
                if len(psbt_in.redeem_script) == 0:
                    continue
                script_pub_key = psbt_in.redeem_script
                p2sh = True

            is_wit, wit_ver, _ = is_witness(script_pub_key)

            curr_script_addrtype = AddressType.LEGACY
            if is_wit:
                if p2sh:
                    if wit_ver == 0:
                        curr_script_addrtype = AddressType.SH_WIT
                    else:
                        raise BadArgumentError("Cannot have witness v1+ in p2sh")
                else:
                    if wit_ver == 0:
                        curr_script_addrtype = AddressType.WIT
                    elif wit_ver == 1:
                        curr_script_addrtype = AddressType.TAP
                    else:
                        continue

            if script_addrtype is None:
                script_addrtype = curr_script_addrtype
            elif script_addrtype != curr_script_addrtype:
                raise BadArgumentError("Cypherock X1 does not support inputs with different script address types yet")

            # Check if P2WSH
            if is_p2wsh(script_pub_key):
                if len(psbt_in.witness_script) == 0:
                    continue
                script_pub_key = psbt_in.witness_script

            multisig = parse_multisig(script_pub_key)
            if multisig:
                raise BadArgumentError("Cypherock X1 does not support multisig yet")

            # Extract change_index and address_index from derivation path
            change_index = None
            address_index = None
            for _, keypath in psbt_in.hd_keypaths.items():
                if keypath.fingerprint == master_fp:
                    if not is_standard_path(keypath.path, curr_script_addrtype, Chain.MAIN):
                        raise BadArgumentError(f"Cypherock X1 requires BIP 44 standard paths, but {keypath.path} is not a standard path")
                    change_index = keypath.path[3]
                    address_index = keypath.path[4]
                    break
            if change_index is None or address_index is None:
                raise BadArgumentError("Could not determine change_index and address_index from derivation path")

            txn_inputs.append(SignTxnInputData(
                prev_txn_id=prev_txid,
                prev_index=prev_index,
                value=value,
                script_pub_key=script_pub_key,
                change_index=change_index,
                address_index=address_index,
                prev_txn=prev_txn_bytes,
                sequence=sequence,
            ))

        # Convert PSBT outputs (similar logic for outputs)
        txn_outputs = []
        for i, psbt_out in py_enumerate(tx.outputs):
            output = tx.tx.vout[i]
            value = output.nValue
            script_pub_key = output.scriptPubKey

            # Determine if change output (check hd_keypaths)
            is_change = False
            address_index = None
            for _, keypath in psbt_out.hd_keypaths.items():
                if keypath.fingerprint == master_fp:
                    path = keypath.path
                    if len(path) >= 5:
                        # If change index (path[3]) is 1, it's a change output
                        is_change = path[3] == 1
                        if is_change:
                            address_index = path[4]

            txn_outputs.append(SignTxnOutputData(
                value=value,
                script_pub_key=script_pub_key,
                is_change=is_change,
                address_index=address_index,
            ))

        # Create transaction data
        txn_data = SignTxnTxnData(
            inputs=txn_inputs,
            outputs=txn_outputs,
            locktime=tx.tx.nLockTime if hasattr(tx.tx, 'nLockTime') else None,
            hash_type=tx.inputs[0].sighash if tx.inputs and tx.inputs[0].sighash else None,
        )

        # Sign transaction
        params = SignTxnParams(
            wallet_id=self.select_wallet(),
            derivation_path=derivation_path,
            txn=txn_data,
        )
        result = self.btc_app.sign_txn(params)

        # Add signatures back to PSBT
        for i, signature in py_enumerate(result.signatures):
            psbt_in = tx.inputs[i]

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
                psbt_in.tap_key_sig = signature[:64]
            else:
                # Find the pubkey that matches our derivation path
                for pubkey, keypath in psbt_in.hd_keypaths.items():
                    if keypath.fingerprint == master_fp:
                        # signature is script sig, extract der from it
                        der_sig = signature[1: signature[2] + 3]
                        psbt_in.partial_sigs[pubkey] = der_sig
                        break

        return tx

    def sign_message(self, message: Union[str, bytes], keypath: str) -> str:
        """
        Cypherock X1 does not support signing messages yet.

        :raises UnavailableActionError: this function is unavailable for now
        """
        raise UnavailableActionError('The Cypherock X1 does not support signing messages yet')

    def display_singlesig_address(
        self,
        keypath: str,
        addr_type: AddressType,
    ) -> str:
        parsed_path = parse_path(keypath)
        if not is_standard_path(parsed_path, addr_type, self.chain):
            raise BadArgumentError(f"Cypherock X1 requires BIP 44 standard paths, but {keypath} is not a standard path")

        wallet_id = self.select_wallet()
        params = GetPublicKeyParams(wallet_id=wallet_id, derivation_path=parsed_path)
        response = self.btc_app.get_public_key(params)
        return response.address

    def display_multisig_address(
        self,
        addr_type: AddressType,
        multisig: MultisigDescriptor,
    ) -> str:
        """
        Cypherock X1 does not support multisig addresses yet.

        :raises UnavailableActionError: this function is unavailable for now
        """
        raise UnavailableActionError('The Cypherock X1 does not support multisig addresses yet')

    def setup_device(self, label: str = "", passphrase: str = "") -> bool:
        """
        Cypherock X1 does not support setup via software.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Cypherock X1 does not support software setup')

    def wipe_device(self) -> bool:
        """
        Cypherock X1 does not support wiping via software.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Cypherock X1 does not support wiping via software')

    def restore_device(self, label: str = "", word_count: int = 24) -> bool:
        """
        Cypherock X1 does not support restoring via software.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Cypherock X1 does not support restoring via software')

    def backup_device(self, label: str = "", passphrase: str = "") -> bool:
        """
        Cypherock X1 does not support backing up via software.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Cypherock X1 does not support creating a backup via software')

    def close(self) -> None:
        self.connection.destroy()

    def prompt_pin(self) -> bool:
        """
        Cypherock X1 does not need a PIN sent from the host.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Cypherock X1 does not need a PIN sent from the host')

    def send_pin(self, pin: str) -> bool:
        """
        Cypherock X1 does not need a PIN sent from the host.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Cypherock X1 does not need a PIN sent from the host')

    def toggle_passphrase(self) -> bool:
        """
        Cypherock X1 does not support toggling passphrase from the host.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Cypherock X1 does not support toggling passphrase from the host')

    def can_sign_taproot(self) -> bool:
        """
        Cypherock X1 supports Taproot if the Firmware version is greater than or equal to 0.6.3089

        :returns: True if Firmware version is greater than or equal to 0.6.3089, False otherwise.
        """
        return True

    def select_wallet(self) -> bytes:
        wallet_info = self.manager_app.select_wallet()
        return wallet_info.wallet.id

def enumerate(password: Optional[str] = None, expert: bool = False, chain: Chain = Chain.MAIN, allow_emulators: bool = False) -> List[Dict[str, Any]]:
    return get_available_devices()
