"""
BitBox02
********
"""

from typing import (
    cast,
    Any,
    Callable,
    Dict,
    Optional,
    Mapping,
    Union,
    Tuple,
    List,
    Sequence,
    TypeVar,
)
import base64
import builtins
import sys
from functools import wraps

from .._base58 import decode_check, encode_check
from ..descriptor import MultisigDescriptor
from ..hwwclient import HardwareWalletClient
from ..key import ExtendedKey
from .._script import (
    is_p2pkh,
    is_p2wpkh,
    is_p2wsh,
    is_p2tr,
    parse_multisig,
)
from ..psbt import PSBT
from ..tx import (
    CTxOut,
)
from .._serialize import (
    ser_uint256,
    ser_sig_der,
)
from ..errors import (
    HWWError,
    ActionCanceledError,
    BadArgumentError,
    DeviceNotReadyError,
    UnavailableActionError,
    DEVICE_NOT_INITIALIZED,
    handle_errors,
    common_err_msgs,
)
from ..key import (
    KeyOriginInfo,
    parse_path,
)
from ..common import (
    AddressType,
    Chain,
)

import hid

from .bitbox02_lib import util
from .bitbox02_lib import bitbox02
from .bitbox02_lib.communication import (
    devices,
    u2fhid,
    FirmwareVersionOutdatedException,
    Bitbox02Exception,
    UserAbortException,
    HARDENED,
    ERR_GENERIC,
)

from .bitbox02_lib.communication.bitbox_api_protocol import (
    Platform,
    BitBox02Edition,
    BitBoxNoiseConfig,
)

class BitBox02Error(UnavailableActionError):
    def __init__(self, msg: str):
        """
        BitBox02 unexpected error. The BitBox02 does not return give granular error messages,
        so we give hints to as what could be wrong.
        """
        msg = "Input error: {}. A keypath might be invalid. Supported keypaths are: ".format(
            msg
        )
        msg += "m/49'/0'/<account'> for p2wpkh-p2sh; "
        msg += "m/84'/0'/<account'> for p2wpkh; "
        msg += "m/86'/0'/<account'> for p2tr; "
        msg += "m/48'/0'/<account'>/2' for p2wsh multisig; "
        msg += "m/48'/0'/<account'>/1' for p2wsh-p2sh multisig; "
        msg += "m/48'/0'/<account'>' for any supported multisig; "
        msg += "account can be between 0' and 99'; "
        msg += "For address keypaths, append /0/<address index> for a receive and /1/<change index> for a change address."
        super().__init__(msg)


ERR_INVALID_INPUT = 101

PURPOSE_P2WPKH_P2SH = 49 + HARDENED
PURPOSE_P2WPKH = 84 + HARDENED
PURPOSE_MULTISIG_P2WSH = 48 + HARDENED

# External GUI tools using hwi.py as a command line tool to integrate hardware wallets usually do
# not have an actual terminal for IO.
_using_external_gui = sys.stdout is not None and not sys.stdout.isatty()
if _using_external_gui:
    _unpaired_errmsg = "Device not paired yet. Please pair using the BitBoxApp, then close the BitBoxApp and try again."
else:
    _unpaired_errmsg = "Device not paired yet. Please use any subcommand to pair"


class SilentNoiseConfig(util.BitBoxAppNoiseConfig):
    """
    Used during `enumerate()`. Raises an exception if the device is unpaired.
    Attestation check is silent.

    Rationale: enumerate() should not show any dialogs.
    """

    def show_pairing(self, code: str, device_response: Callable[[], bool]) -> bool:
        raise DeviceNotReadyError(_unpaired_errmsg)

    def attestation_check(self, result: bool) -> None:
        pass


class CLINoiseConfig(util.BitBoxAppNoiseConfig):
    """ Noise pairing and attestation check handling in the terminal (stdin/stdout) """

    def show_pairing(self, code: str, device_response: Callable[[], bool]) -> bool:
        if _using_external_gui:
            # The user can't see the pairing in the terminal. The
            # output format is also not appropriate for parsing by
            # external tools doing inter process communication using
            # stdin/stdout. For now, we direct the user to pair in the
            # BitBoxApp instead.
            raise DeviceNotReadyError(_unpaired_errmsg)

        print("Please compare and confirm the pairing code on your BitBox02:")
        print(code)
        if not device_response():
            return False
        return input("Accept pairing? [y]/n: ").strip() != "n"

    def attestation_check(self, result: bool) -> None:
        if result:
            sys.stderr.write("BitBox02 attestation check PASSED\n")
        else:
            sys.stderr.write("BitBox02 attestation check FAILED\n")
            sys.stderr.write(
                "Your BitBox02 might not be genuine. Please contact support@shiftcrypto.ch if the problem persists.\n"
            )


def _keypath_hardened_prefix(keypath: Sequence[int]) -> Sequence[int]:
    for i, e in builtins.enumerate(keypath):
        if e & HARDENED == 0:
            return keypath[:i]
    return keypath


def _xpubs_equal_ignoring_version(xpub1: bytes, xpub2: bytes) -> bool:
    """
    Xpubs: 78 bytes. Returns true if the xpubs are equal, ignoring the 4 byte version.
    The version is not important and allows compatibility with Electrum, which exports PSBTs with
    xpubs using Electrum-style xpub versions.
    """
    return xpub1[4:] == xpub2[4:]


def enumerate(password: Optional[str] = None, expert: bool = False, chain: Chain = Chain.MAIN, allow_emulators: bool = False) -> List[Dict[str, Any]]:
    """
    Enumerate all BitBox02 devices. Bootloaders excluded.
    """
    result = []
    for device_info in devices.get_any_bitbox02s():
        path = device_info["path"].decode()
        client = Bitbox02Client(path)
        client.set_noise_config(SilentNoiseConfig())
        d_data: Dict[str, object] = {}
        bb02 = None
        with handle_errors(common_err_msgs["enumerate"], d_data):
            bb02 = client.init(expect_initialized=None)
        version, platform, edition, unlocked = bitbox02.BitBox02.get_info(
            client.transport
        )
        if platform != Platform.BITBOX02:
            client.close()
            continue
        if edition not in (BitBox02Edition.MULTI, BitBox02Edition.BTCONLY):
            client.close()
            continue

        assert isinstance(edition, BitBox02Edition)

        d_data.update(
            {
                "type": "bitbox02",
                "path": path,
                "model": {
                    BitBox02Edition.MULTI: "bitbox02_multi",
                    BitBox02Edition.BTCONLY: "bitbox02_btconly",
                }[edition],
                "needs_pin_sent": False,
                "needs_passphrase_sent": False,
            }
        )

        if bb02 is not None:
            with handle_errors(common_err_msgs["enumerate"], d_data):
                if not bb02.device_info()["initialized"]:
                    raise DeviceNotReadyError(
                        "BitBox02 is not initialized. Please initialize it using the BitBoxApp."
                    )
                elif not unlocked:
                    raise DeviceNotReadyError(
                        "Please load wallet to unlock."
                        if _using_external_gui
                        else "Please use any subcommand to unlock"
                    )
                d_data["fingerprint"] = client.get_master_fingerprint().hex()

        result.append(d_data)

        client.close()
    return result


T = TypeVar("T", bound=Callable[..., Any])


def bitbox02_exception(f: T) -> T:
    """
    Maps bitbox02 library exceptions into a HWI exceptions.
    """

    @wraps(f)
    def func(*args, **kwargs):  # type: ignore
        """ Wraps f, mapping exceptions. """
        try:
            return f(*args, **kwargs)
        except UserAbortException:
            raise ActionCanceledError("{} canceled".format(f.__name__))
        except Bitbox02Exception as exc:
            if exc.code in (ERR_GENERIC, ERR_INVALID_INPUT):
                raise BitBox02Error(str(exc))
            raise exc
        except FirmwareVersionOutdatedException as exc:
            raise DeviceNotReadyError(str(exc))

    return cast(T, func)


# This class extends the HardwareWalletClient for BitBox02 specific things
class Bitbox02Client(HardwareWalletClient):
    def __init__(self, path: str, password: Optional[str] = None, expert: bool = False, chain: Chain = Chain.MAIN) -> None:
        """
        Initializes a new BitBox02 client instance.
        """
        if password is not None:
            raise BadArgumentError(
                "The BitBox02 does not accept a passphrase from the host. Please enable the passphrase option and enter the passphrase on the device during unlock."
            )
        super().__init__(path, password=password, expert=expert, chain=chain)

        hid_device = hid.device()
        hid_device.open_path(path.encode())
        self.transport = u2fhid.U2FHid(hid_device)
        self.device_path = path

        # use self.init() to access self.bb02.
        self.bb02: Optional[bitbox02.BitBox02] = None

        self.noise_config: BitBoxNoiseConfig = CLINoiseConfig()

    def set_noise_config(self, noise_config: BitBoxNoiseConfig) -> None:
        self.noise_config = noise_config

    def init(self, expect_initialized: Optional[bool] = True) -> bitbox02.BitBox02:
        if self.bb02 is not None:
            return self.bb02

        for device_info in devices.get_any_bitbox02s():
            if device_info["path"].decode() != self.device_path:
                continue

            bb02 = bitbox02.BitBox02(
                transport=self.transport,
                device_info=device_info,
                noise_config=self.noise_config,
            )
            try:
                bb02.check_min_version()
            except FirmwareVersionOutdatedException as exc:
                sys.stderr.write("WARNING: {}\n".format(exc))
                raise
            self.bb02 = bb02
            is_initialized = bb02.device_info()["initialized"]
            if expect_initialized is not None:
                if expect_initialized:
                    if not is_initialized:
                        raise HWWError(
                            "The BitBox02 must be initialized first.",
                            DEVICE_NOT_INITIALIZED,
                        )
                elif is_initialized:
                    raise UnavailableActionError(
                        "The BitBox02 must be wiped before setup."
                    )

            return bb02
        raise Exception(
            "Could not find the hid device info for path {}".format(self.device_path)
        )

    def close(self) -> None:
        self.transport.close()

    def get_master_fingerprint(self) -> bytes:
        """
        HWI by default retrieves the fingerprint at m/ by getting the xpub at m/0', which contains the parent fingerprint.
        The BitBox02 does not support querying arbitrary keypaths, but has an api call return the fingerprint at m/.
        """
        bb02 = self.init()
        return bb02.root_fingerprint()

    def prompt_pin(self) -> bool:
        raise UnavailableActionError(
            "The BitBox02 does not need a PIN sent from the host"
        )

    def send_pin(self, pin: str) -> bool:
        raise UnavailableActionError(
            "The BitBox02 does not need a PIN sent from the host"
        )

    def _get_coin(self) -> "bitbox02.btc.BTCCoin.V":
        if self.chain != Chain.MAIN:
            return bitbox02.btc.TBTC
        return bitbox02.btc.BTC

    def _get_xpub(self, keypath: Sequence[int]) -> str:
        xpub_type = (
            bitbox02.btc.BTCPubRequest.TPUB
            if self.chain != Chain.MAIN
            else bitbox02.btc.BTCPubRequest.XPUB
        )
        return self.init().btc_xpub(
            keypath, coin=self._get_coin(), xpub_type=xpub_type, display=False
        )

    def get_pubkey_at_path(self, bip32_path: str) -> ExtendedKey:
        """
        Fetch the public key at the derivation path.

        The BitBox02 has strict keypath validation.

        The only accepted keypaths for xpubs are (as of firmware v9.4.0):

        - `m/49'/0'/<account'>` for `p2wpkh-p2sh` (segwit wrapped in P2SH)
        - `m/84'/0'/<account'>` for `p2wpkh` (native segwit v0)
        - `m/86'/0'/<account'>` for `p2tr` (native segwit v1)
        - `m/48'/0'/<account'>/2'` for p2wsh multisig (native segwit v0 multisig).
        - `m/48'/0'/<account'>/1'` for p2wsh-p2sh multisig (p2sh-wrapped segwit v0 multisig).
        - `m/48'/0'/<account'>` for p2wsh and p2wsh-p2sh multisig.

        `account'` can be between `0'` and `99'`.

        For address keypaths, append `/0/<address index>` for a receive and `/1/<change index>` for a change
        address. Up to `10000` addresses are supported.

        In testnet mode, the second element must be `1'` (e.g. `m/49'/1'/...`).

        Public keys for the Legacy address type (i.e. P2WPKH and P2SH multisig) derivation path is unsupported.
        """
        path_uint32s = parse_path(bip32_path)
        try:
            xpub_str = self._get_xpub(path_uint32s)
        except Bitbox02Exception as exc:
            raise BitBox02Error(str(exc))
        xpub = ExtendedKey.deserialize(xpub_str)
        return xpub

    def _maybe_register_script_config(
        self, script_config: bitbox02.btc.BTCScriptConfig, keypath: Sequence[int]
    ) -> None:
        bb02 = self.init()
        is_registered = bb02.btc_is_script_config_registered(
            self._get_coin(), script_config, keypath
        )
        if not is_registered:
            bb02.btc_register_script_config(
                coin=self._get_coin(),
                script_config=script_config,
                keypath=keypath,
                name="",  # enter name on the device
                xpub_type=bitbox02.btc.BTCRegisterScriptConfigRequest.AUTO_XPUB_TPUB,
            )

    def _multisig_scriptconfig(
        self,
        threshold: int,
        origin_infos: Mapping[bytes, KeyOriginInfo],
        script_type: "bitbox02.btc.BTCScriptConfig.Multisig.ScriptType.V",
    ) -> Tuple[bytes, bitbox02.btc.BTCScriptConfigWithKeypath]:
        """
        From a threshold, {xpub: KeyOriginInfo} mapping and multisig script type,
        return our xpub and the BitBox02 multisig script config.
        """
        # Figure out which of the cosigners is us.
        device_fingerprint = self.get_master_fingerprint()
        our_xpub_index = None
        our_account_keypath = None

        xpubs: List[bytes] = []
        for i, (xpub, keyinfo) in builtins.enumerate(origin_infos.items()):
            xpubs.append(xpub)
            if device_fingerprint == keyinfo.fingerprint and keyinfo.path:
                if _xpubs_equal_ignoring_version(
                    decode_check(self._get_xpub(keyinfo.path)), xpub
                ):
                    our_xpub_index = i
                    our_account_keypath = keyinfo.path

        if our_xpub_index is None:
            raise BadArgumentError("This BitBox02 is not one of the cosigners")
        assert our_account_keypath

        if len(xpubs) != len(set(xpubs)):
            raise BadArgumentError("Duplicate xpubs not supported")

        return (
            xpubs[our_xpub_index],
            bitbox02.btc.BTCScriptConfigWithKeypath(
                script_config=bitbox02.btc.BTCScriptConfig(
                    multisig=bitbox02.btc.BTCScriptConfig.Multisig(
                        threshold=threshold,
                        xpubs=[util.parse_xpub(encode_check(xpub)) for xpub in xpubs],
                        our_xpub_index=our_xpub_index,
                        script_type=script_type,
                    )
                ),
                keypath=our_account_keypath,
            ),
        )

    @bitbox02_exception
    def display_singlesig_address(
        self,
        bip32_path: str,
        addr_type: AddressType,
    ) -> str:
        if addr_type == AddressType.SH_WIT:
            script_config = bitbox02.btc.BTCScriptConfig(
                simple_type=bitbox02.btc.BTCScriptConfig.P2WPKH_P2SH
            )
        elif addr_type == AddressType.WIT:
            script_config = bitbox02.btc.BTCScriptConfig(
                simple_type=bitbox02.btc.BTCScriptConfig.P2WPKH
            )
        elif addr_type == AddressType.LEGACY:
            raise UnavailableActionError(
                "The BitBox02 does not support legacy p2pkh addresses"
            )
        elif addr_type == AddressType.TAP:
            script_config = bitbox02.btc.BTCScriptConfig(
                simple_type=bitbox02.btc.BTCScriptConfig.P2TR
            )
        else:
            raise BadArgumentError("Unknown address type")
        address = self.init().btc_address(
            parse_path(bip32_path),
            coin=self._get_coin(),
            script_config=script_config,
            display=True,
        )
        return address

    @bitbox02_exception
    def display_multisig_address(
        self,
        addr_type: AddressType,
        multisig: MultisigDescriptor,
    ) -> str:
        if not multisig.is_sorted:
            raise BadArgumentError("BitBox02 only supports sortedmulti descriptors")

        path_suffixes = set(p.deriv_path for p in multisig.pubkeys)
        if len(path_suffixes) != 1:
            # Path suffix refers to the path after the account-level xpub, usually /<change>/<address>.
            # The BitBox02 currently enforces that all of them are the same.
            raise BadArgumentError("All multisig path suffixes must be the same")

        # Figure out which of the cosigners is us.
        key_origin_infos = {}
        keypaths = {}
        for pk in multisig.pubkeys:
            assert pk.extkey and pk.origin
            key_origin_infos[pk.extkey.serialize()] = pk.origin
            keypaths[pk.extkey.serialize()] = pk.get_full_derivation_path(0)

        if addr_type == AddressType.SH_WIT:
            script_type = bitbox02.btc.BTCScriptConfig.Multisig.P2WSH_P2SH
        elif addr_type == AddressType.WIT:
            script_type = bitbox02.btc.BTCScriptConfig.Multisig.P2WSH
        else:
            raise BadArgumentError(
                "BitBox02 currently only supports the following multisig script types: P2WSH, P2WSH_P2SH"
            )
        our_xpub, script_config_with_keypath = self._multisig_scriptconfig(
            multisig.thresh, key_origin_infos, script_type
        )
        script_config = script_config_with_keypath.script_config
        account_keypath: Sequence[int] = script_config_with_keypath.keypath
        self._maybe_register_script_config(script_config, account_keypath)
        keypath = parse_path(keypaths[our_xpub])

        bb02 = self.init()
        address = bb02.btc_address(
            keypath, coin=self._get_coin(), script_config=script_config, display=True
        )
        return address

    @bitbox02_exception
    def sign_tx(self, psbt: PSBT) -> PSBT:
        """
        Sign a transaction with the BitBox02.

        The BitBox02 allows mixing inputs of different script types (e.g. and `p2wpkh-p2sh` `p2wpkh`), as
        long as the keypaths use the appropriate bip44 purpose field per input (e.g. `49'` and `84'`) and
        all account indexes are the same.

        Transactions with legacy inputs are not supported.
        """
        def find_our_key(
            keypaths: Dict[bytes, KeyOriginInfo]
        ) -> Tuple[Optional[bytes], Optional[Sequence[int]]]:
            """
            Keypaths is a map of pubkey to hd keypath, where the first element in the keypath is the master
            fingerprint. We attempt to find the key which belongs to the BitBox02 by matching the fingerprint,
            and then matching the pubkey.
            Returns the pubkey and the keypath, without the fingerprint.
            """
            for pubkey, origin in keypaths.items():
                # Cheap check if the key is ours.
                if origin.fingerprint != master_fp:
                    continue

                # Expensive check if the key is ours.
                # TODO: check for fingerprint collision
                # keypath_account = keypath[:-2]

                return pubkey, origin.path
            return None, None

        script_configs: List[bitbox02.btc.BTCScriptConfigWithKeypath] = []

        def add_script_config(
            script_config: bitbox02.btc.BTCScriptConfigWithKeypath
        ) -> int:
            # Find index of script config if already added.
            script_config_index = next(
                (
                    i
                    for i, e in builtins.enumerate(script_configs)
                    if e.SerializeToString() == script_config.SerializeToString()
                ),
                None,
            )
            if script_config_index is not None:
                return script_config_index
            script_configs.append(script_config)
            return len(script_configs) - 1

        def script_config_from_utxo(
            output: CTxOut,
            keypath: Sequence[int],
            redeem_script: bytes,
            witness_script: bytes,
        ) -> bitbox02.btc.BTCScriptConfigWithKeypath:
            if is_p2pkh(output.scriptPubKey):
                raise BadArgumentError(
                    "The BitBox02 does not support legacy p2pkh scripts"
                )
            if is_p2wpkh(output.scriptPubKey):
                return bitbox02.btc.BTCScriptConfigWithKeypath(
                    script_config=bitbox02.btc.BTCScriptConfig(
                        simple_type=bitbox02.btc.BTCScriptConfig.P2WPKH
                    ),
                    keypath=_keypath_hardened_prefix(keypath),
                )
            if output.is_p2sh() and is_p2wpkh(redeem_script):
                return bitbox02.btc.BTCScriptConfigWithKeypath(
                    script_config=bitbox02.btc.BTCScriptConfig(
                        simple_type=bitbox02.btc.BTCScriptConfig.P2WPKH_P2SH
                    ),
                    keypath=_keypath_hardened_prefix(keypath),
                )
            if is_p2tr(output.scriptPubKey):
                return bitbox02.btc.BTCScriptConfigWithKeypath(
                    script_config=bitbox02.btc.BTCScriptConfig(
                        simple_type=bitbox02.btc.BTCScriptConfig.P2TR
                    ),
                    keypath=_keypath_hardened_prefix(keypath),
                )
            # Check for segwit multisig (p2wsh or p2wsh-p2sh).
            is_p2wsh_p2sh = output.is_p2sh() and is_p2wsh(redeem_script)
            if output.is_p2wsh() or is_p2wsh_p2sh:
                multisig = parse_multisig(witness_script)
                if multisig:
                    threshold, _ = multisig
                    # We assume that all xpubs in the PSBT are part of the multisig. This is okay
                    # since the BitBox02 enforces the same script type for all inputs and
                    # changes. If that should change, we need to find and use the subset of xpubs
                    # corresponding to the public keys in the current multisig script.
                    _, script_config = self._multisig_scriptconfig(
                        threshold,
                        psbt.xpub,
                        bitbox02.btc.BTCScriptConfig.Multisig.P2WSH
                        if output.is_p2wsh()
                        else bitbox02.btc.BTCScriptConfig.Multisig.P2WSH_P2SH,
                    )
                    return script_config

            raise BadArgumentError("Input or change script type not recognized.")

        master_fp = self.get_master_fingerprint()

        inputs: List[bitbox02.BTCInputType] = []

        bip44_account = None

        # One pubkey per input. The pubkey identifies the key per input with which we sign. There
        # must be exactly one pubkey per input that belongs to the BitBox02.
        found_pubkeys: List[bytes] = []

        for input_index, psbt_in in builtins.enumerate(psbt.inputs):
            assert psbt_in.prev_txid is not None
            assert psbt_in.prev_out is not None
            assert psbt_in.sequence is not None

            if psbt_in.sighash and psbt_in.sighash != 1:
                raise BadArgumentError(
                    "The BitBox02 only supports SIGHASH_ALL. Found sighash: {}".format(
                        psbt_in.sighash
                    )
                )

            utxo = None
            prevtx = None

            # psbt_in.witness_utxo was originally used for segwit utxo's, but since it was
            # discovered that the amounts are not correctly committed to in the segwit sighash, the
            # full prevtx (non_witness_utxo) is supplied for both segwit and non-segwit inputs.
            # See
            # - https://medium.com/shiftcrypto/bitbox-app-firmware-update-6-2020-c70f733a5330
            # - https://blog.trezor.io/details-of-firmware-updates-for-trezor-one-version-1-9-1-and-trezor-model-t-version-2-3-1-1eba8f60f2dd.
            # - https://github.com/zkSNACKs/WalletWasabi/pull/3822
            # The BitBox02 requires all prevtxs if not all of the inputs are taproot.

            if psbt_in.non_witness_utxo:
                assert psbt_in.non_witness_utxo.sha256 is not None
                if psbt_in.prev_txid != ser_uint256(psbt_in.non_witness_utxo.sha256):
                    raise BadArgumentError(
                        "Input {} has a non_witness_utxo with the wrong hash".format(
                            input_index
                        )
                    )
                assert psbt_in.prev_out is not None
                utxo = psbt_in.non_witness_utxo.vout[psbt_in.prev_out]
                prevtx = psbt_in.non_witness_utxo
            elif psbt_in.witness_utxo:
                utxo = psbt_in.witness_utxo
            if utxo is None:
                raise BadArgumentError("No utxo found for input {}".format(input_index))

            key_origin_infos = psbt_in.hd_keypaths.copy()
            if len(psbt_in.tap_internal_key) > 0:
                # adding taproot keys to the keypaths to be checked
                for pubkey, (leaf_hashes, key_origin_info) in psbt_in.tap_bip32_paths.items():
                    if len(leaf_hashes) > 0:
                        raise BadArgumentError(
                            "The BitBox02 does not support Taproot script path spending. Found leaf hashes: {}"
                            .format(leaf_hashes)
                        )
                    key_origin_infos[pubkey] = key_origin_info

            found_pubkey, keypath = find_our_key(key_origin_infos)

            if not found_pubkey:
                raise BadArgumentError("No key found for input {}".format(input_index))
            assert keypath is not None
            found_pubkeys.append(found_pubkey)

            if bip44_account is None:
                bip44_account = keypath[2]
            elif bip44_account != keypath[2]:
                raise BadArgumentError(
                    "The bip44 account index must be the same for all inputs and changes"
                )

            script_config_index = add_script_config(
                script_config_from_utxo(
                    utxo, keypath, psbt_in.redeem_script, psbt_in.witness_script
                )
            )
            inputs.append(
                {
                    "prev_out_hash": psbt_in.prev_txid,
                    "prev_out_index": psbt_in.prev_out,
                    "prev_out_value": utxo.nValue,
                    "sequence": psbt_in.sequence,
                    "keypath": keypath,
                    "script_config_index": script_config_index,
                    "prev_tx": None if prevtx is None else {
                        "version": prevtx.nVersion,
                        "locktime": prevtx.nLockTime,
                        "inputs": [
                            {
                                "prev_out_hash": ser_uint256(prev_in.prevout.hash),
                                "prev_out_index": prev_in.prevout.n,
                                "signature_script": prev_in.scriptSig,
                                "sequence": prev_in.nSequence,
                            }
                            for prev_in in prevtx.vin
                        ],
                        "outputs": [
                            {
                                "value": prev_out.nValue,
                                "pubkey_script": prev_out.scriptPubKey,
                            }
                            for prev_out in prevtx.vout
                        ],
                    },
                }
            )

        outputs: List[bitbox02.BTCOutputType] = []

        for output_index, psbt_out in builtins.enumerate(psbt.outputs):
            tx_out = psbt_out.get_txout()

            key_origin_infos = psbt_out.hd_keypaths.copy()
            if len(psbt_out.tap_internal_key) > 0:
                # adding taproot keys to the keypaths to be checked
                for pubkey, (leaf_hashes, key_origin_info) in psbt_out.tap_bip32_paths.items():
                    if len(leaf_hashes) > 0:
                        raise BadArgumentError(
                            "The BitBox02 does not support Taproot script path spending. Found leaf hashes: {}"
                            .format(leaf_hashes)
                        )
                    key_origin_infos.update({pubkey: key_origin_info})

            _, keypath = find_our_key(key_origin_infos)

            is_change = keypath and keypath[-2] == 1
            if is_change:
                assert keypath is not None
                script_config_index = add_script_config(
                    script_config_from_utxo(
                        tx_out, keypath, psbt_out.redeem_script, psbt_out.witness_script
                    )
                )
                outputs.append(
                    bitbox02.BTCOutputInternal(
                        keypath=keypath,
                        value=tx_out.nValue,
                        script_config_index=script_config_index,
                    )
                )
            else:
                if tx_out.is_p2pkh():
                    output_type = bitbox02.btc.P2PKH
                    output_payload = tx_out.scriptPubKey[3:23]
                elif is_p2wpkh(tx_out.scriptPubKey):
                    output_type = bitbox02.btc.P2WPKH
                    output_payload = tx_out.scriptPubKey[2:]
                elif tx_out.is_p2sh():
                    output_type = bitbox02.btc.P2SH
                    output_payload = tx_out.scriptPubKey[2:22]
                elif is_p2wsh(tx_out.scriptPubKey):
                    output_type = bitbox02.btc.P2WSH
                    output_payload = tx_out.scriptPubKey[2:]
                elif is_p2tr(tx_out.scriptPubKey):
                    output_type = bitbox02.btc.P2TR
                    output_payload = tx_out.scriptPubKey[2:]
                else:
                    raise BadArgumentError(
                        "Output type not recognized of output {}".format(output_index)
                    )

                outputs.append(
                    bitbox02.BTCOutputExternal(
                        output_type=output_type,
                        output_payload=output_payload,
                        value=tx_out.nValue,
                    )
                )

        assert bip44_account is not None
        if (
            len(script_configs) == 1
            and script_configs[0].script_config.WhichOneof("config") == "multisig"
        ):
            self._maybe_register_script_config(
                script_configs[0].script_config, script_configs[0].keypath
            )

        assert psbt.tx_version is not None
        sigs = self.init().btc_sign(
            self._get_coin(),
            script_configs,
            inputs=inputs,
            outputs=outputs,
            locktime=psbt.compute_lock_time(),
            version=psbt.tx_version,
        )

        for (_, sig), pubkey, psbt_in in zip(sigs, found_pubkeys, psbt.inputs):
            r, s = sig[:32], sig[32:64]

            if len(psbt_in.tap_internal_key) > 0:
                # taproot keypath input
                psbt_in.tap_key_sig = sig
            else:
                # ser_sig_der() adds SIGHASH_ALL
                psbt_in.partial_sigs[pubkey] = ser_sig_der(r, s)

        return psbt

    @bitbox02_exception
    def sign_message(
        self, message: Union[str, bytes], bip32_path: str
    ) -> str:
        if isinstance(message, str):
            message = message.encode("utf-8")
        keypath = parse_path(bip32_path)
        purpose = keypath[0]
        simple_type = {
            PURPOSE_P2WPKH: bitbox02.btc.BTCScriptConfig.P2WPKH,
            PURPOSE_P2WPKH_P2SH: bitbox02.btc.BTCScriptConfig.P2WPKH_P2SH,
        }.get(purpose)
        if simple_type is None:
            raise BitBox02Error(
                "For message signing, the keypath bip44 purpose must be 84' or 49'"
            )
        _, _, sig65 = self.init().btc_sign_msg(
            self._get_coin(),
            bitbox02.btc.BTCScriptConfigWithKeypath(
                script_config=bitbox02.btc.BTCScriptConfig(
                    simple_type=simple_type,
                ),
                keypath=keypath,
            ),
            message)
        return base64.b64encode(sig65).decode("ascii")

    @bitbox02_exception
    def toggle_passphrase(self) -> bool:
        bb02 = self.init()
        info = bb02.device_info()
        if info["mnemonic_passphrase_enabled"]:
            bb02.disable_mnemonic_passphrase()
        else:
            bb02.enable_mnemonic_passphrase()
        return True

    @bitbox02_exception
    def setup_device(
        self, label: str = "", passphrase: str = ""
    ) -> bool:
        if passphrase:
            raise UnavailableActionError(
                "Passphrase not needed when setting up a BitBox02."
            )

        bb02 = self.init(expect_initialized=False)

        if label:
            bb02.set_device_name(label)
        if not bb02.set_password():
            return False
        return bb02.create_backup()

    @bitbox02_exception
    def wipe_device(self) -> bool:
        return self.init().reset()

    @bitbox02_exception
    def backup_device(
        self, label: str = "", passphrase: str = ""
    ) -> bool:
        if label or passphrase:
            raise UnavailableActionError(
                "Label/passphrase not needed when exporting mnemonic from the BitBox02."
            )

        self.init().show_mnemonic()
        return True

    @bitbox02_exception
    def restore_device(
        self, label: str = "", word_count: int = 24
    ) -> bool:
        bb02 = self.init(expect_initialized=False)

        if label:
            bb02.set_device_name(label)

        bb02.restore_from_mnemonic()
        return True

    def can_sign_taproot(self) -> bool:
        """
        The BitBox02 does not support Taproot yet.

        :returns: False, always
        """
        return False
