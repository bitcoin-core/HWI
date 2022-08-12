"""
Tapsigner
********
"""
import os
import pyaes
import getpass
import datetime
from base64 import b64encode
from functools import wraps
from typing import List, Dict, Any, Union, Callable
from cktap.transport import find_cards, CKTapUnixTransport, CKTapCard, CardRuntimeError  # type: ignore
from cktap.utils import ser_compact_size, pick_nonce, path2str  # type: ignore
from cktap.bip32 import InvalidKeyError  # type: ignore
from ..common import Chain, AddressType, hash256, hash160
from ..key import ExtendedKey
from ..psbt import PSBT
from ..descriptor import MultisigDescriptor
from ..errors import UnavailableActionError, BadArgumentError, NO_PASSWORD, NoPasswordError, UnknownDeviceError
from ..hwwclient import HardwareWalletClient
from .._serialize import ser_sig_der


def tapsigner_exception(f: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(f)
    def func(*args: Any, **kwargs: Any) -> Any:
        try:
            return f(*args, **kwargs)
        except (ValueError, InvalidKeyError, AssertionError) as e:
            raise BadArgumentError(str(e))
        except (RuntimeError, CardRuntimeError) as e:
            raise UnknownDeviceError(str(e))
    return func


def is_cvc_length_range(cvc: str) -> bool:
    """CVC has to be at least 6 characters long and at most 32 characters long"""
    return 6 <= len(cvc) <= 32


def find_card_by_path(path: str) -> CKTapCard:
    # path is actually an ident
    for card in find_cards():
        if path in card.card_ident:
            return card
    raise RuntimeError("Card not found! Is it on the reader?")


class TapsignerClient(HardwareWalletClient):
    # In path variable we store card ident
    # In password variable we store card CVC
    def __init__(self, path: str, password: str = "", expert: bool = False, chain: Chain = Chain.MAIN) -> None:
        super(TapsignerClient, self).__init__(path, password, expert, chain)
        self.device = find_card_by_path(path=path)
        if not password:
            raise NoPasswordError('Password (cvc) must be supplied for Tapsigner')

    @tapsigner_exception
    def get_master_fingerprint(self) -> bytes:
        """
        m fingerprint
        """
        extended_key_m = self.get_pubkey_at_path("m")
        fingerprint = hash160(extended_key_m.pubkey)[:4]
        return fingerprint

    @tapsigner_exception
    def get_pubkey_at_path(self, bip32_path: str) -> ExtendedKey:
        xpub = self.device.derive_xpub_at_path(self.password, fullpath=bip32_path)
        return ExtendedKey.deserialize(xpub)

    @tapsigner_exception
    def sign_tx(self, tx: PSBT) -> PSBT:
        """
        Tapsigner blind signing.

        Tapsigner can only sign paths that have no more than 8 hardened components. If path contains
        non-hardened components, they must be after hardened ones (cannot have hardened component after non-hardened).
        Length of non-hardened components is limited to 2.
        """
        # Get the master key fingerprint
        master_fp = self.get_master_fingerprint()

        sighash_tuples = tx.get_sighash_tuples(master_fp=master_fp)
        if sighash_tuples is None:
            return tx

        for sighash, keypath, i_num, pubkey in sighash_tuples:
            int_path = keypath.path
            rec_sig = self.device.sign_digest(cvc=self.password, slot=0, digest=sighash, fullpath=path2str(int_path))
            assert len(rec_sig) == 65  # recoverable signature
            # ignore header byte
            der_sig = ser_sig_der(rec_sig[1:33], rec_sig[33:65])
            # add sigs to tx
            tx.inputs[i_num].partial_sigs[pubkey] = der_sig

        return tx

    @tapsigner_exception
    def sign_message(self, message: Union[str, bytes], bip32_path: str) -> str:
        message = message.encode('ascii') if not isinstance(message, bytes) else message
        xmsg = b'\x18Bitcoin Signed Message:\n' + ser_compact_size(len(message)) + message
        md = hash256(xmsg)
        rec_sig = self.device.sign_digest(cvc=self.password, slot=0, digest=md, fullpath=bip32_path)
        sig = str(b64encode(rec_sig), 'ascii').replace('\n', '')
        return sig

    def display_singlesig_address(self, bip32_path: str, addr_type: AddressType) -> str:
        """
        The Tapsigner does not have a screen to display addresses on.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Tapsigner does not have a screen to display addresses on')

    def display_multisig_address(self, addr_type: AddressType, multisig: MultisigDescriptor) -> str:
        """
        The Tapsigner does not have a screen to display addresses on.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Tapsigner does not have a screen to display addresses on')

    def wipe_device(self) -> bool:
        """
        The Tapsigner does not support wiping via software.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Tapsigner does not support wiping via software')

    @tapsigner_exception
    def setup_device(self, label: str = "", passphrase: str = "") -> bool:
        """
        Setup the device.

        :param label: Value is ignored
        :param passphrase: Value is ignored
        """
        args: Dict[str, Union[int, bytes]] = dict(slot=0)
        args['chain_code'] = hash256(os.urandom(128))
        ses_key, resp = self.device.send_auth('new', self.password, **args)
        if "error" in resp:
            raise RuntimeError(resp["error"])
        return True

    @tapsigner_exception
    def restore_device(self, label: str = "", word_count: int = 24) -> bool:
        """
        The Tapsigner does not support restoring via software. This method is used to
        decrypt previously created backup with 'backup_device' command. All data it needs
        are asked via command prompt. CAUTION: Secret data are dumped to stdout, so
        make sure you know what you're doing.

        :param label: Value is ignored
        :param word_count: Value is ignored
        """
        warn = input("This operation will dump secret data (xprv) to command line. "
                     "Are you sure you want to continue?[y/n]")
        if warn.lower() == "y":
            print(f"Possible backup files in cwd: {[i for i in os.listdir() if i.endswith('.aes')]}")
            file_path = input("Path to backup file:\n")
            with open(file_path, "rb") as f:
                # read encrypted secret from a file and close fd immediately after done reading
                secret = f.read()
            # 3 shots per call
            for _ in range(3):
                # this is hard to type, so better to use input so user can verify screen
                # xprv
                backup_key_str = input("Provide 'Backup Key' (32 hex digits) "
                                       "from the back of your TAPSIGNER card:\n").lower()
                try:
                    backup_key = bytes.fromhex(backup_key_str)
                    counter = pyaes.Counter(initial_value=0)
                    aes = pyaes.AESModeOfOperationCTR(backup_key, counter=counter)
                    decrypted_bytes = aes.decrypt(secret)
                    decrypted_str = decrypted_bytes.decode()
                    # expect additional lines in file
                    sep_split = decrypted_str.split()
                    # current format -> 2 lines -> 1. xprv, 2. derivation
                    extended_private_key, derivation_path = sep_split[0], sep_split[1]
                    if extended_private_key[0:4] in ["xprv", "tprv"]:
                        print(f"Derivation path: {derivation_path}")
                        print(f"Extended private key: {extended_private_key}")
                        return True
                    raise ValueError
                except (UnicodeError, ValueError):
                    print("Invalid backup key. Try again")
                    continue
            else:
                raise ValueError("Invalid 'Backup Key' after 3 attempts")

        return False

    @tapsigner_exception
    def backup_device(self, label: str = "", passphrase: str = "") -> bool:
        """
        Creates a AES-128-CTR encrypted backup file in the current working directory.

        :param label: Value is ignored
        :param passphrase: Value is ignored
        """
        nowish = datetime.datetime.now().isoformat()[0:16].replace(':', '')
        ident = self.device.card_ident.split('-')[0]
        outfile = f'backup-{ident}-{nowish}.aes'
        enc = self.device.make_backup(self.password)
        with open(outfile, "wb") as f:
            f.write(enc)
        return True

    def close(self) -> None:
        self.device.close()

    def prompt_pin(self) -> bool:
        """
        The Tapsigner does not need a PIN sent from the host.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Tapsigner does not need a PIN sent from the host')

    def send_pin(self, pin: str) -> bool:
        """
        The Tapsigner does not need a PIN sent from the host.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Tapsigner does not need a PIN sent from the host')

    @tapsigner_exception
    def toggle_passphrase(self) -> bool:
        """
        The Tapsigner does not support toggling passphrase from the host. This method is used to
        change card CVC (here treated as password).

        :raises UnavailableActionError: Always, this function is unavailable
        """
        warn = input("This operation will change your card CVC code. "
                     "Are you sure you want to continue?[y/n]")
        if warn.lower() == "y":
            try:
                # 1. verify current CVC is correct, or fail fast
                self.device.send_auth("read", self.password, **dict(nonce=pick_nonce()))
            except (CardRuntimeError, AssertionError):
                raise ValueError("Invalid CVC")
            new_cvc = getpass.getpass("New CVC:\n")
            if not is_cvc_length_range(new_cvc):
                raise ValueError("CVC has to be min: 6 chars and max: 32 chars long")
            new_cvc_confirm = getpass.getpass("Confirm new CVC:\n")
            # 2. confirm that new CVC matches one from confirmation prompt
            if new_cvc != new_cvc_confirm:
                raise ValueError("Confirmation failure. CVC mismatch")
            if self.password == new_cvc:
                print("New CVC same as old one. NOOP")
                return False
            try:
                # 3. actual CVC change
                self.device.change_cvc(self.password, new_cvc)  # here it is 100% htat CVC (password is correct) #2
            except CardRuntimeError as e:
                if e.code == 425:
                    raise ValueError("Card not yet backed-up. "
                                     "Please use 'backup' command first to back-up your card")
            print("New CVC in effect.")
            return True
        return False

    def can_sign_taproot(self) -> bool:
        """
        Whether the device has a version that can sign for Taproot inputs

        :return: Whether Taproot is supported
        """
        return False


def enumerate(password: str = "") -> List[Dict[str, Any]]:
    results = []
    devices = find_cards()
    while True:
        try:
            card = next(devices)
        except StopIteration:
            break
        except Exception:
            continue
        if not card.is_tapsigner:
            continue
        d_data: Dict[str, Any] = {}
        d_data['path'] = card.card_ident
        d_data['type'] = 'tapsigner'
        d_data['model'] = 'tapsigner'
        d_data['label'] = None
        d_data['needs_pin_sent'] = False
        d_data['needs_passphrase_sent'] = True

        if isinstance(card.tr, CKTapUnixTransport):
            d_data['model'] += '_simulator'
        if d_data['needs_passphrase_sent'] and not password:
            # this is kind of unfortunate that we need password (a.k.a CVC) to get master fp
            # because when using it with core, one has to provide password on the command line
            # -signer='/home/more/PycharmProjects/HWI/venv/lib/python3.8/site-packages/hwi.py -p 123456'
            d_data["error"] = "Passphrase needs to be specified before the fingerprint information can be retrieved"
            d_data["code"] = NO_PASSWORD
        else:
            d_data['fingerprint'] = card.get_xfp(password).hex().lower()
        card.close()
        results.append(d_data)

    return results
