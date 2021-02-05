from typing import (
    Dict,
    List,
    Optional,
    Union,
)
from .descriptor import PubkeyProvider
from .key import ExtendedKey
from .serializations import AddressType, PSBT
from .common import Chain


class HardwareWalletClient(object):
    """Create a client for a HID device that has already been opened.

    This abstract class defines the methods
    that hardware wallet subclasses should implement.
    """

    def __init__(self, path: str, password: str, expert: bool) -> None:
        self.path = path
        self.password = password
        self.message_magic = b"\x18Bitcoin Signed Message:\n"
        self.chain = Chain.MAIN
        self.fingerprint: Optional[str] = None
        # {bip32_path: <xpub string>}
        self.xpub_cache: Dict[str, str] = {}
        self.expert = expert

    def get_master_xpub(self) -> ExtendedKey:
        """
        Get the master BIP 44 public key.

        Retrieves the public key at the "m/44h/0h/0h" derivation path.

        :return: The extended public key at "m/44h/0h/0h"
        """
        # FIXME testnet is not handled yet
        return self.get_pubkey_at_path("m/44h/0h/0h")

    def get_master_fingerprint_hex(self) -> str:
        """
        Get the master public key fingerprint as a hex string.

        Retrieves the fingerprint of the master public key of a device.
        Typically implemented by fetching the extended public key at "m/0h"
        and extracting the parent fingerprint from it.

        :return: The fingerprint as a hex string
        """
        return self.get_pubkey_at_path("m/0h").parent_fingerprint.hex()

    def get_pubkey_at_path(self, bip32_path: str) -> ExtendedKey:
        """
        Get the public key at the BIP 32 derivation path.

        :param bip32_path: The BIP 32 derivation path
        :return: The extended public key
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def sign_tx(self, psbt: PSBT) -> Dict[str, str]:
        """Sign a partially signed bitcoin transaction (PSBT).

        Return {"psbt": <base64 psbt string>}.
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def sign_message(
        self, message: Union[str, bytes], bip32_path: str
    ) -> Dict[str, str]:
        """Sign a message (bitcoin message signing).

        Sign the message according to the bitcoin message signing standard:
        usually, the message is a string that is encoded to bytes;
        anyway, if the message is already bytes it is processed untouched.

        Retrieve the signing key at the specified BIP32 derivation path.

        Return {"signature": <base64 signature string>}.
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def display_singlesig_address(
        self,
        bip32_path: str,
        addr_type: AddressType,
    ) -> str:
        """
        Display and return the single sig address of specified type
        at the given derivation path.

        :param bip32_path: The BIP 32 derivation path to get the address for
        :param addr_type: The address type
        :return: The retrieved address also being shown by the device
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def display_multisig_address(
        self,
        threshold: int,
        pubkeys: List[PubkeyProvider],
        addr_type: AddressType,
    ) -> str:
        """
        Display and return the multisig address of specified type given the threshold and pubkeys.

        :param threshold: The number of signers required in the multisig
        :param pubkeys: The public keys, as found in a descriptor, in the multisig
        :param addr_type: The address type
        :return: The retrieved address also being shown by the device
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def wipe_device(self) -> Dict[str, Union[bool, str, int]]:
        """Wipe the HID device.

        Must return a dictionary with the "success" key,
        possibly including also "error" and "code", e.g.:
        {"success": bool, "error": srt, "code": int}.

        Raise UnavailableActionError if appropriate for the device.
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def setup_device(
        self, label: str = "", passphrase: str = ""
    ) -> Dict[str, Union[bool, str, int]]:
        """Setup the HID device.

        Must return a dictionary with the "success" key,
        possibly including also "error" and "code", e.g.:
        {"success": bool, "error": str, "code": int}.

        Raise UnavailableActionError if appropriate for the device.
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def restore_device(
        self, label: str = "", word_count: int = 24
    ) -> Dict[str, Union[bool, str, int]]:
        """Restore the HID device from mnemonic.

        Must return a dictionary with the "success" key,
        possibly including also "error" and "code", e.g.:
        {"success": bool, "error": srt, "code": int}.

        Raise UnavailableActionError if appropriate for the device.
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def backup_device(
        self, label: str = "", passphrase: str = ""
    ) -> Dict[str, Union[bool, str, int]]:
        """Backup the HID device.

        Must return a dictionary with the "success" key,
        possibly including also "error" and "code", e.g.:
        {"success": bool, "error": srt, "code": int}.

        Raise UnavailableActionError if appropriate for the device.
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def close(self) -> None:
        "Close the HID device."
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def prompt_pin(self) -> Dict[str, Union[bool, str, int]]:
        """Prompt for PIN.

        Must return a dictionary with the "success" key,
        possibly including also "error" and "code", e.g.:
        {"success": bool, "error": srt, "code": int}.

        Raise UnavailableActionError if appropriate for the device.
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def send_pin(self, pin: str) -> Dict[str, Union[bool, str, int]]:
        """Send PIN.

        Must return a dictionary with the "success" key,
        possibly including also "error" and "code", e.g.:
        {"success": bool, "error": srt, "code": int}.

        Raise UnavailableActionError if appropriate for the device.
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def toggle_passphrase(self) -> Dict[str, Union[bool, str, int]]:
        """Toggle passphrase.

        Must return a dictionary with the "success" key,
        possibly including also "error" and "code", e.g.:
        {"success": bool, "error": srt, "code": int}.

        Raise UnavailableActionError if appropriate for the device.
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")
