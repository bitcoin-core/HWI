from typing import Dict, Optional, Union

from .base58 import get_xpub_fingerprint_hex
from .descriptor import Descriptor
from .serializations import PSBT


class HardwareWalletClient(object):
    """Create a client for a HID device that has already been opened.

    This abstract class defines the methods
    that hardware wallet subclasses should implement.
    """

    def __init__(self, path: str, password: str, expert: bool) -> None:
        self.path = path
        self.password = password
        self.message_magic = b"\x18Bitcoin Signed Message:\n"
        self.is_testnet = False
        self.fingerprint: Optional[str] = None
        # {bip32_path: <xpub string>}
        self.xpub_cache: Dict[str, str] = {}
        self.expert = expert

    def get_master_xpub(self) -> Dict[str, str]:
        """Return the master BIP44 public key.

        Retrieve the public key at the "m/44h/0h/0h" derivation path.

        Return {"xpub": <xpub string>}.
        """
        # FIXME testnet is not handled yet
        return self.get_pubkey_at_path("m/44h/0h/0h")

    def get_master_fingerprint_hex(self) -> str:
        """Return the master public key fingerprint as hex-string.

        Retrieve the master public key at the "m/0h" derivation path.
        """
        master_xpub = self.get_pubkey_at_path("m/0h")["xpub"]
        return get_xpub_fingerprint_hex(master_xpub)

    def get_pubkey_at_path(self, bip32_path: str) -> Dict[str, str]:
        """Return the public key at the BIP32 derivation path.

        Return {"xpub": <xpub string>}.
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

    def display_address(
        self,
        bip32_path: str,
        p2sh_p2wpkh: bool,
        bech32: bool,
        redeem_script: Optional[str] = None,
        descriptor: Optional[Descriptor] = None,
    ) -> Dict[str, str]:
        """Display and return the address of specified type.

        redeem_script is a hex-string.

        Retrieve the public key at the specified BIP32 derivation path.

        Return {"address": <base58 or bech32 address string>}.
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
