from typing import (
    Dict,
    List,
    Optional,
    Union,
)
from .descriptor import PubkeyProvider
from .key import ExtendedKey
from .serializations import PSBT
from .common import AddressType, Chain


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

    def get_master_fingerprint(self) -> bytes:
        """
        Get the master public key fingerprint as bytes.

        Retrieves the fingerprint of the master public key of a device.
        Typically implemented by fetching the extended public key at "m/0h"
        and extracting the parent fingerprint from it.

        :return: The fingerprint as bytes
        """
        return self.get_pubkey_at_path("m/0h").parent_fingerprint

    def get_pubkey_at_path(self, bip32_path: str) -> ExtendedKey:
        """
        Get the public key at the BIP 32 derivation path.

        :param bip32_path: The BIP 32 derivation path
        :return: The extended public key
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def sign_tx(self, psbt: PSBT) -> PSBT:
        """
        Sign a partially signed bitcoin transaction (PSBT).

        :param psbt: The PSBT to sign
        :return: The PSBT after being processed by the hardware wallet
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def sign_message(
        self, message: Union[str, bytes], bip32_path: str
    ) -> str:
        """
        Sign a message (bitcoin message signing).

        Signs a message using the legacy Bitcoin Core signed message format.
        The message is signed with the key at the given path.

        :param message: The message to be signed. First encoded as bytes if not already.
        :param bip32_path: The BIP 32 derivation for the key to sign the message with.
        :return: The signature
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

    def wipe_device(self) -> bool:
        """
        Wipe the device.

        :return: Whether the wipe was successful
        :raises UnavailableActionError: if appropriate for the device.
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def setup_device(
        self, label: str = "", passphrase: str = ""
    ) -> bool:
        """
        Setup the device.

        :return: Whether the setup was successful
        :raises UnavailableActionError: if appropriate for the device.
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def restore_device(
        self, label: str = "", word_count: int = 24
    ) -> bool:
        """
        Restore the device.

        :return: Whether the restore was successful
        :raises UnavailableActionError: if appropriate for the device.
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def backup_device(
        self, label: str = "", passphrase: str = ""
    ) -> bool:
        """
        Backup the device.

        :return: Whether the backup was successful
        :raises UnavailableActionError: if appropriate for the device.
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def close(self) -> None:
        "Close the HID device."
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def prompt_pin(self) -> bool:
        """
        Prompt for PIN.

        :return: Whether the PIN prompt was successful
        :raises UnavailableActionError: if appropriate for the device.
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def send_pin(self, pin: str) -> bool:
        """
        Send PIN.

        :return: Whether the PIN successfully unlocked the device
        :raises UnavailableActionError: if appropriate for the device.
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def toggle_passphrase(self) -> bool:
        """
        Toggle passphrase.

        :return: Whether the passphrase was successfully toggled
        :raises UnavailableActionError: if appropriate for the device.
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")
