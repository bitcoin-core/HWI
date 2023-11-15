"""
Hardware Wallet Client Interface
********************************

The :class:`HardwareWalletClient` is the class which all of the specific device implementations subclass.
"""

from typing import (
    Any,
    Dict,
    Optional,
    Union,
)

from .wallet_policy import WalletPolicy
from .descriptor import MultisigDescriptor, parse_descriptor
from .key import (
    ExtendedKey,
    get_bip44_purpose,
    get_bip44_chain,
)
from .psbt import PSBT
from .common import AddressType, Chain


class HardwareWalletClient(object):
    """Create a client for a HID device that has already been opened.

    This abstract class defines the methods
    that hardware wallet subclasses should implement.
    """

    def __init__(self, path: str, password: Optional[str], expert: bool, chain: Chain = Chain.MAIN) -> None:
        """
        :param path: Path to the device as returned by :func:`~hwilib.commands.enumerate`
        :param password: A password/passphrase to use with the device.
            Typically a BIP 39 passphrase, but not always.
            See device specific documentation for further details.
        :param expert: Whether to return additional information intended for experts.
        """
        self.path = path
        self.password = password
        self.message_magic = b"\x18Bitcoin Signed Message:\n"
        self.chain = chain
        self.fingerprint: Optional[str] = None
        # {bip32_path: <xpub string>}
        self.xpub_cache: Dict[str, str] = {}
        self.expert = expert

    def get_master_xpub(self, addrtype: AddressType = AddressType.WIT, account: int = 0) -> ExtendedKey:
        """
        Retrieves a BIP 44 master public key

        Get the extended public key used to derive receiving and change addresses with the BIP 44 derivation path scheme.
        The returned xpub will be dependent on the address type requested, the chain type, and the BIP 44 account number.

        :return: The extended public key
        """
        path = f"m/{get_bip44_purpose(addrtype)}h/{get_bip44_chain(self.chain)}h/{account}h"
        return self.get_pubkey_at_path(path)

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
        addr_type: AddressType,
        multisig: MultisigDescriptor,
    ) -> str:
        """
        Display and return the multisig address of specified type given the descriptor.

        :param addr_type: The address type
        :param multisig: A :class:`~hwilib.descriptor.MultisigDescriptor` that describes the multisig to display.
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

        :param label: A label to apply to the device.
            See device specific documentation for details as to what this actually does.
        :param passphrase: A passphrase to apply to the device.
            Typically a BIP 39 passphrase.
            See device specific documentation for details as to what this actually does.
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

        :param label: A label to apply to the device.
            See device specific documentation for details as to what this actually does.
        :param word_count: The number of BIP 39 mnemonic words.
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

        :param label: A label to apply to the backup.
            See device specific documentation for details as to what this actually does.
        :param passphrase: A passphrase to apply to the backup.
            See device specific documentation for details as to what this actually does.
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

        :param pin: The PIN
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

    def can_sign_taproot(self) -> bool:
        """
        Whether the device has a version that can sign for Taproot inputs

        :return: Whether Taproot is supported
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def can_register_wallet_policies(self) -> bool:
        """
        Whether the device can register wallet policies

        :return: Whether wallet policies are supported
        """
        return False

    def register_wallet_policy(self, wallet_policy: WalletPolicy, extra: Dict[str, Any]) -> bytes:
        """
        Registers a wallet policy on the device.

        :param wallet_policy: The WalletPolicy to register
        :param extra: A dictionary with any additional parameters needed from the hardware wallet
        :return: A binary string to be used as proof_of_registration if required from the hardware wallet, or
                 an empty binary string b'' if the hardware wallet does not require a proof of registration
        """
        raise NotImplementedError("The HardwareWalletClient base class "
                                  "does not implement this method")

    def display_wallet_policy_address(self, wallet_policy: WalletPolicy, is_change: bool, address_index: int, extra: Dict[str, Any]) -> str:
        """
        Display and return the specified address for the wallet policy.

        :param wallet_policy: The WalletPolicy to be used to show an address from
        :param is_change: False if a normal receive address is shown, True for a change address
        :param address_index: The index of the address to show. It must be at least 0 and at most 2147483647.
        :param extra: Any additional parameters needed from the hardware wallet
        :return: The retrieved address also being shown by the device
        """

        # TODO: Default behavior: if the wallet policy is a standard single signature address, use display_singlesig_address;
        #       if standard multisig, use display_multisig_address; otherwise, fail.

        fpr = self.get_master_fingerprint()

        if len(wallet_policy.keys_info) == 1 and wallet_policy.keys_info[0][0] == '[':

            key_info = wallet_policy.keys_info[0]
            key_fingerprint = bytes.fromhex(key_info[1:9])

            assert key_info.find(']') != -1

            if fpr == key_fingerprint:
                if wallet_policy.descriptor_template in ["pkh(@0/**)", "pkh(@0/<0;1>/*)"]:
                    addr_type = AddressType.LEGACY
                elif wallet_policy.descriptor_template in ["wpkh(@0/**)", "wpkh(@0/<0;1>/*)"]:
                    addr_type = AddressType.WIT
                elif wallet_policy.descriptor_template in ["sh(wpkh(@0/**))", "sh(wpkh(@0/<0;1>/*))"]:
                    addr_type = AddressType.SH_WIT
                elif wallet_policy.descriptor_template in ["tr(@0/**)", "tr(@0/<0;1>/*)"]:
                    addr_type = AddressType.TAP
                else:
                    raise NotImplementedError("The HardwareWalletClient base class "
                                              "does not implement this method")

            # TODO we're assuming here that if the fingerprint matches, it's an internal input.
            #      we might want to compare the derived pubkey and compare in order to be sure

            key_origin_path = key_info[10:key_info.find(']')]
            bip32_path = f"m/{key_origin_path}/{int(is_change)}/{address_index}"

            return self.display_singlesig_address(bip32_path, addr_type)
        else:
            desc = wallet_policy.to_descriptor()
            desc = desc.replace("/<0;1>/*", f"/{int(is_change)}/{address_index}")

            addr_type: Optional[AddressType] = None

            if desc.startswith("sh(wsh("):
                multisig_desc = desc[len("sh(wsh("):-2]
                addr_type = AddressType.SH_WIT
            elif desc.startswith("wsh("):
                multisig_desc = desc[len("wsh("):-1]
                addr_type = AddressType.WIT
            elif desc.startswith("sh("):
                multisig_desc = desc[len("sh("):-1]
                addr_type = AddressType.LEGACY

            if addr_type is not None:
                descriptor = parse_descriptor(multisig_desc)
                return self.display_multisig_address(addr_type, descriptor)

        raise NotImplementedError("The HardwareWalletClient base class does not "
                                  "implement this method for the given parameters")

    def sign_tx_with_wallet_policy(self, psbt: PSBT, wallet_policy: WalletPolicy, extra: Dict[str, Any]) -> PSBT:
        """
        Sign a partially signed bitcoin transaction (PSBT) using the specified wallet policy.
        Inputs that do not belong to the wallet policy (or with insufficient information in the PSBT) are not signed.

        :param psbt: The PSBT to sign
        :param wallet_policy: The WalletPolicy to be used for signing
        :param extra: A dictionary with any additional parameters needed from the hardware wallet
        :return: The PSBT after being processed by the hardware wallet
        """

        # TODO: Default behavior: fail if not standard wallet policy; then, sign using sign_tx, but only retain signatures
        #       for inputs that match the wallet policy

        # TODO: just for initial testing, yolo-sign everything
        return self.sign_tx(psbt)
