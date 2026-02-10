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

from hwilib.descriptor import MultisigDescriptor
from hwilib.errors import DeviceConnectionError, UnavailableActionError
from hwilib.hwwclient import HardwareWalletClient
from hwilib.key import ExtendedKey
from hwilib.psbt import PSBT

from ..common import (
    AddressType,
    Chain,
)

from .cypherock_sdk.hw_hid import get_available_devices, DeviceConnection
from .cypherock_sdk.interfaces import IDevice

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
        except Exception as e:
            raise DeviceConnectionError(f"Failed to connect to Cypherock X1: {e}")

    def get_master_fingerprint(self) -> bytes:
        return bytes.fromhex(self.device["fingerprint"])

    def get_pubkey_at_path(self, path: str) -> ExtendedKey:
        raise NotImplementedError("The CypherockClient class "
                                  "has not yet implemented this method")

    def sign_tx(self, tx: PSBT) -> PSBT:
        raise NotImplementedError("The CypherockClient class "
                                  "has not yet implemented this method")

    def sign_message(self, message: Union[str, bytes], keypath: str) -> str:
        raise NotImplementedError("The CypherockClient class "
                                  "has not yet implemented this method")

    def display_singlesig_address(
        self,
        keypath: str,
        addr_type: AddressType,
    ) -> str:
        raise NotImplementedError("The CypherockClient class "
                                  "has not yet implemented this method")

    def display_multisig_address(
        self,
        addr_type: AddressType,
        multisig: MultisigDescriptor,
    ) -> str:
        raise NotImplementedError("The CypherockClient class "
                                  "has not yet implemented this method")

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
        raise NotImplementedError("The CypherockClient class "
                                  "has not yet implemented this method")


def enumerate(password: Optional[str] = None, expert: bool = False, chain: Chain = Chain.MAIN, allow_emulators: bool = False) -> List[Dict[str, Any]]:
    return get_available_devices()
