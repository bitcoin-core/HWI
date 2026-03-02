from ..interfaces import IDeviceConnection
from ..core import SDK
from . import operations


class BtcApp:
    """
    Bitcoin application class for Cypherock SDK.
    """

    APPLET_ID = 2

    def __init__(self, sdk: SDK):
        """
        Private constructor. Use create() class method instead.

        Args:
            sdk: SDK instance
        """
        self._sdk = sdk

    @classmethod
    def create(cls, connection: IDeviceConnection) -> "BtcApp":
        """
        Create a new BtcApp instance.

        Args:
            connection: Device connection instance

        Returns:
            BtcApp instance
        """
        sdk = SDK.create(connection, cls.APPLET_ID)
        return cls(sdk)

    def get_public_key(
        self, params: operations.GetPublicKeyParams
    ) -> operations.GetPublicKeyResult:
        """
        Get public key from device.

        Args:
            params: Parameters for getting public key

        Returns:
            Public key result
        """
        return self._sdk.run_operation(
            lambda: operations.get_public_key(self._sdk, params)
        )

    def get_xpubs(
        self, params: operations.GetXpubsParams
    ) -> operations.GetXpubsResultResponse:
        """
        Get extended public keys from device.

        Args:
            params: Parameters for getting xpubs

        Returns:
            Extended public keys result
        """
        return self._sdk.run_operation(
            lambda: operations.get_xpubs(self._sdk, params)
        )

    def sign_txn(
        self, params: operations.SignTxnParams
    ) -> operations.SignTxnResult:
        """
        Sign Bitcoin transaction on device.

        Args:
            params: Parameters for signing transaction

        Returns:
            Sign transaction result
        """
        return self._sdk.run_operation(
            lambda: operations.sign_txn(self._sdk, params)
        )

    def destroy(self) -> None:
        """
        Destroy the SDK instance and cleanup resources.
        """
        return self._sdk.destroy()

    def abort(self) -> None:
        """
        Send abort signal to device.
        """
        self._sdk.send_abort()
