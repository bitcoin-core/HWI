from ..interfaces import IDeviceConnection
from ..core import sdk as core_sdk
from ..core.types import ISDK

from . import operations


class ManagerApp:
    APPLET_ID = 1

    def __init__(self, sdk: ISDK):
        self._sdk = sdk

    @classmethod
    def create(cls, connection: IDeviceConnection) -> "ManagerApp":
        sdk = core_sdk.SDK.create(connection, cls.APPLET_ID)
        return cls(sdk)

    def get_device_info(self):
        return self._sdk.run_operation(
            lambda: operations.get_device_info(self._sdk)
        )

    def get_wallets(self):
        return self._sdk.run_operation(lambda: operations.get_wallets(self._sdk))

    def get_logs(self, on_event: operations.GetLogsEventHandler = None):
        return self._sdk.run_operation(
            lambda: operations.get_logs(self._sdk, on_event)
        )

    def select_wallet(self):
        return self._sdk.run_operation(
            lambda: operations.select_wallet(self._sdk)
        )

    def destroy(self):
        return self._sdk.destroy()

    def abort(self):
        return self._sdk.send_abort()
