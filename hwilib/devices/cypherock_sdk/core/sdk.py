from typing import Optional, Dict, Any, Callable
from ..interfaces import IDeviceConnection
from .operations import proto as operations
from .utils.packet_version import PacketVersionMap
from .types import ISDK
from .encoders.proto.generated.core_pb2 import DeviceIdleState
from ..errors import DeviceAppError, DeviceAppErrorType

import logging

logger = logging.getLogger(__name__)

class SDK:
    def __init__(
        self,
        connection: IDeviceConnection,
        applet_id: int,
    ):
        self.connection = connection
        self.applet_id = applet_id

    @classmethod
    def create(
        cls,
        connection: IDeviceConnection,
        applet_id: int,
    ) -> ISDK:
        return cls(
            connection,
            applet_id,
        )

    def get_connection(self) -> IDeviceConnection:
        return self.connection

    def get_sequence_number(self) -> int:
        return self.connection.get_sequence_number()

    def get_new_sequence_number(self) -> int:
        return self.connection.get_new_sequence_number()

    def before_operation(self) -> None:
        return self.connection.before_operation()

    def after_operation(self) -> None:
        return self.connection.after_operation()

    def configure_applet_id(self, applet_id: int) -> None:
        self.applet_id = applet_id

    def destroy(self) -> None:
        return self.connection.destroy()

    # ************** v3 Packet Version with protobuf ****************
    def send_query(
        self,
        data: bytes,
        options: Optional[Dict[str, Any]] = None,
    ) -> None:
        sequence_number = options.get("sequence_number") if options else None
        if sequence_number is None:
            sequence_number = self.get_new_sequence_number()

        max_tries = options.get("max_tries") if options else None
        timeout = options.get("timeout") if options else None

        # Set defaults for None values
        if max_tries is None:
            max_tries = 5

        return operations.send_query(
            connection=self.connection,
            data=data,
            applet_id=self.applet_id,
            sequence_number=sequence_number,
            version=PacketVersionMap.v3,
            max_tries=max_tries,
            timeout=timeout,
        )

    def get_result(self, options: Optional[Dict[str, Any]] = None):
        sequence_number = options.get("sequence_number") if options else None
        if sequence_number is None:
            sequence_number = self.get_sequence_number()

        max_tries = options.get("max_tries") if options else None
        timeout = options.get("timeout") if options else None

        # Set defaults for None values
        if max_tries is None:
            max_tries = 5

        return operations.get_result(
            connection=self.connection,
            applet_id=self.applet_id,
            sequence_number=sequence_number,
            version=PacketVersionMap.v3,
            max_tries=max_tries,
            timeout=timeout,
        )

    def wait_for_result(self, params: Optional[Dict[str, Any]] = None):
        sequence_number = params.get("sequence_number") if params else None
        if sequence_number is None:
            sequence_number = self.get_sequence_number()

        on_status = params.get("on_status") if params else None
        options = params.get("options") if params else None

        return operations.wait_for_result(
            connection=self.connection,
            version=PacketVersionMap.v3,
            applet_id=self.applet_id,
            sequence_number=sequence_number,
            on_status=on_status,
            options=options,
        )

    def get_status(
        self,
        max_tries: Optional[int] = None,
        timeout: Optional[int] = None,
        dont_log: Optional[bool] = None,
    ):
        # Set defaults for None values
        if max_tries is None:
            max_tries = 5
        if dont_log is None:
            dont_log = False

        return operations.get_status(
            connection=self.connection,
            version=PacketVersionMap.v3,
            max_tries=max_tries,
            timeout=timeout,
            dont_log=dont_log,
        )

    def send_abort(self, options: Optional[Dict[str, Any]] = None):
        sequence_number = options.get("sequence_number") if options else None
        if sequence_number is None:
            sequence_number = self.get_new_sequence_number()

        max_tries = options.get("max_tries") if options else None
        timeout = options.get("timeout") if options else None

        # Set defaults for None values
        if max_tries is None:
            max_tries = 5

        return operations.send_abort(
            connection=self.connection,
            sequence_number=sequence_number,
            version=PacketVersionMap.v3,
            max_tries=max_tries,
            timeout=timeout,
        )

    def make_device_ready(self) -> None:
        self.ensure_if_usb_idle()

        status = self.get_status()
        if status.device_idle_state in [
            DeviceIdleState.DEVICE_IDLE_STATE_USB,
            DeviceIdleState.DEVICE_IDLE_STATE_DEVICE,
        ]:
            if status.abort_disabled:
                raise DeviceAppError(DeviceAppErrorType.EXECUTING_OTHER_COMMAND)

            self.send_abort()

    def run_operation(self, operation: Callable[[], Any]) -> Any:
        try:
            self.connection.before_operation()
            self.make_device_ready()

            result = operation()

            if self.connection.is_connected():
                self.connection.after_operation()

            return result
        except Exception as error:
            if self.connection.is_connected():
                self.connection.after_operation()

            raise error

    def ensure_if_usb_idle(self) -> None:
        try:
            operations.wait_for_idle(
                connection=self.connection,
                version=PacketVersionMap.v3,
            )
        except Exception as error:
            logger.warn("Error while checking for idle state")
            logger.warn(error)


__all__ = ["SDK"]
