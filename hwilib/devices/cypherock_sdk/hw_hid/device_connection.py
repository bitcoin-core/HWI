from typing import Any, List, Optional
import logging
import hid

from ..interfaces import (
    IDevice,
    PoolData,
    IDeviceConnection,
)

from .helpers import DataListener, get_available_devices

from hwilib.errors import DeviceConnectionError

logger = logging.getLogger(__name__)


class DeviceConnection(IDeviceConnection):
    def __init__(self, device: IDevice, connection: Any):
        self.device: IDevice = device
        self.sequence_number = 0
        self.initialized = True
        self.is_port_open = True
        self.connection = connection

        listener_params = {
            "connection": self.connection,
            "device": self.device,
            "on_close": self.on_close,
            "on_error": self.on_error,
        }
        self.data_listener: DataListener = DataListener(listener_params)

    @staticmethod
    def connect(device: IDevice) -> "DeviceConnection":
        try:
            connection = hid.device()
            connection.open_path(device["path"].encode())
        except Exception as e:
            raise DeviceConnectionError(f"Failed to connect to device: {e}")

        return DeviceConnection(device, connection)

    @staticmethod
    def list():
        return get_available_devices()

    @staticmethod
    def create():
        devices = get_available_devices()

        if not devices:
            raise DeviceConnectionError("No devices found")

        device_to_connect = devices[0]
        return DeviceConnection.connect(device_to_connect)

    @staticmethod
    def get_available_connection():
        connection_info = get_available_devices()
        return connection_info

    def is_initialized(self) -> bool:
        return self.initialized

    def get_new_sequence_number(self) -> int:
        self.sequence_number += 1
        return self.sequence_number

    def get_sequence_number(self) -> int:
        return self.sequence_number

    def is_connected(self) -> bool:
        return self.is_port_open

    def destroy(self) -> None:
        if not self.is_port_open:
            return

        self.data_listener.destroy()
        try:
            self.connection.close()
        except Exception as error:
            logger.warn("Error while closing device connection")
            logger.warn(error)

    def before_operation(self) -> None:
        self.data_listener.start_listening()

    def after_operation(self) -> None:
        self.data_listener.stop_listening()

    def send(self, data: bytearray) -> None:
        data_to_write = [0x00] + list(data) + [0x00] * (64 - len(data))
        self.connection.write(bytes(data_to_write))

    def receive(self) -> Optional[bytearray]:
        result = self.data_listener.receive()
        return bytearray(result) if result is not None else None

    def peek(self) -> List[PoolData]:
        return self.data_listener.peek()

    def on_close(self):
        self.is_port_open = False

    def on_error(self, error: Exception):
        logger.error("Error on device connection callback")
        logger.error(error)
