from enum import Enum
from typing import Dict
from .device_error import DeviceError


class DeviceConnectionErrorType(Enum):
    NOT_CONNECTED = "CON_0100"
    CONNECTION_CLOSED = "CON_0101"
    FAILED_TO_CONNECT = "CON_0102"


class CodeToErrorMap:
    def __init__(self):
        self._map: Dict[DeviceConnectionErrorType, Dict[str, str]] = {
            DeviceConnectionErrorType.NOT_CONNECTED: {"message": "No device connected"},
            DeviceConnectionErrorType.CONNECTION_CLOSED: {
                "message": "Connection was closed while in process"
            },
            DeviceConnectionErrorType.FAILED_TO_CONNECT: {
                "message": "Failed to create device connection"
            },
        }

    def __getitem__(self, key: DeviceConnectionErrorType) -> Dict[str, str]:
        return self._map.get(key)


deviceConnectionErrorTypeDetails = CodeToErrorMap()


class DeviceConnectionError(DeviceError):
    def __init__(self, error_code: DeviceConnectionErrorType):
        super().__init__(
            error_code.value,
            deviceConnectionErrorTypeDetails[error_code]["message"],
            DeviceConnectionError,
        )
