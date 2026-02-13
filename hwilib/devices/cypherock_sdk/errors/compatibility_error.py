from enum import Enum
from typing import Dict
from .device_error import DeviceError


class DeviceCompatibilityErrorType(Enum):
    INVALID_SDK_OPERATION = "COM_0200"
    DEVICE_NOT_SUPPORTED = "COM_0201"


class CodeToErrorMap:
    def __init__(self):
        self._map: Dict[DeviceCompatibilityErrorType, Dict[str, str]] = {
            DeviceCompatibilityErrorType.INVALID_SDK_OPERATION: {
                "message": "The device sdk does not support this function"
            },
            DeviceCompatibilityErrorType.DEVICE_NOT_SUPPORTED: {
                "message": "The connected device is not supported by this SDK"
            },
        }

    def __getitem__(self, key: DeviceCompatibilityErrorType) -> Dict[str, str]:
        return self._map.get(key)


deviceCompatibilityErrorTypeDetails = CodeToErrorMap()


class DeviceCompatibilityError(DeviceError):
    def __init__(self, error_code: DeviceCompatibilityErrorType):
        super().__init__(
            error_code.value,
            deviceCompatibilityErrorTypeDetails[error_code]["message"],
            DeviceCompatibilityError,
        )
