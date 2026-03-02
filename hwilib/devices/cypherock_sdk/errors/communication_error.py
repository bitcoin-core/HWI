from enum import Enum
from typing import Dict
from .device_error import DeviceError


class DeviceCommunicationErrorType(Enum):
    IN_BOOTLOADER = "COM_0000"
    UNKNOWN_COMMUNICATION_ERROR = "COM_0100"
    WRITE_ERROR = "COM_0101"
    WRITE_TIMEOUT = "COM_0102"
    READ_TIMEOUT = "COM_0103"
    WRITE_REJECTED = "COM_0104"


class CodeToErrorMap:
    def __init__(self):
        self._map: Dict[DeviceCommunicationErrorType, Dict[str, str]] = {
            DeviceCommunicationErrorType.IN_BOOTLOADER: {
                "message": "Device is in bootloader mode"
            },
            DeviceCommunicationErrorType.WRITE_REJECTED: {
                "message": "The write packet operation was rejected by the device"
            },
            DeviceCommunicationErrorType.WRITE_ERROR: {
                "message": "Unable to write packet to the device"
            },
            DeviceCommunicationErrorType.WRITE_TIMEOUT: {
                "message": "Did not receive ACK of sent packet on time"
            },
            DeviceCommunicationErrorType.READ_TIMEOUT: {
                "message": "Did not receive the expected data from device on time"
            },
            DeviceCommunicationErrorType.UNKNOWN_COMMUNICATION_ERROR: {
                "message": "Unknown Error at communication module"
            },
        }

    def __getitem__(self, key: DeviceCommunicationErrorType) -> Dict[str, str]:
        return self._map.get(key)


deviceCommunicationErrorTypeDetails = CodeToErrorMap()


class DeviceCommunicationError(DeviceError):
    """
    Device communication error class.
    """

    def __init__(self, error_code: DeviceCommunicationErrorType):
        super().__init__(
            error_code.value,
            deviceCommunicationErrorTypeDetails[error_code]["message"],
            DeviceCommunicationError,
        )
