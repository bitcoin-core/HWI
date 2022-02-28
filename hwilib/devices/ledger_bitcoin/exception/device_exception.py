import enum
from typing import Dict, Any, Union

from .errors import *


class DeviceException(Exception):  # pylint: disable=too-few-public-methods
    exc: Dict[int, Any] = {
        0x6985: DenyError,
        0x6982: SecurityStatusNotSatisfiedError,
        0x6A80: IncorrectDataError,
        0x6A82: NotSupportedError,
        0x6A86: WrongP1P2Error,
        0x6A87: WrongDataLengthError,
        0x6D00: InsNotSupportedError,
        0x6E00: ClaNotSupportedError,
        0xB000: WrongResponseLengthError,
        0xB007: BadStateError,
        0xB008: SignatureFailError,
        0xE000: InterruptedExecution,  # not an error
    }

    def __new__(cls,
                error_code: int,
                ins: Union[int, enum.IntEnum, None] = None,
                message: str = ""
                ) -> Any:
        error_message: str = (f"Error in {ins!r} command"
                              if ins else "Error in command")

        if error_code in DeviceException.exc:
            return DeviceException.exc[error_code](hex(error_code),
                                                   error_message,
                                                   message)

        return UnknownDeviceError(hex(error_code), error_message, message)
