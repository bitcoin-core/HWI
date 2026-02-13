from enum import Enum
from typing import Dict, Any, Optional, Union
from .device_error import DeviceError


class DeviceAppErrorType(Enum):
    UNKNOWN_ERROR = "APP_0000"
    EXECUTING_OTHER_COMMAND = "APP_0101"
    PROCESS_ABORTED = "APP_0102"
    DEVICE_ABORT = "APP_0103"
    INVALID_MSG_FROM_DEVICE = "APP_0200"
    INVALID_APP_ID_FROM_DEVICE = "APP_0201"
    INVALID_MSG = "APP_0202"
    UNKNOWN_APP = "APP_0203"
    APP_NOT_ACTIVE = "APP_0204"
    DEVICE_SETUP_REQUIRED = "APP_0205"
    APP_TIMEOUT = "APP_0206"
    DEVICE_SESSION_INVALID = "APP_0207"
    WALLET_NOT_FOUND = "APP_0300"
    WALLET_PARTIAL_STATE = "APP_0301"
    CARD_OPERATION_FAILED = "APP_0400"
    USER_REJECTION = "APP_0501"
    CORRUPT_DATA = "APP_0600"
    DEVICE_AUTH_FAILED = "APP_0700"
    CARD_AUTH_FAILED = "APP_0701"


# Import here to avoid circular imports
from .card_error import cardErrorTypeDetails

deviceAppErrorTypeDetails: Dict[DeviceAppErrorType, Dict[str, Any]] = {
    DeviceAppErrorType.UNKNOWN_ERROR: {
        "subError": {},
        "message": "Unknown application error",
    },
    DeviceAppErrorType.EXECUTING_OTHER_COMMAND: {
        "subError": {},
        "message": "The device is executing some other command",
    },
    DeviceAppErrorType.PROCESS_ABORTED: {
        "subError": {},
        "message": "The process was aborted",
    },
    DeviceAppErrorType.DEVICE_ABORT: {
        "subError": {},
        "message": "The request was timed out on the device",
    },
    DeviceAppErrorType.INVALID_MSG_FROM_DEVICE: {
        "subError": {},
        "message": "Invalid result received from device",
    },
    DeviceAppErrorType.INVALID_APP_ID_FROM_DEVICE: {
        "subError": {},
        "message": "Invalid appId received from device",
    },
    DeviceAppErrorType.INVALID_MSG: {
        "subError": {},
        "message": "Invalid result sent from app",
    },
    DeviceAppErrorType.UNKNOWN_APP: {
        "subError": {},
        "message": "The app does not exist on device",
    },
    DeviceAppErrorType.APP_NOT_ACTIVE: {
        "subError": {},
        "message": "The app is active on the device",
    },
    DeviceAppErrorType.APP_TIMEOUT: {
        "subError": {},
        "message": "Operation timed out on device",
    },
    DeviceAppErrorType.DEVICE_SETUP_REQUIRED: {
        "subError": {},
        "message": "Device setup is required",
    },
    DeviceAppErrorType.WALLET_NOT_FOUND: {
        "subError": {},
        "message": "Selected wallet is not present on the device",
    },
    DeviceAppErrorType.WALLET_PARTIAL_STATE: {
        "subError": {},
        "message": "Selected wallet is in partial state",
    },
    DeviceAppErrorType.CARD_OPERATION_FAILED: {
        "subError": cardErrorTypeDetails,
        "message": "Card operation failed",
    },
    DeviceAppErrorType.USER_REJECTION: {
        "subError": {},
        "message": "User rejected the operation",
    },
    DeviceAppErrorType.CORRUPT_DATA: {
        "subError": {},
        "message": "Corrupt data error from device",
    },
    DeviceAppErrorType.DEVICE_AUTH_FAILED: {
        "subError": {},
        "message": "Device seems to be compromised. Contact Cypherock support",
    },
    DeviceAppErrorType.CARD_AUTH_FAILED: {
        "subError": {},
        "message": "Card seems to be compromised. Contact Cypherock support",
    },
    DeviceAppErrorType.DEVICE_SESSION_INVALID: {
        "subError": {},
        "message": "Could not establish session on device. Try again, or contact Cypherock support",
    },
}


class DeviceAppError(DeviceError):
    def __init__(
        self,
        error_code: DeviceAppErrorType,
        error_value: Optional[Union[int, str]] = None,
    ):
        message: str
        error_code_key: str

        details = deviceAppErrorTypeDetails[error_code]

        if error_value is not None and error_value in details["subError"]:
            sub_error = details["subError"][error_value]
            message = sub_error.message
            error_code_key = sub_error.error_code
        else:
            message = details["message"]
            if error_value is not None:
                message = f"{message} ({error_value})"
            error_code_key = error_code.value

        super().__init__(error_code_key, message, DeviceAppError)
