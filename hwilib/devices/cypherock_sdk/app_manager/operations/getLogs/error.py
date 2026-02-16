from enum import Enum
from ....errors import DeviceError


class GetLogsErrorType(Enum):
    LOGS_DISABLED = "MGA_GL_0000"


get_logs_error_type_details = {
    GetLogsErrorType.LOGS_DISABLED: {
        "message": "Logs are disabled on the device",
    },
}


class GetLogsError(DeviceError):
    def __init__(self, error_code: GetLogsErrorType):
        error_details = get_logs_error_type_details[error_code]
        super().__init__(error_code.value, error_details["message"], GetLogsError)
