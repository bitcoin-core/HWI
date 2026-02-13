from ....errors import (
    DeviceAppError,
    DeviceAppErrorType,
    DeviceCommunicationError,
    DeviceCommunicationErrorType,
    DeviceConnectionErrorType,
)


def can_retry(error: Exception) -> bool:
    dont_retry = False

    if isinstance(error, Exception) and hasattr(error, "code"):
        if error.code in [e.value for e in DeviceConnectionErrorType]:
            dont_retry = True

    if (
        isinstance(error, DeviceCommunicationError)
        and hasattr(error, "code")
        and error.code == DeviceCommunicationErrorType.WRITE_REJECTED
    ):
        dont_retry = True

    if (
        isinstance(error, DeviceAppError)
        and hasattr(error, "code")
        and error.code
        in [
            DeviceAppErrorType.PROCESS_ABORTED,
            DeviceAppErrorType.DEVICE_ABORT,
        ]
    ):
        dont_retry = True

    return not dont_retry
