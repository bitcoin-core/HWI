"""
Errors and Error Codes
**********************

HWI has several possible Exceptions with corresponding error codes.

:class:`~hwilib.hwwclient.HardwareWalletClient` functions and :mod:`~hwilib.commands` functions will generally raise an exception that is a subclass of :class:`HWWError`.
The HWI command line tool will convert these exceptions into a dictionary containing the error message and error code.
These look like ``{"error": "<msg>", "code": <code>}``.
"""

from typing import Any, Dict, Iterator, Optional
from contextlib import contextmanager

# Error codes
NO_DEVICE_TYPE = -1 #: Device type was not specified
MISSING_ARGUMENTS = -2 #: Arguments are missing
DEVICE_CONN_ERROR = -3 #: Error connecting to the device
UNKNWON_DEVICE_TYPE = -4 #: Device type is unknown
INVALID_TX = -5 #: Transaction is invalid
NO_PASSWORD = -6 #: No password provided, but one is needed
BAD_ARGUMENT = -7 #: Bad, malformed, or conflicting argument was provided
NOT_IMPLEMENTED = -8 #: Function is not implemented
UNAVAILABLE_ACTION = -9 #: Function is not available for this device
DEVICE_ALREADY_INIT = -10 #: Device is already initialized
DEVICE_ALREADY_UNLOCKED = -11 #: Device is already unlocked
DEVICE_NOT_READY = -12 #: Device is not ready
UNKNOWN_ERROR = -13 #: An unknown error occurred
ACTION_CANCELED = -14 #: Action was canceled by the user
DEVICE_BUSY = -15 #: Device is busy
NEED_TO_BE_ROOT = -16 #: User needs to be root to perform action
HELP_TEXT = -17 #: Help text was requested by the user
DEVICE_NOT_INITIALIZED = -18 #: Device is not initialized

# Exceptions
class HWWError(Exception):
    """
    Generic exception type produced by HWI
    Subclassed by specific Errors to have Exceptions that have specific error codes.

    Contains a message and error code.
    """
    def __init__(self, msg: str, code: int) -> None:
        """
        Create an exception with the message and error code

        :param msg: The error message
        :param code: The error code
        """
        Exception.__init__(self)
        self.code = code
        self.msg = msg

    def get_code(self) -> int:
        """
        Get the error code for this Error

        :return: The error code
        """
        return self.code

    def get_msg(self) -> str:
        """
        Get the error message for this Error

        :return: The error message
        """
        return self.msg

    def __str__(self) -> str:
        return self.msg

class NoPasswordError(HWWError):
    """
    :class:`HWWError` for :data:`NO_PASSWORD`
    """
    def __init__(self, msg: str):
        """
        :param msg: The error message
        """
        HWWError.__init__(self, msg, NO_PASSWORD)

class UnavailableActionError(HWWError):
    """
    :class:`HWWError` for :data:`UNAVAILABLE_ACTION`
    """
    def __init__(self, msg: str):
        """
        :param msg: The error message
        """
        HWWError.__init__(self, msg, UNAVAILABLE_ACTION)

class DeviceAlreadyInitError(HWWError):
    """
    :class:`HWWError` for :data:`DEVICE_ALREADY_INIT`
    """
    def __init__(self, msg: str):
        """
        :param msg: The error message
        """
        HWWError.__init__(self, msg, DEVICE_ALREADY_INIT)

class DeviceNotReadyError(HWWError):
    """
    :class:`HWWError` for :data:`DEVICE_NOT_READY`
    """
    def __init__(self, msg: str):
        """
        :param msg: The error message
        """
        HWWError.__init__(self, msg, DEVICE_NOT_READY)

class DeviceAlreadyUnlockedError(HWWError):
    """
    :class:`HWWError` for :data:`DEVICE_ALREADY_UNLOCKED`
    """
    def __init__(self, msg: str):
        """
        :param msg: The error message
        """
        HWWError.__init__(self, msg, DEVICE_ALREADY_UNLOCKED)

class UnknownDeviceError(HWWError):
    """
    :class:`HWWError` for :data:`DEVICE_TYPE`
    """
    def __init__(self, msg: str):
        """
        :param msg: The error message
        """
        HWWError.__init__(self, msg, UNKNWON_DEVICE_TYPE)

class NotImplementedError(HWWError):
    """
    :class:`HWWError` for :data:`NOT_IMPLEMENTED`
    """
    def __init__(self, msg: str):
        """
        :param msg: The error message
        """
        HWWError.__init__(self, msg, NOT_IMPLEMENTED)

class PSBTSerializationError(HWWError):
    """
    :class:`HWWError` for :data:`INVALID_TX`
    """
    def __init__(self, msg: str):
        """
        :param msg: The error message
        """
        HWWError.__init__(self, msg, INVALID_TX)

class BadArgumentError(HWWError):
    """
    :class:`HWWError` for :data:`BAD_ARGUMENT`
    """
    def __init__(self, msg: str):
        """
        :param msg: The error message
        """
        HWWError.__init__(self, msg, BAD_ARGUMENT)

class DeviceFailureError(HWWError):
    """
    :class:`HWWError` for :data:`UNKNOWN_ERROR`
    """
    def __init__(self, msg: str):
        """
        :param msg: The error message
        """
        HWWError.__init__(self, msg, UNKNOWN_ERROR)

class ActionCanceledError(HWWError):
    """
    :class:`HWWError` for :data:`ACTION_CANCELED`
    """
    def __init__(self, msg: str):
        """
        :param msg: The error message
        """
        HWWError.__init__(self, msg, ACTION_CANCELED)

class DeviceConnectionError(HWWError):
    """
    :class:`HWWError` for :data:`DEVICE_CONN_ERROR`
    """
    def __init__(self, msg: str):
        """
        :param msg: The error message
        """
        HWWError.__init__(self, msg, DEVICE_CONN_ERROR)

class DeviceBusyError(HWWError):
    """
    :class:`HWWError` for :data:`DEVICE_BUSY`
    """
    def __init__(self, msg: str):
        """
        :param msg: The error message
        """
        HWWError.__init__(self, msg, DEVICE_BUSY)

class NeedsRootError(HWWError):
    def __init__(self, msg: str):
        HWWError.__init__(self, msg, NEED_TO_BE_ROOT)

@contextmanager
def handle_errors(
    msg: Optional[str] = None,
    result: Optional[Dict[str, Any]] = None,
    code: int = UNKNOWN_ERROR,
    debug: bool = False,
) -> Iterator[None]:
    """
    Context manager to catch all Exceptions and HWWErrors to return them as dictionaries containing the error message and code.

    :param msg: Error message prefix. Attached to the beginning of each error message
    :param result: The dictionary to put the resulting error in
    :param code: The default error code to use for Exceptions
    :param debug: Whether to also print out the traceback for debugging purposes
    """
    if result is None:
        result = {}

    if msg is None:
        msg = ""
    else:
        msg = msg + " "

    try:
        yield

    except HWWError as e:
        result['error'] = msg + e.get_msg()
        result['code'] = e.get_code()
    except Exception as e:
        result['error'] = msg + str(e)
        result['code'] = code
        if debug:
            import traceback
            traceback.print_exc()
    return result


common_err_msgs = {
    "enumerate": "Could not open client or get fingerprint information:"
}
