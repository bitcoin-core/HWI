# Defines errors and error codes

# Error codes
NO_DEVICE_PATH = -1
NO_DEVICE_TYPE = -2
DEVICE_CONN_ERROR = -3
UNKNWON_DEVICE_TYPE = -4
INVALID_TX = -5
NO_PASSWORD = -6
BAD_ARGUMENT = -7
NOT_IMPLEMENTED = -8
UNAVAILABLE_ACTION = -9
DEVICE_ALREADY_INIT = -10
DEVICE_ALREADY_UNLOCKED = -11

# Exceptions
class HWWError(Exception):
    def __init__(self, msg, code):
        Exception.__init__(self)
        self.code = code
        self.msg = msg

    def get_code(self):
        return self.code

    def get_msg(self):
        return self.msg

    def __str__(self):
        return self.msg

class NoPasswordError(HWWError):
    def __init__(self, msg):
        HWWError.__init__(self, msg, NO_PASSWORD)

class UnavailableActionError(HWWError):
    def __init__(self, msg):
        HWWError.__init__(self, msg, UNAVAILABLE_ACTION)

class DeviceAlreadyInitError(HWWError):
    def __init__(self, msg):
        HWWError.__init__(self, msg, DEVICE_ALREADY_INIT)

class DeviceNotReadyError(HWWError):
    def __init__(self, msg):
        HWWError.__init__(self, msg, DEVICE_NOT_READY)

class DeviceAlreadyUnlockedError(HWWError):
    def __init__(self, msg):
        HWWError.__init__(self, msg, DEVICE_ALREADY_UNLOCKED)

class UnknownDeviceError(HWWError):
    def __init__(self, msg):
        HWWError.__init__(self, msg, UNKNWON_DEVICE_TYPE)
