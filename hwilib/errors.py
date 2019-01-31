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
class NoPasswordError(Exception):
    def __init__(self,*args,**kwargs):
        Exception.__init__(self,*args,**kwargs)

class UnavailableActionError(Exception):
    def __init__(self,*args,**kwargs):
        Exception.__init__(self,*args,**kwargs)

class DeviceAlreadyInitError(Exception):
    def __init__(self,*args,**kwargs):
        Exception.__init__(self,*args,**kwargs)

class DeviceNotReadyError(Exception):
    def __init__(self,*args,**kwargs):
        Exception.__init__(self,*args,**kwargs)

class DeviceAlreadyUnlockedError(Exception):
    def __init__(self,*args,**kwargs):
        Exception.__init__(self,*args,**kwargs)

class UnknownDeviceError(Exception):
    def __init__(self,*args,**kwargs):
        Exception.__init__(self,*args,**kwargs)
