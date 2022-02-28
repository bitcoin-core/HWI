class UnknownDeviceError(Exception):
    pass


class SecurityStatusNotSatisfiedError(Exception):
    pass


class DenyError(Exception):
    pass


class IncorrectDataError(Exception):
    pass


class NotSupportedError(Exception):
    pass


class WrongP1P2Error(Exception):
    pass


class WrongDataLengthError(Exception):
    pass


class InsNotSupportedError(Exception):
    pass


class ClaNotSupportedError(Exception):
    pass


class WrongResponseLengthError(Exception):
    pass


class BadStateError(Exception):
    pass


class SignatureFailError(Exception):
    pass


# Not really an error
class InterruptedExecution(Exception):
    pass
