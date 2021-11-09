SIGN_TX = "sgtx"
SIGN_MESSAGE = "sgms"
RESP = "resp"
PING = "ping"
EXIT = "exit"
XPUB = "xpub"

# Class that represents an ipc message: a command with a raw payload
# For serialization capability the payload is always a string so use
# base64 encoding for binary data
class IpcMessage:
    def __init__(self, cmd: str, value: str):
        self._cmd = cmd
        self._value = value

    def get_cmd(self) -> str:
        return self._cmd

    def get_raw_value(self) -> str:
        return self._value

    @staticmethod
    def get_cmd_msg_size() -> int:
        return 4

    @staticmethod
    def get_size_msg_size() -> int:
        return 8
