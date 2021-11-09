import os
import socket
from typing import Optional

from .ipc_message import IpcMessage


# Connect to the service
def ipc_connect(port: int) -> Optional[socket.socket]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # we use a very short timeout for connection in this way we are very fast to enumerate (especially on Windows)
        if os.name == "nt":
            sock.settimeout(1)
        else:
            sock.settimeout(None)

        sock.connect(("127.0.0.1", port))

        # If connection succeeded remove the timeout
        sock.settimeout(None)

        return sock
    except Exception:
        return None


# Read an IPC message from the socket.
# IPC messages are in TLV format: [type: 4 bytes | payload_size: 8 bytes | payload: payload_size bytes]
# The payload is always as text
def ipc_read_message(sock: socket.socket) -> Optional[IpcMessage]:
    try:
        # get the type
        cmd = sock.recv(IpcMessage.get_cmd_msg_size()).decode("utf-8")
        cmd = cmd.strip().replace(" ", "")

        # get the size
        size = sock.recv(IpcMessage.get_size_msg_size()).decode("utf-8")
        size = size.strip().replace(" ", "")

        if len(size) == 0:
            return None

        # read the payload
        int_size = int(size)
        value = sock.recv(int_size)

        return IpcMessage(cmd, str(value.decode("utf-8")))

    except Exception:
        return None


# Send an IPC message through the socket.
# IPC messages are in TLV format: [type: 4 bytes | payload_size: 8 bytes | payload: payload_size bytes]
# The payload is always as text
def ipc_send_message(sock: socket.socket, msg: IpcMessage) -> bool:

    try:
        # serialize the type
        cmd = msg.get_cmd().ljust(IpcMessage.get_cmd_msg_size())

        # serialize the size
        size = len(msg.get_raw_value())
        str_size = str(size).ljust(IpcMessage.get_size_msg_size())

        # serialize the payload and send all
        complete = cmd + str_size + msg.get_raw_value()
        sock.sendall(str.encode(complete))
        return True
    except Exception:
        return False


def ipc_send_and_get_response(
    sock: socket.socket, msg: IpcMessage
) -> Optional[IpcMessage]:
    if not ipc_send_message(sock, msg):
        return None

    return ipc_read_message(sock)
