"""ledgercomm.transport module."""

import enum
import logging
import struct
from typing import Union, Tuple, Optional, cast

from .interfaces.tcp_client import TCPClient
from .interfaces.hid_device import HID
from .log import LOG


class TransportType(enum.Enum):
    """Type of interface available."""

    HID = 1
    TCP = 2


class Transport:
    """Transport class to send APDUs.

    Allow to communicate using HID device such as Nano S/X or through TCP
    socket with the Speculos emulator.

    Parameters
    ----------
    interface : str
        Either "hid" or "tcp" for the underlying communication interface.
    server : str
        IP adress of the TCP server if interface is "tcp".
    port : int
        Port of the TCP server if interface is "tcp".
    debug : bool
        Whether you want debug logs or not.

    Attributes
    ----------
    interface : TransportType
        Either TransportType.HID or TransportType.TCP.
    com : Union[TCPClient, HID]
        Communication interface to send/receive APDUs.

    """

    def __init__(self,
                 interface: str = "tcp", # Literal["hid", "tcp"]
                 server: str = "127.0.0.1",
                 port: int = 9999,
                 hid_path: Optional[bytes] = None,
                 debug: bool = False) -> None:
        """Init constructor of Transport."""
        if debug:
            LOG.setLevel(logging.DEBUG)

        self.interface: TransportType

        try:
            self.interface = TransportType[interface.upper()]
        except KeyError as exc:
            raise Exception(f"Unknown interface '{interface}'!") from exc

        self.com: Union[TCPClient, HID] = (TCPClient(server=server, port=port)
                                           if self.interface == TransportType.TCP
                                           else HID(hid_path=hid_path))

        self.com.open()

    @staticmethod
    def apdu_header(cla: int,
                    ins: Union[int, enum.IntEnum],
                    p1: int = 0,
                    p2: int = 0,
                    opt: Optional[int] = None,
                    lc: int = 0) -> bytes:
        """Pack the APDU header as bytes.

        Parameters
        ----------
        cla : int
            Instruction class: CLA (1 byte)
        ins : Union[int, IntEnum]
            Instruction code: INS (1 byte)
        p1 : int
            Instruction parameter: P1 (1 byte).
        p2 : int
            Instruction parameter: P2 (1 byte).
        opt : Optional[int]
            Optional parameter: Opt (1 byte).
        lc : int
            Number of bytes in the payload: Lc (1 byte).

        Returns
        -------
        bytes
            APDU header packed with parameters.

        """
        ins = cast(int, ins.value) if isinstance(ins, enum.IntEnum) else cast(int, ins)

        if opt:
            return struct.pack("BBBBBB",
                               cla,
                               ins,
                               p1,
                               p2,
                               1 + lc,  # add option to length
                               opt)

        return struct.pack("BBBBB",
                           cla,
                           ins,
                           p1,
                           p2,
                           lc)

    def send(self,
             cla: int,
             ins: Union[int, enum.IntEnum],
             p1: int = 0,
             p2: int = 0,
             option: Optional[int] = None,
             cdata: bytes = b"") -> int:
        """Send structured APDUs through `self.com`.

        Parameters
        ----------
        cla : int
            Instruction class: CLA (1 byte)
        ins : Union[int, IntEnum]
            Instruction code: INS (1 byte)
        p1 : int
            Instruction parameter: P1 (1 byte).
        p2 : int
            Instruction parameter: P2 (1 byte).
        option : Optional[int]
            Optional parameter: Opt (1 byte).
        cdata : bytes
            Command data (variable length).

        Returns
        -------
        int
            Total lenght of the APDU sent.

        """
        header: bytes = Transport.apdu_header(cla, ins, p1, p2, option, len(cdata))

        return self.com.send(header + cdata)

    def send_raw(self, apdu: Union[str, bytes]) -> int:
        """Send raw bytes `apdu` through `self.com`.

        Parameters
        ----------
        apdu : Union[str, bytes]
            Hexstring or bytes within APDU to be sent through `self.com`.

        Returns
        -------
        Optional[int]
            Total lenght of APDU sent if any.

        """
        if isinstance(apdu, str):
            apdu = bytes.fromhex(apdu)

        return self.com.send(apdu)

    def recv(self) -> Tuple[int, bytes]:
        """Receive data from `self.com`.

        Blocking IO.

        Returns
        -------
        Tuple[int, bytes]
            A pair (sw, rdata) for the status word (2 bytes represented
            as int) and the reponse data (variable lenght).

        """
        return self.com.recv()

    def exchange(self,
                 cla: int,
                 ins: Union[int, enum.IntEnum],
                 p1: int = 0,
                 p2: int = 0,
                 option: Optional[int] = None,
                 cdata: bytes = b"") -> Tuple[int, bytes]:
        """Send structured APDUs and wait to receive datas from `self.com`.

        Parameters
        ----------
        cla : int
            Instruction class: CLA (1 byte)
        ins : Union[int, IntEnum]
            Instruction code: INS (1 byte)
        p1 : int
            Instruction parameter: P1 (1 byte).
        p2 : int
            Instruction parameter: P2 (1 byte).
        option : Optional[int]
            Optional parameter: Opt (1 byte).
        cdata : bytes
            Command data (variable length).

        Returns
        -------
        Tuple[int, bytes]
            A pair (sw, rdata) for the status word (2 bytes represented
            as int) and the reponse data (bytes of variable lenght).

        """
        header: bytes = Transport.apdu_header(cla, ins, p1, p2, option, len(cdata))

        return self.com.exchange(header + cdata)

    def exchange_raw(self, apdu: Union[str, bytes]) -> Tuple[int, bytes]:
        """Send raw bytes `apdu` and wait to receive datas from `self.com`.

        Parameters
        ----------
        apdu : Union[str, bytes]
            Hexstring or bytes within APDU to send through `self.com`.

        Returns
        -------
        Tuple[int, bytes]
            A pair (sw, rdata) for the status word (2 bytes represented
            as int) and the reponse (bytes of variable lenght).

        """
        if isinstance(apdu, str):
            apdu = bytes.fromhex(apdu)

        return self.com.exchange(apdu)

    def close(self) -> None:
        """Close `self.com` interface.

        Returns
        -------
        None

        """
        self.com.close()
