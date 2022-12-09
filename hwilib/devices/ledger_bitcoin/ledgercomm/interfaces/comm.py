"""ledgercomm.comm module."""

from abc import ABCMeta, abstractmethod
from typing import Tuple


class Comm(metaclass=ABCMeta):
    """Abstract class for communication interface."""

    @abstractmethod
    def open(self) -> None:
        """Just open the interface."""
        raise NotImplementedError

    @abstractmethod
    def send(self, data: bytes) -> int:
        """Allow to send raw bytes from the interface."""
        raise NotImplementedError

    @abstractmethod
    def recv(self) -> Tuple[int, bytes]:
        """Allow to receive raw bytes from the interface."""
        raise NotImplementedError

    @abstractmethod
    def exchange(self, data: bytes) -> Tuple[int, bytes]:
        """Allow to send and receive raw bytes from the interface."""
        raise NotImplementedError

    @abstractmethod
    def close(self) -> None:
        """Just close the interface."""
        raise NotImplementedError
