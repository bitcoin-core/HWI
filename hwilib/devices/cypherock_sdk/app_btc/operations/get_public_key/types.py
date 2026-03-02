from typing import Callable, Optional, List
from dataclasses import dataclass
from enum import IntEnum


class GetPublicKeyEvent(IntEnum):
    """Events that can occur during get public key operation."""

    INIT = 0
    CONFIRM = 1
    PASSPHRASE = 2
    PIN_CARD = 3
    VERIFY = 4


GetPublicKeyEventHandler = Callable[[GetPublicKeyEvent], None]


@dataclass
class GetPublicKeyParams:
    """Parameters for get public key operation."""

    wallet_id: bytes
    derivation_path: List[int]
    on_event: Optional[GetPublicKeyEventHandler] = None


@dataclass
class GetPublicKeyResult:
    """Result of get public key operation."""

    public_key: bytes
    address: str
