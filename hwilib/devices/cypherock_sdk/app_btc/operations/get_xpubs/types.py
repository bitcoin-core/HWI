from typing import Callable, Optional, List
from dataclasses import dataclass
from enum import IntEnum


class GetXpubsEvent(IntEnum):
    """Events that can occur during get xpubs operation."""

    INIT = 0
    CONFIRM = 1
    PASSPHRASE = 2
    PIN_CARD = 3


GetXpubsEventHandler = Callable[[GetXpubsEvent], None]


@dataclass
class GetXpubsParams:
    """Parameters for get xpubs operation."""

    wallet_id: bytes
    derivation_paths: List[dict]
    on_event: Optional[GetXpubsEventHandler] = None
