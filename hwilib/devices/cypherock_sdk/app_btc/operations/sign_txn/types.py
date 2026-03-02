from typing import Callable, Optional, List
from dataclasses import dataclass
from enum import IntEnum


class SignTxnEvent(IntEnum):
    """Events that can occur during sign transaction operation."""

    INIT = 0
    CONFIRM = 1
    VERIFY = 2
    PASSPHRASE = 3
    PIN_CARD = 4


SignTxnEventHandler = Callable[[SignTxnEvent], None]


@dataclass
class SignTxnInputData:
    """Input data for transaction signing."""

    prev_txn_id: bytes
    prev_index: int
    value: int
    script_pub_key: bytes
    change_index: int
    address_index: int
    prev_txn: bytes
    sequence: Optional[int] = None


@dataclass
class SignTxnOutputData:
    """Output data for transaction signing."""

    value: int
    script_pub_key: bytes
    is_change: bool
    address_index: Optional[int] = None


@dataclass
class SignTxnTxnData:
    """Transaction data for signing."""

    inputs: List[SignTxnInputData]
    outputs: List[SignTxnOutputData]
    locktime: Optional[int] = None
    hash_type: Optional[int] = None


@dataclass
class SignTxnParams:
    """Parameters for sign transaction operation."""

    wallet_id: bytes
    derivation_path: List[int]
    txn: SignTxnTxnData
    on_event: Optional[SignTxnEventHandler] = None


@dataclass
class SignTxnResult:
    """Result of sign transaction operation."""

    signatures: List[bytes]
