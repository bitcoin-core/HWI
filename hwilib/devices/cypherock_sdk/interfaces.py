from typing import List, Literal, Optional, Protocol, TypedDict, runtime_checkable

class IDevice(TypedDict):
    path: str
    vendor_id: int
    product_id: int
    serial: str
    type: Literal['cypherock']
    model: Literal['cypherock-x1']
    label: Optional[str]
    needs_pin_sent: bool
    needs_passphrase_sent: bool
    fingerprint: str

class PoolData(TypedDict):
    id: str
    data: bytes

@runtime_checkable
class IDeviceConnection(Protocol):
    def get_connection_type(self) -> str: ...

    def is_connected(self) -> bool: ...

    def before_operation(self) -> None: ...

    def after_operation(self) -> None: ...

    def get_sequence_number(self) -> int: ...

    def get_new_sequence_number(self) -> int: ...

    def send(self, data: bytes) -> None: ...

    def receive(self) -> Optional[bytes]: ...

    def peek(self) -> List[PoolData]: ...

    def destroy(self) -> None: ...