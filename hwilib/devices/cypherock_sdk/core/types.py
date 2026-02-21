# flake8: noqa E704
from typing import (
    Protocol,
    Optional,
    Callable,
    Any,
    Dict,
)
from ..interfaces import IDeviceConnection


class ISDK(Protocol):
    def get_connection(self) -> IDeviceConnection: ...

    def get_sequence_number(self) -> int: ...

    def get_new_sequence_number(self) -> int: ...

    def before_operation(self) -> None: ...

    def after_operation(self) -> None: ...

    def configure_applet_id(self, applet_id: int) -> None: ...

    def destroy(self) -> None: ...

    def send_query(
        self,
        data: bytes,
        options: Optional[Dict[str, Any]] = None,
    ) -> None: ...

    def get_result(
        self,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]: ...

    def wait_for_result(
        self,
        params: Optional[Dict[str, Any]] = None,
    ) -> bytes: ...

    def get_status(
        self,
        max_tries: Optional[int] = None,
        timeout: Optional[int] = None,
        dont_log: Optional[bool] = None,
    ) -> Any:  # Status from proto types
        ...

    def send_abort(
        self,
        options: Optional[Dict[str, Any]] = None,
    ) -> Any:  # Status from proto types
        ...

    def run_operation(self, operation: Callable[[], Any]) -> Any: ...


__all__ = [
    "ISDK",
]
