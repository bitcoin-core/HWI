from typing import TypeVar, Optional, Dict, Any
from ...errors import DeviceAppError, DeviceAppErrorType
from ..encoders.proto.generated.error_pb2 import CommonError
from ...common_utils import assert_condition

T = TypeVar("T")


def assert_or_throw_invalid_result(condition: T) -> T:
    assert_condition(
        condition is not None,
        DeviceAppError(DeviceAppErrorType.INVALID_MSG_FROM_DEVICE),
    )
    return condition


def _is_truthy_error_value(value: Any) -> bool:
    try:
        if isinstance(value, bool):
            return value is True
        if isinstance(value, int):
            return value != 0
        if isinstance(value, (bytes, str, list, tuple, dict)):
            return len(value) > 0
    except Exception:
        pass
    return value is not None


def parse_common_error(error: Optional[CommonError]) -> None:
    if error is None:
        return

    error_types_map: Dict[str, DeviceAppErrorType] = {
        "unknown_error": DeviceAppErrorType.UNKNOWN_ERROR,
        "device_setup_required": DeviceAppErrorType.DEVICE_SETUP_REQUIRED,
        "wallet_not_found": DeviceAppErrorType.WALLET_NOT_FOUND,
        "wallet_partial_state": DeviceAppErrorType.WALLET_PARTIAL_STATE,
        "card_error": DeviceAppErrorType.CARD_OPERATION_FAILED,
        "user_rejection": DeviceAppErrorType.USER_REJECTION,
        "corrupt_data": DeviceAppErrorType.CORRUPT_DATA,
    }

    for key, field in getattr(error, "__dataclass_fields__", {}).items():
        value = getattr(error, key)
        if key in error_types_map and _is_truthy_error_value(value):
            raise DeviceAppError(error_types_map[key], value)
