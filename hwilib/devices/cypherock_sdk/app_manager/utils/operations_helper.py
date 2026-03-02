from typing import TypeVar, Generic, Callable, Optional, Any, Dict
from ...core.types import ISDK
from ...core.encoders.proto.generated.core_pb2 import Status
from ...errors.app_error import DeviceAppError, DeviceAppErrorType
from ..proto.generated.manager.core_pb2 import Query, Result
from ...core.utils.common_error import assert_or_throw_invalid_result, parse_common_error

Q = TypeVar("Q")
R = TypeVar("R")


def decode_result(data: bytes) -> Result:
    """
    Decode result data from bytes using standard protobuf.

    Args:
        data: The bytes to decode

    Returns:
        Decoded Result object

    Raises:
        DeviceAppError: If decoding fails
    """
    try:
        result = Result()
        result.ParseFromString(data)
        return result
    except Exception as error:
        raise DeviceAppError(DeviceAppErrorType.INVALID_MSG_FROM_DEVICE) from error


def encode_query(query_data: Dict[str, Any]) -> bytes:
    """
    Encode query object to bytes.

    Args:
        query_data: Dictionary with query field and value

    Returns:
        Encoded query as bytes
    """
    query = Query(**query_data)
    return query.SerializeToString()


class OperationHelper(Generic[Q, R]):
    """
    Helper class for managing device operations with typed query and result handling.
    """

    def __init__(self, sdk: ISDK, query_key: str, result_key: str):
        """
        Initialize the operation helper.

        Args:
            sdk: The SDK instance to use for communication
            query_key: The key name for the query field
            result_key: The key name for the result field
        """
        self.sdk = sdk
        self.query_key = query_key
        self.result_key = result_key

    def send_query(self, query: Any) -> None:
        """
        Send a query to the device.

        Args:
            query: The query object to send
        """
        query_data = {self.query_key: query}
        encoded_query = encode_query(query_data)
        return self.sdk.send_query(encoded_query)

    def wait_for_result(
        self, on_status: Optional[Callable[[Status], None]] = None
    ) -> Any:
        """
        Wait for and process the result from the device.

        Args:
            on_status: Optional callback for status updates

        Returns:
            The result data for the specified result key

        Raises:
            DeviceAppError: If the result is invalid or contains errors
        """
        params = {"on_status": on_status} if on_status else None
        result_data = self.sdk.wait_for_result(params=params)
        result = decode_result(result_data)
        if result.common_error:
            parse_common_error(result.common_error)

        result_value = getattr(result, self.result_key, None)
        assert_or_throw_invalid_result(result_value)

        if hasattr(result_value, "common_error") and result_value.common_error:
            parse_common_error(result_value.common_error)

        return result_value
