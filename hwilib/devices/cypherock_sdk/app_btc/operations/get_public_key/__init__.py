from ....core.types import ISDK
from ....common_utils import assert_condition, create_status_listener
from ....errors import DeviceAppError, DeviceAppErrorType
from ...proto.generated.btc.get_public_key_pb2 import GetPublicKeyStatus
from ...proto.generated.common_pb2 import SeedGenerationStatus
from ...utils import (
    assert_or_throw_invalid_result,
    OperationHelper,
    assert_derivation_path,
)
from .types import (
    GetPublicKeyEvent,
    GetPublicKeyParams,
    GetPublicKeyResult,
)

__all__ = [
    "get_public_key",
    "GetPublicKeyEvent",
    "GetPublicKeyParams",
    "GetPublicKeyResult",
]

import logging
logger = logging.getLogger(__name__)


def get_public_key(
    sdk: ISDK,
    params: GetPublicKeyParams,
) -> GetPublicKeyResult:
    """
    Get public key from device.

    Args:
        sdk: SDK instance
        params: Parameters including wallet_id, derivation_path, and optional on_event handler

    Returns:
        Result containing public_key

    Raises:
        AssertionError: If parameters are invalid
    """
    assert_condition(params, "params should be defined")
    assert_condition(params.wallet_id, "wallet_id should be defined")
    assert_derivation_path(params.derivation_path)
    assert_condition(
        len(params.derivation_path) == 5,
        "derivation_path should be of depth 5",
    )

    status_listener = create_status_listener(
        {
            "enums": GetPublicKeyEvent,
            "operationEnums": GetPublicKeyStatus,
            "seedGenerationEnums": SeedGenerationStatus,
            "onEvent": params.on_event,
            "logger": logger,
        }
    )
    on_status = status_listener["onStatus"]
    force_status_update = status_listener["forceStatusUpdate"]

    helper = OperationHelper(
        sdk=sdk,
        query_key="get_public_key",
        result_key="get_public_key",
        on_status=on_status,
    )

    helper.send_query(
        {
            "initiate": {
                "wallet_id": params.wallet_id,
                "derivation_path": params.derivation_path,
            }
        }
    )

    result = helper.wait_for_result()
    assert_or_throw_invalid_result(result.result)

    force_status_update(GetPublicKeyEvent.VERIFY)

    if not result.result.public_key or len(result.result.public_key) == 0:
        raise DeviceAppError(DeviceAppErrorType.INVALID_MSG_FROM_DEVICE)

    # TODO: Firmware should return the address

    return GetPublicKeyResult(
        public_key=result.result.public_key,
        address="",
    )
