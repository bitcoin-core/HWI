from ....core.types import ISDK
from ....common_utils import assert_condition, create_status_listener
from ...proto.generated.btc.get_xpubs_pb2 import GetXpubsStatus, GetXpubsResultResponse
from ...proto.generated.common_pb2 import SeedGenerationStatus
from ...utils import (
    assert_or_throw_invalid_result,
    OperationHelper,
    assert_derivation_path,
)
from .types import GetXpubsEvent, GetXpubsParams

import logging
logger = logging.getLogger(__name__)

__all__ = ["get_xpubs", "GetXpubsEvent", "GetXpubsParams"]


def get_xpubs(
    sdk: ISDK,
    params: GetXpubsParams,
) -> GetXpubsResultResponse:
    """
    Get extended public keys from device.
    Direct port of TypeScript getXpubs function.

    Args:
        sdk: SDK instance
        params: Parameters including wallet_id, derivation_paths, and optional on_event handler

    Returns:
        Result containing list of xpubs

    Raises:
        AssertionError: If parameters are invalid
    """
    assert_condition(params, "params should be defined")
    assert_condition(params.derivation_paths, "derivation_paths should be defined")
    assert_condition(params.wallet_id, "wallet_id should be defined")
    assert_condition(
        len(params.derivation_paths) > 0,
        "derivation_paths should not be empty",
    )
    for derivation_path in params.derivation_paths:
        assert_derivation_path(derivation_path["path"])
    assert_condition(
        all(len(path["path"]) == 3 for path in params.derivation_paths),
        "derivation_paths should be of depth 3",
    )

    status_listener = create_status_listener(
        {
            "enums": GetXpubsEvent,
            "operationEnums": GetXpubsStatus,
            "seedGenerationEnums": SeedGenerationStatus,
            "onEvent": params.on_event,
            "logger": logger,
        }
    )
    on_status = status_listener["onStatus"]
    force_status_update = status_listener["forceStatusUpdate"]

    helper = OperationHelper(
        sdk=sdk,
        query_key="get_xpubs",
        result_key="get_xpubs",
        on_status=on_status,
    )

    helper.send_query(
        {
            "initiate": {
                "wallet_id": params.wallet_id,
                "derivation_paths": params.derivation_paths,
            }
        }
    )

    result = helper.wait_for_result()

    assert_or_throw_invalid_result(result.result)

    force_status_update(GetXpubsEvent.PIN_CARD)

    return GetXpubsResultResponse(xpubs=result.result.xpubs)
