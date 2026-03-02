from typing import Optional
from ....core.types import ISDK
from ....common_utils import create_status_listener
from ...proto.generated.manager.get_logs_pb2 import GetLogsStatus, GetLogsErrorResponse
from ...utils import assert_or_throw_invalid_result, OperationHelper
from .types import GetLogsError, GetLogsErrorType, GetLogsEventHandler

import logging
logger = logging.getLogger(__name__)

__all__ = ["get_logs", "GetLogsError", "GetLogsErrorType", "GetLogsEventHandler"]


def parse_get_logs_error(error: Optional[GetLogsErrorResponse]) -> None:
    if error is None:
        return

    error_types_map = {
        "logsDisabled": GetLogsErrorType.LOGS_DISABLED,
    }

    for key, error_type in error_types_map.items():
        if hasattr(error, key) and getattr(error, key):
            raise GetLogsError(error_type)


def fetch_logs_data(helper: OperationHelper, on_status) -> str:
    result = helper.wait_for_result(on_status)

    parse_get_logs_error(result.error)
    assert_or_throw_invalid_result(result.logs)

    return result.logs


def get_logs(
    sdk: ISDK,
    on_event: Optional[GetLogsEventHandler] = None,
) -> str:
    logger.info("Started")
    helper = OperationHelper(sdk, "get_logs", "get_logs")

    status_listener = create_status_listener(
        {
            "enums": GetLogsStatus,
            "onEvent": on_event,
            "logger": logger,
        }
    )
    on_status = status_listener["onStatus"]
    force_status_update = status_listener["forceStatusUpdate"]

    # ASCII decoder for log data
    def decode_ascii(data: bytes) -> str:
        return data.decode("ascii", errors="replace")

    all_logs: list[str] = []
    is_confirmed = False
    has_more = False

    helper.send_query({"initiate": {}})

    while True:
        result = fetch_logs_data(helper, on_status)

        if not is_confirmed:
            force_status_update(GetLogsStatus.GET_LOGS_STATUS_USER_CONFIRMED)

        is_confirmed = True
        has_more = result.has_more

        all_logs.append(decode_ascii(result.data))

        if has_more:
            helper.send_query({"fetch_next": {}})
        else:
            break

    logger.info("Completed")
    return "".join(all_logs)
