from ....core.types import ISDK
from ...proto.generated.manager.get_device_info_pb2 import GetDeviceInfoResultResponse
from ...utils import assert_or_throw_invalid_result, OperationHelper

import logging
logger = logging.getLogger(__name__)


def get_device_info(sdk: ISDK) -> GetDeviceInfoResultResponse:
    logger.info("Started")
    helper = OperationHelper(sdk, "get_device_info", "get_device_info")
    helper.send_query({"initiate": {}})
    result = helper.wait_for_result()
    logger.info("GetDeviceInfoResponse", {"result": result})
    assert_or_throw_invalid_result(result.result)
    logger.info("Completed")
    return result.result
