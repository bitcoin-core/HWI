from ....core.types import ISDK
from ...proto.generated.manager.get_wallets_pb2 import GetWalletsResultResponse
from ...utils import assert_or_throw_invalid_result, OperationHelper

import logging
logger = logging.getLogger(__name__)


def get_wallets(sdk: ISDK) -> GetWalletsResultResponse:
    logger.info("Started")

    helper = OperationHelper(sdk, "get_wallets", "get_wallets")

    helper.send_query({"initiate": {}})
    result = helper.wait_for_result()
    logger.info("GetWalletsResponse", {"result": result})
    assert_or_throw_invalid_result(result.result)

    logger.info("Completed")
    return result.result
