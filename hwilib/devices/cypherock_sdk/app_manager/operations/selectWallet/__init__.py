from ....core.types import ISDK
from ...proto.generated.manager.wallet_selector_pb2 import (
    SelectWalletResultResponse,
)
from ...utils import assert_or_throw_invalid_result, OperationHelper

import logging
logger = logging.getLogger(__name__)

def select_wallet(sdk: ISDK) -> SelectWalletResultResponse:
    logger.info("Started")

    helper = OperationHelper(sdk, "select_wallet", "select_wallet")

    helper.send_query({"initiate": {}})
    result = helper.wait_for_result()
    logger.info("SelectWalletResponse", {"result": result})
    assert_or_throw_invalid_result(result.result)

    logger.info("Completed")
    return result.result
