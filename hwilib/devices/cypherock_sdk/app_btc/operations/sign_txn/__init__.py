import copy
from typing import List
from ....core.types import ISDK
from ....common_utils import (
    create_status_listener,
    hex_to_uint8array,
    uint8array_to_hex,
)
from ...proto.generated.btc.sign_txn_pb2 import SignTxnStatus
from ...proto.generated.common_pb2 import SeedGenerationStatus
from ...utils import (
    assert_or_throw_invalid_result,
    OperationHelper,
)
from .helpers import assert_sign_txn_params
from .types import SignTxnParams, SignTxnResult, SignTxnEvent
from hwilib.key import AddressType, get_addrtype_from_bip44_purpose

import logging
logger = logging.getLogger(__name__)

__all__ = ["sign_txn", "SignTxnEvent", "SignTxnParams", "SignTxnResult"]


SIGN_TXN_DEFAULT_PARAMS = {
    "version": 2,
    "locktime": 0,
    "hashtype": 1,
    "input": {
        "sequence": 0xFFFFFFFF,
    },
}


def sign_txn(
    sdk: ISDK,
    params: SignTxnParams,
) -> SignTxnResult:
    """
    Sign Bitcoin transaction on device.

    Args:
        sdk: SDK instance
        params: Parameters including wallet_id, derivation_path, txn data, and optional on_event handler

    Returns:
        Result containing signatures

    Raises:
        AssertionError: If parameters are invalid
    """
    assert_sign_txn_params(params)
    logger.info("Started")

    status_listener = create_status_listener(
        {
            "enums": SignTxnEvent,
            "operationEnums": SignTxnStatus,
            "seedGenerationEnums": SeedGenerationStatus,
            "onEvent": params.on_event,
            "logger": logger,
        }
    )
    on_status = status_listener["onStatus"]
    force_status_update = status_listener["forceStatusUpdate"]

    helper = OperationHelper(
        sdk=sdk,
        query_key="sign_txn",
        result_key="sign_txn",
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
    assert_or_throw_invalid_result(result.confirmation)
    force_status_update(SignTxnEvent.CONFIRM)

    helper.send_query(
        {
            "meta": {
                "version": SIGN_TXN_DEFAULT_PARAMS["version"],
                "locktime": params.txn.locktime or SIGN_TXN_DEFAULT_PARAMS["locktime"],
                "input_count": len(params.txn.inputs),
                "output_count": len(params.txn.outputs),
                "sighash": params.txn.hash_type
                or (
                    0
                    if get_addrtype_from_bip44_purpose(params.derivation_path[0]) == AddressType.TAP
                    else SIGN_TXN_DEFAULT_PARAMS["hashtype"]
                ),
            }
        }
    )
    result = helper.wait_for_result()
    assert_or_throw_invalid_result(result.meta_accepted)

    inputs = copy.deepcopy(params.txn.inputs)

    for i, input_data in enumerate(params.txn.inputs):
        prev_txn_hash = bytes.fromhex(input_data.prev_txn_id)[::-1].hex()

        helper.send_query(
            {
                "input": {
                    "prev_txn_hash": hex_to_uint8array(prev_txn_hash),
                    "prev_output_index": input_data.prev_index,
                    "script_pub_key": hex_to_uint8array(input_data.script_pub_key),
                    "value": int(input_data.value),
                    "sequence": input_data.sequence
                    or SIGN_TXN_DEFAULT_PARAMS["input"]["sequence"],
                    "change_index": input_data.change_index,
                    "address_index": input_data.address_index,
                }
            }
        )
        result = helper.wait_for_result()
        assert_or_throw_invalid_result(result.input_accepted)

        helper.send_in_chunks(
            hex_to_uint8array(input_data.prev_txn),
            "prev_txn_chunk",
            "prev_txn_chunk_accepted",
        )

    for output in params.txn.outputs:
        helper.send_query(
            {
                "output": {
                    "script_pub_key": hex_to_uint8array(output.script_pub_key),
                    "value": int(output.value),
                    "is_change": output.is_change,
                    "changes_index": output.address_index,
                }
            }
        )
        result = helper.wait_for_result()
        assert_or_throw_invalid_result(result.output_accepted)

    signatures: List[str] = []

    for i in range(len(params.txn.inputs)):
        helper.send_query(
            {
                "signature": {
                    "index": i,
                }
            }
        )

        result = helper.wait_for_result()
        assert_or_throw_invalid_result(result.signature)

        signatures.append(uint8array_to_hex(result.signature.signature))

    force_status_update(SignTxnEvent.PIN_CARD)

    logger.info("Completed")
    return SignTxnResult(
        signatures=signatures,
    )
