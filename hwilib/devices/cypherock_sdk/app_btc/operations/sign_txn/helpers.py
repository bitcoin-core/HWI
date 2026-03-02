from ....common_utils import assert_condition, is_hex
from ...utils import assert_derivation_path
from .types import SignTxnParams


def assert_sign_txn_params(params: SignTxnParams) -> None:
    """
    Assert that sign transaction parameters are valid.

    Args:
        params: Parameters to validate

    Raises:
        AssertionError: If any parameter is invalid
    """
    assert_condition(params, "params should be defined")
    assert_condition(params.wallet_id, "wallet_id should be defined")

    assert_derivation_path(params.derivation_path)
    assert_condition(
        len(params.derivation_path) == 3,
        "derivation_path should be of depth 3",
    )

    assert_condition(params.txn, "txn be defined")
    assert_condition(params.txn.inputs, "txn.inputs should be defined")
    assert_condition(len(params.txn.inputs) > 0, "txn.inputs should not be empty")
    assert_condition(params.txn.outputs, "txn.outputs should be defined")
    assert_condition(len(params.txn.outputs) > 0, "txn.outputs should not be empty")

    for i, input_data in enumerate(params.txn.inputs):
        assert_condition(input_data.value, f"txn.inputs[{i}].value should be defined")
        assert_condition(
            input_data.script_pub_key, f"txn.inputs[{i}].script_pub_key should be define"
        )
        assert_condition(
            input_data.change_index, f"txn.inputs[{i}].change_index should be define"
        )
        assert_condition(
            input_data.address_index,
            f"txn.inputs[{i}].address_index should be define",
        )
        assert_condition(
            input_data.prev_index, f"txn.inputs[{i}].prev_index should be define"
        )

        assert_condition(
            input_data.prev_txn_id, f"txn.inputs[{i}].prev_txn_id should not be empty"
        )
        assert_condition(
            is_hex(input_data.prev_txn_id),
            f"txn.inputs[{i}].prev_txn_id should be valid hex string",
        )

        assert_condition(
            input_data.prev_txn, f"txn.inputs[{i}].prev_txn should be defined"
        )

        assert_condition(
            is_hex(input_data.prev_txn),
            f"txn.inputs[{i}].prev_txn should be valid hex string",
        )

    for i, output in enumerate(params.txn.outputs):
        assert_condition(output.value, f"txn.outputs[{i}].value should be defined")
        assert_condition(output.script_pub_key, f"txn.outputs[{i}].script_pub_key should be define")

        if output.is_change:
            assert_condition(
                output.address_index,
                f"txn.outputs[{i}].address_index should be define when it's a change output",
            )
