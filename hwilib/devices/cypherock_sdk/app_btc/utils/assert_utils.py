from hwilib.common import Chain
from ...common_utils import assert_condition
from typing import List
from hwilib.key import H_, get_addrtype_from_bip44_purpose, get_bip44_chain

def assert_derivation_path(path: List[int]) -> None:
    """
    Assert that derivation path is valid.

    Args:
        path: Derivation path to validate
    """
    assert_condition(path, "derivation_path should be defined")
    assert_condition(len(path) >= 3, "derivation_path should be of at least depth 3")
    assert_condition(get_addrtype_from_bip44_purpose(path[0]) is not None, "derivation_path should be of a supported address type")
    assert_condition(path[1] == H_(get_bip44_chain(Chain.MAIN)), "derivation_path should be on the mainnet network")
