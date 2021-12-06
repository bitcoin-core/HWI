from enum import IntEnum
from typing import List

from hashlib import sha256

from ...common import AddressType
from .merkle import MerkleTree, element_hash
from ..._serialize import ser_compact_size as write_varint


def serialize_str(value: str) -> bytes:
    return len(value).to_bytes(1, byteorder="big") + value.encode("latin-1")


class WalletType(IntEnum):
    POLICYMAP = 1


# should not be instantiated directly
class Wallet:
    def __init__(self, name: str, wallet_type: WalletType) -> None:
        self.name = name
        self.type = wallet_type

    def serialize(self) -> bytes:
        return b"".join([
            self.type.value.to_bytes(1, byteorder="big"),
            serialize_str(self.name)
        ])

    @property
    def id(self) -> bytes:
        return sha256(self.serialize()).digest()


class PolicyMapWallet(Wallet):
    """
    Represents a wallet stored with a policy map and a number of keys_info.
    The wallet is serialized as follows:
       - 1 byte   : wallet type
       - 1 byte   : length of the wallet name (max 16)
       - (var)    : wallet name (ASCII string)
       - (varint) : length of the policy map, at most 74 bytes at this time
       - (var)    : policy map
       - (varint) : number of keys (not larger than 252)
       - 32-bytes : root of the Merkle tree of all the keys information.

    The specific format of the keys is deferred to subclasses.
    """

    def __init__(self, name: str, policy_map: str, keys_info: List[str]):
        super().__init__(name, WalletType.POLICYMAP)
        self.policy_map = policy_map
        self.keys_info = keys_info

    @property
    def n_keys(self) -> int:
        return len(self.keys_info)

    def serialize(self) -> bytes:
        keys_info_hashes = map(lambda k: element_hash(k.encode("latin-1")), self.keys_info)

        return b"".join([
            super().serialize(),
            write_varint(len(self.policy_map)),
            self.policy_map.encode("latin-1"),
            write_varint(len(self.keys_info)),
            MerkleTree(keys_info_hashes).root
        ])


class MultisigWallet(PolicyMapWallet):
    def __init__(self, name: str, address_type: AddressType, threshold: int, keys_info: List[str], sorted: bool = True) -> None:
        n_keys = len(keys_info)

        if not (1 <= threshold <= n_keys <= 15):
            raise ValueError("Invalid threshold or number of keys")

        multisig_op = "sortedmulti" if sorted else "multi"

        if (address_type == AddressType.LEGACY):
            policy_prefix = f"sh({multisig_op}("
            policy_suffix = f"))"
        elif address_type == AddressType.WIT:
            policy_prefix = f"wsh({multisig_op}("
            policy_suffix = f"))"
        elif address_type == AddressType.SH_WIT:
            policy_prefix = f"sh(wsh({multisig_op}("
            policy_suffix = f")))"
        else:
            raise ValueError(f"Unexpected address type: {address_type}")

        policy_map = "".join([
            policy_prefix,
            str(threshold) + ",",
            ",".join("@" + str(l) for l in range(n_keys)),
            policy_suffix
        ])

        super().__init__(name, policy_map, keys_info)

        self.threshold = threshold
