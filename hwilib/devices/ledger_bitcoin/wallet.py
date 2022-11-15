import re

from enum import IntEnum
from typing import List

from hashlib import sha256

from ...common import AddressType
from .merkle import MerkleTree, element_hash
from ..._serialize import ser_compact_size as write_varint


def serialize_str(value: str) -> bytes:
    return len(value).to_bytes(1, byteorder="big") + value.encode("latin-1")


class WalletType(IntEnum):
    WALLET_POLICY_V1 = 1
    WALLET_POLICY_V2 = 2


# should not be instantiated directly
class WalletPolicyBase:
    def __init__(self, name: str, version: WalletType) -> None:
        self.name = name
        self.version = version

        if (version != WalletType.WALLET_POLICY_V1 and version != WalletType.WALLET_POLICY_V2):
            raise ValueError("Invalid wallet policy version")

    def serialize(self) -> bytes:
        return b"".join([
            self.version.value.to_bytes(1, byteorder="big"),
            serialize_str(self.name)
        ])

    @property
    def id(self) -> bytes:
        return sha256(self.serialize()).digest()


class WalletPolicy(WalletPolicyBase):
    """
    Represents a wallet stored with a wallet policy.
    For version V2, the wallet is serialized as follows:
       - 1 byte   : wallet version
       - 1 byte   : length of the wallet name (max 64)
       - (var)    : wallet name (ASCII string)
       - (varint) : length of the descriptor template
       - 32-bytes : sha256 hash of the descriptor template
       - (varint) : number of keys (not larger than 252)
       - 32-bytes : root of the Merkle tree of all the keys information.

    The specific format of the keys is deferred to subclasses.
    """

    def __init__(self, name: str, descriptor_template: str, keys_info: List[str], version: WalletType = WalletType.WALLET_POLICY_V2):
        super().__init__(name, version)
        self.descriptor_template = descriptor_template
        self.keys_info = keys_info

    @property
    def n_keys(self) -> int:
        return len(self.keys_info)

    def serialize(self) -> bytes:
        keys_info_hashes = map(lambda k: element_hash(k.encode()), self.keys_info)

        descriptor_template_sha256 = sha256(self.descriptor_template.encode()).digest()

        return b"".join([
            super().serialize(),
            write_varint(len(self.descriptor_template.encode())),
            self.descriptor_template.encode() if self.version == WalletType.WALLET_POLICY_V1 else descriptor_template_sha256,
            write_varint(len(self.keys_info)),
            MerkleTree(keys_info_hashes).root
        ])

    def get_descriptor(self, change: bool) -> str:
        desc = self.descriptor_template
        for i in reversed(range(self.n_keys)):
            key = self.keys_info[i]
            desc = desc.replace(f"@{i}", key)

        # in V1, /** is part of the key; in V2, it's part of the policy map. This handles either
        desc = desc.replace("/**", f"/{1 if change else 0}/*")

        if self.version == WalletType.WALLET_POLICY_V2:
            # V2, the /<M;N> syntax is supported. Replace with M if not change, or with N if change
            regex = r"/<(\d+);(\d+)>"
            desc = re.sub(regex, "/\\2" if change else "/\\1", desc)

        return desc


class MultisigWallet(WalletPolicy):
    def __init__(self, name: str, address_type: AddressType, threshold: int, keys_info: List[str], sorted: bool = True, version: WalletType = WalletType.WALLET_POLICY_V2) -> None:
        n_keys = len(keys_info)

        if not (1 <= threshold <= n_keys <= 16):
            raise ValueError("Invalid threshold or number of keys")

        multisig_op = "sortedmulti" if sorted else "multi"

        if (address_type == AddressType.LEGACY):
            policy_prefix = f"sh({multisig_op}("
            policy_suffix = "))"
        elif address_type == AddressType.WIT:
            policy_prefix = f"wsh({multisig_op}("
            policy_suffix = "))"
        elif address_type == AddressType.SH_WIT:
            policy_prefix = f"sh(wsh({multisig_op}("
            policy_suffix = ")))"
        else:
            raise ValueError(f"Unexpected address type: {address_type}")

        key_placeholder_suffix = "/**" if version == WalletType.WALLET_POLICY_V2 else ""

        descriptor_template = "".join([
            policy_prefix,
            str(threshold) + ",",
            ",".join("@" + str(k) + key_placeholder_suffix for k in range(n_keys)),
            policy_suffix
        ])

        super().__init__(name, descriptor_template, keys_info, version)

        self.threshold = threshold
