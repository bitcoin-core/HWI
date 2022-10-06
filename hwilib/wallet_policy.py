from typing import Any, Dict, List

class WalletPolicy(object):
    """Simple class to represent wallet policies."""

    def __init__(self, name: str, descriptor_template: str, keys_info: List[str], extra: Dict[str, Any] = {}):
        """TODO: document constructor arguments"""
        self.name = name
        self.descriptor_template = descriptor_template
        self.keys_info = keys_info
        self.extra = extra

    def to_descriptor(self) -> str:
        """Converts a wallet policy into the descriptor (with the /<M,N> syntax, if present)."""

        desc = self.descriptor_template

        # replace each "/**" with "/<0;1>/*"
        desc = desc.replace("/**", "/<0;1>/*")

        # process all the @N expressions in decreasing order. This guarantees that string replacements
        # works as expected (as any prefix expression is processed after).
        for i in reversed(range(len(self.keys_info))):
            desc = desc.replace(f"@{i}", self.keys_info[i])

        # there should not be any remaining "@" expressions
        if desc.find("@") != -1:
            return Exception("Invalid descriptor template: contains invalid key index")

        return desc
