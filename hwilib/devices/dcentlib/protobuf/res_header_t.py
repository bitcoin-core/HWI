# Automatically generated by pb2py
# fmt: off
from .. import prototrez as p

if __debug__:
    try:
        from typing import Dict, List  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
        EnumTypecointype_t = Literal[0, 1, 4096, 4097, 4098, 4099, 4352, 4353, 4608, 4609, 4610, 4611, 4865, 4997, 5120, 5121, 5376, 5377, 5632, 5633, 5888, 5889, 5890, 5891, 6144, 6145, 8192, 8224, 8240, 8241, 8448, 8449, 8480, 8481, 12288, 16384, 20480, 20481, 20482, 20483, 24576, 24577, 28672, 28673, 65535]
    except ImportError:
        pass


class res_header_t(p.MessageType):

    def __init__(
        self,
        version: int = None,
        response_from: EnumTypecointype_t = None,
        is_error: bool = None,
    ) -> None:
        self.version = version
        self.response_from = response_from
        self.is_error = is_error

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('version', p.UVarintType, 0),  # required
            2: ('response_from', p.EnumType("cointype_t", (0, 1, 4096, 4097, 4098, 4099, 4352, 4353, 4608, 4609, 4610, 4611, 4997, 4865, 5120, 5121, 5376, 5377, 5632, 5633, 5888, 5889, 5890, 5891, 6144, 6145, 8192, 8224, 8240, 8241, 8448, 8449, 8480, 8481, 12288, 16384, 20480, 20481, 20482, 20483, 24576, 24577, 28672, 28673, 65535)), 0),  # required
            3: ('is_error', p.BoolType, 0),  # required
        }
