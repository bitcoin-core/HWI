from typing import Literal, List

PacketVersion = Literal["v1", "v2", "v3"]


class PacketVersionMap:
    v1: PacketVersion = "v1"
    v2: PacketVersion = "v2"
    v3: PacketVersion = "v3"


# Order is from older to newer
PacketVersionList: List[PacketVersion] = [
    PacketVersionMap.v1,
    PacketVersionMap.v2,
    PacketVersionMap.v3,
]
