from typing import Optional
from ....interfaces import IDeviceConnection
from ....common_utils import hex_to_uint8array
from ...utils.packet_version import PacketVersion
from ..helpers import get_status as get_status_helper
from ...encoders.proto.generated.core_pb2 import Status
import logging

logger = logging.getLogger(__name__)

def get_status(
    connection: IDeviceConnection,
    version: PacketVersion,
    max_tries: int = 5,
    timeout: Optional[int] = None,
    dont_log: bool = False,
) -> Status:
    result = get_status_helper(
        connection=connection,
        version=version,
        max_tries=max_tries,
        timeout=timeout,
    )

    protobuf_data = result["protobuf_data"]
    # Parse using standard protobuf
    status = Status()
    status.ParseFromString(hex_to_uint8array(protobuf_data))

    if not dont_log:
        try:
            # Standard protobuf doesn't have to_dict(), use str representation
            meta = {'status': str(status)}
        except Exception:
            meta = {'status': str(status)}
        logger.debug('Received status', meta)

    return status