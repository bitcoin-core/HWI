from typing import Optional
from ....interfaces import IDeviceConnection
from ....common_utils import assert_condition, uint8array_to_hex
from ...utils.packet_version import PacketVersion
from ...encoders.proto.generated.core_pb2 import Msg, Command
from ..helpers import send_command as send_command_helper
import logging

logger = logging.getLogger(__name__)

def send_query(
    connection: IDeviceConnection,
    applet_id: int,
    data: bytes,
    version: PacketVersion,
    sequence_number: int,
    max_tries: int = 5,
    timeout: Optional[int] = None,
) -> None:
    assert_condition(applet_id, 'Invalid appletId')
    assert_condition(data, 'Invalid data')

    assert_condition(applet_id >= 0, 'appletId cannot be negative')
    assert_condition(len(data) > 0, 'data cannot be empty')

    raw_data = uint8array_to_hex(data)
    logger.debug('Sending query', {'appletId': applet_id, 'rawData': raw_data})

    msg = Msg(cmd=Command(applet_id=applet_id))
    msg_data = uint8array_to_hex(msg.SerializeToString())

    return send_command_helper(
        connection=connection,
        proto_data=msg_data,
        raw_data=raw_data,
        version=version,
        max_tries=max_tries,
        sequence_number=sequence_number,
        timeout=timeout,
    )