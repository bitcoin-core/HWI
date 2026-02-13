from typing import Optional, Union, Dict
from ....errors import DeviceAppError, DeviceAppErrorType
from ....interfaces import IDeviceConnection
from ....common_utils import assert_condition, hex_to_uint8array
from ...utils.packet_version import PacketVersion
from ..helpers import get_command_output
from ...encoders.proto.generated.core_pb2 import Status, Msg, ErrorType


async def get_result(
    connection: IDeviceConnection,
    version: PacketVersion,
    sequence_number: int,
    applet_id: int,
    max_tries: int = 5,
    timeout: Optional[int] = None,
    allow_core_data: Optional[bool] = None,
) -> Dict[str, Union[bool, Union[Status, bytes]]]:
    assert_condition(applet_id, 'Invalid appletId')

    command_output = await get_command_output(
        connection=connection,
        version=version,
        max_tries=max_tries,
        sequence_number=sequence_number,
        timeout=timeout
    )

    is_status = command_output["is_status"]
    protobuf_data = command_output["protobuf_data"]
    raw_data = command_output["raw_data"]

    output: Union[bytes, Status]

    if is_status:
        status = Status()
        status.ParseFromString(hex_to_uint8array(protobuf_data))
        if status.current_cmd_seq != sequence_number:
            raise DeviceAppError(DeviceAppErrorType.EXECUTING_OTHER_COMMAND)
        output = status
    else:
        msg = Msg()
        msg.ParseFromString(hex_to_uint8array(protobuf_data))

        # Determine which oneof is set and route accordingly
        active_field = None
        try:
            active_field = msg.WhichOneof("type")
        except Exception:
            active_field = None
        if not active_field:
            try:
                applet = getattr(msg, "cmd", None)
                if applet is not None and getattr(applet, "applet_id", 0):
                    active_field = "cmd"
            except Exception:
                active_field = None

        # Error handling only if error oneof is active and not NO_ERROR
        if active_field == "error" and msg.error and msg.error.type != ErrorType.NO_ERROR:
            error_map = {
                ErrorType.NO_ERROR: DeviceAppErrorType.UNKNOWN_ERROR,
                ErrorType.UNKNOWN_APP: DeviceAppErrorType.UNKNOWN_APP,
                ErrorType.INVALID_MSG: DeviceAppErrorType.INVALID_MSG,
                ErrorType.APP_NOT_ACTIVE: DeviceAppErrorType.APP_NOT_ACTIVE,
                ErrorType.APP_TIMEOUT_OCCURRED: DeviceAppErrorType.APP_TIMEOUT,
                ErrorType.DEVICE_SESSION_INVALID: DeviceAppErrorType.DEVICE_SESSION_INVALID,
            }
            raise DeviceAppError(error_map[msg.error.type])

        # If command oneof is active, validate applet id and return raw_data; otherwise return protobuf_data
        if active_field == "cmd":
            if not msg.cmd:
                raise DeviceAppError(DeviceAppErrorType.INVALID_MSG_FROM_DEVICE)
            if msg.cmd.applet_id != applet_id:
                raise DeviceAppError(DeviceAppErrorType.INVALID_APP_ID_FROM_DEVICE)
            # If raw_data is empty, treat it as a protobuf-only response
            if raw_data:
                output = hex_to_uint8array(raw_data)
            else:
                output = hex_to_uint8array(protobuf_data)
        else:
            output = hex_to_uint8array(protobuf_data)

    return {"is_status": is_status, "result": output}