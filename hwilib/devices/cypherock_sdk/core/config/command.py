from types import SimpleNamespace


def dict_to_namespace(d):
    if isinstance(d, dict):
        return SimpleNamespace(**{k: dict_to_namespace(v) for k, v in d.items()})
    return d


v1 = dict_to_namespace(
    {
        "ACK_PACKET": 1,
        "NACK_PACKET": 7,
        "USB_CONNECTION_STATE_PACKET": 8,
    }
)

v3 = dict_to_namespace(
    {
        "PACKET_TYPE": {
            "STATUS_REQ": 1,
            "CMD": 2,
            "CMD_OUTPUT_REQ": 3,
            "STATUS": 4,
            "CMD_ACK": 5,
            "CMD_OUTPUT": 6,
            "ERROR": 7,
            "ABORT": 8,
        },
    }
)
