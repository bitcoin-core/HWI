from types import SimpleNamespace


def dict_to_namespace(d):
    if isinstance(d, dict):
        return SimpleNamespace(**{k: dict_to_namespace(v) for k, v in d.items()})
    return d


# Base radix constants
RADIX_HEX = 16
RADIX_DECIMAL = 10
RADIX_OCTAL = 8
RADIX_BINARY = 2

# Version-specific radix configurations
v1 = dict_to_namespace(
    {
        "current_packet_number": 16,
        "total_packet": 16,
        "data_size": 8,
        "command_type": 8,
        "wallet_index": 8,
        "coin_type": 8,
        "future_use": 8,
        "input_output_count": 8,
        "address_index": 32,
        "account_index": 8,
        "crc": 16,
        "output_length": 8,
        "add_coins": {
            "wallet": 128,
            "no_of_coins": 8,
            "coin_type": 32,
        },
        "receive_address": {
            "coin_type": 32,
            "account_index": 32,
        },
    }
)
v2 = dict_to_namespace(
    {
        "current_packet_number": 16,
        "total_packet": 16,
        "data_size": 8,
        "command_type": 8 * 4,
        "wallet_index": 8,
        "coin_type": 8,
        "future_use": 8,
        "input_output_count": 8,
        "address_index": 32,
        "account_index": 8,
        "crc": 16,
        "output_length": 8,
        "add_coins": {
            "wallet": 128,
            "no_of_coins": 8,
            "coin_type": 32,
        },
        "receive_address": {
            "coin_type": 32,
            "account_index": 32,
        },
    }
)
v3 = dict_to_namespace(
    {
        "current_packet_number": 16,
        "total_packet": 16,
        "sequence_number": 16,
        "packet_type": 8,
        "command_type": 32,
        "payload_length": 8,
        "timestamp_length": 32,
        "data_size": 16,
        "crc": 16,
        "status": {
            "device_state": 8,
            "abort_disabled": 8,
            "current_cmd_seq": 16,
            "cmd_state": 8,
            "flow_status": 16,
        },
    }
)
