from typing import Dict, Any, Optional, Callable, List, TypedDict, Type
from enum import Enum
from .crypto import num_to_byte_array

ForceStatusUpdate = Callable[[int], None]
OnStatus = Callable[[Dict[str, int]], None]
EventCallback = Callable[[int], None]


class CreateStatusListenerParams(TypedDict):
    enums: Type[Enum]
    operationEnums: Optional[Type[Enum]]
    seedGenerationEnums: Optional[Type[Enum]]
    onEvent: Optional[EventCallback]
    logger: Optional[Any]


def get_numbers_from_enums(enums: Type[Enum]) -> List[int]:
    try:
        return [
            member.value
            for member in enums
            if isinstance(member.value, int) and member.value >= 0
        ]
    except Exception as e:
        return enums.values()

def get_names_from_enums(enums: Type[Enum]) -> List[str]:
    try:
        return [member.name for member in enums]
    except Exception as e:
        return enums.keys()

def create_dict_from_enums(enums: Type[Enum]) -> Dict[str, int]:
    values = get_numbers_from_enums(enums)
    keys = get_names_from_enums(enums)
    return dict(zip(keys, values))

def get_numbers_from_dict(enums: Dict[str, int]) -> List[int]:
    return list(enums.values())

def get_names_from_dict(enums: Dict[str, int]) -> List[str]:
    return list(enums.keys())

def create_status_listener(params: CreateStatusListenerParams) -> Dict[str, Any]:
    enums: Type[Enum] = params["enums"]
    enum_dict: Dict[str, int] = create_dict_from_enums(enums)
    on_event: Optional[EventCallback] = params.get("onEvent")
    logger: Optional[Any] = params.get("logger")
    _operation_enums: Optional[Type[Enum]] = params.get("operationEnums")
    seed_generation_enums: Optional[Type[Enum]] = params.get("seedGenerationEnums")

    operation_enums: Type[Enum] = (
        _operation_enums if _operation_enums is not None else enums
    )
    already_sent: Dict[int, bool] = {}

    event_list = get_numbers_from_dict(enum_dict)
    seed_generation_event_list = (
        get_numbers_from_enums(seed_generation_enums) if seed_generation_enums else []
    )
    operation_event_names = get_names_from_dict(enum_dict)

    operation_seed_generation_event_name: Optional[str] = next(
        (e for e in operation_event_names if "SEED_GENERATED" in e), None
    )

    def on_status(status: Dict[str, int]) -> None:
        flow_status = getattr(status, "flow_status", 0)
        byte_array = num_to_byte_array(flow_status)
        operation_status = byte_array[-1] if byte_array else 0
        core_status = byte_array[-2] if len(byte_array) > 1 else 0

        for event_index in event_list:
            operation_seed_gen_value = 0
            if operation_seed_generation_event_name:
                try:
                    operation_seed_gen_value = getattr(
                        operation_enums, operation_seed_generation_event_name
                    ).value
                except AttributeError:
                    pass

            seed_gen_boundary = len(seed_generation_event_list) - 1

            diff_event_op_seed = event_index - operation_seed_gen_value

            is_before_seed_generation = (
                not operation_seed_generation_event_name
                or event_index < operation_seed_gen_value
            )

            is_seed_generation = (
                operation_seed_generation_event_name
                and 0 <= diff_event_op_seed < seed_gen_boundary
            )

            is_after_seed_generation = (
                operation_seed_generation_event_name
                and diff_event_op_seed >= seed_gen_boundary
            )

            is_completed = is_before_seed_generation and operation_status >= event_index

            if is_seed_generation:
                is_completed = core_status > diff_event_op_seed
            elif is_after_seed_generation:
                is_completed = operation_status > (diff_event_op_seed + 1)

            if is_completed and not already_sent.get(event_index, False):
                already_sent[event_index] = True

                if logger:
                    event_name = next(
                        (
                            key
                            for key, value in enum_dict.items()
                            if value == event_index
                        ),
                        str(event_index),
                    )
                    logger.verbose(
                        "Event", {"event": event_name, "eventIndex": event_index}
                    )

                if on_event:
                    on_event(event_index)

    def force_status_update(flow_status: int) -> None:
        for event_index in event_list:
            if flow_status >= event_index and not already_sent.get(event_index, False):
                already_sent[event_index] = True

                if logger:
                    # Find the enum member name corresponding to the event_index
                    event_name = next(
                        (
                            key
                            for key, value in enum_dict.items()
                            if value == event_index
                        ),
                        str(event_index),
                    )
                    logger.verbose(
                        "Event", {"event": event_name, "eventIndex": event_index}
                    )

                if on_event:
                    on_event(event_index)

    return {"onStatus": on_status, "forceStatusUpdate": force_status_update}
