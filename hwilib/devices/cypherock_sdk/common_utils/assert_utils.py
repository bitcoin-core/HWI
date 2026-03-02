from typing import TypeVar, Union, Any

T = TypeVar("T")


def assert_condition(condition: Any, error: Union[str, Exception]) -> None:
    if condition is None or condition is False:
        if isinstance(error, str):
            raise AssertionError(error)
        else:
            raise error
