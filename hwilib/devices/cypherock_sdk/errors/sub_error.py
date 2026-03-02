from typing import Dict, TypeVar, Generic, Union

T = TypeVar("T", int, str)


class SubErrorDetail:
    def __init__(self, error_code: str, message: str):
        self.error_code = error_code
        self.message = message


class SubErrorToMap(Generic[T]):
    def __init__(self):
        self._map: Dict[T, SubErrorDetail] = {}

    def __getitem__(self, key: T) -> SubErrorDetail:
        return self._map.get(key)

    def __setitem__(self, key: T, value: SubErrorDetail) -> None:
        self._map[key] = value

    def get(self, key: T) -> Union[SubErrorDetail, None]:
        return self._map.get(key)

    def items(self):
        return self._map.items()

    def keys(self):
        return self._map.keys()

    def values(self):
        return self._map.values()
