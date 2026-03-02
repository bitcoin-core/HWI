from typing import Any, Dict, Type


class DeviceError(Exception):
    def __init__(self, error_code: str, message: str, cls: Type):
        super().__init__(message)
        self.code = error_code
        self.message = message
        self.is_device_error = True
        self.set_prototype(cls)

    def set_prototype(self, cls: Type) -> None:
        # In Python, this is handled by proper inheritance, but we keep the method
        # for API compatibility with the TypeScript version
        pass

    def to_json(self) -> Dict[str, Any]:
        """
        Convert the error to a JSON-serializable dictionary.

        Returns:
            Dict with error details
        """
        return {
            "code": self.code,
            "message": f"{self.code}: {self.message}",
            "isDeviceError": self.is_device_error,
            "stack": self.__traceback__,
        }
