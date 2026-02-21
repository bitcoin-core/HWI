from typing import Callable
from ...proto.generated.manager.get_logs_pb2 import GetLogsStatus
from .error import GetLogsError, GetLogsErrorType

GetLogsEventHandler = Callable[[GetLogsStatus], None]

# Re-export error types
__all__ = ["GetLogsError", "GetLogsErrorType", "GetLogsEventHandler"]
