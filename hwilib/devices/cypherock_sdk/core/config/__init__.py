from . import command
from . import constants
from . import radix
from types import SimpleNamespace

# Version configurations
v1 = SimpleNamespace(
    commands=command.v1,
    constants=constants.v1,
    radix=radix.v1,
)
v2 = SimpleNamespace(
    commands=command.v1,
    constants=constants.v2,
    radix=radix.v2,
)
v3 = SimpleNamespace(
    commands=command.v3,
    constants=constants.v3,
    radix=radix.v3,
)

__all__ = ["v1", "v2", "v3", "command", "constants", "radix"]
