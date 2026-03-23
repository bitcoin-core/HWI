from typing import Any

from .protocol import resolve_profile


def contains_onekey_marker(value: Any) -> bool:
    if not value:
        return False
    if isinstance(value, bytes):
        value = value.decode(errors="ignore")
    return "onekey" in str(value).lower()


def is_onekey_features(features: Any) -> bool:
    vendor = (getattr(features, "vendor", None) or "").lower()
    return "onekey" in vendor or getattr(features, "onekey_device_type", None) is not None


def uses_host_pin(model_or_features: Any) -> bool:
    return resolve_profile(model_or_features).uses_host_pin


def locked_instructions(model_or_features: Any) -> str:
    if uses_host_pin(model_or_features):
        return "OneKey is locked. Unlock by using 'promptpin' and then 'sendpin'."
    return "OneKey is locked. Please unlock it on the device and try again."
