"""Lightweight wrappers around QUERY_MODULES / QUERY_CAPABILITIES.

``ArkClient`` already exposes ``query_modules`` and ``query_capabilities`` as
typed methods that return ctypes arrays. ``ModuleQuery`` adapts those into
plain ``dict`` payloads the UI / plugin loader can render without needing to
know ctypes internals.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

from ..protocol.core import (
    MODULE_STATE_DISABLED,
    MODULE_STATE_ENABLED,
    MODULE_STATE_FAILED,
    MYARK_CORE_CAPABILITY_ENTRY,
    MYARK_CORE_MODULE_INFO,
)

if TYPE_CHECKING:
    from .ark_client import ArkClient


_STATE_NAMES = {
    MODULE_STATE_DISABLED: "disabled",
    MODULE_STATE_ENABLED: "enabled",
    MODULE_STATE_FAILED: "failed",
}


@dataclass
class ModuleInfo:
    module_id: int
    name: str
    description: str
    state: str
    ioctl_count: int
    last_error: int

    @classmethod
    def from_struct(cls, src: MYARK_CORE_MODULE_INFO) -> "ModuleInfo":
        name = src.ModuleName.split(b"\x00", 1)[0].decode("ascii", errors="replace")
        desc = src.ModuleDescription.split(b"\x00", 1)[0].decode("ascii", errors="replace")
        return cls(
            module_id=int(src.ModuleId),
            name=name,
            description=desc,
            state=_STATE_NAMES.get(int(src.State), f"unknown({src.State})"),
            ioctl_count=int(src.IoctlCount),
            last_error=int(src.LastError),
        )

    def as_dict(self) -> dict:
        return {
            "module_id": self.module_id,
            "name": self.name,
            "description": self.description,
            "state": self.state,
            "ioctl_count": self.ioctl_count,
            "last_error": self.last_error,
        }


@dataclass
class CapabilityInfo:
    ioctl_code: int
    name: str
    module_id: int

    @classmethod
    def from_struct(cls, src: MYARK_CORE_CAPABILITY_ENTRY) -> "CapabilityInfo":
        name = src.Name.split(b"\x00", 1)[0].decode("ascii", errors="replace")
        return cls(
            ioctl_code=int(src.IoctlCode),
            name=name,
            module_id=int(src.ModuleId),
        )

    def as_dict(self) -> dict:
        return {
            "ioctl_code": self.ioctl_code,
            "name": self.name,
            "module_id": self.module_id,
        }


@dataclass
class ModuleQuery:
    """Adapter over ``ArkClient`` that returns Python dicts."""

    client: "ArkClient"
    _modules_cache: Optional[list[ModuleInfo]] = field(default=None, init=False)
    _caps_cache: Optional[list[CapabilityInfo]] = field(default=None, init=False)

    def query_modules(self) -> list[ModuleInfo]:
        self._modules_cache = [ModuleInfo.from_struct(m) for m in self.client.query_modules()]
        return self._modules_cache

    def query_capabilities(self) -> list[CapabilityInfo]:
        self._caps_cache = [CapabilityInfo.from_struct(c) for c in self.client.query_capabilities()]
        return self._caps_cache

    def capabilities_by_code(self) -> dict[int, CapabilityInfo]:
        return {c.ioctl_code: c for c in self.query_capabilities()}

    def active_module_ids(self) -> set[int]:
        return {m.module_id for m in self.query_modules() if m.state == "enabled"}


__all__ = [
    "ModuleInfo",
    "CapabilityInfo",
    "ModuleQuery",
]