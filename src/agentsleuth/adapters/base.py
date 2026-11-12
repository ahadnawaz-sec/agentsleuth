"""Adapter protocol and registry.

An adapter converts one framework's raw run log into a normalized `Run`.
Add support for a new framework by writing a single `to_run` function and
registering it; nothing in `core/` changes.
"""
from __future__ import annotations

from typing import Any, Callable, Protocol

from ..core.schema import Run


class Adapter(Protocol):
    def to_run(self, raw: Any) -> Run: ...


_REGISTRY: dict[str, Callable[[Any], Run]] = {}


def register_adapter(name: str, to_run: Callable[[Any], Run]) -> None:
    _REGISTRY[name] = to_run


def get_adapter(name: str) -> Callable[[Any], Run]:
    if name not in _REGISTRY:
        raise KeyError(f"unknown adapter '{name}'. available: {sorted(_REGISTRY)}")
    return _REGISTRY[name]


def available() -> list[str]:
    return sorted(_REGISTRY)
