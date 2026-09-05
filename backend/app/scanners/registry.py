"""Scanner plugin registry.

Scanners self-register via @register_scanner decorator. New scanner types are
picked up automatically; the core never needs modification.
"""
from __future__ import annotations

from .base import BaseScanner

_REGISTRY: list[type[BaseScanner]] = []


def register_scanner(cls):
    _REGISTRY.append(cls)
    return cls


def scanner_registry() -> list[type[BaseScanner]]:
    return list(_REGISTRY)


def get_scanners(kind: str | None = None) -> list[BaseScanner]:
    import importlib
    # Ensure web/network/server packages are imported so decorators run
    for mod in ("app.scanners.web", "app.scanners.network", "app.scanners.server"):
        try:
            importlib.import_module(mod)
        except Exception:
            pass
    clamp = kind.casefold() if kind else None
    return [cls() for cls in _REGISTRY if clamp is None or cls.kind == clamp]


def get_scanner(name: str) -> BaseScanner | None:
    for cls in _REGISTRY:
        if cls.name == name:
            return cls()
    return None
