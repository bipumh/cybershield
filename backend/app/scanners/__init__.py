"""Plugin-based scanner framework.

Every scanner implements the BaseScanner contract so new scanner types can be
added without modifying the core platform. Safety (rate limiting, timeouts,
scope checks) is enforced by the ScanSafetyGuard wrapper.
"""
from .base import BaseScanner, NormalizedFinding, ScannerCheck, ScanContext
from .registry import scanner_registry, get_scanners, get_scanner, register_scanner

__all__ = ["BaseScanner", "NormalizedFinding", "ScannerCheck", "ScanContext",
           "scanner_registry", "get_scanners", "get_scanner", "register_scanner"]
