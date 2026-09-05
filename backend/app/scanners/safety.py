"""Scan Safety Control (requirement #15, #46).

Central enforcement of:
- per-request rate limits (token bucket) honoring the scan profile cap
- timeouts
- scope allow/deny lists
- hard global caps

This module is the *enforcement* layer; the scan orchestrator also enforces
authorization and maximum concurrency before work is dispatched.
"""
from __future__ import annotations

import threading
import time
from typing import Iterable

from ..core.config import settings
from ..core.constants import ScanProfile
from ..core.exceptions import ScanSafetyError, ScopeViolationError


class TokenBucket:
    """Thread-safe token bucket rate limiter."""

    def __init__(self, rate: int, burst: int | None = None):
        self.rate = max(1, rate)
        self.burst = max(burst or self.rate, self.rate)
        self._tokens = float(self.burst)
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, n: int = 1) -> bool:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
            self._last = now
            if self._tokens >= n:
                self._tokens -= n
                return True
            return False


class ScanSafetyGuard:
    """Enforces a safe, authorized scan. Never enables destructive behavior."""

    DEFAULT_PROFILE_CAPS = ScanProfile.RATE_CAP

    def __init__(self, *, tenant_id: int, profile: str, rate_limit: int,
                 timeout: int, concurrency: int,
                 excluded_ips: Iterable[str] = (),
                 excluded_domains: Iterable[str] = (),
                 allow_insecure: bool = False):
        self.profile = profile
        self.timeout = min(timeout or settings.scan_default_timeout, 120)
        self.concurrency = min(concurrency, settings.scan_max_concurrency)

        profile_cap = self.DEFAULT_PROFILE_CAPS.get(profile, 40)
        self.rate_limit = min(rate_limit or settings.scan_global_rate_limit,
                              settings.scan_global_rate_limit * 2,
                              profile_cap)
        self.bucket = TokenBucket(self.rate_limit)

        # Scope restrictions
        self.excluded_ips = set(excluded_ips or ())
        self.excluded_domains = set((d.lower() for d in (excluded_domains or ())))
        self.allow_insecure = allow_insecure and settings.scan_allow_insecure

    def throttle(self) -> None:
        """Block until a token is available (rate limiting)."""
        for _ in range(3):
            if self.bucket.acquire():
                return
            time.sleep(0.05)
        raise TimeoutError("Scan throttled by rate limit")

    def is_excluded_target(self, value: str) -> bool:
        low = value.lower()
        for dom in self.excluded_domains:
            if low == dom or low.endswith("." + dom):
                return True
        for ip in self.excluded_ips:
            if low == ip:
                return True
        return False

    def validate_target(self, value: str) -> None:
        if self.is_excluded_target(value):
            raise ScopeViolationError(f"Target {value} is on the exclusion list")

    def assert_not_destructive(self, action: str) -> None:
        """Hard blocklist for unsafe actions regardless of configuration."""
        lowered = action.casefold()
        forbidden = ("exploit", "ransom", "persistence", "credential-dump",
                     "bruteforce", "sqlmap", "metasploit --exploit", "ddos",
                     "dos", "malware", "backdoor", "shell", "reverse")
        if any(token in lowered for token in forbidden):
            raise ScanSafetyError(f"Destructive or unauthorized action prohibited: {action}")


def build_guard(profile: str, rate_limit: int, timeout: int, concurrency: int,
                excluded_ips: list[str] | None = None,
                excluded_domains: list[str] | None = None,
                allow_insecure: bool | None = None) -> ScanSafetyGuard:
    return ScanSafetyGuard(
        tenant_id=0, profile=profile, rate_limit=rate_limit, timeout=timeout,
        concurrency=concurrency, excluded_ips=excluded_ips or (),
        excluded_domains=excluded_domains or (),
        allow_insecure=allow_insecure or False,
    )
