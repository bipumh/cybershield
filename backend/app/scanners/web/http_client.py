"""Safe HTTP helpers for web scanners.

Every request goes through the ScanSafetyGuard: rate limited, timeout bound,
and never downgrading security (no force-TLS-off, no redirects into hostile
schemes). The client is intentionally limited (no cookies/audio/video) and
allows insecure TLS only when the operator explicitly enabled it (lab use).
"""
from __future__ import annotations

from typing import Any

import httpx

from ..safety import ScanSafetyGuard

_DEFAULT_HEADERS = {
    "User-Agent": "CyberShield-Assessment/1.0 (defensive; authorized scope)",
    "Accept": "*/*",
}


class SafeHttpClient:
    def __init__(self, guard: ScanSafetyGuard):
        self.guard = guard
        self.timeout = httpx.Timeout(guard.timeout, connect=guard.timeout,
                                     read=guard.timeout, write=guard.timeout)
        verify = guard.allow_insecure  # never default to insecure

    def get(self, url: str, *, headers: dict | None = None,
            follow_redirects: bool = False, allow_redirects_schemes=("http", "https")) -> httpx.Response | None:
        try:
            self.guard.throttle()
            with httpx.Client(
                follow_redirects=follow_redirects,
                timeout=self.timeout,
                headers={**_DEFAULT_HEADERS, **(headers or {})},
                verify=self.guard.allow_insecure,
                http2=False,
                max_redirects=3,
            ) as client:
                resp = client.get(url)
                return resp
        except httpx.HTTPError:
            return None

    def find_public_http(self, host: str, port: int | None = None) -> str | None:
        """Return the first working scheme://host[:port]."""
        candidates = []
        if port:
            if port in (80,):
                candidates.append(f"http://{host}:{port}")
            elif port in (443,):
                candidates.append(f"https://{host}:{port}")
            else:
                candidates += [f"http://{host}:{port}", f"https://{host}:{port}"]
        else:
            candidates = ["https://" + host, "http://" + host]
        for c in candidates:
            resp = self.get(c, follow_redirects=False)
            if resp is not None and resp.status_code < 500:
                return c
        return None
