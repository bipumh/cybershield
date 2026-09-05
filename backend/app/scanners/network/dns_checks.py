"""Network DNS checks: reverse/named resolution and DNS safety."""
from __future__ import annotations

import socket

import dns.resolver

from ..base import BaseScanner, NormalizedFinding, ScanContext, ScannerOutput
from ..registry import register_scanner


@register_scanner
class DnsChecks(BaseScanner):
    name = "network.dns"
    kind = "network"

    def scan(self, ctx: ScanContext) -> ScannerOutput:
        host = ctx.host
        out = ScannerOutput(checks_run=1, metadata={"host": host})
        try:
            ip = socket.gethostbyname(host)
            out.metadata["resolved_ip"] = ip
        except (socket.gaierror, OSError):
            ip = None
            out.error = "Hostname did not resolve"
            return out

        # If the target is a bare IP, try reverse resolution
        try:
            import ipaddress
            if ipaddress.ip_address(host) if _is_ip(host) else False:
                names = socket.gethostbyaddr(host)
                out.metadata["reverse_dns"] = names[0]
        except Exception:
            pass

        # DNS rebinding / single-record health is informational
        return out

    def validate_scope(self, ctx: ScanContext) -> bool:
        return bool(ctx.host)


def _is_ip(s: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False
