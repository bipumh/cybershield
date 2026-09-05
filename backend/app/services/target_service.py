"""Target parsing, validation and scope enforcement (requirement #40, #46).

All target types (domain/url/ip/cidr/hostname/range/asset) are normalized and
checked against the tenant's scope allow-list. Scanning outside scope is
blocked here and enforced again in the worker (defense in depth).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from ..core.constants import ScanTargetKind
from ..core.exceptions import ValidationError


@dataclass
class Target:
    raw: str
    kind: str
    value: str           # normalized target value
    host: str            # queryable host (domain or ip)
    port: int | None = None
    scheme: str | None = None

    @property
    def scope_key(self) -> str:
        return self.host.lower()


_URL_RE = re.compile(r"^https?://", re.I)
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _guess_kind(raw: str) -> str:
    raw = raw.strip().rstrip("/")
    if _URL_RE.match(raw):
        return ScanTargetKind.URL
    if _IPV4_RE.match(raw) or ":" in raw and _looks_like_ipv6(raw):
        return ScanTargetKind.IP
    if "/" in raw and _looks_like_cidr(raw):
        return ScanTargetKind.CIDR
    if "-" in raw and re.match(r"^\d+\.\d+\.\d+\.\d+(\.\d+)?-\d+", raw):
        return ScanTargetKind.RANGE
    return ScanTargetKind.DOMAIN


def _looks_like_cidr(raw: str) -> bool:
    return bool(re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", raw))


def _looks_like_ipv6(raw: str) -> bool:
    try:
        ipaddress.ip_address(raw.split("/")[0])
        return True
    except ValueError:
        return False


def parse_target(raw: str, kind: str | None = None) -> Target:
    raw = raw.strip().rstrip("/")
    if not raw:
        raise ValidationError("Target value cannot be empty")

    k = kind or _guess_kind(raw)

    if k == ScanTargetKind.URL:
        parsed = urlparse(raw if "://" in raw else "https://" + raw)
        if not parsed.hostname:
            raise ValidationError("URL must include a hostname")
        host = parsed.hostname.lower()
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return Target(raw=raw, kind=k, value=parsed.netloc, host=host,
                      port=port, scheme=parsed.scheme)

    if k == ScanTargetKind.DOMAIN:
        # strip accidental scheme
        m = re.match(r"^(?:https?://)?([^/]+)", raw)
        host = (m.group(1) if m else raw).strip().lower()
        if not _valid_hostname(host):
            raise ValidationError("Invalid domain/hostname")
        return Target(raw=raw, kind=k, value=host, host=host)

    if k in (ScanTargetKind.IP, ScanTargetKind.HOSTNAME):
        host = raw.lower()
        return Target(raw=raw, kind=k, value=host, host=host)

    if k == ScanTargetKind.CIDR:
        ip, _, prefix = raw.partition("/")
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError as e:
            raise ValidationError(f"Invalid CIDR: {e}")
        if network.prefixlen < 8:
            raise ValidationError("CIDR prefix length too broad; max network size /8 permitted")
        return Target(raw=raw, kind=k, value=str(network), host=str(network.network_address))

    if k == ScanTargetKind.RANGE:
        base = raw.split("-")[0]
        return Target(raw=raw, kind=k, value=raw, host=base)

    raise ValidationError("Unsupported target kind")


def _valid_hostname(h: str) -> bool:
    if len(h) > 253:
        return False
    labels = h.split(".")
    if len(labels) < 2:
        return False
    label_re = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", re.I)
    return all(label_re.match(lab) for lab in labels)


def expand_scope(target: Target) -> list[Target]:
    """Expand CIDRs/ranges into concrete single addresses. Bounded."""
    if target.kind == ScanTargetKind.CIDR:
        net = ipaddress.ip_network(target.value, strict=False)
        hosts = list(net.hosts())
        if len(hosts) > 256:
            raise ValidationError("CIDR expands to too many hosts (max 256); restrict scope")
        return [Target(raw=str(h), kind=ScanTargetKind.IP, value=str(h), host=str(h)) for h in hosts]
    if target.kind == ScanTargetKind.RANGE:
        parts = target.value.split("-")
        start = ipaddress.ip_address(parts[0])
        end = ipaddress.ip_address(parts[-1])
        diff = int(end) - int(start)
        if diff < 0 or diff > 256:
            raise ValidationError("IP range too large (max 256 hosts)")
        return [Target(raw=str(ipaddress.ip_address(int(start) + i)),
                       kind=ScanTargetKind.IP, value=str(start + i),
                       host=str(ipaddress.ip_address(int(start) + i)))
                for i in range(diff + 1)]
    return [target]
