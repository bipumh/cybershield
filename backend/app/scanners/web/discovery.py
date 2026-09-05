"""Passive + light subdomain discovery (safe, detection-only).

Uses Certificate Transparency (crt.sh) and a curated common-name wordlist with
non-intrusive DNS resolution. Never scans discovered subdomains automatically;
the platform requires explicit scope approval first.
"""
from __future__ import annotations

import dns.resolver
import requests

from ..base import BaseScanner, ScanContext, ScannerOutput

# Lightweight, namespaced wordlist of common subdomains
_COMMON = [
    "www", "mail", "portal", "vpn", "api", "dev", "test", "stage", "staging",
    "app", "app1", "apps", "web", "cms", "admin", "login", "auth", "account",
    "dashboard", "media", "cdn", "images", "static", "assets", "download",
    "support", "help", "wiki", "blog", "docs", "doc", "forum", "status",
    "monitor", "monitoring", "grafana", "prometheus", "jenkins", "gitlab",
    "github", "git", "ci", "build", "qa", "uat", "sit", "sftp", "ftp",
    "remote", "vpn1", "vpn2", "mailsrv", "mail1", "smtp", "mx", "ns1", "ns2",
    "dns", "db", "database", "mysql", "pg", "redis", "cache", "elastic",
    "kibana", "log", "logs", "old", "new", "preview", "beta", "alpha", "edge",
    "gateway", "proxy", "waf", "ns", "backup", "archive", "cloud", "saas",
    "portal2", "secure", "sso", "id", "identity", "scheduler", "worker",
]


class SubdomainDiscovery:
    """Discovers subdomains and classifies their state (requirement #2)."""

    def __init__(self, domain: str, timeout: float = 15.0, wordlist: list[str] | None = None):
        self.domain = domain.lower()
        self.timeout = timeout
        self.wordlist = wordlist or _COMMON

    def discover(self) -> list[dict]:
        found: dict[str, dict] = {}
        for name in self._ct_names():
            found[name] = {"name": name, "source": "crt.sh"}
        for name in self._brute_names():
            found.setdefault(name, {"name": name, "source": "wordlist"})
        return list(found.values())

    def _ct_names(self) -> set[str]:
        names: set[str] = set()
        try:
            resp = requests.get(
                "https://crt.sh/?q=%25.{}&output=json".format(self.domain),
                timeout=self.timeout,
                headers={"User-Agent": "CyberShield-Discovery/1.0"},
            )
            if resp.status_code == 200 and resp.content:
                import json
                data = resp.json()
                for entry in data:
                    for cname in entry.get("name_value", "").split("\n"):
                        cname = cname.strip().lower()
                        if cname.endswith("." + self.domain) and len(cname) < 200:
                            names.add(cname)
        except Exception:
            pass
        return names

    def _brute_names(self) -> set[str]:
        names: set[str] = set()
        for prefix in self.wordlist:
            name = f"{prefix}.{self.domain}"
            if self._resolves(name):
                names.add(name)
        return names

    def _resolves(self, name: str) -> bool:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            ans = resolver.resolve(name, "A")
            return bool(ans)
        except Exception:
            return False

    def resolve_ip(self, name: str) -> str | None:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            ans = resolver.resolve(name, "A")
            return ",".join({r.address for r in ans}) or None
        except Exception:
            return None


class DiscoveryScanner(BaseScanner):
    """Adapter exposing discovery via the scanner contract (metadata only)."""
    name = "web.discovery"
    kind = "web"

    def scan(self, ctx: ScanContext) -> ScannerOutput:
        disc = SubdomainDiscovery(ctx.host, timeout=ctx.timeout)
        found = disc.discover()
        enriched = []
        for item in found:
            ip = disc.resolve_ip(item["name"])
            enriched.append({"name": item["name"], "resolved_ip": ip,
                             "status": "responsive" if ip else "unresponsive"})
        return ScannerOutput(checks_run=len(found), metadata={"subdomains": enriched},
                             normalized=[])
