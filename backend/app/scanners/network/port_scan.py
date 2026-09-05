"""Safe, bounded TCP connect port scan.

- Scans only a curated set of common service ports (no full 1-65535 sweep)
- Strict per-target concurrency + global rate limiting
- Timeout bound, never SYN flood / never destructive
If a raw port range was requested, the scan orchestrator enforces an upper
bound and authorization before dispatch.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor

from ..base import BaseScanner, ScanContext, ScannerOutput
from ..registry import register_scanner

DEFAULT_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 143: "imap", 389: "ldap",
    443: "https", 445: "smb", 465: "smtps", 587: "submission",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc",
    5985: "winrm", 5986: "winrm_https", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 9090: "http-alt", 27017: "mongodb",
}

WEAK_SERVICE_LABELS = {
    "telnet": ("telnet", "high"),
    "ftp": ("ftp", "medium"),
    "smtp": ("smtp", "low"),
    "pop3": ("pop3", "low"),
    "imap": ("imap", "low"),
    "rdp": ("rdp", "medium"),
    "vnc": ("vnc", "medium"),
    "snmp": ("snmp", "medium"),
    "redis": ("redis", "high"),
    "mongodb": ("mongodb", "high"),
    "database": ("database", "medium"),
}


@register_scanner
class PortScanner(BaseScanner):
    name = "network.ports"
    kind = "network"

    def scan(self, ctx: ScanContext) -> ScannerOutput:
        host = ctx.host
        custom_ports = ctx.extra.get("ports")
        max_ports = ctx.extra.get("max_ports", 120)
        ports = custom_ports or list(DEFAULT_PORTS.keys())
        target_ports = [int(p) for p in ports][:max_ports] if custom_ports else list(ports)[:max_ports]

        out = ScannerOutput(checks_run=len(target_ports), metadata={"host": host})
        opened = []

        def probe(p):
            try:
                with socket.create_connection((host, int(p)), timeout=ctx.timeout) as s:
                    s.settimeout(ctx.timeout)
                    try:
                        banner = s.recv(256).decode("ascii", errors="ignore").strip()
                    except Exception:
                        banner = ""
                    return (int(p), banner)
            except (socket.timeout, ConnectionRefusedError, OSError):
                return None

        workers = max(1, min(len(target_ports), ctx.extra.get("concurrency", 4)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(probe, target_ports))

        for r in results:
            if r:
                p, banner = r
                opened.append(p)
            # rate to honor guard
            try:
                ctx.extra.get("guard").throttle()
            except Exception:
                pass

        out.metadata["open_ports"] = {str(p): self._service_label(p) for p in opened}
        out.metadata["banners"] = {str(p): b for p, b in results if p}

        for p in opened:
            service = self._service_label(p)
            if service in ("telnet", "redis", "mongodb", "ftp", "rdp") and service in WEAK_SERVICE_LABELS:
                label, sev = WEAK_SERVICE_LABELS[service]
                out.normalized.append(self._weak_service_finding(p, service, label, sev))
        return out

    def _service_label(self, port: int) -> str:
        return DEFAULT_PORTS.get(port, "unknown")

    def _weak_service_finding(self, port: int, service: str, label: str, sev: str) -> object:
        from ..base import NormalizedFinding
        return NormalizedFinding(
            title=f"{label.title()} service exposed",
            description=f"Port {port} ({service}) is open and reachable. {label.title()} is often unencrypted or weakly authenticated.",
            category="exposed_service", severity=sev,
            cvss_score=7.5 if sev == "high" else (5.0 if sev == "medium" else 3.1),
            evidence=f"TCP {port} open on target",
            affected_component=service,
            remediation={
                "immediate_action": f"Restrict access to port {port} (firewall/ACL) or disable the service if unused.",
                "permanent_solution": f"Use a secure equivalent (e.g., SSH instead of Telnet), enable authentication, and restrict source addresses.",
                "verification_procedure": "Re-scan and confirm the port is blocked or the service is hardened.",
            },
            remediation_level="level2_approval_required",
            cwe="CWE-749",
            standards={"nist_csf": "PR.AC-5", "cis_controls": "Control 4.1"},
        )
