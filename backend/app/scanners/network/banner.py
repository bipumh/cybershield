"""Banner & service fingerprint scanner (safe, no auth attempts)."""
from __future__ import annotations

import re

from ..base import BaseScanner, NormalizedFinding, ScanContext, ScannerOutput
from ..registry import register_scanner

_UNSUPPORTED = {
    "windows xp": "Windows XP",
    "windows 2000": "Windows 2000",
    "windows server 2003": "Windows Server 2003",
    "ubuntu 12": "Ubuntu 12.04",
    "ubuntu 14": "Ubuntu 14.04",
    "centos 6": "CentOS 6",
    "centos 7": "CentOS 7",
    "debian 8": "Debian 8",
    "red hat 5": "Red Hat 5",
    "red hat 6": "Red Hat 6",
    "openssh_5": "OpenSSH 5.x",
    "openssh_6": "OpenSSH 6.x",
    "openssh_7.0": "OpenSSH 7.0",
    "openssh_7.1": "OpenSSH 7.1",
    "openssh_7.2": "OpenSSH 7.2",
    "openssh_7.3": "OpenSSH 7.3",
    "openssh_7.4": "OpenSSH 7.4",
    "openssh_7.5": "OpenSSH 7.5",
    "openssh_7.6": "OpenSSH 7.6",
    "openssh_7.7": "OpenSSH 7.7",
    "apache/2.2": "Apache 2.2",
    "apache 2.2": "Apache 2.2",
    "nginx/1.0": "nginx 1.0",
    "nginx/1.4": "nginx 1.4",
    "nginx/1.6": "nginx 1.6",
    "nginx/1.8": "nginx 1.8",
    "nginx/1.9": "nginx 1.9",
    "nginx/1.10": "nginx 1.10",
    "nginx/1.12": "nginx 1.12",
    "nginx/1.14": "nginx 1.14",
    "nginx/1.16": "nginx 1.16",
    "nginx/1.18": "nginx 1.18",
}


@register_scanner
class BannerScanner(BaseScanner):
    name = "network.banners"
    kind = "network"

    def scan(self, ctx: ScanContext) -> ScannerOutput:
        host = ctx.host
        ports = ctx.extra.get("open_ports") or []
        out = ScannerOutput(checks_run=len(ports), metadata={"host": host})
        for port, banner in (ctx.extra.get("banners") or {}).items():
            self._evaluate(host, int(port), str(banner), out)
        return out

    def _evaluate(self, host: str, port: int, banner: str, out: ScannerOutput) -> None:
        low = banner.lower()
        if not low.strip():
            return
        for needle, label in _UNSUPPORTED.items():
            if needle in low:
                out.normalized.append(NormalizedFinding(
                    title=f"Unsupported/End-of-life software: {label}",
                    description=f"Service banner indicates '{label}', which is end-of-life and no longer receives security updates.",
                    category="outdated_component", severity="high", cvss_score=8.1,
                    evidence=f"Banner on {host}:{port}: {banner[:200]}",
                    affected_component=self._service(port), detected_version=label,
                    exploitability="none",
                    remediation={
                        "immediate_action": f"Upgrade or replace {label} with a supported version.",
                        "verification_procedure": "Re-scan and confirm the banner reflects a supported version.",
                    },
                    remediation_level="level3_manual", cwe="CWE-1104",
                    standards={"owasp_top10": "A06:2021-Vulnerable and Outdated Components", "cwe": "CWE-1104"},
                ))
                break

        if ":// root " in banner.lower() or "welcome to nginx" in banner.lower():
            pass  # informational only

        # Exposed management / default pages
        if re.search(r"(pfSense|Sophos|FortiGate|Cisco IOS|MikroTik|RouterOS|Apache tomcat)", banner, re.I):
            if not any(f in out.metadata for f in ("mgmt_detected",)):
                out.metadata["management_exposed"] = banner[:200]
                out.normalized.append(NormalizedFinding(
                    title="Device/management interface fingerprint",
                    description=f"The banner reveals a network device/management interface: {self._service(port)}.",
                    category="exposed_management", severity="medium", cvss_score=5.0,
                    evidence=f"Banner on {host}:{port}: {banner[:200]}",
                    affected_component=self._service(port), exploitability="none",
                    remediation={"immediate_action": "Restrict access to management interfaces (ACL/that VLAN), disable HTTP management where HTTPS/SSH is available."},
                    remediation_level="level2_approval_required", cwe="CWE-200",
                    standards={"cis_controls": "Control 5.3", "nist_csf": "PR.PT-3"},
                ))

    def _service(self, port: int) -> str:
        from .port_scan import DEFAULT_PORTS
        return DEFAULT_PORTS.get(port, f"port-{port}")
