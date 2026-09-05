"""Server HTTP exposure scanner for infrastructure targets.

Detects common web-based services on a server/endpoint asset (default page,
HTTP management, directory listing) — bounded to a few safe requests.
"""
from __future__ import annotations

import re

from ..base import BaseScanner, NormalizedFinding, ScanContext, ScannerOutput
from ..registry import register_scanner

_COMMON_WEB_PORTS = [80, 443, 8080, 8443, 8000, 8081]


@register_scanner
class ServerHttpScanner(BaseScanner):
    name = "server.http"
    kind = "server"

    def scan(self, ctx: ScanContext) -> ScannerOutput:
        host = ctx.host
        from ..web.http_client import SafeHttpClient
        client = SafeHttpClient(ctx.extra.get("guard"))
        out = ScannerOutput(checks_run=min(len(_COMMON_WEB_PORTS), 4), metadata={"host": host})
        checked = 0
        for port in _COMMON_WEB_PORTS:
            if checked >= 3:
                break
            url = client.find_public_http(host, port)
            if not url:
                continue
            checked += 1
            resp = client.get(url, follow_redirects=True)
            if resp is None:
                continue
            out.metadata.setdefault("http_services", []).append({"port": port, "url": url,
                                                                 "status": resp.status_code})
            self._as_report(url, resp, out)
        return out

    def _as_report(self, url: str, resp, out: ScannerOutput) -> None:
        low = (resp.text or "").lower()
        status = resp.status_code
        if status == 401 and "basic realm" in (resp.headers.get("www-authenticate") or "").lower():
            out.normalized.append(NormalizedFinding(
                title="HTTP management with Basic auth exposed",
                description=f"A management service at {url} is backed by HTTP Basic auth.",
                category="exposed_management", severity="medium", cvss_score=5.9,
                evidence=f"GET {url} -> HTTP {status}, WWW-Authenticate present",
                affected_component="Web management", exploitability="none",
                remediation={"immediate_action": "Enable HTTPS + modern auth (not Basic) and restrict by ACL."},
                remediation_level="level2_approval_required", cwe="CWE-522",
                standards={"cis_controls": "Control 5.3", "cwe": "CWE-522"},
            ))
        if any(s in low for s in ("phpinfo()", "server version:")):
            out.normalized.append(NormalizedFinding(
                title="Diagnostic page exposes configuration",
                description=f"The response from {url} reveals server/diagnostic information.",
                category="information_disclosure", severity="medium", cvss_score=5.0,
                evidence=f"GET {url} -> diagnostic markers in body",
                affected_component="Web service", exploitability="none",
                remediation={"immediate_action": "Disable diagnostic endpoints (phpinfo, status pages)."},
                remediation_level="level2_approval_required", cwe="CWE-653",
                standards={"owasp_wstg": "WSTG-INFO-05", "cwe": "CWE-653"},
            ))
