"""HTTP security headers scanner (OWASP WSTG / Secure Headers)."""
from __future__ import annotations

from ..base import BaseScanner, NormalizedFinding, ScanContext, ScannerOutput
from ..registry import register_scanner

# (header, severity, guidance, predicate(value) -> bool ok, cwe)
_HEADER_RULES = [
    ("Content-Security-Policy", "high",
     "Restrict content sources to mitigate XSS and data injection.",
     lambda v: v and "default-src" in v.lower(), "CWE-693"),
    ("Strict-Transport-Security", "high",
     "Force HTTPS via HSTS to prevent protocol downgrade attacks.",
     lambda v: v and "max-age=" in v.lower(), "CWE-319"),
    ("X-Content-Type-Options", "medium",
     "Prevent MIME sniffing (should be 'nosniff').",
     lambda v: v and "nosniff" in v.lower(), "CWE-693"),
    ("X-Frame-Options", "medium",
     "Prevent clickjacking / frame embedding.",
     lambda v: bool(v), "CWE-1021"),
    ("Referrer-Policy", "medium",
     "Control how much referrer data can leak to third parties.",
     lambda v: bool(v), "CWE-200"),
    ("Permissions-Policy", "medium",
     "Restrict browser features (camera, geolocation, notifications, etc.).",
     lambda v: bool(v), "CWE-250"),
]


@register_scanner
class HeaderScanner(BaseScanner):
    name = "web.headers"
    kind = "web"

    def scan(self, ctx: ScanContext) -> ScannerOutput:
        from .http_client import SafeHttpClient
        client = SafeHttpClient(ctx.extra.get("guard"))
        url = ctx.extra.get("url") or (f"https://{ctx.host}" if ":" not in ctx.host else ctx.host)
        resp = client.get(url, follow_redirects=False)
        out = ScannerOutput(checks_run=len(_HEADER_RULES), metadata={"url": url})
        if resp is None:
            out.error = "Unable to reach target over HTTPS"
            return out

        headers = {k.lower(): v for k, v in resp.headers.items()}
        for name, severity, guidance, ok, cwe in _HEADER_RULES:
            value = headers.get(name.lower())
            if not ok(value):
                out.normalized.append(NormalizedFinding(
                    title=f"Missing or weak security header: {name}",
                    description=f"The HTTP response does not include a valid '{name}' header. {guidance}",
                    category="security_misconfiguration",
                    severity=severity,
                    cvss_score=5.3 if severity == "high" else 4.3,
                    evidence=f"GET {url} -> header '{name}={value!r}' (absent or weak)",
                    affected_component="HTTP response headers",
                    exploitability="none",
                    remediation={
                        "immediate_action": f"Add a compliant '{name}' header to all responses.",
                        "permanent_solution": f"Configure '{name}' at the web server / reverse-proxy layer and assert it in CI.",
                        "verification_procedure": f"Re-scan: confirm a valid '{name}' header is present.",
                    },
                    remediation_level="level2_approval_required",
                    cwe=cwe,
                    standards={
                        "owasp_top10": "A05:2021-Security Misconfiguration",
                        "owasp_wstg": "WSTG-CONF-07",
                        "cwe": cwe,
                        "nist_csf": "PR.DS-1",
                    },
                ))

        if resp.http_version == "HTTP/1.0":
            out.normalized.append(NormalizedFinding(
                title="Legacy HTTP/1.0 protocol",
                description="The server uses the legacy HTTP/1.0 protocol; modern HTTP/1.1+ security, efficiency and protocol features are unavailable.",
                category="server_configuration", severity="low", cvss_score=2.0,
                evidence=f"Response protocol: HTTP/1.0",
                remediation={"immediate_action": "Upgrade the web server to support HTTP/1.1 or later."},
                remediation_level="level2_approval_required", cwe="CWE-693",
            ))
        return out
