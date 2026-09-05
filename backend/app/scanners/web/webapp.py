"""Web application assessment (OWASP-adjacent, detection-only).

Covers config-level weaknesses that can be checked safely: CORS misconfig,
CSRF protection gaps, auth weaknesses, missing security.txt, exposed docs.
No injected payloads (XSS/SQLi) are sent — those are covered via safe
configuration/header checks instead of active exploitation.
"""
from __future__ import annotations

import re

from ..base import BaseScanner, NormalizedFinding, ScanContext, ScannerOutput
from ..registry import register_scanner


@register_scanner
class WebAppScanner(BaseScanner):
    name = "web.application"
    kind = "web"

    def scan(self, ctx: ScanContext) -> ScannerOutput:
        from .http_client import SafeHttpClient
        client = SafeHttpClient(ctx.extra.get("guard"))
        base = ctx.extra.get("url") or f"https://{ctx.host}"
        resp = client.get(base, follow_redirects=True)
        out = ScannerOutput(checks_run=5, metadata={"url": base})
        if resp is None:
            out.error = "Unable to reach target"
            return out

        self._check_cors(base, resp, out)
        self._check_csrf(base, resp, out)
        self._check_auth(base, resp, out)
        self._check_security_txt(base, client, out)
        self._check_robots(base, client, out)
        return out

    def _check_cors(self, base, resp, out):
        aoa = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "")
        if aoa == "*" and acac.lower() == "true":
            out.normalized.append(NormalizedFinding(
                title="CORS misconfiguration (wildcard + credentials)",
                description="CORS allows any origin AND credentials, enabling cross-origin data theft.",
                category="cors_misconfiguration", severity="high", cvss_score=8.1,
                evidence=f"Access-Control-Allow-Origin: {aoa}, Allow-Credentials: {acac}",
                affected_component="CORS", exploitability="none",
                remediation={"immediate_action": "Do not use wildcard + Allow-Credentials; restrict allowed origins."},
                remediation_level="level2_approval_required", cwe="CWE-942",
                standards={"owasp_top10": "A01:2021-Broken Access Control", "cwe": "CWE-942"},
            ))
        elif aoa and aoa not in self._genuine_origins(base):
            out.normalized.append(NormalizedFinding(
                title="CORS reflects arbitrary origins",
                description="The Access-Control-Allow-Origin header reflects a request Origin that was not listed.",
                category="cors_misconfiguration", severity="medium", cvss_score=5.0,
                evidence=f"Access-Control-Allow-Origin: {aoa}",
                affected_component="CORS", exploitability="none",
                remediation={"immediate_action": "Whitelist authorized origins only."},
                remediation_level="level2_approval_required", cwe="CWE-942",
                standards={"owasp_top10": "A01:2021-Broken Access Control", "cwe": "CWE-942"},
            ))

    def _genuine_origins(self, base: str) -> set[str]:
        host = re.sub(r"^https?://", "", base)
        host = host.split("/")[0].split(":")[0]
        return {f"https://{host}", f"http://{host}"}

    def _check_csrf(self, base, resp, out):
        body = resp.text or ""
        has_token = bool(re.search(r"name=[\"'](?:csrf|_token|csrfmiddlewaretoken|__RequestVerificationToken)[\"']", body))
        acdf = resp.headers.get("x-csrf-token") or resp.headers.get("x-xsrf-token")
        if not has_token and not acdf:
            out.normalized.append(NormalizedFinding(
                title="No CSRF protection detected",
                description="Forms/state-changing endpoints appear to lack a CSRF token or SameSite-protected cookies.",
                category="csrf", severity="medium", cvss_score=5.0,
                evidence=f"GET {base} -> no CSRF token found in response",
                affected_component="Session/CSRF", exploitability="none",
                remediation={"immediate_action": "Add CSRF tokens to state-changing forms and enforce SameSite cookies."},
                remediation_level="level2_approval_required", cwe="CWE-352",
                standards={"owasp_top10": "A01:2021-Broken Access Control", "owasp_wstg": "WSTG-SESS-05",
                           "cwe": "CWE-352"},
            ))

    def _check_auth(self, base, resp, out):
        if resp.status_code in (401, 403) and "basic" in (resp.headers.get("www-authenticate") or "").lower():
            out.normalized.append(NormalizedFinding(
                title="Basic authentication exposed",
                description="The endpoint uses HTTP Basic authentication (credentials sent in cleartext over the wire without TLS protection).",
                category="authentication", severity="medium", cvss_score=5.9,
                evidence=f"WWW-Authenticate: {resp.headers.get('www-authenticate')}",
                affected_component="Authentication", exploitability="none",
                remediation={"immediate_action": "Replace HTTP Basic with OAuth/OIDC or ensure it is only over HTTPS."},
                remediation_level="level2_approval_required", cwe="CWE-522",
                standards={"owasp_top10": "A07:2021-Identification and Authentication Failures", "cwe": "CWE-522"},
            ))

    def _check_security_txt(self, base, client, out):
        url = base.rstrip("/") + "/.well-known/security.txt"
        r = client.get(url, follow_redirects=False)
        valid = r is not None and r.status_code == 200 and "contact:" in (r.text or "").lower()
        if valid:
            return
        detail = "no response" if r is None else f"HTTP {r.status_code}"
        out.normalized.append(NormalizedFinding(
            title="security.txt not published",
            description="RFC 9116 security.txt provides a channel for researchers to report vulnerabilities; it is missing or malformed.",
            category="security_policy", severity="low", cvss_score=2.0,
            evidence=f"GET {url} -> {detail}",
            affected_component="/.well-known/security.txt", exploitability="none",
            remediation={"immediate_action": "Publish a valid security.txt with a security contact and policy."},
            remediation_level="level2_approval_required", cwe="CWE-710",
            standards={"nist_csf": "PR.IR-1"},
        ))

    def _check_robots(self, base, client, out):
        url = base.rstrip("/") + "/robots.txt"
        r = client.get(url, follow_redirects=False)
        if r is not None and r.status_code == 200:
            txt = r.text or ""
            # Only informational; do not flag as a vulnerability, but capture a finding for evidence if interesting
            if "disallow:" in txt.lower() and ("admin" in txt.lower() or "private" in txt.lower()):
                out.normalized.append(NormalizedFinding(
                    title="Sensitive paths in robots.txt",
                    description="robots.txt references sensitive paths; while not a vulnerability by itself, it can aid discovery of restricted areas.",
                    category="information_disclosure", severity="low", cvss_score=2.0,
                    evidence=f"GET {url} -> Disallow entries visible",
                    affected_component="robots.txt", exploitability="none",
                    remediation={"immediate_action": "Robots.txt cannot hide content; ensure sensitive paths are access-controlled."},
                    remediation_level="level2_approval_required", cwe="CWE-200",
                    standards={"owasp_wstg": "WSTG-INFO-01"},
                ))
