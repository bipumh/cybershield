"""Cookie & session security scanner."""
from __future__ import annotations

from http.cookies import SimpleCookie

from ..base import BaseScanner, NormalizedFinding, ScanContext, ScannerOutput
from ..registry import register_scanner


@register_scanner
class CookieScanner(BaseScanner):
    name = "web.cookies"
    kind = "web"

    def scan(self, ctx: ScanContext) -> ScannerOutput:
        from .http_client import SafeHttpClient
        client = SafeHttpClient(ctx.extra.get("guard"))
        url = ctx.extra.get("url") or f"https://{ctx.host}"
        resp = client.get(url, follow_redirects=False)
        out = ScannerOutput(checks_run=4, metadata={"url": url})
        if resp is None:
            out.error = "Unable to reach target"
            return out

        set_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else [
            resp.headers.get("set-cookie")] if resp.headers.get("set-cookie") else []
        if not set_cookies:
            out.metadata["cookies"] = []
            return out

        for raw in set_cookies:
            if not raw:
                continue
            jar = SimpleCookie()
            try:
                jar.load(raw)
            except Exception:
                continue
            for name, morsel in jar.items():
                self._evaluate(name, morsel, raw, out)
        return out

    def _evaluate(self, name, morsel, raw, out) -> None:
        if morsel.get("httponly", False) is not True:
            out.normalized.append(NormalizedFinding(
                title=f"Cookie '{name}' missing HttpOnly flag",
                description="Cookies without HttpOnly can be read by JavaScript, increasing XSS impact.",
                category="session_security", severity="medium", cvss_score=5.0,
                evidence=f"Set-Cookie: {raw[:160]}",
                affected_component=f"Cookie: {name}", exploitability="none",
                remediation={"immediate_action": f"Set HttpOnly on cookie '{name}'."},
                remediation_level="level2_approval_required", cwe="CWE-1004",
                standards={"owasp_top10": "A05:2021-Security Misconfiguration", "cwe": "CWE-1004"},
            ))
        if morsel.get("secure", False) is not True:
            out.normalized.append(NormalizedFinding(
                title=f"Cookie '{name}' missing Secure flag",
                description="Cookies without Secure can be sent over HTTP in cleartext.",
                category="session_security", severity="medium", cvss_score=5.0,
                evidence=f"Set-Cookie: {raw[:160]}",
                affected_component=f"Cookie: {name}", exploitability="none",
                remediation={"immediate_action": f"Set Secure on cookie '{name}'."},
                remediation_level="level2_approval_required", cwe="CWE-614",
                standards={"owasp_top10": "A05:2021-Security Misconfiguration", "cwe": "CWE-614"},
            ))
        samesite = morsel.get("samesite")
        if samesite not in ("Lax", "Strict"):
            out.normalized.append(NormalizedFinding(
                title=f"Cookie '{name}' missing/weak SameSite",
                description="SameSite should be Lax or Strict to mitigate CSRF.",
                category="session_security", severity="low", cvss_score=3.1,
                evidence=f"Set-Cookie: {raw[:160]}",
                affected_component=f"Cookie: {name}", exploitability="none",
                remediation={"immediate_action": f"Set SameSite=Lax or Strict on cookie '{name}'."},
                remediation_level="level2_approval_required", cwe="CWE-1275",
                standards={"owasp_wstg": "WSTG-SESS-02", "cwe": "CWE-1275"},
            ))
