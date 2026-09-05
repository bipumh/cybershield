"""Web content & fingerprint scanner: info disclosure, directory listing,
sensitive files, exposed admin/debug, tech fingerprint (safe, no payloads)."""
from __future__ import annotations

import re

from ..base import BaseScanner, NormalizedFinding, ScanContext, ScannerOutput
from ..registry import register_scanner

# Highly indicative sensitive/exposed paths — checked via safe GET, never POST/exploit
_SENSITIVE_PATHS = [
    ("/.env", "Environment / secrets file exposed", "high"),
    ("/.git/config", "Git repository metadata exposed", "high"),
    ("/backup.sql", "Database backup exposed", "high"),
    ("/.DS_Store", "macOS metadata leak", "low"),
    ("/server-status", "Apache server-status exposed", "medium"),
    ("/phpinfo.php", "phpinfo() diagnostic page exposed", "medium"),
    ("/swagger-ui.html", "Swagger/API documentation exposed", "medium"),
    ("/api-docs", "API documentation exposed", "medium"),
    ("/actuator", "Spring actuator endpoint exposed", "medium"),
    ("/dbadmin", "Exposed database admin interface", "high"),
    ("/phpMyAdmin", "Exposed phpMyAdmin interface", "high"),
    ("/webadmin", "Exposed admin interface", "medium"),
]

_FILE_EXT_SIGNALS = [
    (r"\.sql$", "Source/database file disclosure", "medium"),
    (r"\.bak$|\.old$|\.orig$", "Backup file exposure", "medium"),
    (r"\.zip$|\.tar\.gz$", "Archive exposure", "medium"),
]

_TECH_SIGNATURES = {
    "server": {
        r"WordPress": "WordPress", r"nginx": "nginx", r"Apache": "Apache",
        r"IIS": "Microsoft IIS", r"Cloudflare": "Cloudflare", r"Express": "Express",
        r"Django": "Django", r"Rails": "Ruby on Rails", r"Laravel": "Laravel",
        r"Joomla": "Joomla", r"Spring": "Spring", r"Jetty": "Jetty",
    },
    "powered_by": {
        r"PHP": "PHP", r"ASP\.NET": "ASP.NET", r"Next\.js": "Next.js",
        r"Vite": "Vite", r"React": "React", r"jQuery": "jQuery",
    },
    "body_signal": {
        r"wordpress": "WordPress", r"wp-content": "WordPress",
    },
}


@register_scanner
class ContentScanner(BaseScanner):
    name = "web.content"
    kind = "web"

    def scan(self, ctx: ScanContext) -> ScannerOutput:
        from .http_client import SafeHttpClient
        client = SafeHttpClient(ctx.extra.get("guard"))
        base = ctx.extra.get("url") or f"https://{ctx.host}"
        resp = client.get(base, follow_redirects=True)
        out = ScannerOutput(checks_run=len(_SENSITIVE_PATHS) + 4, metadata={"url": base})
        if resp is None:
            out.error = "Unable to reach target"
            return out
        body = resp.text or ""
        out.metadata["status_code"] = resp.status_code

        self._check_protocol(base, resp, out)
        self._check_tech(resp, body, out)
        self._check_directory_listing(base, resp, out)
        self._check_error_debug(base, resp, out)

        # Sensitive path probing (safe GET only). Only flag when the response
        # is DISTINCT from the base app page — avoids false positives on
        # catch-all routers that return the same view for every path.
        for path, title, severity in _SENSITIVE_PATHS:
            url = base.rstrip("/") + path
            r = client.get(url, follow_redirects=False)
            if r is not None and r.status_code == 200 and self._distinct_content(r.text, body):
                out.normalized.append(NormalizedFinding(
                    title=title,
                    description=f"The path '{path}' returned HTTP 200 with distinct content, suggesting a potentially exposed sensitive resource. Confirm before acting.",
                    category="information_disclosure", severity=severity,
                    cvss_score=7.5 if severity == "high" else 5.0,
                    evidence=f"GET {url} -> HTTP 200, len={len(r.text)} (differs from base page)",
                    affected_component="Static content", exploitability="none",
                    remediation={
                        "immediate_action": f"Confirm and restrict access to '{path}' or remove the file.",
                        "verification_procedure": "Re-scan and confirm the path no longer serves distinct content.",
                    },
                    remediation_level="level2_approval_required",
                    cwe="CWE-200",
                    standards={"owasp_top10": "A05:2021-Security Misconfiguration",
                               "owasp_wstg": "WSTG-CONF-05", "cwe": "CWE-200"},
                ))
        return out

    def _distinct_content(self, text: str, base_text: str) -> bool:
        """True when path content is meaningfully different from the base page."""
        low = text.strip().lower()
        base = base_text.strip().lower()
        if not low:
            return False
        if "404 not found" in low or "page not found" in low or "no logon servers" in low:
            return False
        # Same page served for every path (catch-all) => not a real exposure
        if base and (low == base or abs(len(low) - len(base)) < max(10, len(base) // 10)):
            return False
        return True

    def _check_protocol(self, base: str, resp, out) -> None:
        """"Redirect / http->https enforcement."""
        # If we're scanning an http URL and the server supports https, note it.
        if base.startswith("http://"):
            https_url = "https://" + base[len("http://"):]
            if resp is not None:
                out.normalized.append(NormalizedFinding(
                    title="Cleartext HTTP exposed",
                    description="The site serves content over HTTP (cleartext). Redirect clients to HTTPS to prevent interception.",
                    category="transport_security", severity="high", cvss_score=7.5,
                    evidence=f"GET {base} responded over cleartext HTTP",
                    affected_component="Transport", exploitability="none",
                    remediation={"immediate_action": "Redirect all HTTP requests to HTTPS and enable HSTS."},
                    remediation_level="level2_approval_required", cwe="CWE-319",
                    standards={"owasp_top10": "A02:2021-Cryptographic Failures", "cwe": "CWE-319"},
                ))

    def _check_tech(self, resp, body: str, out) -> None:
        headers = resp.headers
        found: dict[str, str] = {}
        server = headers.get("server", "")
        for pattern, label in _TECH_SIGNATURES["server"].items():
            if re.search(pattern, server, re.I):
                found[label] = server[:120]
        powered = headers.get("x-powered-by", "")
        for pattern, label in _TECH_SIGNATURES["powered_by"].items():
            if re.search(pattern, powered, re.I):
                found[label] = powered[:120]
        if not found:
            for pattern, label in _TECH_SIGNATURES["body_signal"].items():
                if re.search(pattern, body, re.I):
                    found[label] = "inferred from HTML"
        if found:
            out.normalized.append(NormalizedFinding(
                title="Technology fingerprint disclosed",
                description="Reachable technology fingerprint aids attackers in targeting known vulnerabilities.",
                category="information_disclosure", severity="low", cvss_score=3.1,
                evidence=f"Detected: {', '.join(found.keys())}",
                affected_component="Server stack", exploitability="none",
                remediation={"immediate_action": "Remove verbose Server / X-Powered-By headers where possible."},
                remediation_level="level2_approval_required", cwe="CWE-200",
                standards={"owasp_wstg": "WSTG-INFO-02", "cwe": "CWE-200"},
            ))

    def _check_directory_listing(self, base: str, resp, out) -> None:
        low = (resp.text or "").lower()
        signals = [
            "index of /", "directory listing for", "<h1>index of ", "parent directory</a>",
        ]
        if any(s in low for s in signals):
            out.normalized.append(NormalizedFinding(
                title="Directory listing enabled",
                description="Directory listing is enabled, exposing the full contents of a directory to unauth users.",
                category="server_configuration", severity="medium", cvss_score=5.0,
                evidence=f"GET {base} returned a directory index page",
                affected_component="Web server", exploitability="none",
                remediation={"immediate_action": "Disable automatic directory indexing."},
                remediation_level="level2_approval_required", cwe="CWE-548",
                standards={"owasp_wstg": "WSTG-CONF-05", "cwe": "CWE-548"},
            ))

    def _check_error_debug(self, base: str, resp, out) -> None:
        low = (resp.text or "").lower()
        for token, label, sev in [
            ("traceback (most recent call last):", "Python traceback (debug mode)", "medium"),
            ("debugger active!", "Exposed Flask debugger", "high"),
            ("exception: ", "Verbose exception page", "medium"),
            ("<stacktrace>", "Java stack trace", "medium"),
            ("/debug/log</phrase>", "Debug log exposure", "low"),
        ]:
            if token in low:
                out.normalized.append(NormalizedFinding(
                    title=label,
                    description=f"The page reveals internal error/debug information: '{label}'.",
                    category="information_disclosure", severity=sev, cvss_score=5.0,
                    evidence=f"GET {base} -> contains debug/stack trace marker",
                    affected_component="Error handling", exploitability="none",
                    remediation={"immediate_action": "Disable debug mode and verbose error output in production."},
                    remediation_level="level2_approval_required", cwe="CWE-209",
                    standards={"owasp_top10": "A05:2021-Security Misconfiguration", "cwe": "CWE-209"},
                ))
                break
