"""TLS/SSL & certificate scanner (safe, non-exploitative)."""
from __future__ import annotations

import datetime as dt
import socket
import ssl

from ..base import BaseScanner, NormalizedFinding, ScanContext, ScannerOutput
from ..registry import register_scanner

# Modern minimums for safe web traffic
MIN_TLS_VERSION = ssl.TLSVersion.TLSv1_2
WEAK_CIPHERS = ["NULL", "RC4", "3DES", "DES", "EXPORT", "ANON"]


@register_scanner
class TlsScanner(BaseScanner):
    name = "web.tls"
    kind = "web"

    def scan(self, ctx: ScanContext) -> ScannerOutput:
        host = ctx.host
        port = int(ctx.extra.get("port", 443))
        out = ScannerOutput(checks_run=6, metadata={"host": host, "port": port})
        try:
            ctx_sock = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=ctx.timeout) as raw:
                with ctx_sock.wrap_socket(raw, server_hostname=host) as tls:
                    tls_version = tls.version()
                    cipher = tls.cipher()
                    cert_bin = tls.getpeercert()
            out.metadata.update({"tls_version": tls_version, "cipher": cipher})
            self._check_version(tls_version, out)
            self._check_cipher(cipher, out)
            self._check_cert(cert_bin, out)
        except ssl.SSLError as e:
            out.error = f"TLS handshake failed: {e}"
            out.normalized.append(NormalizedFinding(
                title="TLS/SSL configuration issue",
                description=f"Unable to establish a secure TLS connection: {e}. The site may not support modern TLS or the certificate is invalid.",
                category="tls_configuration", severity="high", cvss_score=7.5,
                evidence=f"TLS handshake to {host}:{port} failed: {e}",
                exploitability="none",
                remediation={"immediate_action": "Ensure the endpoint supports TLS 1.2+ with a valid certificate."},
                remediation_level="level3_manual", cwe="CWE-295", standards={"nist_csf": "PR.DS-2"},
            ))
        except (socket.timeout, ConnectionError, OSError):
            out.error = "Connection failed"
        return out

    def _check_version(self, version: str, out: ScannerOutput) -> None:
        if version not in ("TLSv1.2", "TLSv1.3"):
            out.normalized.append(NormalizedFinding(
                title="Weak TLS protocol in use",
                description=f"The endpoint negotiates '{version}', which is obsolete and vulnerable to downgrade / protocol attacks.",
                category="tls_configuration", severity="high", cvss_score=7.5,
                evidence=f"Negotiated TLS version: {version}",
                affected_component="TLS", detected_version=version, fixed_version="TLSv1.2+",
                exploitability="none",
                remediation={
                    "immediate_action": "Disable TLS 1.0/1.1 and obsolete cipher suites.",
                    "permanent_solution": "Require TLS 1.2 or 1.3 only; configure HSTS.",
                    "verification_procedure": "Re-run this scanner and confirm negotiated version >= TLS 1.2.",
                },
                remediation_level="level2_approval_required", cwe="CWE-326",
                standards={"owasp_top10": "A02:2021-Cryptographic Failures", "nist_csf": "PR.DS-2",
                           "cwe": "CWE-326"},
            ))

    def _check_cipher(self, cipher: tuple, out: ScannerOutput) -> None:
        if not cipher:
            return
        try:
            name = cipher[0]
        except (IndexError, TypeError):
            return
        if any(w in name.upper() for w in WEAK_CIPHERS):
            out.normalized.append(NormalizedFinding(
                title="Weak TLS cipher suite enabled",
                description=f"The negotiated cipher '{name}' is weak or export-grade, enabling protocol attacks.",
                category="tls_configuration", severity="high", cvss_score=7.5,
                evidence=f"Cipher negotiated: {name}",
                affected_component="TLS cipher", detected_version=name,
                remediation={"immediate_action": "Disable NULL/RC4/3DES/DES/EXPORT ciphers."},
                remediation_level="level2_approval_required", cwe="CWE-326",
                standards={"owasp_top10": "A02:2021-Cryptographic Failures"},
            ))

    def _check_cert(self, cert: dict, out: ScannerOutput) -> None:
        if not cert:
            return
        import ssl as _ssl
        now = dt.datetime.now(dt.timezone.utc)
        not_after_raw = cert.get("notAfter", "")
        try:
            not_after = dt.datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=dt.timezone.utc)
        except (ValueError, TypeError):
            return
        days = (not_after - now).days
        if not_after < now:
            out.normalized.append(NormalizedFinding(
                title="Expired TLS certificate",
                description="The TLS certificate has expired, so clients may reject the connection and it cannot provide identity assurance.",
                category="certificate", severity="high", cvss_score=7.5,
                evidence=f"Certificate expired on {not_after.isoformat()}",
                affected_component="Certificate", detected_version=not_after_raw,
                remediation={"immediate_action": "Renew and deploy a valid certificate immediately."},
                remediation_level="level3_manual", cwe="CWE-295",
                standards={"owasp_top10": "A02:2021-Cryptographic Failures", "cwe": "CWE-295"},
            ))
        elif days <= 14:
            out.normalized.append(NormalizedFinding(
                title="TLS certificate expiring soon",
                description=f"The TLS certificate expires in {days} day(s). Schedule renewal to avoid outage and loss of trust.",
                category="certificate", severity="medium", cvss_score=5.0,
                evidence=f"Certificate notAfter: {not_after.isoformat()}",
                affected_component="Certificate", detected_version=not_after_raw,
                remediation={"immediate_action": f"Renew the certificate within {max(days, 1)} day(s)."},
                remediation_level="level3_manual", cwe="CWE-295",
                standards={"owasp_top10": "A02:2021-Cryptographic Failures", "cwe": "CWE-295"},
            ))

    def progress_format(self) -> tuple[int, int]:
        return (6, 100)
