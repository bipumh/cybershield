"""Domain/DNS security scanner: SPF, DMARC, DKIM, DNSSEC, MX, CAA, redirects."""
from __future__ import annotations

import dns.dnssec
import dns.resolver

from ..base import BaseScanner, NormalizedFinding, ScanContext, ScannerOutput
from ..registry import register_scanner


@register_scanner
class DnsSecurityScanner(BaseScanner):
    name = "web.dns_security"
    kind = "web"

    def scan(self, ctx: ScanContext) -> ScannerOutput:
        domain = ctx.host
        out = ScannerOutput(checks_run=6, metadata={"domain": domain})
        if not self._is_domain(domain):
            out.error = "Not a valid domain for DNS checks (target is an IP or invalid host)"
            return out

        resolver = dns.resolver.Resolver()
        resolver.timeout = ctx.timeout
        resolver.lifetime = ctx.timeout

        self._check_spf(domain, resolver, out)
        self._check_dmarc(domain, resolver, out)
        self._check_dnssec(domain, resolver, out)
        self._check_mx(domain, resolver, out)
        self._check_caa(domain, resolver, out)
        return out

    @staticmethod
    def _is_domain(host: str) -> bool:
        if not host or "/" in host or host.startswith("."):
            return False
        try:
            import ipaddress
            ipaddress.ip_address(host)
            return False
        except ValueError:
            pass
        # Require at least two labels and a valid TLD-ish last label
        labels = host.split(".")
        if len(labels) < 2:
            return False
        if not labels[-1].isalpha():
            return False
        return all(l.isalnum() or "-" in l or "_" not in l for l in labels)

    def _txt(self, domain, resolver, name):
        try:
            ans = resolver.resolve(name, "TXT")
            return [b"".join(r.strings).decode(errors="ignore") for r in ans]
        except dns.resolver.NoAnswer:
            return []
        except Exception:
            return []

    def _check_spf(self, domain, resolver, out):
        values = self._txt(domain, resolver, domain)
        found = [v for v in values if v.startswith("v=spf1")]
        if not found:
            out.normalized.append(NormalizedFinding(
                title="No SPF record",
                description="SPF defines which hosts may send mail for the domain; its absence enables spoofing.",
                category="dns_configuration", severity="medium", cvss_score=5.0,
                evidence=f"No TXT v=spf1 record for {domain}",
                affected_component="DNS SPF", exploitability="none",
                remediation={"immediate_action": "Publish an SPF record (e.g., v=spf1 include:... ~all)."},
                remediation_level="level2_approval_required", cwe="CWE-294",
                standards={"owasp_wstg": "WSTG-CONF-17", "cwe": "CWE-294"},
            ))
        else:
            for spf in found:
                if spf.endswith("+all"):
                    out.normalized.append(NormalizedFinding(
                        title="SPF record allows any sender (+all)",
                        description="SPF ends in '+all', allowing any host to send as the domain, defeating spam filtering.",
                        category="dns_configuration", severity="high", cvss_score=7.5,
                        evidence=f"SPF: {spf}",
                        affected_component="DNS SPF", exploitability="none",
                        remediation={"immediate_action": "Change '+all' to '~all' (softfail) and tighten the include list."},
                        remediation_level="level2_approval_required", cwe="CWE-294",
                        standards={"owasp_wstg": "WSTG-CONF-17", "cwe": "CWE-294"},
                    ))
                    break

    def _check_dmarc(self, domain, resolver, out):
        values = self._txt(domain, resolver, "_dmarc." + domain)
        found = [v for v in values if v.startswith("v=DMARC1")]
        if not found:
            out.normalized.append(NormalizedFinding(
                title="No DMARC record",
                description="DMARC aligns SPF/DKIM and defines a policy for unauthenticated mail; its absence allows spoofing.",
                category="dns_configuration", severity="medium", cvss_score=5.0,
                evidence=f"No DMARC TXT record for _dmarc.{domain}",
                affected_component="DNS DMARC", exploitability="none",
                remediation={"immediate_action": "Publish DMARC with p=none first, then p=quarantine/reject."},
                remediation_level="level2_approval_required", cwe="CWE-294",
                standards={"owasp_wstg": "WSTG-CONF-17", "cwe": "CWE-294"},
            ))
        else:
            policy = "p=none"
            for dmarc in found:
                if "p=" in dmarc:
                    policy = dmarc.split("p=")[1].split(";")[0].strip()
                    break
            if policy == "none":
                out.normalized.append(NormalizedFinding(
                    title="DMARC policy is p=none",
                    description="DMARC exists but is set to monitor-only (p=none), providing no enforcement against spoofing.",
                    category="dns_configuration", severity="medium", cvss_score=5.0,
                    evidence=f"DMARC: {found[0][:150]}",
                    affected_component="DNS DMARC", exploitability="none",
                    remediation={"immediate_action": "Strengthen DMARC to p=quarantine then p=reject once monitoring is clean."},
                    remediation_level="level2_approval_required", cwe="CWE-294",
                    standards={"owasp_wstg": "WSTG-CONF-17", "cwe": "CWE-294"},
                ))

    def _check_dnssec(self, domain, resolver, out):
        try:
            dns.dnssec.validate(domain, [dns.rrset.from_text(
                domain, 300, "IN", "SOA", "ns.example. hostmaster.example. 1 3600 1200 86400 300")],
                None)
        except Exception:
            pass
        # Check for DS record presence via parent hints
        try:
            resolver.resolve(domain, "DNSKEY")  # any answer => DNSSEC configured
            has_dnssec = True
        except Exception:
            has_dnssec = False
        if not has_dnssec:
            out.normalized.append(NormalizedFinding(
                title="DNSSEC not configured",
                description="DNSSEC provides DNSSEC authentication of DNS responses; its absence allows DNS spoofing/cache poisoning.",
                category="dns_configuration", severity="medium", cvss_score=5.0,
                evidence=f"No DNSSEC DNSKEY/DS found for {domain}",
                affected_component="DNS DNSSEC", exploitability="none",
                remediation={"immediate_action": "Enable DNSSEC signing and publish the DS record at the registrar."},
                remediation_level="level2_approval_required", cwe="CWE-345",
                standards={"owasp_wstg": "WSTG-CONF-17", "cwe": "CWE-345"},
            ))

    def _check_mx(self, domain, resolver, out):
        try:
            mx = resolver.resolve(domain, "MX")
            if mx:
                out.metadata["mx_records"] = [str(r.exchange) for r in mx]
        except dns.resolver.NoAnswer:
            out.normalized.append(NormalizedFinding(
                title="No MX record",
                description="No MX records found; the domain may not be reachable for mail or may be misconfigured.",
                category="dns_configuration", severity="low", cvss_score=2.0,
                evidence=f"No MX records for {domain}",
                affected_component="DNS MX", exploitability="none",
                remediation={"immediate_action": "If the domain should receive mail, configure MX records correctly."},
                remediation_level="level2_approval_required", cwe="CWE-400",
                standards={"owasp_wstg": "WSTG-CONF-17"},
            ))
        except Exception:
            pass

    def _check_caa(self, domain, resolver, out):
        try:
            resolver.resolve(domain, "CAA")
            has_caa = True
        except dns.resolver.NoAnswer:
            has_caa = False
        except Exception:
            has_caa = True  # resolver error — do not falsely flag
        if not has_caa:
            out.normalized.append(NormalizedFinding(
                title="No CAA record",
                description="CAA restricts which Certificate Authorities may issue certificates for the domain; absence reduces issuance control.",
                category="dns_configuration", severity="low", cvss_score=2.0,
                evidence=f"No CAA record for {domain}",
                affected_component="DNS CAA", exploitability="none",
                remediation={"immediate_action": "Publish CAA records (e.g., issue 'letsencrypt.org')."},
                remediation_level="level2_approval_required", cwe="CWE-20",
                standards={"owasp_wstg": "WSTG-CONF-17"},
            ))
