"""Vulnerability intelligence engine (requirement #9, #28).

Converts raw scanner evidence into a normalized vulnerability record, computes
CVSS scores/severity, resolves CVE/CWE descriptors, and marks CISA KEV status.
Connects to feeds through a modular connector interface (no hard-coded DB).
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.constants import Severity
from ..db.models import CisaKev, CveInfo, Vulnerability

CVSS_ORDER = {
    "S": {"U": 0.85, "C": 1.0},  # scope
    "C": {"N": 0.0, "L": 0.22, "H": 0.56},   # confidentiality
    "I": {"N": 0.0, "L": 0.22, "H": 0.56},   # integrity
    "A": {"N": 0.0, "L": 0.22, "H": 0.56},   # availability
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27}, # privileges required (unscoped)
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
}
# scope-adjusted values (when S=C)
PR_SCOPED = {"N": 0.85, "L": 0.68, "H": 0.50}


def cvss31_base_score(vector: str | None) -> float:
    """Compute a CVSS v3.1 base score from a vector (0.0 if invalid)."""
    if not vector:
        return 0.0
    m = dict(kv.split(":", 1) for kv in vector.split("/") if ":" in kv)
    try:
        av = m["AV"]; ac = m["AC"]; pr = m["PR"]; ui = m["UI"]
        s = m["S"]; c = m["C"]; i = m["I"]; a = m["A"]
    except KeyError:
        return 0.0
    iss = 1 - ((1 - CVSS_ORDER["C"][c]) * (1 - CVSS_ORDER["I"][i]) * (1 - CVSS_ORDER["A"][a]))
    if s == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    pr_v = CVSS_ORDER["PR"].get(pr, 0.85)
    if s == "C":
        pr_v = PR_SCOPED.get(pr, 0.85)
    exploitability = 8.22 * CVSS_ORDER["AV"][av] * CVSS_ORDER["AC"][ac] \
        * pr_v * CVSS_ORDER["UI"][ui]
    if impact <= 0:
        return 0.0
    if s == "U":
        score = round_sf(min((impact + exploitability), 10))
    else:
        score = round_sf(min(1.08 * (impact + exploitability), 10))
    return round(score, 1)


def round_sf(x: float, dp: int = 1) -> float:
    """CVSS v3.1 uses 0.1 rounding up (ceiling on the 2nd decimal)."""
    if x <= 0:
        return 0.0
    scaled = x * (10 ** (dp + 1))
    return math.ceil(scaled) / (10 ** (dp + 1))


def severity_from_score(score: float) -> str:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


def severity_from_band(risk_band: str) -> str:
    band_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                "medium": Severity.MEDIUM, "low": Severity.LOW}
    return band_map.get(risk_band, Severity.MEDIUM)


def infer_exploitability_enabled_kev(kev: bool, score: float, vector: str | None) -> str:
    if kev:
        return "exploited_in_wild"
    if vector and "AV:N" in vector and score >= 9.0:
        return "likely_exploitable"
    if score >= 7.0:
        return "possible"
    return "none"


def resolve_cwe(cwe_id: str | None) -> tuple[str, str] | None:
    """Return (name, description) for a CWE id from a curated map."""
    if not cwe_id:
        return None
    catalog = {
        "CWE-79": ("Cross-Site Scripting (XSS)", "Improper neutralization of input during web page generation."),
        "CWE-89": ("SQL Injection", "Improper neutralization of special elements in SQL."),
        "CWE-200": ("Information Exposure", "Exposure of sensitive information to an unauthorized actor."),
        "CWE-209": ("Information Exposure Through Error Message", "Error messages reveal internal details."),
        "CWE-287": ("Improper Authentication", "Authentication mechanism is weak or bypassable."),
        "CWE-295": ("Improper Certificate Validation", "TLS certificate validation is improper."),
        "CWE-326": ("Inadequate Encryption Strength", "Use of weak cryptographic algorithm/protocol."),
        "CWE-352": ("CSRF", "Cross-Site Request Forgery."),
        "CWE-522": ("Insufficiently Protected Credentials", "Credentials transmitted or stored insecurely."),
        "CWE-693": ("Protection Mechanism Failure", "A security control is missing or ineffective."),
        "CWE-749": ("Reachable Public Service", "An externally reachable service used for internal/logical operations."),
        "CWE-1004": ("Sensitive Cookie Without HttpOnly", "Cookie exposed to scripting."),
        "CWE-1104": ("Use of Unmaintained Third-Party Components", "Outdated/unsupported dependency."),
        "CWE-548": ("Directory Listing", "Directory listing exposed."),
        "CWE-614": ("Sensitive Cookie Without Secure", "Cookie sent over cleartext."),
        "CWE-1275": ("Improper Cookie SameSite", "SameSite cookie attribute missing/weak."),
        "CWE-942": ("Permissive Cross-Domain Policy", "CORS allows arbitrary origins."),
        "CWE-319": ("Cleartext Transmission", "Sensitive data transmitted in cleartext."),
        "CWE-294": ("Authentication Bypass by Spoofing", "Spoofable identity, e.g., DNS."),
    }
    return catalog.get(cwe_id)


@dataclass
class EnrichedVuln:
    cve: str | None
    cwe: str | None
    cvss_score: float
    severity: str
    is_kev: bool
    title: str
    description: str
    fixed_version: str | None
    references: list[str]
    exploitability: str


class IntelligenceEngine:
    """Facade over local vulnerability store + feeds + KEV (modular connectors)."""

    def __init__(self, db: Session | None = None):
        self.db = db

    def enrich(self, *, fingerprint: str, product: str | None = None,
               version: str | None = None, vendor: str | None = None,
               cve: str | None = None, cwe: str | None = None,
               vector: str | None = None, title: str = "",
               description: str = "") -> EnrichedVuln:
        score = cvss31_base_score(vector)
        cve_lookup = self._lookup_cve(cve) if cve else None
        if cve_lookup:
            score = score or cve_lookup.cvss_score
            title = title or cve_lookup.description[:200]
            vector = vector or cve_lookup.cvss_vector
        if score == 0.0 and not vector:
            # derived default for the fingerprint
            score = self._default_score(product)

        kev = self._lookup_kev(cve)
        severity = severity_from_score(score)
        exploitable = infer_exploitability_enabled_kev(kev, score, vector)
        return EnrichedVuln(
            cve=cve, cwe=cwe, cvss_score=score, severity=severity,
            is_kev=bool(kev), title=title, description=description,
            fixed_version=self._find_fixed_version(fingerprint, product, vendor, version),
            references=self._references(cve),
            exploitability=exploitable,
        )

    def _lookup_cve(self, cve: str) -> CveInfo | None:
        if not self.db:
            return None
        return self.db.execute(select(CveInfo).where(CveInfo.cve_id == cve)).scalar_one_or_none()

    def _lookup_kev(self, cve: str | None) -> CisaKev | None:
        if not cve or not self.db:
            return None
        return self.db.execute(select(CisaKev).where(CisaKev.cve_id == cve)).scalar_one_or_none()

    def _references(self, cve: str | None) -> list[str]:
        if not cve:
            return []
        base = cve
        return [
            f"https://nvd.nist.gov/vuln/detail/{base}",
            f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={base}",
        ]

    def _default_score(self, product: str | None) -> float:
        if product and re.search(r"(apache|nginx|web|http)", product, re.I):
            return 5.3
        return 4.0

    def _find_fixed_version(self, fingerprint, product, vendor, version) -> str | None:
        if not self.db:
            return None
        rec = self.db.execute(
            select(Vulnerability).where(Vulnerability.fingerprint == fingerprint)
        ).scalar_one_or_none()
        if rec and rec.fixed_versions:
            import json
            versions = json.loads(rec.fixed_versions)
            return versions[0] if versions else None
        return None
