"""Compliance / standards mapping engine (requirement #3, #20).

Only *defensible* mappings are produced: findings are mapped to a standard
control only when there is an explicit, documented relationship (per the
curated mapping table + the requirement's caveat). Never invent compliance
claims. Production deployments load the authoritative mapping table from the
DB (seeded), augmenting this curated fallback.
"""
from __future__ import annotations

from ..core.constants import Standard

_CURATED = {
    "security_misconfiguration": {
        "owasp_top10": {"id": "A05:2021", "title": "Security Misconfiguration"},
        "nist_csf": {"id": "PR.DS-1", "title": "Data-at-rest protection"},
        "cis_controls": {"id": "Control 4.1", "title": "Establish and maintain a secure configuration process"},
    },
    "tls_configuration": {
        "owasp_top10": {"id": "A02:2021", "title": "Cryptographic Failures"},
        "nist_csf": {"id": "PR.DS-2", "title": "Data-in-transit protection"},
        "cis_controls": {"id": "Control 4.2", "title": "Secure configurations of mobile devices"},
    },
    "injection": {
        "owasp_top10": {"id": "A03:2021", "title": "Injection"},
        "cwe": {"id": "CWE-89", "title": "SQL Injection"},
    },
    "broken_access_control": {
        "owasp_top10": {"id": "A01:2021", "title": "Broken Access Control"},
        "nist_csf": {"id": "PR.AC-4", "title": "Access permissions managed"},
    },
    "authentication": {
        "owasp_top10": {"id": "A07:2021", "title": "Identification and Authentication Failures"},
        "nist_csf": {"id": "PR.AC-7", "title": "Users, devices and services authenticated"},
        "cis_controls": {"id": "Control 6.x", "title": "Access control management"},
    },
    "session_security": {
        "owasp_top10": {"id": "A07:2021", "title": "Identification and Authentication Failures"},
        "owasp_wstg": {"id": "WSTG-SESS-02", "title": "Session management"},
    },
    "cors_misconfiguration": {
        "owasp_top10": {"id": "A01:2021", "title": "Broken Access Control"},
        "cwe": {"id": "CWE-942", "title": "Permissive Cross-domain Policy"},
    },
    "csrf": {
        "owasp_top10": {"id": "A01:2021", "title": "Broken Access Control"},
        "owasp_wstg": {"id": "WSTG-SESS-05", "title": "Cross-Site Request Forgery"},
    },
    "information_disclosure": {
        "owasp_top10": {"id": "A05:2021", "title": "Security Misconfiguration"},
        "nist_csf": {"id": "PR.DS-1", "title": "Data-at-rest protection"},
    },
    "outdated_component": {
        "owasp_top10": {"id": "A06:2021", "title": "Vulnerable and Outdated Components"},
        "cis_controls": {"id": "Control 7.x", "title": "Continuous vulnerability management"},
        "nist_csf": {"id": "PR.DS-6", "title": "Integrity checking mechanisms"},
    },
    "vulnerable_component": {
        "owasp_top10": {"id": "A06:2021", "title": "Vulnerable and Outdated Components"},
        "nist_csf": {"id": "ID.RA-1", "title": "Risk assessments performed"},
    },
    "exposed_service": {
        "nist_csf": {"id": "PR.PT-4", "title": "Communications and control networks protected"},
        "cis_controls": {"id": "Control 4.4", "title": "Segment and restrict network access"},
    },
    "exposed_management": {
        "cis_controls": {"id": "Control 5.3", "title": "Secure web management interfaces"},
        "nist_csf": {"id": "PR.PT-3", "title": "Maintenance and repairs of assets"},
    },
    "dns_configuration": {
        "nist_csf": {"id": "PR.DS-2", "title": "Data-in-transit protection"},
        "cis_controls": {"id": "Control 4.6", "title": "Configure network integrity monitoring"},
    },
    "certificate": {
        "owasp_top10": {"id": "A02:2021", "title": "Cryptographic Failures"},
        "nist_csf": {"id": "PR.DS-2", "title": "Data-in-transit protection"},
    },
}


def map_finding_to_standards(category: str, cwe: str | None = None) -> dict:
    mapping = dict(_CURATED.get(category, {}))
    if cwe:
        mapping.setdefault("cwe", {"id": cwe, "title": "Common Weakness Enumeration"})
    if not mapping:
        mapping["general"] = {"id": "N/A", "title": "No specific mapping; review against applicable standards"}
    return mapping


# Control mappings for the compliance *report* generator.
# Only seeded with defensible, public, well-known mappings.
COMPLIANCE_BREAKDOWN = {
    Standard.OWASP_TOP10: {
        "A01:2021-Broken Access Control": ["broken_access_control", "cors_misconfiguration", "csrf"],
        "A02:2021-Cryptographic Failures": ["tls_configuration", "certificate"],
        "A03:2021-Injection": ["injection"],
        "A05:2021-Security Misconfiguration": ["security_misconfiguration", "information_disclosure"],
        "A06:2021-Vulnerable and Outdated Components": ["outdated_component", "vulnerable_component"],
        "A07:2021-Identification and Authentication Failures": ["authentication", "session_security"],
    },
    Standard.NIST_CSF: {
        "ID.RA-Risk Assessment": ["vulnerable_component"],
        "PR.AC-Access Control": ["broken_access_control", "authentication"],
        "PR.DS-Data Security": ["tls_configuration", "certificate", "security_misconfiguration"],
        "PR.PT-Protective Technology": ["exposed_service", "exposed_management"],
    },
    Standard.CIS_CONTROLS: {
        "Control 4-Secure Configuration": ["security_misconfiguration", "exposed_service"],
        "Control 5-Account Management": ["exposed_management", "authentication"],
        "Control 6-Access Control": ["authentication", "broken_access_control"],
        "Control 7-Continuous Vulnerability Management": ["outdated_component", "vulnerable_component"],
    },
}
