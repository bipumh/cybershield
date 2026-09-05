"""Remediation engine (requirement #12, #13).

Produces a structured remediation plan for a finding and classifies the safe
automation level. Level assignment is conservative: config/metadata actions
that can be reversed and are low-risk become Level 1 or 2; anything that may
affect availability or data is Level 3 (manual only).
"""
from __future__ import annotations

from ..core.constants import RemediationLevel, RemediationStatus

# Category keywords that map to a recommended action + level
_ACTION_HINTS = {
    "security_misconfiguration": ("Enable a secure configuration default.",
                                  RemediationLevel.LEVEL2_APPROVAL_REQUIRED),
    "server_configuration": ("Apply a secure server hardening configuration.",
                             RemediationLevel.LEVEL2_APPROVAL_REQUIRED),
    "exposed_management": ("Restrict exposure of the management interface via access control.",
                           RemediationLevel.LEVEL2_APPROVAL_REQUIRED),
    "exposed_service": ("Disable or firewall-restrict the exposed service.",
                        RemediationLevel.LEVEL2_APPROVAL_REQUIRED),
    "outdated_component": ("Upgrade the component to a supported, patched version.",
                           RemediationLevel.LEVEL3_MANUAL),
    "vulnerable_component": ("Apply the vendor patch/advisory upgrade.",
                             RemediationLevel.LEVEL3_MANUAL),
    "tls_configuration": ("Harden TLS configuration (disable weak protocols/ciphers).",
                          RemediationLevel.LEVEL2_APPROVAL_REQUIRED),
    "certificate": ("Renew/replace the TLS certificate.",
                    RemediationLevel.LEVEL3_MANUAL),
    "session_security": ("Apply secure session/cookie flags.",
                         RemediationLevel.LEVEL2_APPROVAL_REQUIRED),
    "cors_misconfiguration": ("Restrict CORS allowed origins.",
                              RemediationLevel.LEVEL2_APPROVAL_REQUIRED),
    "csrf": ("Implement CSRF protection and SameSite cookies.",
             RemediationLevel.LEVEL2_APPROVAL_REQUIRED),
    "authentication": ("Strengthen the authentication configuration.",
                       RemediationLevel.LEVEL2_APPROVAL_REQUIRED),
    "information_disclosure": ("Remove or restrict exposure of sensitive information.",
                               RemediationLevel.LEVEL2_APPROVAL_REQUIRED),
    "dns_configuration": ("Publish a corrected DNS record (e.g., SPF/DMARC/DNSSEC).",
                          RemediationLevel.LEVEL2_APPROVAL_REQUIRED),
    "security_policy": ("Publish a secure configuration/policy document.",
                        RemediationLevel.LEVEL2_APPROVAL_REQUIRED),
    "transport_security": ("Enforce HTTPS and HSTS.",
                           RemediationLevel.LEVEL2_APPROVAL_REQUIRED),
    "default": (None, RemediationLevel.LEVEL2_APPROVAL_REQUIRED),
}


def classify_level(category: str, severity: str) -> str:
    # Anything that manipulates production state / may cause downtime is manual
    if category in ("outdated_component", "vulnerable_component", "certificate",
                    "database", "firewall"):
        return RemediationLevel.LEVEL3_MANUAL
    if severity == "critical":
        # Even critical misconfiguration allows auto-ticket/notify (L1) but
        # actual change requires approval. Keep conservative default.
        return RemediationLevel.LEVEL3_MANUAL
    hint = _ACTION_HINTS.get(category, _ACTION_HINTS["default"])
    return hint[1] if hint[1] else RemediationLevel.LEVEL2_APPROVAL_REQUIRED


def build_remediation_plan(category: str, severity: str, title: str,
                           detected_version: str | None,
                           fixed_version: str | None) -> dict:
    action, _ = _ACTION_HINTS.get(category, _ACTION_HINTS["default"])
    base_action = action or "Apply the recommended configuration."
    level = classify_level(category, severity)

    if fixed_version:
        upgrade = (
            f"Upgrade {detected_version or 'the affected component'} to "
            f"{fixed_version} or later."
        )
    else:
        upgrade = "Apply the latest vendor security patch/update or move to a supported version."

    plan = {
        "immediate_action": base_action,
        "permanent_solution": (
            f"{base_action} Align the system/configuration with a security baseline and "
            "enforce it via policy/CI."
        ),
        "recommended_config": self_recommended(category),
        "patch_recommendation": upgrade,
        "verification_procedure": (
            "After remediation, re-run the corresponding scanner / check and confirm the "
            "finding no longer appears; then mark the finding Verified and Closed."
        ),
        "rollback_procedure": (
            "Keep a pre-change configuration or system snapshot. If the change causes an "
            "outage or breaks functionality, restore the previous configuration and open a "
            "rollback approval if required (Level 3 only)."
        ),
        "business_impact": impact_for(category, severity),
        "complexity": complexity_for(category),
        "level": level,
    }
    return plan


def self_recommended(category: str) -> str:
    map = {
        "tls_configuration": "TLS 1.2+ only; disable weak ciphers; enable HSTS; use strong certs.",
        "cors_misconfiguration": "Access-Control-Allow-Origin = exact allowed origin(s); never '*' with credentials.",
        "csrf": "CSRF tokens on state-changing requests; SameSite=Lax/Strict cookies.",
        "session_security": "HttpOnly + Secure + SameSite cookies; rotate session IDs; set short idle timeout.",
        "auth": "Enforce MFA; use OIDC/OAuth2; disable anonymous access.",
        "dns_configuration": "SPF (no +all), DKIM, DMARC p=reject, DNSSEC, CAA.",
        "default": "Follow the OWASP / CIS hardening baseline for the affected component.",
    }
    return map.get(category, map["default"])


def complexity_for(category: str) -> str:
    if category in ("outdated_component", "vulnerable_component", "certificate"):
        return "high"
    if category in ("firewall", "database", "exposed_management"):
        return "high"
    if category in ("tls_configuration", "authentication", "network"):
        return "medium"
    return "low"


def impact_for(category: str, severity: str) -> str:
    map = {
        "tls_configuration": "Confidentiality/Integrity: enables interception and downgrade of sensitive traffic.",
        "cors_misconfiguration": "Confidentiality/Integrity: cross-origin data theft and unauthorized API calls.",
        "session_security": "Confidentiality: session hijacking leading to account takeover.",
        "authentication": "Confidentiality/Integrity: unauthorized access to the system.",
        "outdated_component": "Confidentiality/Integrity/Availability: known and possibly exploited weaknesses.",
        "information_disclosure": "Confidentiality/Compliance: exposure of sensitive data or credentials.",
        "security_misconfiguration": "Confidentiality/Integrity/Compliance: broad attack surface exposure.",
        "default": "Depends on asset; risk to confidentiality, integrity, availability and compliance.",
    }
    return map.get(category, map["default"])
