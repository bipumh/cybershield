"""Unit tests for engines and services."""
import pytest

from app.engines.intelligence import cvss31_base_score, severity_from_score
from app.engines import risk, remediation
from app.services.target_service import parse_target, expand_scope
from app.core.constants import RemediationLevel
from app.core.exceptions import ValidationError, ScopeViolationError


@pytest.mark.parametrize("vector,expected", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N", 4.7),
])
def test_cvss_base_score(vector, expected):
    assert abs(cvss31_base_score(vector) - expected) < 0.15


def test_severity_mapping():
    assert severity_from_score(9.0) == "critical"
    assert severity_from_score(7.1) == "high"
    assert severity_from_score(4.3) == "medium"
    assert severity_from_score(1.0) == "low"


def test_risk_band_calibration():
    # critical + KEV + internet + critical asset ages high
    s = risk.compute_risk_score(cvss=9.8, exploitability="exploited_in_wild",
                                asset_criticality="critical", internet_exposed=True,
                                is_kev=True, age_days=90)
    assert 70 <= s <= 100  # high or critical
    # benign internal medium
    s2 = risk.compute_risk_score(cvss=2.0, exploitability="none",
                                 asset_criticality="low", internet_exposed=False,
                                 age_days=1)
    assert risk.band_from_score(s2) == "low"


def test_remediation_level_conservative():
    assert remediation.classify_level("outdated_component", "high") == RemediationLevel.LEVEL3_MANUAL
    assert remediation.classify_level("certificate", "medium") == RemediationLevel.LEVEL3_MANUAL
    assert remediation.classify_level("security_misconfiguration", "medium") == RemediationLevel.LEVEL2_APPROVAL_REQUIRED


def test_target_parsing():
    t = parse_target("https://example.com/app")
    assert t.kind == "url" and t.host == "example.com" and t.port == 443
    t2 = parse_target("example.com")
    assert t2.kind == "domain"
    t3 = parse_target("192.168.1.5")
    assert t3.kind == "ip"
    t4 = parse_target("10.0.0.0/28")
    assert t4.kind == "cidr"
    assert len(expand_scope(t4)) == 14


def test_target_rejects_bad():
    with pytest.raises((ValidationError, Exception)):
        parse_target("")


def test_scope_exclusion():
    from app.services.scan_service import _is_excluded
    assert _is_excluded("admin.example.com", ["example.com"], []) is True
    assert _is_excluded("example.com", ["example.com"], []) is True
    assert _is_excluded("safe.example.org", ["example.com"], []) is False
    assert _is_excluded("192.168.1.5", [], ["192.168.1.5"]) is True
