"""Enterprise risk scoring engine (requirement #10, #12).

Risk = weighted combination of CVSS, exploitability, asset criticality,
internet exposure, threat intel (KEV), age, compensating controls, attack
surface, auth requirement and potential impact. Normalized to 0-100.

Weights are configurable by administrators (defaults below) and are enforced
to sum to 1.0.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..core.constants import RiskBand, Severity


@dataclass
class RiskWeights:
    cvss: float = 0.18
    exploitability: float = 0.14
    asset_criticality: float = 0.14
    internet_exposure: float = 0.12
    threat_intelligence: float = 0.12      # KEV / active exploitation
    age: float = 0.08
    attack_surface: float = 0.08
    auth_requirement: float = 0.06
    potential_impact: float = 0.08
    compensating_control: float = 0.16     # subtractive

    def normalized(self) -> "RiskWeights":
        """Normalize only the positive (additive) weights to sum to 1.0. The
        compensating-control weight remains a separate subtractive term."""
        total = (self.cvss + self.exploitability + self.asset_criticality
                 + self.internet_exposure + self.threat_intelligence + self.age
                 + self.attack_surface + self.auth_requirement + self.potential_impact)
        if total <= 0:
            return self
        k = 1.0 / total
        return RiskWeights(
            cvss=self.cvss * k, exploitability=self.exploitability * k,
            asset_criticality=self.asset_criticality * k, internet_exposure=self.internet_exposure * k,
            threat_intelligence=self.threat_intelligence * k, age=self.age * k,
            attack_surface=self.attack_surface * k, auth_requirement=self.auth_requirement * k,
            potential_impact=self.potential_impact * k, compensating_control=self.compensating_control,
        )


CRITICALITY_SUBSCORE = {"critical": 100.0, "high": 80.0, "medium": 60.0, "low": 30.0}
EXPLOIT_SUBSCORE = {"exploited_in_wild": 100.0, "likely_exploitable": 85.0,
                    "possible": 60.0, "unknown": 40.0, "none": 10.0}
AUTH_SUBSCORE = {"none": 100.0, "low": 70.0, "single": 50.0, "multi": 20.0}


def age_subscore(days: int) -> float:
    # age accelerates risk on a 0-100 scale, saturating near 180 days
    return min(100.0, days * 0.6)


def compute_risk_score(
    *, cvss: float = 0.0, exploitability: str = "none",
    asset_criticality: str = "medium", internet_exposed: bool = False,
    threats: list[str] | None = None, is_kev: bool = False,
    age_days: int = 0, attack_surface: float = 0.0,
    auth_requirement: str = "single", potential_impact: float = 0.0,
    compensating_controls: float = 0.0,
    weights: RiskWeights | None = None,
) -> float:
    w = (weights or RiskWeights()).normalized()

    # Each component is on a 0-100 scale
    cvss_component = min(cvss, 10.0) * 10.0
    exploitable_component = EXPLOIT_SUBSCORE.get(exploitability, 40.0)
    crit_component = CRITICALITY_SUBSCORE.get(asset_criticality, 60.0)
    exposure_component = 100.0 if internet_exposed else 20.0
    intel_component = 100.0 if is_kev else (60.0 if threats else 20.0)
    age_component = age_subscore(age_days)
    attack_component = min(attack_surface * 10.0, 100.0)
    auth_component = AUTH_SUBSCORE.get(auth_requirement, 50.0)
    impact_component = min(potential_impact * 10.0, 100.0)

    score = (
        w.cvss * cvss_component
        + w.exploitability * exploitable_component
        + w.asset_criticality * crit_component
        + w.internet_exposure * exposure_component
        + w.threat_intelligence * intel_component
        + w.age * age_component
        + w.attack_surface * attack_component
        + w.auth_requirement * auth_component
        + w.potential_impact * impact_component
    )
    # compensating controls reduce score (0-100 scale, scaled to weight)
    score -= w.compensating_control * min(compensating_controls, 10.0) * 10.0
    return max(0.0, min(100.0, round(score, 1)))


def band_from_score(score: float) -> str:
    return RiskBand.band_for(int(score))


def band_from_severity(severity: str) -> str:
    mapping = {
        Severity.CRITICAL: "critical", Severity.HIGH: "high",
        Severity.MEDIUM: "medium", Severity.LOW: "low", Severity.INFO: "low",
    }
    return mapping.get(severity, "medium")
