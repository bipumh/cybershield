"""Security posture score engine (requirement #34).

Computes a 0-100 posture based on open critical/high vulns, patch status,
internet exposure, asset criticality, KEV exposure, vuln age and SLA
remediation progress. Higher is healthier.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PostureInputs:
    critical_open: int = 0
    high_open: int = 0
    medium_open: int = 0
    low_open: int = 0
    total_assets: int = 0
    internet_exposed: int = 0
    kev_open: int = 0
    mean_age_days: float = 0.0
    remediated: int = 0
    total_findings: int = 0
    sla_breach: int = 0
    assets_scanned: int = 0


def compute_posture(i: PostureInputs) -> dict:
    # Start healthy at 100, subtract penalties, keep within bounds
    score = 100.0
    factors: list[dict] = []

    crit_penalty = i.critical_open * 6.0
    if crit_penalty:
        score -= crit_penalty
        factors.append({"factor": "Critical vulnerabilities open", "impact": -min(crit_penalty, 100), "weight": i.critical_open})

    high_penalty = i.high_open * 3.0
    if high_penalty:
        score -= high_penalty
        factors.append({"factor": "High vulnerabilities open", "impact": -min(high_penalty, 100), "weight": i.high_open})

    med_penalty = i.medium_open * 0.8
    if med_penalty:
        score -= med_penalty
        factors.append({"factor": "Medium vulnerabilities open", "impact": -min(med_penalty, 100), "weight": i.medium_open})

    kev_penalty = i.kev_open * 8.0
    if kev_penalty:
        score -= kev_penalty
        factors.append({"factor": "CISA KEV (actively exploited) exposure", "impact": -min(kev_penalty, 100), "weight": i.kev_open})

    if i.mean_age_days > 15:
        age_penalty = (i.mean_age_days - 15) * 0.3
        score -= min(age_penalty, 40)
        factors.append({"factor": "High mean vulnerability age", "impact": -min(age_penalty, 40), "weight": round(i.mean_age_days, 1)})

    if i.sla_breach:
        sla_penalty = i.sla_breach * 4.0
        score -= min(sla_penalty, 60)
        factors.append({"factor": "SLA breaches", "impact": -min(sla_penalty, 60), "weight": i.sla_breach})

    # Patch/remediation compliance bonus
    if i.total_findings and i.assets_scanned:
        rem_rate = i.remediated / max(i.total_findings, 1) * 100
        if rem_rate > 50:
            bonus = (rem_rate - 50) * 0.1
            score += min(bonus, 10)
            factors.append({"factor": "Remediation progress", "impact": round(bonus, 1), "weight": round(rem_rate, 1)})

    # Exposure penalty (internet facing)
    if i.total_assets:
        exposed_ratio = i.internet_exposed / i.total_assets
        if exposed_ratio > 0.4:
            exp_penalty = (exposed_ratio - 0.4) * 20
            score -= min(exp_penalty, 15)
            factors.append({"factor": "High internet-exposed asset ratio", "impact": -min(exp_penalty, 15), "weight": round(exposed_ratio, 2)})

    score = max(0.0, min(100.0, round(score, 1)))
    score_class = "excellent" if score >= 85 else ("good" if score >= 70 else
                     ("fair" if score >= 50 else ("poor" if score >= 30 else "critical")))
    factors.sort(key=lambda f: f["impact"])
    return {"score": score, "class": score_class, "factors": factors}
