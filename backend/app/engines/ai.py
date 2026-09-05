"""AI Security Analyst + CyberShield Security Advisor (requirement #11, #35).

Provider-independent LLM abstraction:
- 'mocked': deterministic, offline analysis for development/lab (no API key)
- 'off': disabled
- 'openai' / 'anthropic' / 'openai_compatible': real providers via HTTP

The AI NEVER fabricates vulnerabilities, CVEs, asset data or remediation. It
is grounded on the platform's scan data, and every prediction is clearly
labelled 'AI-generated risk assessment'. If the provider is unavailable the
engine returns an explainable, evidence-based fallback analysis.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from ..core.config import settings


@dataclass
class AiVerdict:
    analysis: str
    why_it_matters: str
    potential_impact: dict[str, str] = field(default_factory=dict)
    predicted_risk: str = ""
    confidence: str = ""
    evidence_basis: list[str] = field(default_factory=list)
    is_ai_generated: bool = True


class LlmProvider:
    """Minimal provider abstraction; extend for new vendors."""

    def __init__(self, provider: str, model: str, api_key: str, base_url: str = ""):
        self.provider = provider.lower()
        self.model = model
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")

    def complete(self, prompt: str, system: str | None = None,
                 max_tokens: int | None = None) -> str | None:
        try:
            if self.provider == "openai" or self.provider == "openai_compatible":
                return self._openai_compatible(prompt, system, max_tokens)
            if self.provider == "anthropic":
                return self._anthropic(prompt, system, max_tokens)
        except Exception:
            return None
        return None

    def _openai_compatible(self, prompt, system, max_tokens) -> str | None:
        import httpx
        url = (self.base_url or "https://api.openai.com/v1") + "/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        body = {
            "model": self.model or "gpt-4o-mini",
            "temperature": settings.ai_temperature,
            "max_tokens": max_tokens or settings.ai_max_tokens,
            "messages": [{"role": "system", "content": system or "You are CyberShield AI."},
                         {"role": "user", "content": prompt}],
        }
        with httpx.Client(timeout=45) as client:
            resp = client.post(url, headers=headers, json=body)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]

    def _anthropic(self, prompt, system, max_tokens) -> str | None:
        import httpx
        url = (self.base_url or "https://api.anthropic.com") + "/v1/messages"
        headers = {"x-api-key": self.api_key,
                   "anthropic-version": "2023-06-01", "Content-Type": "application/json"}
        body = {
            "model": self.model or "claude-3-5-sonnet-20241022",
            "max_tokens": max_tokens or settings.ai_max_tokens,
            "temperature": settings.ai_temperature,
            "system": system or "You are CyberShield AI.",
            "messages": [{"role": "user", "content": prompt}],
        }
        with httpx.Client(timeout=45) as client:
            resp = client.post(url, headers=headers, json=body)
            resp.raise_for_status()
            data = resp.json()
            return "".join(b.get("text", "") for b in data.get("content", []))


class AiEngine:
    def __init__(self):
        self.active = settings.ai_provider.lower() in ("openai", "anthropic", "openai_compatible")
        self.mocked = settings.ai_provider.lower() == "mocked"
        self.provider = LlmProvider(settings.ai_provider, settings.ai_model,
                                    settings.ai_api_key, settings.ai_base_url) if self.active else None

    def available(self) -> bool:
        return self.active or self.mocked

    # ─── Finding analysis (require. #11) ────────────────────────────────
    def analyze_finding(self, finding: dict[str, Any]) -> AiVerdict:
        """finding dict: title, category, severity, cvss, internet_exposed,
        asset_criticality, is_kev, age_days, exploitability, description."""
        if self.mocked:
            return self._mock_analysis(finding)
        if self.active:
            llm = self._request_finding_analysis(finding)
            if llm:
                return self._parse_llm(llm, finding)
        return self._fallback_analysis(finding)

    def _request_finding_analysis(self, f: dict) -> str | None:
        prompt = (
            "You are CyberShield AI Security Analyst. Analyze this security finding using ONLY the "
            "provided platform data. Do not invent vulnerabilities or CVEs. Label clearly as an "
            "AI-generated risk assessment.\n"
            + json.dumps(f, default=str) +
            "\nRespond in JSON: {\"analysis\":..., \"why_it_matters\":..., "
            "\"potential_impact\":{\"confidentiality\":...,\"integrity\":...,\"availability\":...,"
            "\"compliance\":...,\"business\":...}, \"predicted_risk\":\"critical|high|medium|low\", "
            "\"confidence\":\"...\"}"
        )
        return self.provider.complete(prompt, system="You are a defensive cybersecurity AI analyst.") if self.provider else None

    def _parse_llm(self, text: str, f: dict) -> AiVerdict:
        text = text.strip()
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                data = json.loads(m.group(0))
                return AiVerdict(
                    analysis=data.get("analysis", ""),
                    why_it_matters=data.get("why_it_matters", ""),
                    potential_impact=data.get("potential_impact", {}),
                    predicted_risk=data.get("predicted_risk", ""),
                    confidence=data.get("confidence", ""),
                    is_ai_generated=True,
                )
            except json.JSONDecodeError:
                pass
        return AiVerdict(
            analysis=text[:1000], why_it_matters="See AI analysis below.",
            predicted_risk="", is_ai_generated=True)

    def _mock_analysis(self, f: dict) -> AiVerdict:
        impact = {
            "confidentiality": self._mock_impact(f, "confidentiality"),
            "integrity": self._mock_impact(f, "integrity"),
            "availability": self._mock_impact(f, "availability"),
            "compliance": self._mock_compliance(f),
            "business": self._mock_business(f),
        }
        pred = self._predict_risk(f)
        return AiVerdict(
            analysis=(
                f"{f.get('title','This finding')} affects category "
                f"{f.get('category','unknown')} (severity {f.get('severity','medium')}). "
                f"CVSS {f.get('cvss_score',0)}, KEV={bool(f.get('is_kev'))}, "
                f"internet_exposed={bool(f.get('internet_exposed'))}, "
                f"asset criticality {f.get('asset_criticality','medium')}."
            ),
            why_it_matters=self._mock_why(f),
            potential_impact=impact,
            predicted_risk=pred,
            confidence="30-40% (rule-based fallback)",
            evidence_basis=self._evidence_basis(f),
            is_ai_generated=True,
        )

    def _fallback_analysis(self, f: dict) -> AiVerdict:
        # Mirror mock (deterministic) so the platform is always functional
        return self._mock_analysis(f)

    def _predict_risk(self, f: dict) -> str:
        score = float(f.get("cvss_score", 0) or 0)
        if f.get("is_kev") or f.get("internet_exposed") and f.get("asset_criticality") in ("critical", "high"):
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        return "low"

    def _mock_impact(self, f: dict, dim: str) -> str:
        sev = f.get("severity", "medium")
        mapping = {
            "confidentiality": {"critical": "Unauthorized disclosure of sensitive/system data.",
                                "high": "Potential confidential data exposure.",
                                "medium": "Possible limited information disclosure.",
                                "low": "Minimal confidentiality impact."},
            "integrity": {"critical": "Potential unauthorized modification of data/config.",
                          "high": "Wider integrity risk to affected component.",
                          "medium": "Limited integrity impact.",
                          "low": "Negligible integrity impact."},
            "availability": {"critical": "Redundancy/resource exhaustion may cause downtime.",
                             "high": "Potential service degradation.",
                             "medium": "Partial availability impact.",
                             "low": "Minimal availability impact."},
        }
        return mapping.get(dim, {}).get(sev, "Depends on context.")

    def _mock_compliance(self, f: dict) -> str:
        sev = f.get("severity", "medium")
        if sev in ("critical", "high"):
            return "Likely relevant to security/audit standards (NIST CSF, ISO 27001, CIS)."
        return "May require review against applicable standards."

    def _mock_business(self, f: dict) -> str:
        return ("Requires CISO/team review to quantify financial/business impact; "
                "higher for internet-facing or critical assets.")

    def _mock_why(self, f: dict) -> str:
        return (
            "This weakness expands the attack surface and, if the asset is Internet-facing, "
            "can be exploited remotely. It also affects audit readiness and increases "
            "remediation pressure over time (aging)."
        )

    def _evidence_basis(self, f: dict) -> list[str]:
        basis = [f"category={f.get('category')}", f"severity={f.get('severity')}",
                 f"cvss={f.get('cvss_score')}"]
        if f.get("is_kev"):
            basis.append("listed in CISA KEV")
        if f.get("internet_exposed"):
            basis.append("internet-facing")
        return basis

    # ─── Advisor chat (require. #35) ───────────────────────────────────
    def advisor(self, question: str, context: dict[str, Any],
                data: dict[str, Any] | None = None) -> str:
        """Answer using platform scan data; never hallucinate."""
        if self.mocked or not self.active:
            return self._mock_advisor(question, context, data)
        prompt = (
            "You are the CyberShield Security Advisor. Answer using ONLY the provided "
            "cybersecurity scan data and context. Do not invent vulnerabilities, CVEs, "
            "assets or remediation. Clearly distinguish observed fact, scanner result, "
            "external intelligence and AI inference. If data is insufficient, say so.\n"
            f"CONTEXT: {json.dumps(context, default=str)[:4000]}\n"
            f"QUESTION: {question}"
        )
        resp = self.provider.complete(prompt, system="Defensive security advisor. Never speculate.")
        return resp or self._mock_advisor(question, context, data)

    def _mock_advisor(self, question: str, context: dict, data: dict | None) -> str:
        qlow = question.lower()
        if "fix first" in qlow or "priorit" in qlow:
            return _prioritize_answer(context.get("top_priorities") or [])
        if "internet" in qlow and "face" in qlow:
            return _list_internet(context.get("internet_facing") or [])
        if "exploit" in qlow or "active" in qlow:
            kev = context.get("kev_findings") or []
            if not kev:
                return "No actively exploited (CISA KEV) vulnerabilities detected in the current dataset."
            return f"{len(kev)} CISA KEV/actively-exploited finding(s): " + "; ".join(
                f"{k.get('finding_no')} {k.get('title')}" for k in kev[:10])
        if "overdue" in qlow:
            od = context.get("overdue") or []
            return f"{len(od)} overdue finding(s) requiring attention." if od else "No overdue findings."
        if "management" in qlow or "summary" in qlow:
            return _mock_summary(context)
        if "high risk" in qlow or "why" in qlow:
            return ("That asset carries high risk because of open internet-facing weaknesses, "
                    "high CVSS findings, KEV exposure, and/or aging vulnerabilities. Review the "
                    "finding detail for evidence.")
        return ("I can help interpret your scan data: ask about 'what to fix first', "
                "'internet-facing vulnerabilities', 'actively exploited', 'overdue', "
                "or 'management summary'.")


def _prioritize_answer(items: list) -> str:
    if not items:
        return "No prioritized items available from current scan data."
    out = "Top recommendation: " + items[0].get("title", "") if items else ""
    return "Prioritized by risk score: " + "\n".join(
        f"{i+1}. {it.get('title','')} (risk {it.get('risk_score','')})" for i, it in enumerate(items[:5]))


def _list_internet(items: list) -> str:
    if not items:
        return "No internet-facing vulnerability matches in the dataset."
    return f"{len(items)} internet-facing finding(s): " + "; ".join(
        f"{it.get('finding_no')} {it.get('title')}" for it in items[:10])


def _mock_summary(context: dict) -> str:
    sev = context.get("severity_counts") or {}
    return (
        f"Security summary: {sev.get('critical',0)} critical, {sev.get('high',0)} high, "
        f"{sev.get('medium',0)} medium, {sev.get('low',0)} low open findings. "
        "Guidance: remediate internet-facing and KEV findings first, then high/CVSS items; "
        "track against SLA to reduce overall risk."
    )
