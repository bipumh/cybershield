"""Scanner contract + normalized finding model.

All scanners return normalized findings (never raw exploited data). The
NormalizedFinding is the single source of truth for DB persistence and is
enriched by the intelligence + risk engines downstream.
"""
from __future__ import annotations

import abc
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScannerCheck:
    """A single executed security check and its evidence."""
    check_id: str
    name: str
    passed: bool
    evidence: str = ""
    score: float = 0.0


@dataclass
class NormalizedFinding:
    """Standardized finding emitted by a scanner.

    Matches section #26 of the requirements (normalized finding schema).
    """
    title: str
    description: str = ""
    category: str = "security_misconfiguration"
    severity: str = "medium"
    cvss_score: float = 0.0
    cvss_vector: str | None = None
    cve: str | None = None
    cwe: str | None = None
    evidence: str = ""
    affected_component: str | None = None
    detected_version: str | None = None
    fixed_version: str | None = None
    exploitability: str = "none"
    remediation: dict[str, Any] = field(default_factory=dict)
    remediation_level: str = "level3_manual"
    standards: dict[str, Any] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanContext:
    """Per-target scan context with safety info for the worker."""
    asset_id: int | None = None
    target: str = ""
    host: str = ""
    asset_criticality: str = "medium"
    asset_type: str = "server"
    internet_exposed: bool = False
    profile: str = "safe"
    rate_limit: int = 20          # requests per second cap
    timeout: float = 15.0
    allow_insecure: bool = False
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScannerOutput:
    normalized: list[NormalizedFinding] = field(default_factory=list)
    checks_run: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class BaseScanner(abc.ABC):
    """Standardized scanner interface (requirement #25).

    Lifecycle: initialize -> validate_scope -> (discover) -> scan ->
    normalize_finding -> cleanup. Risk scoring (calculate_risk) and
    remediation generation (generate_remediation) are provided by the
    dedicated engines, but scanners may attach defaults.
    """

    name: str = "base"
    kind: str = "generic"   # web | network | server | ...
    available_profiles: tuple[str, ...] = ("passive", "safe", "standard", "enterprise")

    def initialize(self) -> None:
        self._start = time.monotonic()

    def cleanup(self) -> None:
        pass

    def validate_scope(self, ctx: ScanContext) -> bool:
        """Return True if the target is permitted for this profile.

        Custom scanners override; the safety guard also enforces global
        scope/rate-limit rules regardless of this method.
        """
        return True

    @abc.abstractmethod
    def scan(self, ctx: ScanContext) -> ScannerOutput:
        """Execute the scan and return normalized findings."""
        raise NotImplementedError

    def normalize_finding(self, raw: dict[str, Any]) -> NormalizedFinding:
        return NormalizedFinding(**{k: raw[k] for k in
                                   ("title", "description", "category", "severity",
                                    "cvss_score", "cve", "cwe", "evidence",
                                    "affected_component", "detected_version",
                                    "fixed_version", "exploitability",
                                    "remediation_level") if k in raw})

    def progress_format(self) -> tuple[int, int]:
        return (0, 0)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Scanner {self.name} ({self.kind})>"
