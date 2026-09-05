# Writing a Scanner Plugin

Scanners self-register; the core platform never needs modification to add new
capabilities (requirements #25, #44).

## Contract (`app/scanners/base.py`)

Every scanner subclasses `BaseScanner` and implements:

```python
class BaseScanner:
    name: str          # e.g. "web.headers"
    kind: str          # web | network | server | ...
    def initialize(self): ...
    def validate_scope(self, ctx: ScanContext) -> bool: ...
    def scan(self, ctx: ScanContext) -> ScannerOutput: ...   # REQUIRED
    def cleanup(self): ...
```

`ScanContext` provides: `host`, `target`, `asset_id`, `asset_criticality`,
`asset_type`, `internet_exposed`, `profile`, `rate_limit`, `timeout`, `extra`
(contains the sanctioned `guard`, and for URL scans full `url`/`port`).

## Emitting findings

Return `ScannerOutput` with `normalized` = list of `NormalizedFinding`. Fields:
`title`, `description`, `category`, `severity`, `cvss_score`, `cve`, `cwe`,
`evidence`, `affected_component`, `detected_version`, `fixed_version`,
`exploitability`, `remediation` (dict), `remediation_level`, `standards` (dict),
`references` (list).

Example:

```python
from app.scanners.base import BaseScanner, NormalizedFinding, ScanContext, ScannerOutput
from app.scanners.registry import register_scanner

@register_scanner
class MyScanner(BaseScanner):
    name = "web.example_check"
    kind = "web"
    def scan(self, ctx: ScanContext) -> ScannerOutput:
        guard = ctx.extra["guard"]           # enforce rate limits
        out = ScannerOutput(checks_run=1)
        if _problem_detected():
            out.normalized.append(NormalizedFinding(
                title="Example weakness",
                description="...",
                category="security_misconfiguration",
                severity="medium", cvss_score=5.0, cwe="CWE-693",
                evidence="What you observed",
                remediation={"immediate_action": "Fix it now."},
                remediation_level="level2_approval_required",
                standards={"owasp_top10": "A05:2021"},
            ))
        return out
```

## Registration

- Put the file under `app/scanners/<kind>/`.
- Import it in the kind package `__init__.py` so the decorator runs.
- Optionally add its `name` to `workers/orchestrator._MODE_SCANNERS` to auto-run
  in a mode.

## Safety rules for scanner authors

- Always use `ctx.extra["guard"]` (`guard.throttle()`) before network calls.
- Never attempt exploitation, auth bypass, brute force, destructive or DoS
  actions (`guard.assert_not_destructive(action)`).
- Never claim a vulnerability without evidence; set `evidence` and keep
  severity proportionate.
- Bound all scans (timeout, limited ports/paths, no full 1-65535 sweeps).
