# REST API Specification

Base URL: `/api/v1`. Interactive docs at `/docs` (Swagger) and `/redoc`.

## Auth

| Method | Path | Desc | Permission |
|---|---|---|---|
| POST | `/auth/login` | OAuth2 password login → tokens | public |
| POST | `/auth/refresh` | Refresh access token | public (refresh token) |
| GET | `/auth/me` | Current user + roles/permissions | authenticated |
| POST | `/auth/logout` | Logout | authenticated |
| POST | `/users` | Create user (tenant) | super_admin |
| PATCH | `/users/{id}` | Update user/roles | super_admin |
| GET | `/users` | List users | authenticated |
| GET | `/users/roles` | Role/permission catalog | authenticated |

## Assets

| Method | Path | Desc | Permission |
|---|---|---|---|
| GET | `/assets` | List (filters: q, asset_type, criticality, internet_facing) | assets:read |
| POST | `/assets` | Register an asset | assets:modify |
| GET | `/assets/{id}` | Detail | assets:read |
| PATCH | `/assets/{id}` | Update | assets:modify |
| DELETE | `/assets/{id}` | Soft-delete | assets:modify |

## Scans

| Method | Path | Desc | Permission |
|---|---|---|---|
| POST | `/scans` | Create & start a scan | scans:create |
| GET | `/scans` | List scans | scans:read |
| GET | `/scans/{id}` | Detail | scans:read |
| GET | `/scans/{id}/status` | Live status/progress | scans:read |
| POST | `/scans/{id}/cancel` | Cancel a running scan | scans:read |
| GET | `/scans/{id}/results` | Per-asset results | scans:read |
| POST | `/scans/discover` | Passive subdomain discovery | scans:create |
| POST | `/scans/{id}/approve-assets` | Approve discovered assets for scanning | scans:approve |

**Create scan body** (`ScanCreate`):

```json
{
  "name": "Quarterly web scan",
  "mode": "web",
  "profile": "safe",
  "targets": [{"kind": "domain", "value": "example.com", "in_scope": true},
              {"kind": "url", "value": "https://example.com/app", "in_scope": true}],
  "rate_limit": 20, "timeout": 15, "concurrency": 2,
  "excluded_ips": [], "excluded_domains": [],
  "safety": {"scope_confirmed": true, "safety_confirmed": true,
             "authorization_statement": "I own / am authorized to test these targets"}
}
```

## Findings / Vulnerabilities

| Method | Path | Desc | Permission |
|---|---|---|---|
| GET | `/findings` | List (filters: severity, status, asset_id, cve, cwe, is_kev, risk_band, search, sort) | vulns:read |
| GET | `/findings/{id}` | Detail (evidence, remediation, standards, AI) | vulns:read |
| PATCH | `/findings/{id}` | Update status/severity | vulns:manage |
| GET | `/findings/compare/{prev}/{curr}` | Lifecycle diff (new/fixed/persistent/reopened) | vulns:read |
| POST | `/findings/{id}/exceptions` | False-positive / accepted-risk / compensating | exceptions:create |
| POST | `/findings/exceptions/{id}/approve` | Approve an exception | exceptions:approve |
| GET | `/findings/{id}/ai` | AI analysis for a finding | ai:read |

## Remediation

| Method | Path | Desc | Permission |
|---|---|---|---|
| GET | `/remediations` | List | remediation:read |
| POST | `/remediations` | Create plan for a finding | remediation:modify |
| GET | `/remediations/{id}` | Detail | remediation:read |
| POST | `/remediations/{id}/submit` | Submit for approval | remediation:modify |
| POST | `/remediations/{id}/approve` | Approve/reject | remediation:approve |
| POST | `/remediations/{id}/execute` | Execute approved | remediation:execute |
| POST | `/remediations/{id}/verify` | Mark verified | remediation:verify |
| POST | `/remediations/{id}/close` | Close | remediation:verify |
| POST | `/remediations/{id}/rollback` | Roll back | remediation:execute |

## Reports & Compliance

| Method | Path | Desc | Permission |
|---|---|---|---|
| POST | `/reports` | Generate (executive/technical/compliance; pdf/html/csv/json/xlsx) | reports:create |
| GET | `/reports` | List | reports:read |
| GET | `/reports/{id}/download` | Download file | reports:read |
| GET | `/compliance/coverage` | Standard coverage of findings | compliance:read |
| GET | `/threat-intelligence/kev` | CISA KEV catalog | vulns:read |
| GET | `/admin/compliance-mappings` | Mapping table | super_admin/auditor |

## Dashboard & SLA

| Method | Path | Desc | Permission |
|---|---|---|---|
| GET | `/dashboard/summary` | Executive summary | dashboard:read |
| GET | `/dashboard/posture` | Security posture 0–100 | dashboard:read |
| GET | `/dashboard/sla` | SLA breaches / MTTR | dashboard:read |
| GET | `/dashboard/top-priorities` | Top 10 things to fix now | dashboard:read |

## Scheduler, Audit, Admin, AI

| Method | Path | Desc | Permission |
|---|---|---|---|
| POST | `/schedules` | Create schedule (daily/weekly/monthly/custom/onetime) | scans:create |
| GET | `/schedules` | List | scans:read |
| PATCH | `/schedules/{id}` | Toggle | scans:create |
| GET | `/audit` | List audit logs | audit:read |
| GET | `/audit/verify-chain` | Verify hash chain integrity | audit:read |
| GET | `/admin/risk-weights` | Current risk weighting | risk:read |
| PUT | `/admin/risk-weights` | Update weighting | super_admin/ciso |
| GET/POST | `/admin/integrations` | SIEM/webhook connectors | super_admin |
| POST | `/ai/advisor` | Ask the Security Advisor (grounded on data) | ai:read |

## Error envelope

All errors return a consistent structure:

```json
{
  "ok": false,
  "error": {"code": "scan_safety", "message": "...", "context": {}}
}
```

Codes: `unauthorized`, `forbidden`, `not_found`, `validation_error`,
`conflict`, `scan_safety`, `scope_violation`, `scanner_error`,
`integrity_error`, `internal_error`.

## Pagination

List endpoints accept `page` (≥1) and `page_size` (1–200) and return
`items`, `total`, `page`, `page_size`, `pages`.
