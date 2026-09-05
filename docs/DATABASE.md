# Database — Schema & ERD

Portable across **SQLite (dev)** and **PostgreSQL (prod)** with **no code
changes**. Migration system: **Alembic** (`backend/alembic`). All timestamps
are timezone-aware (UTC).

## ERD (logical)

```
organizations 1─* users | roles *─* users (user_roles)
organizations 1─* assets | assets *─* asset_groups (asset_group_members)
organizations 1─* domains 1─* subdomains
organizations 1─* scans 1─* scan_targets | scan_results | scan_schedules
findings ── asset_id → assets | scan_id → scans
findings ──* finding_changes
findings 1─* remediations 1─* remediation_approvals | approval_steps
findings 1─* exceptions
vulnerabilities (feed catalog) | cves | cisa_kev | threat_intelligence (feed)
organizations 1─* reports | integrations | notifications | audit_logs
```

## Tables

| Table | Purpose |
|---|---|
| `organizations` | Tenant/org boundary |
| `users`, `roles`, `user_roles` | Auth + RBAC |
| `assets` | Inventory (hosts, endpoints, devices, apps) |
| `asset_groups`, `asset_group_members` | Grouping |
| `domains`, `subdomains` | Discovery results + scope state |
| `scans`, `scan_targets`, `scan_results`, `scan_schedules` | Orchestration |
| `findings`, `finding_changes` | Normalized vulns + lifecycle deltas |
| `vulnerabilities`, `cves`, `cisa_kev`, `threat_intelligence` | Intelligence feed |
| `remediations`, `remediation_approvals`, `approval_steps` | Remediation workflow |
| `exceptions` | False-positive / accepted-risk / compensating control |
| `reports`, `compliance_mappings` | Reporting + standards mapping |
| `audit_logs` | Tamper-evident audit (hash chain) |
| `notifications`, `integrations` | Notification center + SIEM/SOC connectors |

## Core columns (abbreviated)

- **assets**: `asset_key` (unique), `hostname`, `ip_address`, `asset_type`,
  `os_name/version`, `vendor/model/firmware`, `criticality`,
  `is_internet_facing`, `risk_score`, `vulnerability_count`, `tenant_id`.
- **findings**: `finding_no` (VUL-000001), `title`, `category`, `severity`,
  `cvss_score`, `cvss_vector`, `cve`, `cwe`, `evidence`, `risk_score`,
  `risk_band`, `is_kev`, `status`, `remediation_level`, `remediation_json`,
  `standards_json`, `ai_analysis_json`, `first/last_detected_at`, `sla_due_at`,
  `last_change`, `is_suppressed`.
- **scans**: `scan_key`, `mode`, `profile`, `status`, `rate_limit`, `timeout`,
  `concurrency`, `progress`, `total_steps`, `safety_confirmed`, `cancelled`.
- **remediations**: `level` (L1/L2/L3), `status` (proposed…closed),
  `approver_id`, `approved_at`, `execution_status`, `verification_result`,
  `backup_status`, `audit_log_json`.
- **audit_logs**: `action`, `target_type/id`, `source_ip`, `result`,
  `previous_state`, `new_state`, `occurred_at`, `prev_hash`, `record_hash`.

## Conventions

- `idx_` / `uq_` / `fk_` / `pk_` naming via SQLAlchemy naming convention.
- Foreign keys, indexes on frequent filters, `deleted_at` soft-delete on
  `assets`.
- JSON/text blobs (`remediation_json`, `standards_json`, `ai_analysis_json`)
  keep the core relational and store structured sub-payloads.

## Migration workflow

```powershell
cd backend
.\.venv\Scripts\python -m alembic revision --autogenerate -m "describe change"
.\.venv\Scripts\python -m alembic upgrade head
```
