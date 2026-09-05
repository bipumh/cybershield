# Administrator Guide

## First login

Use the bootstrap super-admin (`ADMIN_EMAIL` / `ADMIN_PASSWORD`) and **change
the password immediately**. Create additional users and assign built-in roles
(Super Admin, CISO, Security Analyst, SOC Analyst, Network Admin, System Admin,
AppSec Analyst, Remediation Engineer, Auditor, Management).

## Roles & permissions

Roles are seeded automatically. Permissions are string identifiers
(e.g. `scans:create`, `remediation:approve`). Super Admin has `*`. Adjust roles
under **Administration → Users/Roles**.

## Configure scanning safety

In the backend `.env` / deployment:

- `SCAN_MAX_ACTIVE_SCANS` — cap concurrent scans.
- `SCAN_MAX_CONCURRENCY` — cap per-scan parallelism.
- `SCAN_GLOBAL_RATE_LIMIT`, `SCAN_DEFAULT_TIMEOUT`.
- `SCAN_ALLOW_INSECURE` — ONLY for lab use.
- Provide `excluded_ips` / `excluded_domains` per scan.

## Risk weighting

`GET/PUT /admin/risk-weights` (or **Administration → Risk Model**) to tune the
weighting of CVSS, exploitability, criticality, exposure, threat intel, age,
attack surface, auth and impact.

## Compliance mappings

`GET /admin/compliance-mappings` lists the curated, defensible standard→finding
mappings (OWASP, NIST CSF, CIS, ISO 27001). Only defensible mappings are
shipped; no compliance claim is fabricated.

## Intended SIEM/SOC

Register connectors under **Administration → Integrations** (kind: wazuh,
splunk, sentinel, elastic, syslog, webhook, api). Events include scan
started/completed, critical vuln detected, new internet-facing asset, status
changed, remediation executed/failed. Forward via webhook (`SIEM_WEBHOOK_URL`).

## Scheduled scans

**Administration / Scheduler**: create daily/weekly/monthly/custom schedules.
Schedules run only within authorized scope (they reuse the same safety checks).

## Observability

- `/health` liveness.
- Audit logs (`/audit`) with hash-chain verification (`/audit/verify-chain`).
- Human-readable errors; scanner/worker failures never crash the app.
