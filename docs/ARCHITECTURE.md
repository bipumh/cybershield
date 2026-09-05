# Architecture — CyberShield Vulnerability Assessment & Exposure Management

## 1. System overview

CyberShield is a modular, async, multi-tenant vulnerability & exposure
management platform. It is designed to be **hosting-agnostic** (local VM →
Docker → Kubernetes/OpenShift → cloud) purely via environment configuration.

```
 Frontend (React + TS + Vite)
             │  REST (JSON)
             ▼
        API Gateway / FastAPI (app.main:app)
             │  Auth (JWT OAuth2/OIDC-ready) + RBAC
             ▼
      ┌─────────────┬───────────────┬──────────────┐
      │ Asset Mgmt  │ Scan          │ Audit        │
      │ (inventory) │ (orchestrator│ (tamper-evident │
      │             │  + scheduler)│   hash chain) │
      └──────┬──────┴──────┬───────┴──────┬───────┘
             ▼             ▼              ▼
   Scanner Workers   Intelligence       Risk Engine
   (plugins: web,    (CVSS/CVE/CWE/   (0-100 bands)
    network, server)  KEV connectors)
             │
             ▼
   AI Security Analyst  →  Remediation Engine  →  Reporting
   (LLM abstraction)       (approval workflow)     (PDF/CSV/JSON/XLSX/HTML)
             │
             ▼
   Compliance mappings + SIEM/SOC integration events
```

## 2. Module breakdown

| Module | Path | Responsibility |
|---|---|---|
| Core | `app/core/` | Config (env), security (bcrypt/JWT), logging, error envelope, deps, constants |
| Database | `app/db/` | SQLAlchemy base (naming conventions), session, ORM models, Alembic migrations |
| Schemas | `app/schemas/` | Pydantic request/response models |
| API | `app/api/v1/` | REST routers: auth, users, assets, scans, findings, remediations, reports, dashboard, scheduler, audit, admin, ai, compliance |
| Services | `app/services/` | Business logic: scan_service, finding_service, asset_service, remediation_service, reporting_service, audit_service, rbac_service, scheduler_service, dashboard_service, bootstrap |
| Scanners | `app/scanners/` | Plugin framework + web/network/server scanners + safety guard |
| Engines | `app/engines/` | intelligence (CVSS/CVE/CWE/KEV), risk, posture, remediation, AI, compliance, reporting |
| Workers | `app/workers/` | Async scan run, job queue, scheduler |

## 3. Key flows

### 3.1 Scan workflow (#40)

1. User selects scanner (Domain/Web or Infrastructure)
2. Enters target(s)
3. System validates target (`target_service.parse_target`)
4. System checks authorization/scope (allow/deny lists; safety confirmation)
5. System discovers assets (subdomain discovery for domains)
6. System displays discovered assets (status: discovered/confirmed/responsive)
7. User approves scope
8. User selects scan profile (passive/safe/standard/enterprise)
9. Safety validation (`ScanSafetyGuard` — rate limits, timeouts, max concurrency)
10. Scan begins (async via queue)
11. Progress displayed (`progress`, `total_steps`)
12. Findings normalized (`NormalizedFinding`)
13. Intelligence enrichment (CVSS/CVE/CWE/KEV)
14. Risk calculation (`risk_engine.compute_risk_score`)
15. AI analysis (`AiEngine.analyze_finding`)
16. Remediation recommendations (`remediation_engine.build_remediation_plan`)
17. Optional remediation approval
18. Verification scan
19. Report generation (`reporting_engine`)
20. Dashboard updated

### 3.2 Finding pipeline

`ScannerOutput.normalized` → `FindingService.persist_scan_findings` →
per finding: enrich(intel) → risk score → remediation plan → standards mapping →
AI analysis → persist `Finding` → lifecycle `FindingChange`.

### 3.3 Remediation workflow (#14)

Finding → Recommendation → Risk Review → Approval → Execution → Verification →
Closure. Levels:
- **Level 1 Safe-Automatic**: ticket/notify/status/config recommendation.
- **Level 2 Approval-Required**: changes with blast radius (service disable,
  firewall rule, config). Requires approver.
- **Level 3 Manual**: OS/firmware upgrade, DB/production changes — never
  auto-executed; privileged admin acts, platform tracks & verifies.

## 4. Async & scalability

- Scans run on a **thread-pool** backend (`workers.queue`) so the web app is
  never blocked and the platform is horizontally scalable (multiple workers).
- `ScanStatus`, `progress`, `cancelled` give live state; cancellation is checked
  between steps.
- Production: swap `queue.schedule` for Celery/Redis; workers remain the same
  (`run_scan`).

## 5. Multi-tenancy (#22)

Every tenant-scoped row carries `tenant_id`. Access layers filter by the
requesting user's `tenant_id` in every query; super-admin is the only escape
hatch. Tenant isolation is enforced at the service/query layer and data model.

## 6. Security architecture

- RBAC roles (Super Admin, CISO, Security Analyst, SOC Analyst, Network Admin,
  System Admin, AppSec Analyst, Remediation Engineer, Auditor, Management).
- JWT access/refresh tokens; bcrypt password hashing; MFA-ready (`otp_secret`).
- Tamper-evident audit chain (`prev_hash`, `record_hash`).
- Security headers middleware, CORS allow-list, request-id, client IP capture.
- Credentials never stored plaintext; secrets management (`auth_ref` to vault);
  never logged (redacting filter).
- SIEM/SOC integration-ready events (scan started/completed, critical vuln
  detected, new internet-facing asset, status changed, remediation executed).
