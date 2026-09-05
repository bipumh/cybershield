# CyberShield — Vulnerability Assessment & Exposure Management Platform

An **enterprise, defensive** vulnerability and exposure management platform. It
performs authorized discovery, security assessment, risk scoring, AI-driven
analysis, remediation workflow and executive/technical reporting across
domains, web applications, servers, endpoints and network devices.

> **Defensive only.** CyberShield assesses **assets you own or are explicitly
> authorized to test**. It contains **no** exploitation, DoS, ransomware,
> persistence, credential theft, privilege escalation or malware capabilities.
> Every active scan is wrapped in configurable safety controls (authorization,
> scope, rate limiting, timeouts, cancellation).

---

## Highlights

- **Two scan modes** — Domain / Web App Security, and Infrastructure / Endpoint /
  Network Security.
- **Plugin scanner framework** — web, network and server scanners register
  themselves; new scanners drop in without touching the core.
- **Normalized findings** — CVSS/CVE/CWE/KCV/CISA-KEV, evidence, risk score,
  remediation plan and standards mapping.
- **Risk engine** — configurable 0–100 scoring with critical/high/medium/low
  bands.
- **AI Security Analyst + CyberShield Security Advisor** — provider-independent
  LLM abstraction, grounded on platform data, predictions clearly labelled
  *AI-generated*.
- **Remediation workflow** — Finding → Recommendation → Risk Review → Approval →
  Execution → Verification → Closure, with safe automation levels (L1 auto /
  L2 approval / L3 manual).
- **Reporting** — Executive, Technical and Compliance reports in PDF, HTML,
  CSV, JSON and Excel.
- **Enterprise features** — RBAC, multi-tenant isolation, tamper-evident audit
  chain, schedulers, SLA tracking, SIEM/SOC integration readiness, REST API.

## Technology stack

| Layer | Choice |
|---|---|
| Backend | Python 3.12 · FastAPI · SQLAlchemy 2 · Alembic |
| Database | SQLite (dev) / PostgreSQL (prod) — swappable via `DATABASE_URL` |
| Queue/workers | In-process thread pool (default) — Celery/Redis hotspot |
| Frontend | React + TypeScript + Vite |
| Auth | OAuth2/OIDC-ready JWT (bcrypt, MFA-ready) |
| AI | Provider-independent LLM abstraction (mock/OpenAI/Anthropic) |
| Deploy | Docker, docker-compose, OpenShift/K8s template |

## Quick start (local dev)

Requires **Python 3.12** and **Node 20+**.

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python -m alembic upgrade head        # create schema
.\.venv\Scripts\python -m uvicorn app.main:app --reload --port 8000
```

API + interactive docs: `http://localhost:8000/docs`. Default bootstrap login:

```
email:    admin@cybershieldplatform.com
password: ChangeThis!Now12345
```

Seed demo data (assets + sample findings + a few public CVEs/KEV):

```powershell
.\.venv\Scripts\python scripts\seed_demo.py
```

Frontend (optional):

```powershell
cd ..\frontend
npm install
npm run dev
```

Now go to **Dashboard** and start a scan (**Domain/Web** or **Infrastructure**).

## Project structure

```
backend/
  app/
    core/        config, security, logging, errors, deps, constants
    db/          session, ORM models, Alembic migrations
    schemas/     Pydantic request/response
    api/v1/      REST routers
    services/    business logic (scan, finding, asset, remediation, audit)
    scanners/    plugin framework (web/ network/ server/)
    engines/     intelligence, risk, posture, remediation, AI, compliance, reporting
    workers/     async scan orchestrator, queue, scheduler
  scripts/       seed_demo.py, run.py
  tests/         unit/integration + smoke_scan.py
frontend/        React + TS enterprise UI
infrastructure/  docker-compose, K8s/OpenShift template
docs/            architecture, API, database, security, deployment, guides
```

## Documentation

- [ARCHITECTURE.md](docs/ARCHITECTURE.md) — modules, flows, deployment
- [API.md](docs/API.md) — REST API specification
- [DATABASE.md](docs/DATABASE.md) — schema, ERD, data dictionary
- [SECURITY.md](docs/SECURITY.md) — security model & guardrails
- [DEPLOYMENT.md](docs/DEPLOYMENT.md) — Docker / OpenShift deployment
- [SCANNER_DEVELOPMENT.md](docs/SCANNER_DEVELOPMENT.md) — write a scanner plugin
- [REMEDIATION.md](docs/REMEDIATION.md) — remediation workflow
- [ADMIN_GUIDE.md](docs/ADMIN_GUIDE.md) / [USER_GUIDE.md](docs/USER_GUIDE.md)
- [UI_STRUCTURE.md](docs/UI_STRUCTURE.md) — frontend structure & pages

## Portability (change hosting easily)

The platform is fully environment-driven. To move deployments (local → Docker →
OpenShift / Kubernetes → cloud) you only change environment variables:

- `DATABASE_URL` — SQLite → PostgreSQL
- `SECRET_KEY`, `CORS_ORIGINS` — per environment
- `AI_PROVIDER` / `AI_API_KEY` / `AI_MODEL` — per AI backend
- Backend/Frontend image names in the K8s/OpenShift template

See [DEPLOYMENT.md](docs/DEPLOYMENT.md).

## License & scope

Provided for authorized security assessments. Use only on systems you own or
hold written permission to assess. See [SECURITY.md](docs/SECURITY.md).
