# Deployment

CyberShield is environment-driven. Change hosting by changing configuration —
no code changes needed (SQLite↔PostgreSQL, Docker→OpenShift→K8s→cloud).

## Options

| Runtime | How |
|---|---|
| Local dev (bare) | Python + SQLite + Vite |
| Docker Compose | `docker compose up --build` (Postgres + Redis + backend + frontend + nginx) |
| Kubernetes / OpenShift | `infrastructure/openshift-deployment.yaml` (backend, frontend, Route) |
| Cloud / VM | Same images; point `DATABASE_URL` at managed Postgres |

## Environment variables

| Var | Purpose |
|---|---|
| `ENVIRONMENT` | `development` / `production` (enables HSTS) |
| `SECRET_KEY` | JWT signing key (use random 64 bytes in prod) |
| `DATABASE_URL` | `sqlite:///./cybershield.db` or `postgresql+psycopg://user:pass@host:5432/db` |
| `CORS_ORIGINS` | Comma-separated frontend origins |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | Bootstrap super-admin (first start) |
| `AI_PROVIDER` / `AI_MODEL` / `AI_API_KEY` / `AI_BASE_URL` | AI backend (`off`/`mocked`/`openai`/`anthropic`/`openai_compatible`) |
| `SCAN_ALLOW_INSECURE` | Allow insecure TLS **for lab only** (default `false`) |
| `SIEM_WEBHOOK_URL` / `TOKEN` | SIEM/webhook forwarding |
| `SCAN_MAX_ACTIVE_SCANS` / `SCAN_MAX_CONCURRENCY` | Scan safety caps |

## Docker Compose

```yaml
# docker-compose.yml (provided at repo root)
services:
  db:     postgres:16-alpine
  redis:  redis:7-alpine
  backend: build: ./backend, depends_on db/redis, env DATABASE_URL -> postgres
  frontend: build: ./frontend (nginx), proxies /api to backend
```

```powershell
docker compose up --build -d
# UI: http://localhost:8080   API: http://localhost:8000/docs
```

## OpenShift / Kubernetes

```bash
oc apply -f infrastructure/openshift-deployment.yaml -p SECRET_KEY=... \
  -p POSTGRES_PASSWORD=... -p BACKEND_IMAGE=... -p FRONTEND_IMAGE=...
```

The template defines a `Secret` (env-driven, no plaintext), backend/frontend
`Deployment`s, `Service`s and a TLS `Route`. Bring-your-own managed Postgres
by setting `POSTGRES_HOST`.

## Database migrations

Run migrations on startup / release (recommend an init job or entrypoint):
```bash
.\.venv\Scripts\python -m alembic upgrade head
```

## Backup / restore

- Postgres: `pg_dump` / `pg_restore`.
- Reports output volume (`reports/`) and `.env`/secrets should be backed up
  with your standard backup.

## Upgrade procedure

1. Backup DB and secrets.
2. `git pull`.
3. `alembic upgrade head`.
4. Rebuild images (`docker compose build`), restart.
5. Verify `/health` and `/docs`.
