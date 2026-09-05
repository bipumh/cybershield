---
name: cybershield
description: Use when working on the CyberShield vulnerability-assessment platform (Python/FastAPI backend, React+TS frontend, scanners, engines, RBAC, OpenShip deploys). Covers fresh-machine setup, running the API & UI, running tests, architecture conventions, and deploying via OpenShip (folder-upload MCP, server ARL-243) and GitHub Pages. Trigger on keywords: cybershield, backend, scanner, vulnerability, fastapi, run server, alembic, deploy openship, github pages, seed demo.
---

# CyberShield — Vulnerability Assessment & Exposure Management Platform

Enterprise, **defensive** vulnerability & exposure management. FastAPI backend + React/TS frontend. SQLite (dev) / PostgreSQL (prod) via `DATABASE_URL`. Deployed to OpenShip on server **ARL-243**; UI hosted on GitHub Pages.

## Environment prerequisites (fresh machine)
- **Python 3.12** (must be real python, not the MS Store stub; install with `winget install --id Python.Python.3.12 -e --scope user`)
- **Node 20+** (npm)
- Optional: Docker, git

> Windows/PowerShell gotchas:
> - `npm.ps1` is blocked by the execution policy → always call `npm.cmd` (e.g. `& "C:\Program Files\nodejs\npm.cmd" install`).
> - The user-level python lives at `%LOCALAPPDATA%\Programs\Python\Python312\python.exe`; the project venv is `backend\.venv`.

## Fresh-machine setup (in order)
```powershell
# 1. clone
git clone https://github.com/bipumh/cybershield.git
cd cybershield

# 2. backend
cd backend
<python312>\python.exe -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe scripts\seed_demo.py   # demo assets + findings + a few CVEs/KEV

# 3. frontend
cd ..\frontend
& "C:\Program Files\nodejs\npm.cmd" install
& "C:\Program Files\nodejs\npm.cmd" run dev
```

## Run
- Backend: `cd backend; .\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000` (+ optionally `--host 0.0.0.0`)
- Frontend dev: `cd frontend; npm.cmd run dev` (Vite on :5173, proxies `/api` → :8000)
- Bootstrap login: `admin@cybershieldplatform.com` / `ChangeThis!Now12345` (from `ADMIN_EMAIL`/`ADMIN_PASSWORD`; change in production)
- Docs: `http://localhost:8000/docs`

## Tests
```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest            # 18 unit + API integration tests
.\.venv\Scripts\python.exe tests\smoke_scan.py  # end-to-end web scan against a local target
```
`tests/conftest.py` uses an isolated temp SQLite DB automatically.

## Architecture & conventions
- **Backend** (`backend/app/`):
  - `core/` — config (pydantic-settings), security (bcrypt + JWT), logging (JSON), deps (RBAC/tenant), constants, exceptions
  - `db/` — SQLAlchemy base/session + ORM models + Alembic migrations (portable SQLite↔PostgreSQL, no code change)
  - `schemas/` — Pydantic request/response
  - `api/v1/` — routers: auth, users, assets, scans, findings, remediations, reports, dashboard, scheduler, audit, admin, ai, compliance
  - `services/` — business logic (scan, finding, asset, remediation, reporting, audit, rbac, scheduler, dashboard, bootstrap)
  - `scanners/` — plugin framework (`BaseScanner`, `ScanContext`, `NormalizedFinding`) + `web/`, `network/`, `server/` + `safety.py` (ScanSafetyGuard: rate limit, timeout, scope, destructive-action blocklist)
  - `engines/` — intelligence (CVSS/CVE/CWE/KEV), risk (0-100 bands), posture, remediation, AI (LLM abstraction), compliance, reporting (PDF/CSV/JSON/XLSX/HTML)
  - `workers/` — async scan orchestrator, queue (thread pool; swap for Celery in prod), scheduler
- **Multi-tenant**: every tenant-scoped row carries `tenant_id`; queries filter by it.
- **RBAC**: roles in `core/constants.py` (super_admin, ciso, security_analyst, soc_analyst, network_admin, system_admin, app_security_analyst, remediation_engineer, auditor, management) with permission strings.
- **Defensive only**: no exploitation/DoS/credential-theft. `ScanSafetyGuard.assert_not_destructive()` blocks unsafe actions.
- **Never claim a finding without evidence**; AI output is labelled "AI-generated".

## Produce security findings / scanners
Add a scanner under `app/scanners/<kind>/`, import it in the package `__init__.py`, and (optionally) register its `name` in `workers/orchestrator._MODE_SCANNERS`. Use `ctx.extra["guard"]` (`guard.throttle()`) before any network call. Always set `evidence` on a `NormalizedFinding`.

## Deploy — OpenShip (folder-upload MCP flow)
OpenShip MCP base: `https://deploy.ibos.io/api/proxy/api/mcp` (Authorization: Bearer `<OPENSIP_PAT>`). Target server: **ARL-243** = `7b24d18f-2219-4be3-a9c4-823aea401859`. Project `proj_YyUwgAmPeedTATnt` (docker-compose, services: db/redis/backend/frontend).
Sequence:
1. Pack an **excluded tarball**: `tar -czf out.tar.gz --exclude "*/.venv" --exclude "*/node_modules" --exclude "*/dist" --exclude "*/.git" --exclude "*/*.db" --exclude "*.db" --exclude ".env*" --exclude "logs" ... -C "D:\LOCAL DATA BASE\VA" .` — **use wildcard `*/` excludes** (bare `--exclude "backend/.venv"` does NOT match `./backend/.venv` and bloats the tar; keep it ~180 KB).
2. JSON-RPC `tools/call` to `post_projects_folder_session` (args `{name:"cybershield"}`) → get `sessionId` + `upload.x-upload-ticket`.
3. Upload the tar via raw HTTP POST to `upload.absoluteUrl` with headers: `Authorization: Bearer <PAT>`, `x-upload-ticket: <ticket>`, `Content-Type: application/gzip`.
4. `post_projects_folder_scan_by_sessionId` (args `{sessionId}`) → detects docker-compose + services.
5. `post_projects_ensure` (args `{body:{projectId, name, slug, gitProvider:"upload", framework:"docker-compose", projectType:"services", packageManager:"npm", uploadSessionId, services:[...]}}`). NOTE: masked `••••` env values mean "keep existing" — to change env (e.g. `CORS_ORIGINS`) pass the **real value**, not `\u2022…`.
6. Re-apply frontend exposure if the ensure reset it: `patch_projects_by_id_services_by_serviceId` (body `{exposed:true, exposedPort:"80", domain:"cybershield.opsh.io", domainType:"free", publicEndpoints:[{port:80,...}]}`); `exposedPort` must be a **string**.
7. `post_deployments_build_access` (args `{body:{projectId, uploadSessionId, deployTarget:"server", serverId:"7b24d18f-…", buildStrategy:"server"}}`) — **must pass `serverId` + `deployTarget:"server"`** or it deploys to the "local" sandbox (no Docker) and fails.
8. Poll `get_deployments_by_id` (status) / `get_projects_by_id_deployments` until `ready`; verify backend: `post_projects_by_id_services_by_serviceId_exec` → `python3 -c "...urlopen('http://127.0.0.1:8000/health')..."`.

Important: upload-source temp is cleaned up after build → a plain `post_deployments_by_id_redeploy` will fail ("upload temp gone"); re-run the folder-upload flow to redeploy.

## GitHub Pages (UI only, static)
- Build with subpath base + API base: `VITE_API_BASE=https://cybershield-opsh-io.opsh.io/api/v1; npm.cmd run build -- --base=/cybershield/`
- Push `dist/` to an **isolated** `gh-pages` branch from a **temp repo** (never `git rm -rf` + `add -A` in the main worktree — it deletes `.gitignore` and commits `node_modules`/`.venv`, bloating the branch). Force-push: `git -C <temp> push --force origin HEAD:gh-pages`. Add an empty `.nojekyll`.
- GitHub auto-publishes `gh-pages`; URL = `https://bipumh.github.io/cybershield/`.

## Known gotchas (hard-won)
- **`CORS_ORIGINS`**: typed `Annotated[List[str], NoDecode]` + a `mode="before"` validator that splits on commas. Without `NoDecode`, pydantic-settings tries to JSON-parse the comma string and crashes at import.
- **`psycopg`**: `requirements.txt` must include `psycopg[binary]` for `postgresql+psycopg://`.
- **GitHub PATs**: fine-grained tokens need **Repository access: All repositories** + **Administration: Read & write** to *create* repos, and **Contents: Read & write** to push. GitHub repo-creation API rejects restricted tokens with `403 Resource not accessible`.
- `openship-deploy.json` (contains OpenShip token + secrets) is gitignored — never commit it.
- Public/private toggle: `PATCH /repos/bipumh/cybershield` `{"visibility":"public"|"private"}`.

## Docs (in `docs/`)
ARCHITECTURE, API, DATABASE, SECURITY, DEPLOYMENT, SCANNER_DEVELOPMENT, REMEDIATION, ADMIN_GUIDE, USER_GUIDE, UI_STRUCTURE; README at repo root.
