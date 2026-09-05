# Frontend Structure — React + TypeScript

CyberShield provides a modern enterprise SOC-style UI (React + TS + Vite).
Dark/light mode, charts, severity indicators, search/filter/sort, pagination,
notifications.

## Routes / pages

| Route | Page |
|---|---|
| `/` | Executive Dashboard (summary, posture score, trends, top assets, KEV exposure) |
| `/assets` | Asset Inventory |
| `/scans` | Scans (create, list, detail, progress, cancel) |
| `/scans/domain` | Domain / Web Application Scanner |
| `/scans/infrastructure` | Infrastructure / Endpoint / Network Scanner |
| `/findings` | Vulnerability Management (filters: severity, CVE, CWE, KEV, status, age) |
| `/findings/:id` | Finding Detail (evidence, risk, AI, remediation, verification) |
| `/remediation` | Remediation (approval workflow) |
| `/reports` | Reports (generate/download PDF/CSV/JSON/XLSX) |
| `/compliance` | Compliance Coverage |
| `/scheduler` | Scan Scheduler |
| `/intelligence` | Threat Intelligence / KEV |
| `/integrations` | SIEM/SOC connector config |
| `/audit` | Audit Logs (hash-chain verified) |
| `/admin` | Administration (users, roles, mappings, risk weights) |
| `/advisor` | CyberShield Security Advisor chat |

## Structure

```
frontend/src/
  api/         typed API client (axios/fetch) + auth token handling
  components/  shared UI (tables, charts, severity badges, layout, theme)
  pages/       route components
  hooks/       data fetching, auth, theme
  router.tsx   route definitions
  main.tsx     entry
```

## Design notes

- Recharts/ECHarts for dashboards; React Router for navigation; TanStack Query
  for server state; a theme provider for dark/light mode.
- `VITE_API_BASE` env var points the client at the backend
  (`/api/v1` by default, overridable for OpenShift/cloud).
