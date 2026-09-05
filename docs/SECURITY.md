# Security Model & Guardrails

CyberShield is itself a security product. This document describes both (a) the
platform's **security controls** and (b) its **defensive scanning guardrails**.

## 1. Defensive mandate (#46)

The platform **must not** enable disruptive activity. It contains no
exploitation, DoS/load testing, ransomware, persistence, credential theft,
brute force, malware, privilege escalation or stealth/evasion capability —
enforced in code, not just docs.

**Hard blocklist** (`ScanSafetyGuard.assert_not_destructive`) rejects any
action containing: exploit, ransom, persistence, credential-dump, bruteforce,
sqlmap, metasploit --exploit, dos/ddos, malware, backdoor, shell, reverse (shell).

## 2. Scan safety controls (#15, #46)

- **Authorization confirmation** required before every active scan — body
  `safety.scope_confirmed` and `safety.safety_confirmed` must be `true`
  (`ScanSafetyError` otherwise).
- **Scope**: allow/deny lists (`excluded_ips`, `excluded_domains`); targets
  outside scope are rejected (`ScopeViolationError`).
- **Rate limiting**: token-bucket per request; caps enforced at
  `min(requested, global*2, profile_cap)`.
- **Timeouts**: bounded (default 15s, max 120s).
- **Concurrency**: bounded (max `settings.scan_max_concurrency`).
- **Max active scans**: bounded (`scan_max_active_scans`).
- **Cancellation**: cooperative check between steps; emergency cancel via API.
- **CIDR/range**: expansion capped at 256 hosts; prefix length floor `/8`.

## 3. Web-app security (#37)

- **Auth**: bcrypt (cost 12), JWT access/refresh, MFA-ready (`otp_secret`).
- **RBAC**: role catalog + permission strings; `*` = super-permission.
- **Headers middleware**: `X-Content-Type-Options`, `X-Frame-Options: DENY`,
  `Referrer-Policy`, `Permissions-Policy`, `COOP`; HSTS in production.
- **CORS**: allow-list from config.
- **Validation**: Pydantic v2; max lengths, allowed enumerations, target
  validation.
- **CSRF**: token/SameSite guidance for assessed apps; API uses bearer tokens.
- **Output encoding / XSS**: JSON responses; React escapes rendered content.
- **Secrets**: no plaintext storage; `auth_ref` references vault integrations;
  logging `RedactingFilter` strips credentials; audit `_redact` strips secrets.
- **Rate limiting**: login limiter (in-memory; Redis in prod).

## 4. Data protection (#23)

- Passwords: bcrypt hashed.
- Credentials for authenticated scanning: prefer SSH keys / API tokens /
  SNMPv3 / IAM roles / vault references; never plaintext, never in logs,
  reports, browser responses, errors or AI prompts.

## 5. Audit (#38)

- Every significant action recorded in `audit_logs` with actor, action,
  target, source IP, timestamp, result, previous/new state.
- **Hash chain** (`prev_hash` + `record_hash`) makes silent tampering
  detectable (`/audit/verify-chain`).
- Audit access gated by `audit:read`.

## 6. Multi-tenant isolation (#22)

All tenant-scoped queries filter by `tenant_id`. No cross-tenant access to
assets, findings, reports, credentials, scan data or audit logs.

## 7. Responsibility disclaimer

CyberShield performs **authorized, non-destructive** assessments only. Users
are responsible for obtaining written authorization before scanning any
system. Use test fixtures such as OWASP Juice Shop, DVWA, WebGoat or
Metasploitable in an **isolated lab** for evaluation.
