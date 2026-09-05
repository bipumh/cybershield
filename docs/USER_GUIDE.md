# User Guide

## Start a Domain / Web App scan

1. Open **Domain Scanner**.
2. Enter a domain/URL/IP/web app/API endpoint (e.g. `example.com`).
3. The platform **discovers** subdomains (passive) and shows their state
   (discovered / confirmed / responsive / unresponsive). **Only assets in
   scope are added to scanning** — never automatically.
4. Approve discovered assets for scanning if you want them included.
5. **Select a scan profile**: Passive (no intrusive requests), Safe
   (low-impact), Standard (broader), Enterprise (strict rate limiting).
6. Confirm the **Scan Safety Policy** (authorization statement) and **scope**.
7. Start. Watch progress; you can **Cancel** anytime.

## Start an Infrastructure / Network scan

1. Open **Infrastructure Scanner**, choose asset type (Server, Workstation,
   Router, Switch, Firewall, Database Server, VM, Container host, IoT, etc.).
2. Enter IP / hostname / CIDR / range / CSV import.
   - CIDR/range expansion is **bounded (max 256 hosts)** and authorization +
     scope is required.
3. Pick a profile and confirm safety, then start.

## Review findings

- **Vulnerability Management** lists findings with filters (severity, CVE, CWE,
  CISA KEV, status, age, asset).
- Open a **Finding Detail** to see: evidence, CVSS/CWE, risk score & band, AI
  analysis (clearly labelled *AI-generated*), standards mapping, recommended
  solution, verification method, and references.
- Mark **False Positive / Accepted Risk / Compensating Control** with a reason,
  evidence and expiry. Approved exceptions suppress the finding and auto-expire
  for review.

## Remediate

- From the finding, create a **Remediation** plan. Review the **Safe
  Automation Level** (L1 auto / L2 approval / L3 manual).
- Submit for approval → CISO/approver approves → execute (L2) or a privileged
  admin applies manually (L3) → verification re-scan → verify → close. Rollback
  is available.

## Reports

**Reports → Generate** Executive (management), Technical (admin/SOC) or
Compliance. Download as PDF, HTML, CSV, JSON or Excel.

## Ask the Advisor

**Advisor** answers questions using **your actual scan data**, e.g.
"What should we fix first?", "Which vulnerabilities are internet-facing?",
"Which are actively exploited?", "Why is this server high risk?". AI
predictions are advisory and labelled.
