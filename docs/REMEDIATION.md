# Remediation Engine & Approval Workflow

## Workflow (#14)

```
Finding → Recommendation → Risk Review → Approval → Execution → Verification → Closure
```

Each remediation records: requester, approver, timestamps, target asset,
proposed change, previous config, new config, backup status, execution status,
verification result, rollback option, audit log.

## Safe automation levels (#13)

| Level | Name | Auto? | Examples |
|---|---|---|---|
| L1 | Safe-Automatic | yes | create ticket, notify owner, update status, generate config/patch recommendation, collect verification |
| L2 | Approval-Required | after approval | disable service, change firewall rule, network config, apply baseline, change auth, restart service |
| L3 | Manual | **never** | OS/firmware upgrade, database/production changes, anything that may interrupt business |

`remediation_engine.classify_level` is conservative: destructive/blast-radius
changes default to L3; config/management issues default to L2. The platform
**never remotely mutates** target systems — it orchestrates approval, tracks
execution state (which a privileged admin performs), and verifies via a
re-scan, which is the safe/defensive model.

## API

`POST /remediations` (create) → `POST /remediations/{id}/submit` →
`POST /remediations/{id}/approve` (`approve`/`reject`) →
`POST /remediations/{id}/execute` (L2 only; L3 rejected) →
`POST /remediations/{id}/verify` → `POST /remediations/{id}/close`. Rollback:
`POST /remediations/{id}/rollback`.

## Verification

Re-run the corresponding scanner/check for the affected asset. If the finding no
longer appears, mark Verified then Closed; the vulnerability lifecycle is
updated (Fixed / Closed).
