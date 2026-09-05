import React, { ReactNode } from "react";

export function SevBadge({ sev }: { sev: string }) {
  const map: Record<string, string> = {
    critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info",
  };
  return (
    <span className={`badge ${sev}`}>
      <span className="dot" />
      {map[sev] || sev}
    </span>
  );
}

export function LevelBadge({ level }: { level: string }) {
  const label =
    level === "level1_safe_auto" ? "L1 Safe-Auto" :
    level === "level2_approval_required" ? "L2 Approval" : "L3 Manual";
  const cls = level === "level1_safe_auto" ? "low" : level === "level2_approval_required" ? "medium" : "critical";
  return <span className={`badge ${cls}`}>{label}</span>;
}

export function StatusBadge({ status }: { status: string }) {
  const active = ["open", "investigating", "remediation_in_progress", "remediation_planned", "accepted_risk"];
  const ok = ["resolved", "verified", "closed", "completed", "approved", "executed"];
  const cls = active.includes(status) ? "medium" : ok.includes(status) ? "low" : "info";
  const label = status.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
  return <span className={`badge ${cls}`}>{label}</span>;
}

export function Card({ label, value, sub }: { label: string; value: ReactNode; sub?: string }) {
  return (
    <div className="card">
      <div className="label">{label}</div>
      <div className="value">{value}</div>
      {sub && <div className="small muted mt" style={{ marginTop: 6 }}>{sub}</div>}
    </div>
  );
}

export function Panel({ title, children, right }: { title?: string; children: ReactNode; right?: ReactNode }) {
  return (
    <div className="panel">
      {(title || right) && (
        <div className="space-between" style={{ marginBottom: 14 }}>
          <h3 style={{ margin: 0, fontSize: 15, color: "#fff" }}>{title}</h3>
          {right}
        </div>
      )}
      {children}
    </div>
  );
}

export function KV({ k, v }: { k: string; v: ReactNode }) {
  return (
    <div className="kv">
      <span className="k">{k}</span>
      <span className="v">{v}</span>
    </div>
  );
}

export function Spinner({ text = "Loading…" }: { text?: string }) {
  return <div className="muted small" style={{ padding: 30, textAlign: "center" }}>{text}</div>;
}

export function Empty({ text = "No data to show." }: { text?: string }) {
  return <div className="muted small" style={{ padding: 40, textAlign: "center" }}>{text}</div>;
}
