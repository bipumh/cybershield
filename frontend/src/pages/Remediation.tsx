import React, { useEffect, useState } from "react";
import { api, errText } from "../api/client";
import { Remediation } from "../api/types";
import { Empty, LevelBadge, Panel, Spinner, StatusBadge } from "../components/ui";

export default function RemediationPage() {
  const [items, setItems] = useState<Remediation[]>([]);
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState("");

  const load = () => api.get("/remediations", { params: { page_size: 100, status: status || undefined } }).then((r) => setItems(r.data.items)).finally(() => setLoading(false));
  useEffect(() => { load(); }, [status]);

  const act = async (id: number, action: string) => {
    try { await api.post(`/remediations/${id}/${action}`); load(); }
    catch (e) { alert(errText(e)); }
  };
  const decide = async (id: number, d: string) => {
    try { await api.post(`/remediations/${id}/approve`, { decision: d }); load(); }
    catch (e) { alert(errText(e)); }
  };

  return (
    <div>
      <div className="filters">
        <select value={status} onChange={(e) => setStatus(e.target.value)} style={{ maxWidth: 200 }}>
          <option value="">All statuses</option>
          {["proposed", "pending_approval", "approved", "rejected", "verification_pending", "verified", "executed", "closed", "rolled_back", "failed"].map((s) => (
            <option key={s} value={s}>{s.replace(/_/g, " ")}</option>
          ))}
        </select>
        <div className="spacer" />
        <span className="small muted">Workflow: Plan → Approve → Execute → Verify → Close</span>
      </div>

      {loading ? <Spinner /> : items.length === 0 ? <Empty text="No remediations yet. Create one from a finding." /> : (
        <Panel>
          <table>
            <thead><tr><th>ID</th><th>Finding #</th><th>Title</th><th>Level</th><th>Status</th><th>Exec</th><th>Auto</th><th>Actions</th></tr></thead>
            <tbody>
              {items.map((r) => (
                <tr key={r.id}>
                  <td>{r.id}</td>
                  <td className="muted">{r.finding_id}</td>
                  <td style={{ maxWidth: 320 }}>{r.title}</td>
                  <td><LevelBadge level={r.level} /></td>
                  <td><StatusBadge status={r.status} /></td>
                  <td className="muted">{r.execution_status}</td>
                  <td>{r.auto_remediated ? "✓" : "—"}</td>
                  <td>
                    {r.status === "proposed" && <button className="btn sm" onClick={() => act(r.id, "submit")}>Submit</button>}
                    {r.status === "pending_approval" && (
                      <span style={{ display: "flex", gap: 6 }}>
                        <button className="btn sm" onClick={() => decide(r.id, "approve")}>Approve</button>
                        <button className="btn sm danger" onClick={() => decide(r.id, "reject")}>Reject</button>
                      </span>
                    )}
                    {r.status === "approved" && <button className="btn sm" onClick={() => act(r.id, "execute")}>Execute</button>}
                    {r.status === "verification_pending" && <button className="btn sm" onClick={() => act(r.id, "verify")}>Verify</button>}
                    {r.status === "verified" && <button className="btn sm ghost" onClick={() => act(r.id, "close")}>Close</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}
    </div>
  );
}
