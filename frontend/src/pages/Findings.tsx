import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { Finding } from "../api/types";
import { Empty, Panel, SevBadge, Spinner } from "../components/ui";

export default function Findings() {
  const [items, setItems] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [isKev, setIsKev] = useState("");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);

  const load = () => {
    setLoading(true);
    api.get("/findings", { params: { severity: severity || undefined, status: status || undefined, is_kev: isKev === "" ? undefined : isKev === "1", search: search || undefined, page, page_size: 20, sort_by: "risk_score", sort_desc: true } })
      .then((r) => { setItems(r.data.items); setTotal(r.data.total); })
      .finally(() => setLoading(false));
  };
  useEffect(load, [page]);

  return (
    <div>
      <div className="filters">
        <select value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }} style={{ maxWidth: 140 }}>
          <option value="">All severity</option>
          <option value="critical">Critical</option><option value="high">High</option>
          <option value="medium">Medium</option><option value="low">Low</option>
        </select>
        <select value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }} style={{ maxWidth: 180 }}>
          <option value="">All status</option>
          <option value="open">Open</option><option value="investigating">Investigating</option>
          <option value="remediation_planned">Planned</option><option value="remediation_in_progress">In progress</option>
          <option value="resolved">Resolved</option><option value="verified">Verified</option>
          <option value="closed">Closed</option><option value="accepted_risk">Accepted Risk</option>
          <option value="false_positive">False Positive</option>
        </select>
        <select value={isKev} onChange={(e) => { setIsKev(e.target.value); setPage(1); }} style={{ maxWidth: 160 }}>
          <option value="">CISA KEV: any</option><option value="1">KEV only</option>
        </select>
        <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search title / ID" style={{ maxWidth: 220 }} />
        <button className="btn sm" onClick={() => { setPage(1); load(); }}>Filter</button>
        <div className="spacer" />
        <span className="small muted">{total} findings</span>
      </div>

      {loading ? <Spinner /> : items.length === 0 ? (
        <Empty text="No findings match the filters." />
      ) : (
        <Panel>
          <table>
            <thead>
              <tr><th>ID</th><th>Severity</th><th>Finding</th><th>Category</th><th>CVSS</th><th>KEV</th><th>Risk</th><th>Status</th><th>Age (d)</th></tr>
            </thead>
            <tbody>
              {items.map((f) => (
                <tr key={f.id}>
                  <td><Link to={`/findings/${f.id}`}><b>{f.finding_no}</b></Link></td>
                  <td><SevBadge sev={f.severity} /></td>
                  <td style={{ maxWidth: 320 }}>{f.title}</td>
                  <td className="small muted">{f.category}</td>
                  <td>{f.cvss_score.toFixed(1)}</td>
                  <td>{f.is_kev ? "⚑ KEV" : ""}</td>
                  <td><b>{Math.round(f.risk_score)}</b> <span className="small muted">{f.risk_band}</span></td>
                  <td><span className="small">{f.status.replace(/_/g, " ")}</span></td>
                  <td>{f.age_days}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="pagination">
            <button className="link" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>‹ Prev</button>
            <span>Page {page}</span>
            <button className="link" disabled={page * 20 >= total} onClick={() => setPage((p) => p + 1)}>Next ›</button>
          </div>
        </Panel>
      )}
    </div>
  );
}
