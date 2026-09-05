import React, { useEffect, useState } from "react";
import { api, errText } from "../api/client";
import { Empty, Panel, Spinner } from "../components/ui";

interface Report { id: number; name: string; report_type: string; format: string; status: string; size_bytes: number; created_at: string; }

export default function Reports() {
  const [items, setItems] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState("Security Report");
  const [type, setType] = useState("executive");
  const [format, setFormat] = useState("pdf");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const load = () => api.get("/reports", { params: { page_size: 100 } }).then((r) => setItems(r.data.items)).finally(() => setLoading(false));
  useEffect(() => { load(); }, []);

  const generate = async () => {
    setBusy(true); setError("");
    try {
      await api.post("/reports", { name, report_type: type, format, scope: {} });
      load();
    } catch (e) { setError(errText(e)); } finally { setBusy(false); }
  };

  const download = (id: number) => window.open(`/api/v1/reports/${id}/download`, "_blank");

  return (
    <div>
      <Panel title="Generate a report">
        <div className="filters">
          <input value={name} onChange={(e) => setName(e.target.value)} style={{ maxWidth: 240 }} />
          <select value={type} onChange={(e) => setType(e.target.value)} style={{ maxWidth: 160 }}>
            <option value="executive">Executive</option>
            <option value="technical">Technical</option>
            <option value="compliance">Compliance</option>
          </select>
          <select value={format} onChange={(e) => setFormat(e.target.value)} style={{ maxWidth: 120 }}>
            {["pdf", "html", "csv", "json", "xlsx"].map((f) => <option key={f} value={f}>{f}</option>)}
          </select>
          <button className="btn" onClick={generate} disabled={busy}>{busy ? "Generating…" : "Generate"}</button>
        </div>
        {error && <div className="error">{error}</div>}
        <div className="small muted">Executive (management) · Technical (admin/SOC) · Compliance (OWASP, NIST CSF, CIS, ISO 27001 mapping)</div>
      </Panel>

      <Panel title="Report history">
        {loading ? <Spinner /> : items.length === 0 ? <Empty /> : (
          <table>
            <thead><tr><th>Name</th><th>Type</th><th>Format</th><th>Status</th><th>Size</th><th>Created</th><th /></tr></thead>
            <tbody>
              {items.map((r) => (
                <tr key={r.id}>
                  <td>{r.name}</td>
                  <td className="muted">{r.report_type}</td>
                  <td className="muted">{r.format}</td>
                  <td><span className="badge low">{r.status}</span></td>
                  <td className="muted">{(r.size_bytes / 1024).toFixed(1)} KB</td>
                  <td className="muted small">{r.created_at?.slice(0, 16).replace("T", " ")}</td>
                  <td>{r.status === "completed" && <button className="btn sm" onClick={() => download(r.id)}>Download</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}
