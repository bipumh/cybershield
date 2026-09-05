import React, { useEffect, useState } from "react";
import { api, errText } from "../api/client";
import { Scan } from "../api/types";
import { Empty, Panel, Spinner, StatusBadge } from "../components/ui";

const MODES = [
  { id: "web", label: "Domain / Web Application Security" },
  { id: "network", label: "Infrastructure / Endpoint / Network Security" },
];
const PROFILES = ["passive", "safe", "standard", "enterprise"];

export default function Scans() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [mode, setMode] = useState("web");
  const [profile, setProfile] = useState("safe");
  const [target, setTarget] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState("");
  const [creating, setCreating] = useState(false);
  const [known, setKnown] = useState<{ name: string; status: string }[]>([]);

  const load = () => api.get("/scans", { params: { page_size: 50 } }).then((r) => setScans(r.data.items)).finally(() => setLoading(false));
  useEffect(() => { load(); }, []);

  // poll active scans
  useEffect(() => {
    const t = setInterval(() => {
      api.get("/scans", { params: { page_size: 50 } }).then((r) => setScans(r.data.items)).catch(() => {});
    }, 5000);
    return () => clearInterval(t);
  }, []);

  const discover = async () => {
    setError("");
    try {
      const r = await api.post("/scans/discover", { domain: target });
      setKnown(r.data);
    } catch (e) { setError(errText(e)); }
  };

  const start = async () => {
    if (!target) { setError("Enter a target (domain, URL, IP, CIDR…)"); return; }
    setCreating(true); setError("");
    try {
      const r = await api.post("/scans", {
        name: name || `${mode} scan ${new Date().toLocaleString()}`,
        mode, profile,
        targets: [{ kind: guessKind(target), value: target, in_scope: true }],
        safety: { scope_confirmed: true, safety_confirmed: true, authorization_statement: "I own or am authorized to assess these targets." },
      });
      setTarget(""); setKnown([]);
    } catch (e) { setError(errText(e)); }
    finally { setCreating(false); load(); }
  };

  const cancel = async (id: number) => { await api.post(`/scans/${id}/cancel`); load(); };

  return (
    <div>
      <Panel title="New scan">
        <div className="filters">
          <select value={mode} onChange={(e) => setMode(e.target.value)} style={{ maxWidth: 260 }}>
            {MODES.map((m) => <option key={m.id} value={m.id}>{m.label}</option>)}
          </select>
          <select value={profile} onChange={(e) => setProfile(e.target.value)} style={{ maxWidth: 140 }}>
            {PROFILES.map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
        </div>
        <label className="field">
          <span>Target (domain / URL / IP / CIDR)</span>
          <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="example.com or https://example.com or 192.168.10.0/24" />
        </label>
        <div className="mt" style={{ display: "flex", gap: 10 }}>
          <button className="btn sm ghost" onClick={discover}>Discover subdomains (passive)</button>
          <button className="btn" onClick={start} disabled={creating}>{creating ? "Starting…" : "Start scan"}</button>
        </div>
        {error && <div className="error mt">{error}</div>}
        {known.length > 0 && (
          <div className="mt">
            <div className="small muted" style={{ marginBottom: 6 }}>Discovered subdomains — approve to add to scope:</div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {known.slice(0, 40).map((k) => <span key={k.name} className="badge info"><span className="dot" />{k.name} · {k.status}</span>)}
            </div>
          </div>
        )}
        <div className="small muted mt" style={{ marginTop: 16 }}>
          Active scanning requires explicit scope + safety confirmation.
        </div>
      </Panel>

      <Panel title="Scan history">
        {loading ? <Spinner /> : scans.length === 0 ? <Empty /> : (
          <table>
            <thead><tr><th>Name</th><th>Mode</th><th>Profile</th><th>Status</th><th>Progress</th><th /></tr></thead>
            <tbody>
              {scans.map((s) => (
                <tr key={s.id}>
                  <td>{s.name}</td>
                  <td className="muted">{s.mode}</td>
                  <td className="muted">{s.profile}</td>
                  <td><StatusBadge status={s.status} /></td>
                  <td style={{ minWidth: 140 }}>
                    <div className="progress"><div style={{ width: `${s.progress}%` }} /></div>
                    <span className="small muted">{s.progress}%</span>
                  </td>
                  <td>
                    {["pending", "running", "discovering", "validating"].includes(s.status) && (
                      <button className="btn sm danger" onClick={() => cancel(s.id)}>Cancel</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}

function guessKind(v: string): string {
  if (/^https?:\/\//i.test(v)) return "url";
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v)) return "ip";
  if (/\//.test(v) && /\//.test(v)) return "cidr";
  return "domain";
}
