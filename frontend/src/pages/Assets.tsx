import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { Asset } from "../api/types";
import { Card, Empty, Panel, Spinner } from "../components/ui";

export default function Assets() {
  const [items, setItems] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [q, setQ] = useState("");
  const [type, setType] = useState("");

  const load = () => {
    setLoading(true);
    api.get("/assets", { params: { q: q || undefined, asset_type: type || undefined, page_size: 100 } })
      .then((r) => setItems(r.data.items))
      .finally(() => setLoading(false));
  };
  useEffect(load, []);

  const criticalityCls = (c: string) => (c === "critical" ? "critical" : c === "high" ? "high" : c === "medium" ? "medium" : "low");

  return (
    <div>
      <div className="filters">
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search hostname / IP / domain" style={{ maxWidth: 280 }} />
        <select value={type} onChange={(e) => setType(e.target.value)} style={{ maxWidth: 200 }}>
          <option value="">All types</option>
          {["server", "workstation", "router", "switch", "firewall", "database_server", "application_server", "virtual_machine", "container_host", "storage_device", "iot_device", "domain", "web_application", "other"].map((t) => (
            <option key={t} value={t}>{t.replace("_", " ")}</option>
          ))}
        </select>
        <button className="btn sm" onClick={load}>Filter</button>
        <div className="spacer" />
        <Link to="/scans" className="btn sm" style={{ display: "inline-block" }}>+ Register asset</Link>
      </div>

      {loading ? <Spinner /> : items.length === 0 ? (
        <Empty text="No assets yet. Run a scan or register one." />
      ) : (
        <Panel>
          <table>
            <thead>
              <tr><th>Asset</th><th>Type</th><th>IP</th><th>OS</th><th>Criticality</th><th>Internet</th><th>Risk</th><th>Vulns</th></tr>
            </thead>
            <tbody>
              {items.map((a) => (
                <tr key={a.id}>
                  <td><b>{a.hostname || a.domain || a.asset_key}</b></td>
                  <td className="muted">{a.asset_type}</td>
                  <td className="muted">{a.ip_address || "—"}</td>
                  <td className="muted">{a.os_name || (a.vendor ? a.vendor : "—")}</td>
                  <td><span className={`badge ${criticalityCls(a.criticality)}`}>{a.criticality}</span></td>
                  <td>{a.is_internet_facing ? "🌐" : "—"}</td>
                  <td>{Math.round(a.risk_score)}</td>
                  <td>{a.vulnerability_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}
    </div>
  );
}
