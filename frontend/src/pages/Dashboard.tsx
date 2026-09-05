import React, { useEffect, useState } from "react";
import { api } from "../api/client";
import { DashboardSummary } from "../api/types";
import { Card, Empty, Panel, SevBadge, Spinner } from "../components/ui";
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from "recharts";

export default function Dashboard() {
  const [data, setData] = useState<DashboardSummary | null>(null);
  const [posture, setPosture] = useState<any>(null);
  const [top, setTop] = useState<any[]>([]);

  useEffect(() => {
    api.get("/dashboard/summary").then((r) => setData(r.data)).catch(() => setData(null));
    api.get("/dashboard/posture").then((r) => setPosture(r.data)).catch(() => {});
    api.get("/dashboard/top-priorities").then((r) => setTop(r.data)).catch(() => {});
  }, []);

  if (!data) return <Spinner />;

  const trend = (data.vulnerability_trend || []).map((p) => ({ date: p.date.slice(5), count: p.value }));

  return (
    <div>
      <div className="cards">
        <Card label="Total assets" value={data.total_assets} sub="internet-facing " />
        <Card label="Critical" value={data.critical} sub="open" />
        <Card label="High" value={data.high} sub="open" />
        <Card label="Medium" value={data.medium} sub="open" />
        <Card label="CISA KEV exposure" value={data.kev_exposure} sub="actively exploited" />
        <Card label="Overdue (SLA)" value={data.overdue} sub="breached" />
        <Card label="Risk score" value={Math.round(data.risk_score)} sub="0–100" />
        <Card label="Posture score" value={Math.round(data.posture_score)} sub={posture?.class || ""} />
      </div>

      <div className="grid-2 mt">
        <Panel title="Vulnerability trend (14d)">
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={trend}>
              <XAxis dataKey="date" tick={{ fill: "#8ea4c8", fontSize: 11 }} />
              <YAxis tick={{ fill: "#8ea4c8", fontSize: 11 }} allowDecimals={false} />
              <Tooltip contentStyle={{ background: "#14203a", border: "1px solid #24365a", color: "#dbe6ff" }} />
              <Line type="monotone" dataKey="count" stroke="#4c8dff" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </Panel>
        <Panel title="Top vulnerable assets">
          {data.top_vulnerable_assets.length === 0 ? (
            <Empty />
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={data.top_vulnerable_assets.map((a) => ({ name: a.name, risk: Math.round(a.risk_score) }))}>
                <XAxis dataKey="name" tick={{ fill: "#8ea4c8", fontSize: 10 }} />
                <YAxis tick={{ fill: "#8ea4c8", fontSize: 11 }} domain={[0, 100]} />
                <Tooltip contentStyle={{ background: "#14203a", border: "1px solid #24365a", color: "#dbe6ff" }} />
                <Bar dataKey="risk" radius={[6, 6, 0, 0]}>
                  {data.top_vulnerable_assets.map((_, i) => (
                    <Cell key={i} fill={["#ff5f6d", "#f2a33c", "#3ec6d6"][i % 3]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </Panel>
      </div>

      <Panel title="Top priorities — fix now" right={<span className="small muted">AI-assisted prioritization</span>}>
        {top.length === 0 ? (
          <Empty />
        ) : (
          <table>
            <thead><tr><th>#</th><th>Finding</th><th>Category</th><th>Risk</th><th>Why</th></tr></thead>
            <tbody>
              {top.map((t) => (
                <tr key={t.rank}>
                  <td><b>{t.rank}</b></td>
                  <td>{t.title}</td>
                  <td className="muted">{t.category}</td>
                  <td><span className="badge {t.band}">{t.band}</span></td>
                  <td className="small muted">{t.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}
