import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api, errText } from "../api/client";
import { FindingDetail as FD } from "../api/types";
import { Empty, KV, LevelBadge, Panel, SevBadge, Spinner } from "../components/ui";

const LEVELS = ["level1_safe_auto", "level2_approval_required", "level3_manual"];

export default function FindingDetail() {
  const { id } = useParams();
  const [f, setF] = useState<FD | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [status, setStatus] = useState("");

  useEffect(() => {
    api.get(`/findings/${id}`).then((r) => { setF(r.data); setStatus(r.data.status); }).catch((e) => setError(errText(e))).finally(() => setLoading(false));
  }, [id]);

  if (loading) return <Spinner />;
  if (error || !f) return <div className="error">{error || "Not found"}</div>;

  const ai = f.ai_analysis || {};
  const plan = f.remediation_plan || {};
  const updateStatus = async (s: string) => {
    setStatus(s);
    await api.patch(`/findings/${f.id}`, { status: s }).catch(() => {});
  };

  return (
    <div>
      <Panel
        title={`${f.finding_no} · ${f.title}`}
        right={<SevBadge sev={f.severity} />}
      >
        <div className="detail-grid">
          <KV k="Severity" v={<SevBadge sev={f.severity} />} />
          <KV k="CVSS" v={f.cvss_score.toFixed(1)} />
          <KV k="CVE" v={f.cve || "—"} />
          <KV k="CWE" v={f.cwe || "—"} />
          <KV k="Category" v={f.category} />
          <KV k="Affected component" v={f.affected_component || "—"} />
          <KV k="Detected version" v={f.detected_version || "—"} />
          <KV k="Fixed version" v={f.fixed_version || "—"} />
          <KV k="Asset" v={f.asset ? `${f.asset.name} (${f.asset.criticality})` : "—"} />
          <KV k="Internet exposed" v={f.internet_exposed ? "Yes" : "No"} />
          <KV k="Risk score" v={`${Math.round(f.risk_score)} (${f.risk_band})`} />
          <KV k="KeV (exploited)" v={f.is_kev ? "Added to CISA KEV" : "No"} />
          <KV k="Auto remediation" v={<LevelBadge level={f.remediation_level} />} />
          <KV k="Status" v={f.status.replace(/_/g, " ")} />
        </div>
      </Panel>

      <Panel title="Description & Risk">
        <blockquote>{f.description}</blockquote>
        <h4 style={{ margin: "14px 0 8px", fontSize: 13, color: "#fff" }}>Evidence</h4>
        <pre>{f.evidence}</pre>
      </Panel>

      <div className="grid-2 mt">
        <Panel title="AI Security Analyst">
          <div className="small muted" style={{ marginBottom: 6 }}>AI-generated risk assessment — advisory, not confirmed fact.</div>
          <blockquote>{ai.analysis}</blockquote>
          <p className="small"><b>Why it matters:</b> {ai.why_it_matters}</p>
          <p className="small"><b>Predicted risk:</b> <span className={`badge ${ai.predicted_risk || "info"}`}>{ai.predicted_risk || "n/a"}</span> <span className="muted">({ai.confidence})</span></p>
          {ai.potential_impact && (
            <table className="small">
              <thead><tr><th>Impact</th><th>Assessment</th></tr></thead>
              <tbody>
                {Object.entries(ai.potential_impact).map(([k, v]) => (
                  <tr key={k}><td className="muted">{k}</td><td>{String(v)}</td></tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>

        <Panel title="Recommended Solution">
          <div className="kv"><span className="k">Immediate action</span><span className="v">{plan.immediate_action || "—"}</span></div>
          <div className="kv"><span className="k">Permanent solution</span><span className="v">{plan.permanent_solution || "—"}</span></div>
          <div className="kv"><span className="k">Recommended config</span><span className="v">{plan.recommended_config || "—"}</span></div>
          <div className="kv"><span className="k">Patch / update</span><span className="v">{plan.patch_recommendation || "—"}</span></div>
          <div className="kv"><span className="k">Verification</span><span className="v">{plan.verification_procedure || "—"}</span></div>
          <div className="kv"><span className="k">Rollback</span><span className="v">{plan.rollback_procedure || "—"}</span></div>
          <div className="kv"><span className="k">Business impact</span><span className="v">{plan.business_impact || "—"}</span></div>
          <div className="kv"><span className="k">Complexity</span><span className="v">{plan.complexity || "—"}</span></div>
        </Panel>
      </div>

      <Panel title="Standards mapping" right={<LevelBadge level={f.remediation_level} />}>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {Object.entries(f.standards || {}).map(([k, v]) => (
            <span key={k} className="badge info"><span className="dot" />{k}: {typeof v === "object" && v ? (v as any).id || (v as any).title : String(v)}</span>
          ))}
        </div>
      </Panel>

      <Panel title="Workflow">
        <div className="filters">
          <select value={status} onChange={(e) => setStatus(e.target.value)} style={{ maxWidth: 220 }}>
            {["open", "investigating", "remediation_planned", "remediation_in_progress", "false_positive", "accepted_risk", "resolved", "verified", "closed"].map((s) => (
              <option key={s} value={s}>{s.replace(/_/g, " ")}</option>
            ))}
          </select>
          <button className="btn sm" onClick={() => updateStatus(status)}>Save status</button>
          <div className="spacer" />
          <button className="btn sm ghost" onClick={() => api.post(`/findings/${f.id}/exceptions`, { kind: "false_positive", reason: "Marked as false positive pending review", evidence: "" })}>Mark FP</button>
          <button className="btn sm" onClick={() => api.post(`/findings/${f.id}/exceptions`, { kind: "accepted_risk", reason: "Accepted risk with compensating control", evidence: "" })}>Accept risk</button>
        </div>
      </Panel>
    </div>
  );
}
