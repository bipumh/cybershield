import React, { useState } from "react";
import { api, errText } from "../api/client";
import { Panel } from "../components/ui";

const SUGGESTIONS = [
  "What should we fix first?",
  "Which vulnerabilities are internet-facing?",
  "Which vulnerabilities are actively exploited?",
  "Which vulnerabilities are overdue?",
  "Generate management summary.",
  "Explain the highest-risk asset to a non-technical manager.",
];

interface Msg { role: "user" | "ai"; text: string }

export default function Advisor() {
  const [msgs, setMsgs] = useState<Msg[]>([{ role: "ai", text: "Hello — I am the CyberShield Security Advisor. I answer using your actual scan data. How can I help?" }]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const ask = async (q?: string) => {
    const question = (q || input).trim();
    if (!question || busy) return;
    setInput(""); setBusy(true); setError("");
    setMsgs((m) => [...m, { role: "user", text: question }]);
    try {
      const r = await api.post("/ai/advisor", { question });
      setMsgs((m) => [...m, { role: "ai", text: r.data.answer }]);
    } catch (e) { setError(errText(e)); }
    finally { setBusy(false); }
  };

  return (
    <Panel title="CyberShield Security Advisor">
      <div className="small muted" style={{ marginBottom: 10 }}>
        AI-generated guidance, grounded on platform scan data. Predictions are advisory, not confirmed facts.
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 10, maxHeight: "60vh", overflow: "auto", paddingBottom: 10 }}>
        {msgs.map((m, i) => (
          <div key={i} style={{ alignSelf: m.role === "user" ? "flex-end" : "flex-start", maxWidth: "78%" }}>
            <div
              style={{
                padding: "10px 14px", borderRadius: 12, fontSize: 13.5, whiteSpace: "pre-wrap",
                background: m.role === "user" ? "var(--accent)" : "var(--bg2)",
                color: m.role === "user" ? "#fff" : "var(--text)",
                border: m.role === "user" ? "none" : "1px solid var(--border)",
              }}
            >{m.text}</div>
          </div>
        ))}
        {busy && <div className="muted small">Thinking…</div>}
      </div>
      {error && <div className="error" style={{ margin: "10px 0" }}>{error}</div>}
      <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
        {SUGGESTIONS.map((s) => (
          <button key={s} className="btn sm ghost" onClick={() => ask(s)} style={{ whiteSpace: "nowrap" }}>{s}</button>
        ))}
      </div>
      <div style={{ display: "flex", gap: 8, marginTop: 14 }}>
        <input value={input} onChange={(e) => setInput(e.target.value)} placeholder="Ask about your security data…" onKeyDown={(e) => e.key === "Enter" && ask()} />
        <button className="btn" onClick={() => ask()} disabled={busy}>Ask</button>
      </div>
    </Panel>
  );
}
