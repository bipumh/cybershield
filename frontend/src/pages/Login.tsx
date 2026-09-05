import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, errText, setToken } from "../api/client";

export default function Login() {
  const nav = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [otp, setOtp] = useState("");

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true); setError("");
    const body = new URLSearchParams();
    body.append("username", email);
    body.append("password", password);
    if (otp) body.append("otp", otp);
    try {
      const res = await api.post("/auth/login", body, { headers: { "Content-Type": "application/x-www-form-urlencoded" } });
      setToken(res.data.token.access_token);
      nav("/dashboard");
    } catch (e) {
      setError(errText(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-wrap">
      <form className="login-box" onSubmit={submit}>
        <div className="brand" style={{ padding: 0, marginBottom: 4 }}>
          <div className="logo">CS</div>
          <b style={{ fontSize: 18 }}>CyberShield</b>
        </div>
        <h2>Sign in</h2>
        <p className="small muted" style={{ marginTop: -12, marginBottom: 18 }}>
          Authorized vulnerability assessment platform
        </p>
        {error && <div className="error">{error}</div>}
        <label className="field" style={{ marginBottom: 14 }}>
          <span>Email</span>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoFocus />
        </label>
        <label className="field" style={{ marginBottom: 14 }}>
          <span>Password</span>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        <label className="field" style={{ marginBottom: 20 }}>
          <span>MFA code (optional)</span>
          <input value={otp} onChange={(e) => setOtp(e.target.value)} placeholder="6-digit code" />
        </label>
        <button className="btn" style={{ width: "100%" }} disabled={loading}>
          {loading ? "Signing in…" : "Sign in"}
        </button>
        <p className="small muted" style={{ marginTop: 16, textAlign: "center" }}>
          Use only on assets you own or are authorized to test.
        </p>
      </form>
    </div>
  );
}
