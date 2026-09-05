import React, { useEffect, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { api, clearToken, getToken } from "../api/client";
import { User } from "../api/types";

const NAV = [
  { to: "/dashboard", label: "Dashboard", icon: "◧" },
  { to: "/assets", label: "Assets", icon: "▣" },
  { to: "/findings", label: "Vulnerabilities", icon: "⚠" },
  { to: "/scans", label: "Scan Center", icon: "⌖" },
  { to: "/remediation", label: "Remediation", icon: "✓" },
  { to: "/reports", label: "Reports", icon: "▤" },
  { to: "/advisor", label: "Security Advisor", icon: "✦" },
];

export function Layout() {
  const [user, setUser] = useState<User | null>(null);
  const [menu, setMenu] = useState(false);
  const nav = useNavigate();

  useEffect(() => {
    if (getToken()) {
      api.get("/auth/me").then((r) => setUser(r.data)).catch(() => {});
    }
  }, []);

  const logout = () => {
    api.post("/auth/logout").catch(() => {});
    clearToken();
    nav("/login");
  };

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <div className="logo">CS</div>
          <b>CyberShield</b>
        </div>
        {NAV.map((n) => (
          <NavLink key={n.to} to={n.to} className={({ isActive }) => "nav-link" + (isActive ? " active" : "")}>
            <span style={{ width: 18, opacity: 0.75 }}>{n.icon}</span> {n.label}
          </NavLink>
        ))}
      </aside>
      <div className="main">
        <div className="topbar">
          <h1>Vulnerability Assessment & Exchange Management</h1>
          <div style={{ position: "relative" }}>
            <button className="user-chip" onClick={() => setMenu((m) => !m)} style={{ background: "none", border: "none", cursor: "pointer" }}>
              <span className="avatar">{(user?.full_name || "U").slice(0, 1).toUpperCase()}</span>
              <span>{user?.full_name || user?.email}</span>
              <span style={{ opacity: 0.6 }}>▾</span>
            </button>
            {menu && (
              <div style={{ position: "absolute", right: 0, top: 40, background: "var(--panel2)", border: "1px solid var(--border)", borderRadius: 8, padding: 6, minWidth: 160, zIndex: 20 }}>
                <div className="small muted" style={{ padding: "6px 10px" }}>{user?.email}</div>
                <button className="nav-link" onClick={logout}>Sign out</button>
              </div>
            )}
          </div>
        </div>
        <div className="content">
          <Outlet />
        </div>
      </div>
    </div>
  );
}
