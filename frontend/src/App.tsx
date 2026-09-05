import React from "react";
import { BrowserRouter, Routes, Route, Navigate, Outlet, useNavigate } from "react-router-dom";
import { Layout } from "./components/Layout";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Assets from "./pages/Assets";
import Findings from "./pages/Findings";
import FindingDetail from "./pages/FindingDetail";
import Scans from "./pages/Scans";
import Remediation from "./pages/Remediation";
import Reports from "./pages/Reports";
import Advisor from "./pages/Advisor";
import { getToken } from "./api/client";

function RequireAuth() {
  if (!getToken()) return <Navigate to="/login" replace />;
  return <Outlet />;
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route element={<RequireAuth />}>
          <Route element={<Layout />}>
            <Route index element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/assets" element={<Assets />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/findings/:id" element={<FindingDetail />} />
            <Route path="/scans" element={<Scans />} />
            <Route path="/remediation" element={<Remediation />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/advisor" element={<Advisor />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Route>
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
