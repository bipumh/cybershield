export interface User {
  id: number;
  full_name: string;
  email: string;
  roles: string[];
  permissions: string[];
}

export interface Asset {
  id: number;
  asset_key: string;
  hostname?: string | null;
  ip_address?: string | null;
  domain?: string | null;
  asset_type: string;
  os_name?: string | null;
  vendor?: string | null;
  criticality: string;
  is_production: boolean;
  is_internet_facing: boolean;
  last_scan_at?: string | null;
  risk_score: number;
  vulnerability_count: number;
}

export interface Finding {
  id: number;
  finding_no: string;
  title: string;
  category: string;
  severity: string;
  cvss_score: number;
  cve?: string | null;
  cwe?: string | null;
  asset_criticality: string;
  risk_score: number;
  risk_band: string;
  is_kev: boolean;
  remediation_level: string;
  status: string;
  first_detected_at: string;
  last_detected_at: string;
  sla_due_at?: string | null;
  age_days: number;
  internet_exposed: boolean;
}

export interface FindingDetail extends Finding {
  description: string;
  cvss_vector?: string | null;
  evidence: string;
  affected_component?: string | null;
  detected_version?: string | null;
  fixed_version?: string | null;
  ai_analysis: { analysis?: string; why_it_matters?: string; potential_impact?: Record<string,string>; predicted_risk?: string; confidence?: string };
  remediation_plan: Record<string, string>;
  standards: Record<string, unknown>;
  references: string[];
  asset?: { id: number; name: string; criticality: string } | null;
}

export interface Scan {
  id: number;
  scan_key: string;
  name: string;
  mode: string;
  profile: string;
  status: string;
  progress: number;
  total_steps: number;
  rate_limit: number;
  created_at: string;
  error?: string | null;
  summary: Record<string, unknown>;
}

export interface Remediation {
  id: number;
  finding_id: number;
  asset_id?: number | null;
  level: string;
  title: string;
  status: string;
  complexity: string;
  execution_status: string;
  auto_remediated: boolean;
  created_at: string;
}

export interface DashboardSummary {
  total_assets: number;
  internet_facing_assets: number;
  internal_assets: number;
  open_vulnerabilities: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  remediated: number;
  overdue: number;
  risk_score: number;
  posture_score: number;
  kev_exposure: number;
  patch_compliance: number;
  top_vulnerable_assets: { asset_id: number; name: string; risk_score: number; critical_count: number; high_count: number; total: number }[];
  vulnerability_trend: { date: string; value: number }[];
}
