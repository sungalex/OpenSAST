import axios from "axios";
import { useAuthStore } from "../store/auth";

export const api = axios.create({
  baseURL: "/api",
  headers: { "Content-Type": "application/json" },
});

api.interceptors.request.use((config) => {
  const token = useAuthStore.getState().token;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err?.response?.status === 401) {
      useAuthStore.getState().logout();
    }
    return Promise.reject(err);
  }
);

// ---------------------------------------------------------------------------
// 도메인 타입
// ---------------------------------------------------------------------------

export type Severity = "HIGH" | "MEDIUM" | "LOW";

export type FindingStatus =
  | "new"
  | "confirmed"
  | "exclusion_requested"
  | "excluded"
  | "fixed"
  | "rejected";

export interface Project {
  id: number;
  name: string;
  description: string;
  repo_url: string;
  default_language: string | null;
  created_at: string;
}

export interface Scan {
  id: string;
  project_id: number;
  status: string;
  source_path: string;
  started_at: string | null;
  finished_at: string | null;
  engine_stats: Record<string, number>;
  mois_coverage: Record<string, number>;
  error: string | null;
}

export interface Triage {
  verdict: string;
  fp_probability: number;
  rationale: string;
  recommended_fix: string | null;
  patched_code: string | null;
  model: string;
}

export interface Reference {
  standard: string;
  id: string;
  title: string;
  url?: string;
}

export interface Finding {
  id: number;
  scan_id: string;
  rule_id: string;
  engine: string;
  severity: Severity;
  message: string;
  file_path: string;
  start_line: number;
  end_line: number | null;
  cwe_ids: string[];
  mois_id: string | null;
  category: string | null;
  language: string | null;
  snippet: string | null;
  status: FindingStatus;
  status_reason: string | null;
  reviewed_by: number | null;
  triage: Triage | null;
  references: Reference[];
}

export interface MoisItem {
  id: string;
  name_kr: string;
  name_en: string;
  category: string;
  cwe_ids: string[];
  severity: string;
  primary_engines: string[];
  secondary_engines: string[];
  description: string;
  references: Reference[];
}

export interface DashboardOverview {
  totals: {
    projects: number;
    scans: number;
    findings: number;
    high: number;
    medium: number;
    low: number;
  };
  status_counts: Record<string, number>;
  latest_scan: {
    id: string;
    project_id: number;
    status: string;
    created_at: string | null;
  } | null;
}

export interface TrendPoint {
  date: string;
  scans: number;
  findings: number;
}

export interface TopRule {
  rule_id: string;
  engine: string;
  count: number;
}

export interface MoisCoverageItem {
  mois_id: string;
  name_kr: string;
  category: string;
  severity: string;
  count: number;
  covered: boolean;
}

export interface MoisCoverage {
  total_items: number;
  covered_items: number;
  coverage_ratio: number;
  items: MoisCoverageItem[];
}

export interface CategoryDistribution {
  categories: { name: string; count: number }[];
}

export interface RuleSet {
  id: number;
  name: string;
  description: string;
  enabled_engines: string[];
  include_rules: string[];
  exclude_rules: string[];
  min_severity: string;
  is_default: boolean;
}

export interface Suppression {
  id: number;
  project_id: number;
  kind: "path" | "function" | "rule";
  pattern: string;
  rule_id: string | null;
  reason: string;
}

export interface GatePolicy {
  id: number;
  project_id: number;
  max_high: number;
  max_medium: number;
  max_low: number;
  max_new_high: number;
  block_on_triage_fp_below: number;
  enabled: boolean;
}

export interface GateCheckResult {
  passed: boolean;
  reasons: string[];
  counts: Record<string, number>;
  new_high: number;
}

export interface AuditLog {
  id: number;
  user_id: number | null;
  action: string;
  target_type: string | null;
  target_id: string | null;
  detail: Record<string, unknown>;
  ip: string | null;
  created_at: string;
}

export interface ScanDiff {
  base_scan_id: string | null;
  head_scan_id: string;
  new: Finding[];
  resolved: Finding[];
  persistent: number;
  summary: { new: number; resolved: number; persistent: number; new_high: number };
}

// ---------------------------------------------------------------------------
// 도메인 헬퍼 함수
// ---------------------------------------------------------------------------

export const dashboardApi = {
  overview: () => api.get<DashboardOverview>("/dashboard/overview").then((r) => r.data),
  trends: (days = 30) =>
    api.get<{ days: number; timeline: TrendPoint[] }>(`/dashboard/trends?days=${days}`).then((r) => r.data),
  topRules: (limit = 10) =>
    api.get<{ top: TopRule[] }>(`/dashboard/top-rules?limit=${limit}`).then((r) => r.data),
  moisCoverage: () => api.get<MoisCoverage>("/dashboard/mois-coverage").then((r) => r.data),
  categoryDistribution: () =>
    api.get<CategoryDistribution>("/dashboard/category-distribution").then((r) => r.data),
};

export interface FindingFilterParams {
  scan_id?: string;
  project_id?: number;
  severity?: Severity[];
  engine?: string[];
  status?: FindingStatus[];
  mois_id?: string[];
  cwe?: string[];
  path_glob?: string;
  text?: string;
  include_excluded?: boolean;
  limit?: number;
  offset?: number;
}

export const findingsApi = {
  search: (params: FindingFilterParams) =>
    api.get<Finding[]>("/findings/search", { params }).then((r) => r.data),
  ask: (query: string, project_id?: number, scan_id?: string) =>
    api.post<Finding[]>("/findings/ask", { query, project_id, scan_id }).then((r) => r.data),
  forScan: (scan_id: string) =>
    api.get<Finding[]>(`/findings/scan/${scan_id}`).then((r) => r.data),
  setStatus: (id: number, status: FindingStatus, reason?: string) =>
    api
      .post<Finding>(`/findings/${id}/status`, { status, reason: reason ?? null })
      .then((r) => r.data),
};

export const ruleSetsApi = {
  list: () => api.get<RuleSet[]>("/rule-sets").then((r) => r.data),
  create: (body: Omit<RuleSet, "id">) => api.post<RuleSet>("/rule-sets", body).then((r) => r.data),
  remove: (id: number) => api.delete(`/rule-sets/${id}`),
};

export const suppressionsApi = {
  list: (project_id: number) =>
    api.get<Suppression[]>(`/projects/${project_id}/suppressions`).then((r) => r.data),
  create: (project_id: number, body: Omit<Suppression, "id" | "project_id">) =>
    api.post<Suppression>(`/projects/${project_id}/suppressions`, body).then((r) => r.data),
  remove: (project_id: number, id: number) =>
    api.delete(`/projects/${project_id}/suppressions/${id}`),
};

export const gateApi = {
  policy: (project_id: number) =>
    api.get<GatePolicy>(`/gate/policy/${project_id}`).then((r) => r.data),
  upsert: (body: Omit<GatePolicy, "id">) =>
    api.put<GatePolicy>("/gate/policy", body).then((r) => r.data),
  check: (project_id: number, scan_id?: string, base_scan_id?: string) =>
    api
      .post<GateCheckResult>("/gate/check", { project_id, scan_id, base_scan_id })
      .then((r) => r.data),
};

export const auditApi = {
  list: (params: { action?: string; user_id?: number; limit?: number; offset?: number }) =>
    api.get<AuditLog[]>("/admin/audit", { params }).then((r) => r.data),
};

export const scansApi = {
  diff: (scan_id: string, base?: string) =>
    api
      .get<ScanDiff>(`/scans/${scan_id}/diff${base ? `?base=${base}` : ""}`)
      .then((r) => r.data),
  source: (scan_id: string, path: string) =>
    api
      .get<{ path: string; truncated: boolean; size: number; content: string }>(
        `/scans/${scan_id}/source`,
        { params: { path } }
      )
      .then((r) => r.data),
};
