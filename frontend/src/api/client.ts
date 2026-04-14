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

export interface Finding {
  id: number;
  rule_id: string;
  engine: string;
  severity: "HIGH" | "MEDIUM" | "LOW";
  message: string;
  file_path: string;
  start_line: number;
  end_line: number | null;
  cwe_ids: string[];
  mois_id: string | null;
  category: string | null;
  language: string | null;
  snippet: string | null;
  triage: Triage | null;
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
}
