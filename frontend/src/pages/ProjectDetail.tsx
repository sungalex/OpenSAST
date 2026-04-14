import { FormEvent, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  GateCheckResult,
  GatePolicy,
  Project,
  Scan,
  Suppression,
  api,
  gateApi,
  suppressionsApi,
} from "../api/client";
import { Badge } from "../components/ui/Badge";
import { Panel, StatCard } from "../components/ui/Card";

const KIND_LABEL = { path: "경로", function: "함수", rule: "룰" } as const;

export default function ProjectDetailPage() {
  const { projectId = "" } = useParams();
  const pid = Number(projectId);
  const [project, setProject] = useState<Project | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [supps, setSupps] = useState<Suppression[]>([]);
  const [policy, setPolicy] = useState<GatePolicy | null>(null);
  const [gateResult, setGateResult] = useState<GateCheckResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  // 신규 suppression 폼
  const [kind, setKind] = useState<"path" | "function" | "rule">("path");
  const [pattern, setPattern] = useState("");
  const [reason, setReason] = useState("");

  // gate policy 폼
  const [maxHigh, setMaxHigh] = useState(0);
  const [maxMedium, setMaxMedium] = useState(50);
  const [maxLow, setMaxLow] = useState(500);
  const [maxNewHigh, setMaxNewHigh] = useState(0);
  const [enabled, setEnabled] = useState(true);

  function loadAll() {
    api.get<Project>(`/projects/${pid}`).then((r) => setProject(r.data));
    api.get<Scan[]>(`/scans/project/${pid}`).then((r) => setScans(r.data));
    suppressionsApi.list(pid).then(setSupps);
    gateApi
      .policy(pid)
      .then((p) => {
        setPolicy(p);
        setMaxHigh(p.max_high);
        setMaxMedium(p.max_medium);
        setMaxLow(p.max_low);
        setMaxNewHigh(p.max_new_high);
        setEnabled(p.enabled);
      })
      .catch(() => setPolicy(null));
  }
  useEffect(loadAll, [pid]);

  async function addSupp(e: FormEvent) {
    e.preventDefault();
    if (!pattern) return;
    try {
      await suppressionsApi.create(pid, {
        kind,
        pattern,
        reason,
        rule_id: kind === "rule" ? pattern : null,
      });
      setPattern("");
      setReason("");
      suppressionsApi.list(pid).then(setSupps);
    } catch (err: any) {
      setError(err?.message ?? "추가 실패");
    }
  }

  async function delSupp(id: number) {
    if (!window.confirm("삭제하시겠습니까?")) return;
    await suppressionsApi.remove(pid, id);
    suppressionsApi.list(pid).then(setSupps);
  }

  async function savePolicy(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const p = await gateApi.upsert({
        project_id: pid,
        max_high: maxHigh,
        max_medium: maxMedium,
        max_low: maxLow,
        max_new_high: maxNewHigh,
        block_on_triage_fp_below: 30,
        enabled,
      });
      setPolicy(p);
    } catch (err: any) {
      setError(err?.message ?? "저장 실패");
    }
  }

  async function runGate() {
    setError(null);
    try {
      const r = await gateApi.check(pid);
      setGateResult(r);
    } catch (err: any) {
      setError(err?.response?.data?.detail ?? err?.message ?? "게이트 실패");
    }
  }

  if (!project) return <p className="text-slate-500">로딩…</p>;

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold">{project.name}</h1>
          <p className="text-sm text-slate-500">{project.description || "—"}</p>
        </div>
        <Link
          to="/projects"
          className="text-sm text-brand-accent hover:underline"
        >
          ← 프로젝트 목록
        </Link>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <StatCard label="스캔 수" value={scans.length} />
        <StatCard label="제외 규칙" value={supps.length} />
        <StatCard
          label="게이트"
          value={policy?.enabled ? "활성" : "비활성"}
          tone={policy?.enabled ? "ok" : "default"}
        />
      </div>

      {error && (
        <p className="text-sm text-red-600 bg-red-50 border border-red-200 rounded p-2">
          {error}
        </p>
      )}

      <Panel title="최근 스캔">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left border-b">
              <th className="py-1">ID</th>
              <th>상태</th>
              <th>경로</th>
              <th>시작</th>
            </tr>
          </thead>
          <tbody>
            {scans.slice(0, 10).map((s) => (
              <tr key={s.id} className="border-b">
                <td className="py-1 font-mono text-xs">
                  <Link
                    to={`/scans/${s.id}`}
                    className="text-brand-accent hover:underline"
                  >
                    {s.id}
                  </Link>
                </td>
                <td>
                  <Badge tone={s.status === "completed" ? "ok" : "info"}>
                    {s.status}
                  </Badge>
                </td>
                <td className="font-mono text-xs truncate max-w-md">
                  {s.source_path}
                </td>
                <td className="text-xs">{s.started_at ?? "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Panel title="제외 규칙 (Suppressions)">
          <form
            onSubmit={addSupp}
            className="flex flex-wrap gap-2 mb-3 text-sm"
          >
            <select
              value={kind}
              onChange={(e) =>
                setKind(e.target.value as "path" | "function" | "rule")
              }
              className="rounded border px-2 py-1"
            >
              <option value="path">경로</option>
              <option value="function">함수</option>
              <option value="rule">룰</option>
            </select>
            <input
              value={pattern}
              onChange={(e) => setPattern(e.target.value)}
              placeholder={
                kind === "path"
                  ? "**/tests/**"
                  : kind === "function"
                    ? "sanitize_html"
                    : "mois-sr6-2-debug-print"
              }
              className="flex-1 rounded border px-2 py-1 font-mono text-xs"
            />
            <input
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="사유"
              className="flex-1 rounded border px-2 py-1 text-xs"
            />
            <button className="bg-brand-accent text-white px-3 rounded text-xs">
              추가
            </button>
          </form>
          <ul className="divide-y text-sm">
            {supps.length === 0 && (
              <li className="py-3 text-slate-500 text-center">
                제외 규칙 없음
              </li>
            )}
            {supps.map((s) => (
              <li key={s.id} className="py-2 flex items-center gap-2">
                <Badge tone="info">{KIND_LABEL[s.kind]}</Badge>
                <span className="font-mono text-xs flex-1 truncate">
                  {s.pattern}
                </span>
                <span className="text-xs text-slate-500 truncate max-w-xs">
                  {s.reason}
                </span>
                <button
                  onClick={() => delSupp(s.id)}
                  className="text-xs text-red-600 hover:underline"
                >
                  삭제
                </button>
              </li>
            ))}
          </ul>
        </Panel>

        <Panel title="빌드 게이트 정책">
          <form onSubmit={savePolicy} className="space-y-3 text-sm">
            <div className="grid grid-cols-2 gap-3">
              <label className="block">
                <span className="text-xs text-slate-500">max HIGH</span>
                <input
                  type="number"
                  value={maxHigh}
                  onChange={(e) => setMaxHigh(Number(e.target.value))}
                  className="w-full mt-1 rounded border px-2 py-1"
                />
              </label>
              <label className="block">
                <span className="text-xs text-slate-500">max MEDIUM</span>
                <input
                  type="number"
                  value={maxMedium}
                  onChange={(e) => setMaxMedium(Number(e.target.value))}
                  className="w-full mt-1 rounded border px-2 py-1"
                />
              </label>
              <label className="block">
                <span className="text-xs text-slate-500">max LOW</span>
                <input
                  type="number"
                  value={maxLow}
                  onChange={(e) => setMaxLow(Number(e.target.value))}
                  className="w-full mt-1 rounded border px-2 py-1"
                />
              </label>
              <label className="block">
                <span className="text-xs text-slate-500">신규 HIGH 허용</span>
                <input
                  type="number"
                  value={maxNewHigh}
                  onChange={(e) => setMaxNewHigh(Number(e.target.value))}
                  className="w-full mt-1 rounded border px-2 py-1"
                />
              </label>
            </div>
            <label className="inline-flex items-center gap-1 text-xs">
              <input
                type="checkbox"
                checked={enabled}
                onChange={(e) => setEnabled(e.target.checked)}
              />
              게이트 활성
            </label>
            <div className="flex gap-2">
              <button className="bg-brand-accent text-white px-3 py-2 rounded">
                정책 저장
              </button>
              <button
                type="button"
                onClick={runGate}
                className="bg-emerald-600 text-white px-3 py-2 rounded"
              >
                지금 게이트 체크
              </button>
            </div>
          </form>
          {gateResult && (
            <div
              className={`mt-3 p-3 rounded border text-sm ${
                gateResult.passed
                  ? "bg-emerald-50 border-emerald-200"
                  : "bg-red-50 border-red-200"
              }`}
            >
              <p className="font-semibold">
                {gateResult.passed ? "✅ PASS" : "🚫 BLOCKED"}
              </p>
              <ul className="text-xs mt-1 list-disc list-inside">
                {gateResult.reasons.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
              <p className="text-xs mt-2">
                HIGH={gateResult.counts.HIGH ?? 0} · MEDIUM=
                {gateResult.counts.MEDIUM ?? 0} · LOW=
                {gateResult.counts.LOW ?? 0}
              </p>
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}
