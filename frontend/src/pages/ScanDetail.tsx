import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import {
  Finding,
  Scan,
  ScanDiff,
  api,
  findingsApi,
  scansApi,
} from "../api/client";
import FindingsTable from "../components/FindingsTable";
import { Panel, StatCard } from "../components/ui/Card";
import { useAuthStore } from "../store/auth";

type Tab = "all" | "diff";

export default function ScanDetailPage() {
  const { scanId = "" } = useParams();
  const role = useAuthStore((s) => s.role);
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [diff, setDiff] = useState<ScanDiff | null>(null);
  const [tab, setTab] = useState<Tab>("all");

  useEffect(() => {
    if (!scanId) return;
    api.get<Scan>(`/scans/${scanId}`).then((r) => setScan(r.data));
    findingsApi.forScan(scanId).then(setFindings);
    scansApi
      .diff(scanId)
      .then(setDiff)
      .catch(() => setDiff(null));
  }, [scanId]);

  function updateInList(updated: Finding) {
    setFindings((prev) =>
      prev.map((f) => (f.id === updated.id ? updated : f))
    );
  }

  if (!scan) return <p className="text-slate-500">로딩 중…</p>;

  const high = findings.filter((f) => f.severity === "HIGH").length;
  const medium = findings.filter((f) => f.severity === "MEDIUM").length;
  const low = findings.filter((f) => f.severity === "LOW").length;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">스캔 {scan.id}</h1>
        <p className="text-sm text-slate-500">{scan.source_path}</p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <StatCard label="상태" value={scan.status} />
        <StatCard label="총 이슈" value={findings.length} />
        <StatCard label="HIGH" value={high} tone="high" />
        <StatCard label="MEDIUM" value={medium} tone="medium" />
        <StatCard label="LOW" value={low} tone="low" />
      </div>

      {diff && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard
            label="신규 (vs prev)"
            value={diff.summary.new}
            tone={diff.summary.new_high > 0 ? "high" : "default"}
            hint={diff.base_scan_id ? `기준: ${diff.base_scan_id}` : "이전 스캔 없음"}
          />
          <StatCard
            label="해결"
            value={diff.summary.resolved}
            tone="ok"
          />
          <StatCard label="지속" value={diff.persistent} />
          <StatCard
            label="신규 HIGH"
            value={diff.summary.new_high}
            tone={diff.summary.new_high > 0 ? "high" : "ok"}
          />
        </div>
      )}

      <div className="border-b flex gap-2">
        <button
          onClick={() => setTab("all")}
          className={`px-3 py-2 text-sm border-b-2 ${
            tab === "all"
              ? "border-brand-accent text-brand-accent font-semibold"
              : "border-transparent text-slate-500"
          }`}
        >
          전체 ({findings.length})
        </button>
        <button
          onClick={() => setTab("diff")}
          className={`px-3 py-2 text-sm border-b-2 ${
            tab === "diff"
              ? "border-brand-accent text-brand-accent font-semibold"
              : "border-transparent text-slate-500"
          }`}
        >
          이전 분석 비교
        </button>
        <div className="ml-auto flex items-center gap-3 text-xs">
          <a
            href={`/api/reports/${scan.id}/sarif`}
            target="_blank"
            className="underline text-brand-accent"
          >
            SARIF
          </a>
          <a
            href={`/api/reports/${scan.id}/excel`}
            target="_blank"
            className="underline text-brand-accent"
          >
            Excel
          </a>
          <a
            href={`/api/reports/${scan.id}/html`}
            target="_blank"
            className="underline text-brand-accent"
          >
            HTML
          </a>
        </div>
      </div>

      {tab === "all" && (
        <Panel title={`전체 탐지 결과 (${findings.length})`}>
          <FindingsTable
            findings={findings}
            onUpdate={updateInList}
            isAdmin={role === "admin"}
          />
        </Panel>
      )}

      {tab === "diff" && diff && (
        <div className="space-y-6">
          <Panel title={`신규 이슈 (${diff.new.length})`}>
            <FindingsTable findings={diff.new} isAdmin={role === "admin"} />
          </Panel>
          <Panel title={`해결된 이슈 (${diff.resolved.length})`}>
            <FindingsTable
              findings={diff.resolved}
              isAdmin={role === "admin"}
            />
          </Panel>
        </div>
      )}
      {tab === "diff" && !diff && (
        <p className="text-slate-500">비교할 이전 분석이 없습니다.</p>
      )}
    </div>
  );
}
