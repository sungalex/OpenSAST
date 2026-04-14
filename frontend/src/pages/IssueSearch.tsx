import { FormEvent, useState } from "react";
import {
  Finding,
  FindingFilterParams,
  FindingStatus,
  Severity,
  findingsApi,
} from "../api/client";
import FindingsTable from "../components/FindingsTable";
import NlSearchBox from "../components/NlSearchBox";
import { Panel } from "../components/ui/Card";
import { useAuthStore } from "../store/auth";

const SEVERITIES: Severity[] = ["HIGH", "MEDIUM", "LOW"];
const STATUSES: FindingStatus[] = [
  "new",
  "confirmed",
  "exclusion_requested",
  "excluded",
  "fixed",
  "rejected",
];
const ENGINES = ["opengrep", "bandit", "eslint", "gosec", "spotbugs", "codeql"];

export default function IssueSearchPage() {
  const role = useAuthStore((s) => s.role);
  const [params, setParams] = useState<FindingFilterParams>({
    limit: 100,
    offset: 0,
  });
  const [results, setResults] = useState<Finding[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function toggle<T>(arr: T[] | undefined, value: T): T[] {
    const cur = arr ?? [];
    return cur.includes(value) ? cur.filter((v) => v !== value) : [...cur, value];
  }

  async function runSearch(e?: FormEvent) {
    e?.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const data = await findingsApi.search(params);
      setResults(data);
    } catch (err: any) {
      setError(err?.message ?? "검색 실패");
    } finally {
      setBusy(false);
    }
  }

  function updateInList(updated: Finding) {
    setResults((prev) => prev.map((r) => (r.id === updated.id ? updated : r)));
  }

  return (
    <div className="space-y-6">
      <NlSearchBox />

      <Panel title="Advanced Issue Filter">
        <form onSubmit={runSearch} className="space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">
            <label className="block">
              <span className="text-xs text-slate-500">scan_id</span>
              <input
                value={params.scan_id ?? ""}
                onChange={(e) =>
                  setParams({ ...params, scan_id: e.target.value || undefined })
                }
                className="w-full mt-1 rounded border px-2 py-1 font-mono"
              />
            </label>
            <label className="block">
              <span className="text-xs text-slate-500">project_id</span>
              <input
                type="number"
                value={params.project_id ?? ""}
                onChange={(e) =>
                  setParams({
                    ...params,
                    project_id: e.target.value ? Number(e.target.value) : undefined,
                  })
                }
                className="w-full mt-1 rounded border px-2 py-1"
              />
            </label>
            <label className="block">
              <span className="text-xs text-slate-500">텍스트(rule/message/path)</span>
              <input
                value={params.text ?? ""}
                onChange={(e) =>
                  setParams({ ...params, text: e.target.value || undefined })
                }
                className="w-full mt-1 rounded border px-2 py-1"
              />
            </label>
            <label className="block">
              <span className="text-xs text-slate-500">path glob</span>
              <input
                value={params.path_glob ?? ""}
                onChange={(e) =>
                  setParams({ ...params, path_glob: e.target.value || undefined })
                }
                placeholder="src/**/*.py"
                className="w-full mt-1 rounded border px-2 py-1 font-mono"
              />
            </label>
            <label className="block">
              <span className="text-xs text-slate-500">MOIS ID (콤마구분)</span>
              <input
                value={(params.mois_id ?? []).join(",")}
                onChange={(e) =>
                  setParams({
                    ...params,
                    mois_id: e.target.value
                      ? e.target.value.split(",").map((s) => s.trim())
                      : undefined,
                  })
                }
                placeholder="SR1-1,SR1-3"
                className="w-full mt-1 rounded border px-2 py-1 font-mono"
              />
            </label>
            <label className="block">
              <span className="text-xs text-slate-500">CWE (콤마구분)</span>
              <input
                value={(params.cwe ?? []).join(",")}
                onChange={(e) =>
                  setParams({
                    ...params,
                    cwe: e.target.value
                      ? e.target.value.split(",").map((s) => s.trim())
                      : undefined,
                  })
                }
                placeholder="CWE-89,CWE-79"
                className="w-full mt-1 rounded border px-2 py-1 font-mono"
              />
            </label>
          </div>

          <div className="flex flex-wrap gap-3 text-xs">
            <div>
              <div className="font-medium text-slate-600 mb-1">심각도</div>
              <div className="flex gap-2">
                {SEVERITIES.map((s) => (
                  <label key={s} className="inline-flex items-center gap-1">
                    <input
                      type="checkbox"
                      checked={(params.severity ?? []).includes(s)}
                      onChange={() =>
                        setParams({
                          ...params,
                          severity: toggle(params.severity, s),
                        })
                      }
                    />
                    {s}
                  </label>
                ))}
              </div>
            </div>
            <div>
              <div className="font-medium text-slate-600 mb-1">엔진</div>
              <div className="flex flex-wrap gap-2">
                {ENGINES.map((e) => (
                  <label key={e} className="inline-flex items-center gap-1">
                    <input
                      type="checkbox"
                      checked={(params.engine ?? []).includes(e)}
                      onChange={() =>
                        setParams({
                          ...params,
                          engine: toggle(params.engine, e),
                        })
                      }
                    />
                    {e}
                  </label>
                ))}
              </div>
            </div>
            <div>
              <div className="font-medium text-slate-600 mb-1">상태</div>
              <div className="flex flex-wrap gap-2">
                {STATUSES.map((s) => (
                  <label key={s} className="inline-flex items-center gap-1">
                    <input
                      type="checkbox"
                      checked={(params.status ?? []).includes(s)}
                      onChange={() =>
                        setParams({
                          ...params,
                          status: toggle(params.status, s),
                        })
                      }
                    />
                    {s}
                  </label>
                ))}
              </div>
            </div>
            <label className="inline-flex items-center gap-1">
              <input
                type="checkbox"
                checked={params.include_excluded ?? false}
                onChange={(e) =>
                  setParams({ ...params, include_excluded: e.target.checked })
                }
              />
              제외 항목 포함
            </label>
          </div>

          <div className="flex justify-between items-center">
            <div className="text-xs text-slate-500">
              결과 {results.length}건
            </div>
            <button
              type="submit"
              disabled={busy}
              className="bg-brand-accent text-white px-4 py-2 rounded disabled:opacity-50"
            >
              {busy ? "검색 중…" : "검색 실행"}
            </button>
          </div>
          {error && <p className="text-xs text-red-600">{error}</p>}
        </form>
      </Panel>

      <Panel title={`결과 (${results.length}건)`}>
        <FindingsTable
          findings={results}
          onUpdate={updateInList}
          isAdmin={role === "admin"}
        />
      </Panel>
    </div>
  );
}
