import { FormEvent, useState } from "react";
import { Finding, findingsApi } from "../api/client";
import { Badge, severityTone, statusLabel, statusTone } from "./ui/Badge";

export default function NlSearchBox() {
  const [query, setQuery] = useState("");
  const [busy, setBusy] = useState(false);
  const [results, setResults] = useState<Finding[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!query.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const data = await findingsApi.ask(query);
      setResults(data);
    } catch (err: any) {
      setError(err?.message ?? "검색 실패");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="bg-gradient-to-r from-indigo-50 to-purple-50 border border-indigo-200 rounded-lg p-4">
      <div className="flex items-center gap-2 mb-2">
        <span className="text-indigo-700 text-sm font-semibold">
          🔮 자연어 이슈 검색 (LLM)
        </span>
        <span className="text-xs text-slate-500">
          Sparrow 에 없는 OpenSAST 차별화 기능
        </span>
      </div>
      <form onSubmit={handleSubmit} className="flex gap-2">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder='예: "고위험 SQL 삽입 중 외부 입력이 검증되지 않은 것"'
          className="flex-1 rounded border px-3 py-2 text-sm bg-white"
        />
        <button
          type="submit"
          disabled={busy}
          className="bg-indigo-600 text-white px-4 py-2 rounded hover:bg-indigo-700 disabled:opacity-50 text-sm"
        >
          {busy ? "분석 중…" : "검색"}
        </button>
      </form>
      {error && <p className="text-xs text-red-600 mt-2">{error}</p>}
      {results && (
        <div className="mt-3 bg-white rounded border max-h-60 overflow-y-auto">
          {results.length === 0 ? (
            <p className="p-3 text-sm text-slate-500">결과 없음</p>
          ) : (
            <ul className="divide-y">
              {results.slice(0, 20).map((f) => (
                <li
                  key={f.id}
                  className="p-2 text-xs flex items-center gap-2 hover:bg-slate-50"
                >
                  <Badge tone={severityTone(f.severity)}>{f.severity}</Badge>
                  {f.mois_id && <Badge tone="info">{f.mois_id}</Badge>}
                  <Badge tone={statusTone(f.status)}>
                    {statusLabel(f.status)}
                  </Badge>
                  <span className="truncate flex-1 font-mono text-slate-600">
                    {f.file_path}:{f.start_line}
                  </span>
                  <span className="text-slate-700 truncate max-w-md">
                    {f.message}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </section>
  );
}
