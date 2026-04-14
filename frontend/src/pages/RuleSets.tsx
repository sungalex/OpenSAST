import { FormEvent, useEffect, useState } from "react";
import { RuleSet, ruleSetsApi } from "../api/client";
import { Panel } from "../components/ui/Card";
import { Badge } from "../components/ui/Badge";
import { useAuthStore } from "../store/auth";

const ENGINES = ["opengrep", "bandit", "eslint", "gosec", "spotbugs", "codeql"];
const SEVERITIES = ["LOW", "MEDIUM", "HIGH"];

export default function RuleSetsPage() {
  const role = useAuthStore((s) => s.role);
  const [rows, setRows] = useState<RuleSet[]>([]);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [enabled, setEnabled] = useState<string[]>(ENGINES);
  const [include, setInclude] = useState("");
  const [exclude, setExclude] = useState("");
  const [minSev, setMinSev] = useState("LOW");
  const [isDefault, setIsDefault] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function reload() {
    ruleSetsApi.list().then(setRows);
  }
  useEffect(reload, []);

  async function create(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await ruleSetsApi.create({
        name,
        description,
        enabled_engines: enabled,
        include_rules: include ? include.split(",").map((s) => s.trim()) : [],
        exclude_rules: exclude ? exclude.split(",").map((s) => s.trim()) : [],
        min_severity: minSev,
        is_default: isDefault,
      });
      setName("");
      setDescription("");
      setInclude("");
      setExclude("");
      setIsDefault(false);
      reload();
    } catch (err: any) {
      setError(err?.response?.data?.detail ?? err?.message ?? "생성 실패");
    }
  }

  async function remove(id: number) {
    if (!window.confirm("정말 삭제하시겠습니까?")) return;
    try {
      await ruleSetsApi.remove(id);
      reload();
    } catch (err: any) {
      setError(err?.response?.data?.detail ?? err?.message ?? "삭제 실패");
    }
  }

  function toggleEngine(e: string) {
    setEnabled((prev) =>
      prev.includes(e) ? prev.filter((x) => x !== e) : [...prev, e]
    );
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <div className="lg:col-span-2">
        <Panel title="체커 그룹 (Rule Set) 목록">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b bg-slate-100">
                <th className="py-2 px-2">이름</th>
                <th className="py-2 px-2">엔진</th>
                <th className="py-2 px-2">최소 심각도</th>
                <th className="py-2 px-2">제외 룰</th>
                <th className="py-2 px-2">기본</th>
                <th className="py-2 px-2"></th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    등록된 체커 그룹 없음
                  </td>
                </tr>
              )}
              {rows.map((r) => (
                <tr key={r.id} className="border-b">
                  <td className="py-2 px-2 font-medium">
                    {r.name}
                    <div className="text-xs text-slate-500">{r.description}</div>
                  </td>
                  <td className="py-2 px-2">
                    <div className="flex flex-wrap gap-1">
                      {r.enabled_engines.map((e) => (
                        <Badge key={e} tone="info">
                          {e}
                        </Badge>
                      ))}
                    </div>
                  </td>
                  <td className="py-2 px-2">
                    <Badge tone="neutral">{r.min_severity}</Badge>
                  </td>
                  <td className="py-2 px-2 text-xs text-slate-500">
                    {r.exclude_rules.length} 개
                  </td>
                  <td className="py-2 px-2">
                    {r.is_default && <Badge tone="ok">DEFAULT</Badge>}
                  </td>
                  <td className="py-2 px-2 text-right">
                    {role === "admin" && !r.is_default && (
                      <button
                        onClick={() => remove(r.id)}
                        className="text-xs text-red-600 hover:underline"
                      >
                        삭제
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      </div>

      {role === "admin" ? (
        <Panel title="신규 체커 그룹 생성">
          <form onSubmit={create} className="space-y-3 text-sm">
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="그룹 이름"
              className="w-full rounded border px-2 py-1"
              required
            />
            <input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="설명"
              className="w-full rounded border px-2 py-1"
            />
            <div>
              <div className="text-xs text-slate-500 mb-1">활성 엔진</div>
              <div className="flex flex-wrap gap-2">
                {ENGINES.map((e) => (
                  <label key={e} className="text-xs inline-flex items-center gap-1">
                    <input
                      type="checkbox"
                      checked={enabled.includes(e)}
                      onChange={() => toggleEngine(e)}
                    />
                    {e}
                  </label>
                ))}
              </div>
            </div>
            <input
              value={include}
              onChange={(e) => setInclude(e.target.value)}
              placeholder="포함 룰 ID (콤마구분)"
              className="w-full rounded border px-2 py-1 font-mono text-xs"
            />
            <input
              value={exclude}
              onChange={(e) => setExclude(e.target.value)}
              placeholder="제외 룰 ID (콤마구분)"
              className="w-full rounded border px-2 py-1 font-mono text-xs"
            />
            <select
              value={minSev}
              onChange={(e) => setMinSev(e.target.value)}
              className="w-full rounded border px-2 py-1"
            >
              {SEVERITIES.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
            <label className="inline-flex items-center gap-1 text-xs">
              <input
                type="checkbox"
                checked={isDefault}
                onChange={(e) => setIsDefault(e.target.checked)}
              />
              기본 그룹으로 설정
            </label>
            {error && <p className="text-xs text-red-600">{error}</p>}
            <button
              type="submit"
              className="w-full bg-brand-accent text-white px-3 py-2 rounded"
            >
              생성
            </button>
          </form>
        </Panel>
      ) : (
        <Panel title="신규 생성">
          <p className="text-sm text-slate-500">
            관리자만 체커 그룹을 생성할 수 있습니다.
          </p>
        </Panel>
      )}
    </div>
  );
}
