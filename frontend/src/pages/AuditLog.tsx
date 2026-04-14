import { useEffect, useState } from "react";
import { AuditLog, auditApi } from "../api/client";
import { Panel } from "../components/ui/Card";
import { Badge } from "../components/ui/Badge";

const ACTIONS = [
  "",
  "auth.login",
  "auth.login_failed",
  "finding.status_change",
  "suppression.create",
  "suppression.delete",
];

export default function AuditLogPage() {
  const [rows, setRows] = useState<AuditLog[]>([]);
  const [action, setAction] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function load() {
    setBusy(true);
    setError(null);
    auditApi
      .list({ action: action || undefined, limit: 200 })
      .then(setRows)
      .catch((err: any) => setError(err?.message ?? "조회 실패"))
      .finally(() => setBusy(false));
  }
  useEffect(load, [action]);

  return (
    <Panel
      title="감사 로그 (Audit Log)"
      action={
        <select
          value={action}
          onChange={(e) => setAction(e.target.value)}
          className="text-xs rounded border px-2 py-1"
        >
          {ACTIONS.map((a) => (
            <option key={a} value={a}>
              {a || "전체"}
            </option>
          ))}
        </select>
      }
    >
      {busy && <p className="text-xs text-slate-500">조회 중…</p>}
      {error && <p className="text-xs text-red-600">{error}</p>}
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="text-left border-b bg-slate-100">
              <th className="py-2 px-2">시각</th>
              <th className="py-2 px-2">사용자</th>
              <th className="py-2 px-2">액션</th>
              <th className="py-2 px-2">대상</th>
              <th className="py-2 px-2">IP</th>
              <th className="py-2 px-2">상세</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && !busy && (
              <tr>
                <td colSpan={6} className="py-8 text-center text-slate-500">
                  로그 없음
                </td>
              </tr>
            )}
            {rows.map((r) => (
              <tr key={r.id} className="border-b hover:bg-slate-50">
                <td className="py-1 px-2 font-mono text-[10px]">
                  {new Date(r.created_at).toLocaleString()}
                </td>
                <td className="py-1 px-2">{r.user_id ?? "-"}</td>
                <td className="py-1 px-2">
                  <Badge
                    tone={
                      r.action.includes("failed")
                        ? "high"
                        : r.action.includes("login")
                          ? "info"
                          : r.action.includes("delete")
                            ? "warn"
                            : "neutral"
                    }
                  >
                    {r.action}
                  </Badge>
                </td>
                <td className="py-1 px-2 font-mono text-[10px]">
                  {r.target_type ?? "-"}
                  {r.target_id ? ` #${r.target_id}` : ""}
                </td>
                <td className="py-1 px-2 font-mono text-[10px]">
                  {r.ip ?? "-"}
                </td>
                <td className="py-1 px-2 text-[10px] text-slate-600 max-w-md truncate">
                  {Object.entries(r.detail || {})
                    .map(([k, v]) => `${k}=${JSON.stringify(v)}`)
                    .join(" ")}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}
