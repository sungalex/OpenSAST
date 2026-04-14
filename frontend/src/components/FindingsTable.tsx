import { Fragment, useState } from "react";
import {
  Finding,
  FindingStatus,
  findingsApi,
} from "../api/client";
import { Badge, severityTone, statusLabel, statusTone } from "./ui/Badge";

interface Props {
  findings: Finding[];
  onUpdate?: (updated: Finding) => void;
  isAdmin?: boolean;
}

const SELF_TRANSITIONS: Record<FindingStatus, FindingStatus[]> = {
  new: ["confirmed", "exclusion_requested", "fixed"],
  confirmed: ["exclusion_requested", "fixed", "new"],
  exclusion_requested: ["new"],
  fixed: ["new", "confirmed"],
  rejected: ["new"],
  excluded: [],
};

const ADMIN_TRANSITIONS: Record<FindingStatus, FindingStatus[]> = {
  new: ["excluded"],
  confirmed: ["excluded"],
  exclusion_requested: ["excluded", "rejected", "new"],
  excluded: ["new"],
  fixed: [],
  rejected: [],
};

export default function FindingsTable({
  findings,
  onUpdate,
  isAdmin = false,
}: Props) {
  const [openId, setOpenId] = useState<number | null>(null);
  const [busy, setBusy] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function changeStatus(
    f: Finding,
    target: FindingStatus
  ) {
    const reason = window.prompt(
      `${statusLabel(f.status)} → ${statusLabel(target)} 변경 사유 (선택)`,
      f.status_reason ?? ""
    );
    if (reason === null) return; // 취소
    setBusy(f.id);
    setError(null);
    try {
      const updated = await findingsApi.setStatus(f.id, target, reason);
      onUpdate?.(updated);
    } catch (err: any) {
      setError(
        `상태 변경 실패: ${
          err?.response?.data?.detail ?? err?.message ?? "unknown"
        }`
      );
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="space-y-2">
      {error && (
        <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded p-2">
          {error}
        </p>
      )}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left border-b bg-slate-100">
              <th className="py-2 px-2">심각도</th>
              <th className="py-2 px-2">상태</th>
              <th className="py-2 px-2">MOIS</th>
              <th className="py-2 px-2">엔진</th>
              <th className="py-2 px-2">룰</th>
              <th className="py-2 px-2">위치</th>
              <th className="py-2 px-2">레퍼런스</th>
              <th className="py-2 px-2">LLM</th>
            </tr>
          </thead>
          <tbody>
            {findings.length === 0 && (
              <tr>
                <td colSpan={8} className="py-8 text-center text-slate-500">
                  탐지 결과 없음
                </td>
              </tr>
            )}
            {findings.map((f) => {
              const selfTransitions = SELF_TRANSITIONS[f.status] ?? [];
              const adminTransitions = isAdmin
                ? ADMIN_TRANSITIONS[f.status] ?? []
                : [];
              const allTransitions = [
                ...selfTransitions,
                ...adminTransitions,
              ];
              return (
                <Fragment key={f.id}>
                  <tr
                    className="border-b hover:bg-slate-50 cursor-pointer"
                    onClick={() => setOpenId(openId === f.id ? null : f.id)}
                  >
                    <td className="py-2 px-2">
                      <Badge tone={severityTone(f.severity)}>{f.severity}</Badge>
                    </td>
                    <td className="py-2 px-2">
                      <Badge tone={statusTone(f.status)}>
                        {statusLabel(f.status)}
                      </Badge>
                    </td>
                    <td className="py-2 px-2 font-mono text-xs">
                      {f.mois_id ?? "-"}
                    </td>
                    <td className="py-2 px-2">{f.engine}</td>
                    <td className="py-2 px-2 font-mono text-xs max-w-xs truncate">
                      {f.rule_id}
                    </td>
                    <td className="py-2 px-2 font-mono text-xs">
                      {f.file_path.length > 40
                        ? "…" + f.file_path.slice(-37)
                        : f.file_path}
                      :{f.start_line}
                    </td>
                    <td className="py-2 px-2">
                      <div className="flex flex-wrap gap-1">
                        {f.references.slice(0, 3).map((r) => (
                          <Badge
                            key={`${r.standard}-${r.id}`}
                            tone={r.standard === "OWASP-2021" ? "warn" : "info"}
                            className="text-[10px]"
                          >
                            {r.standard === "CWE" ? r.id : `${r.standard} ${r.id}`}
                          </Badge>
                        ))}
                        {f.references.length > 3 && (
                          <span className="text-[10px] text-slate-400">
                            +{f.references.length - 3}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-2 px-2">
                      {f.triage ? (
                        <Badge
                          tone={
                            f.triage.verdict === "false_positive"
                              ? "ok"
                              : f.triage.verdict === "true_positive"
                                ? "high"
                                : "warn"
                          }
                        >
                          {f.triage.fp_probability}%
                        </Badge>
                      ) : (
                        <span className="text-xs text-slate-400">-</span>
                      )}
                    </td>
                  </tr>
                  {openId === f.id && (
                    <tr className="bg-slate-50">
                      <td colSpan={8} className="p-4 space-y-3">
                        <p className="text-slate-700">{f.message}</p>
                        {f.snippet && (
                          <pre className="bg-slate-900 text-slate-100 rounded p-3 overflow-auto text-xs whitespace-pre-wrap">
                            {f.snippet}
                          </pre>
                        )}

                        {f.references.length > 0 && (
                          <div className="text-xs">
                            <b>레퍼런스:</b>{" "}
                            <span className="inline-flex flex-wrap gap-1 align-middle">
                              {f.references.map((r) => (
                                <a
                                  key={`${r.standard}-${r.id}`}
                                  href={r.url || "#"}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="underline text-indigo-600 hover:text-indigo-800"
                                >
                                  {r.standard} {r.id}
                                </a>
                              ))}
                            </span>
                          </div>
                        )}

                        {f.triage && (
                          <div className="bg-white border rounded p-3 text-sm">
                            <p>
                              <b>LLM 판정:</b> {f.triage.verdict} (오탐 확률{" "}
                              {f.triage.fp_probability}%)
                            </p>
                            <p className="mt-1 text-slate-700">
                              {f.triage.rationale}
                            </p>
                            {f.triage.recommended_fix && (
                              <p className="mt-1">
                                <b>조치 방안:</b> {f.triage.recommended_fix}
                              </p>
                            )}
                            {f.triage.patched_code && (
                              <pre className="mt-2 bg-slate-900 text-slate-100 rounded p-3 overflow-auto text-xs whitespace-pre-wrap">
                                {f.triage.patched_code}
                              </pre>
                            )}
                          </div>
                        )}

                        {f.status_reason && (
                          <p className="text-xs text-slate-600">
                            <b>상태 사유:</b> {f.status_reason}
                          </p>
                        )}

                        <div className="flex flex-wrap gap-2 pt-2 border-t">
                          <span className="text-xs text-slate-500 self-center">
                            상태 전이:
                          </span>
                          {allTransitions.length === 0 && (
                            <span className="text-xs text-slate-400 self-center">
                              가능한 전이 없음
                            </span>
                          )}
                          {allTransitions.map((target) => (
                            <button
                              key={target}
                              disabled={busy === f.id}
                              onClick={(e) => {
                                e.stopPropagation();
                                changeStatus(f, target);
                              }}
                              className="text-xs px-2 py-1 rounded border bg-white hover:bg-slate-100 disabled:opacity-50"
                            >
                              → {statusLabel(target)}
                              {adminTransitions.includes(target) && (
                                <span className="ml-1 text-orange-600">
                                  (admin)
                                </span>
                              )}
                            </button>
                          ))}
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
