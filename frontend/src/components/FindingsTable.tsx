import { Fragment, useState } from "react";
import { Finding } from "../api/client";

const severityStyle: Record<string, string> = {
  HIGH: "bg-red-100 text-red-800",
  MEDIUM: "bg-amber-100 text-amber-800",
  LOW: "bg-blue-100 text-blue-800",
};

const verdictStyle: Record<string, string> = {
  true_positive: "bg-red-50 text-red-700",
  false_positive: "bg-green-50 text-green-700",
  needs_review: "bg-yellow-50 text-yellow-700",
};

export default function FindingsTable({ findings }: { findings: Finding[] }) {
  const [openId, setOpenId] = useState<number | null>(null);
  return (
    <table className="w-full text-sm">
      <thead>
        <tr className="text-left border-b bg-slate-100">
          <th className="py-2 px-2">심각도</th>
          <th className="py-2 px-2">MOIS</th>
          <th className="py-2 px-2">엔진</th>
          <th className="py-2 px-2">룰</th>
          <th className="py-2 px-2">위치</th>
          <th className="py-2 px-2">LLM 판정</th>
        </tr>
      </thead>
      <tbody>
        {findings.map((f) => (
          <Fragment key={f.id}>
            <tr
              className="border-b hover:bg-slate-50 cursor-pointer"
              onClick={() => setOpenId(openId === f.id ? null : f.id)}
            >
              <td className="py-2 px-2">
                <span
                  className={`px-2 py-0.5 rounded text-xs ${
                    severityStyle[f.severity] ?? ""
                  }`}
                >
                  {f.severity}
                </span>
              </td>
              <td className="py-2 px-2 font-mono text-xs">{f.mois_id ?? "-"}</td>
              <td className="py-2 px-2">{f.engine}</td>
              <td className="py-2 px-2 font-mono text-xs max-w-xs truncate">
                {f.rule_id}
              </td>
              <td className="py-2 px-2 font-mono text-xs">
                {f.file_path}:{f.start_line}
              </td>
              <td className="py-2 px-2">
                {f.triage ? (
                  <span
                    className={`text-xs px-2 py-0.5 rounded ${
                      verdictStyle[f.triage.verdict] ?? ""
                    }`}
                  >
                    {f.triage.verdict} ({f.triage.fp_probability}%)
                  </span>
                ) : (
                  <span className="text-xs text-slate-400">미판정</span>
                )}
              </td>
            </tr>
            {openId === f.id && (
              <tr className="bg-slate-50">
                <td colSpan={6} className="p-4 space-y-2">
                  <p className="text-slate-700">{f.message}</p>
                  {f.snippet && (
                    <pre className="bg-slate-900 text-slate-100 rounded p-3 overflow-auto text-xs whitespace-pre-wrap">
                      {f.snippet}
                    </pre>
                  )}
                  {f.triage && (
                    <div className="bg-white border rounded p-3">
                      <p className="text-sm">
                        <b>판정 근거:</b> {f.triage.rationale}
                      </p>
                      {f.triage.recommended_fix && (
                        <p className="text-sm mt-1">
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
                </td>
              </tr>
            )}
          </Fragment>
        ))}
      </tbody>
    </table>
  );
}
