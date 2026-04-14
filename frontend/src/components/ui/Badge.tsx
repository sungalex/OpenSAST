import { ReactNode } from "react";

export type Tone =
  | "high"
  | "medium"
  | "low"
  | "neutral"
  | "ok"
  | "warn"
  | "info";

const toneCls: Record<Tone, string> = {
  high: "bg-red-100 text-red-800 border-red-200",
  medium: "bg-amber-100 text-amber-800 border-amber-200",
  low: "bg-blue-100 text-blue-800 border-blue-200",
  neutral: "bg-slate-100 text-slate-700 border-slate-200",
  ok: "bg-emerald-100 text-emerald-800 border-emerald-200",
  warn: "bg-orange-100 text-orange-800 border-orange-200",
  info: "bg-indigo-100 text-indigo-800 border-indigo-200",
};

export function Badge({
  children,
  tone = "neutral",
  className = "",
}: {
  children: ReactNode;
  tone?: Tone;
  className?: string;
}) {
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${toneCls[tone]} ${className}`}
    >
      {children}
    </span>
  );
}

export function severityTone(severity: string): Tone {
  if (severity === "HIGH") return "high";
  if (severity === "MEDIUM") return "medium";
  if (severity === "LOW") return "low";
  return "neutral";
}

export function statusTone(status: string): Tone {
  switch (status) {
    case "new":
      return "neutral";
    case "confirmed":
      return "warn";
    case "exclusion_requested":
      return "info";
    case "excluded":
      return "ok";
    case "fixed":
      return "ok";
    case "rejected":
      return "high";
    default:
      return "neutral";
  }
}

export function statusLabel(status: string): string {
  return (
    {
      new: "미확인",
      confirmed: "확인",
      exclusion_requested: "제외 신청",
      excluded: "제외",
      fixed: "수정 완료",
      rejected: "거부",
    } as Record<string, string>
  )[status] ?? status;
}
