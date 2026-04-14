import { ReactNode } from "react";

export function StatCard({
  label,
  value,
  hint,
  tone = "default",
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: "default" | "high" | "medium" | "low" | "ok";
}) {
  const toneCls = {
    default: "bg-white",
    high: "bg-red-50 border-red-200",
    medium: "bg-amber-50 border-amber-200",
    low: "bg-blue-50 border-blue-200",
    ok: "bg-emerald-50 border-emerald-200",
  }[tone];
  const valueCls = {
    default: "text-slate-900",
    high: "text-red-700",
    medium: "text-amber-700",
    low: "text-blue-700",
    ok: "text-emerald-700",
  }[tone];
  return (
    <div className={`rounded-lg border shadow-sm p-4 ${toneCls}`}>
      <div className="text-xs text-slate-500 uppercase tracking-wide">{label}</div>
      <div className={`mt-1 text-3xl font-bold ${valueCls}`}>{value}</div>
      {hint && <div className="text-xs text-slate-400 mt-1">{hint}</div>}
    </div>
  );
}

export function Panel({
  title,
  action,
  children,
}: {
  title: string;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="bg-white rounded-lg shadow-sm border p-4">
      <header className="flex justify-between items-center mb-3">
        <h2 className="text-lg font-semibold text-slate-800">{title}</h2>
        {action}
      </header>
      {children}
    </section>
  );
}
