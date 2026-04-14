import { useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  CategoryDistribution,
  DashboardOverview,
  MoisCoverage,
  TopRule,
  TrendPoint,
  dashboardApi,
} from "../api/client";
import { Panel, StatCard } from "../components/ui/Card";
import NlSearchBox from "../components/NlSearchBox";

const PIE_COLORS = [
  "#2563eb",
  "#16a34a",
  "#d97706",
  "#dc2626",
  "#7c3aed",
  "#0891b2",
  "#db2777",
];

export default function DashboardPage() {
  const [overview, setOverview] = useState<DashboardOverview | null>(null);
  const [trends, setTrends] = useState<TrendPoint[]>([]);
  const [topRules, setTopRules] = useState<TopRule[]>([]);
  const [coverage, setCoverage] = useState<MoisCoverage | null>(null);
  const [categories, setCategories] = useState<CategoryDistribution | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      dashboardApi.overview(),
      dashboardApi.trends(30),
      dashboardApi.topRules(10),
      dashboardApi.moisCoverage(),
      dashboardApi.categoryDistribution(),
    ])
      .then(([o, t, r, m, c]) => {
        setOverview(o);
        setTrends(t.timeline);
        setTopRules(r.top);
        setCoverage(m);
        setCategories(c);
      })
      .finally(() => setLoading(false));
  }, []);

  if (loading || !overview) return <p className="text-slate-500">대시보드 로딩 중…</p>;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
        <StatCard label="프로젝트" value={overview.totals.projects} />
        <StatCard label="총 스캔" value={overview.totals.scans} />
        <StatCard label="총 이슈" value={overview.totals.findings} />
        <StatCard label="HIGH" value={overview.totals.high} tone="high" />
        <StatCard label="MEDIUM" value={overview.totals.medium} tone="medium" />
        <StatCard label="LOW" value={overview.totals.low} tone="low" />
      </div>

      <NlSearchBox />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <Panel title="분석 추이 (최근 30일)">
            {trends.length === 0 ? (
              <p className="text-sm text-slate-500">아직 스캔 데이터가 없습니다.</p>
            ) : (
              <ResponsiveContainer width="100%" height={260}>
                <LineChart data={trends}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                  <XAxis dataKey="date" fontSize={11} />
                  <YAxis fontSize={11} />
                  <Tooltip />
                  <Legend />
                  <Line
                    type="monotone"
                    dataKey="findings"
                    name="이슈"
                    stroke="#dc2626"
                    strokeWidth={2}
                  />
                  <Line
                    type="monotone"
                    dataKey="scans"
                    name="스캔"
                    stroke="#2563eb"
                    strokeWidth={2}
                  />
                </LineChart>
              </ResponsiveContainer>
            )}
          </Panel>
        </div>

        <Panel title="카테고리 분포">
          {!categories || categories.categories.length === 0 ? (
            <p className="text-sm text-slate-500">데이터 없음</p>
          ) : (
            <ResponsiveContainer width="100%" height={260}>
              <PieChart>
                <Pie
                  data={categories.categories}
                  dataKey="count"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={90}
                  label={(entry) => entry.name}
                >
                  {categories.categories.map((_, i) => (
                    <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          )}
        </Panel>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Panel title="TOP 10 룰">
          {topRules.length === 0 ? (
            <p className="text-sm text-slate-500">데이터 없음</p>
          ) : (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={topRules} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                <XAxis type="number" fontSize={11} />
                <YAxis
                  type="category"
                  dataKey="rule_id"
                  width={220}
                  fontSize={10}
                  tickFormatter={(v: string) =>
                    v.length > 35 ? "…" + v.slice(-32) : v
                  }
                />
                <Tooltip />
                <Bar dataKey="count" fill="#2563eb" />
              </BarChart>
            </ResponsiveContainer>
          )}
        </Panel>

        <Panel
          title="MOIS 49개 항목 커버리지"
          action={
            coverage && (
              <span className="text-sm text-slate-600">
                {coverage.covered_items}/{coverage.total_items} (
                {Math.round(coverage.coverage_ratio * 100)}%)
              </span>
            )
          }
        >
          {!coverage ? (
            <p className="text-sm text-slate-500">로딩 중…</p>
          ) : (
            <div className="max-h-80 overflow-y-auto text-xs">
              <table className="w-full">
                <thead className="sticky top-0 bg-white">
                  <tr className="text-left border-b">
                    <th className="py-1">ID</th>
                    <th>항목명</th>
                    <th>분류</th>
                    <th className="text-right">건수</th>
                  </tr>
                </thead>
                <tbody>
                  {coverage.items.map((item) => (
                    <tr
                      key={item.mois_id}
                      className={`border-b ${
                        item.covered ? "bg-amber-50" : ""
                      }`}
                    >
                      <td className="py-1 font-mono">{item.mois_id}</td>
                      <td>{item.name_kr}</td>
                      <td className="text-slate-500">{item.category}</td>
                      <td className="text-right font-bold">
                        {item.count > 0 ? item.count : "-"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}
