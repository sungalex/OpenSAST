import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { Finding, Scan, api } from "../api/client";
import FindingsTable from "../components/FindingsTable";

export default function ScanDetailPage() {
  const { scanId = "" } = useParams();
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);

  useEffect(() => {
    if (!scanId) return;
    api.get<Scan>(`/scans/${scanId}`).then((r) => setScan(r.data));
    api
      .get<Finding[]>(`/findings/scan/${scanId}`)
      .then((r) => setFindings(r.data));
  }, [scanId]);

  if (!scan) return <p>로딩 중…</p>;
  return (
    <div className="space-y-6">
      <section className="bg-white p-4 rounded shadow">
        <h2 className="text-xl font-semibold">스캔 {scan.id}</h2>
        <p className="text-sm text-slate-500">{scan.source_path}</p>
        <div className="mt-3 flex gap-4 text-sm">
          <span>상태: <b>{scan.status}</b></span>
          <span>시작: {scan.started_at ?? "-"}</span>
          <span>종료: {scan.finished_at ?? "-"}</span>
        </div>
        <div className="mt-3 text-sm">
          <b>엔진별 탐지:</b>{" "}
          {Object.entries(scan.engine_stats)
            .map(([k, v]) => `${k}:${v}`)
            .join(", ") || "—"}
        </div>
        <div className="mt-1 text-sm">
          <b>MOIS 커버리지:</b>{" "}
          {Object.entries(scan.mois_coverage)
            .map(([k, v]) => `${k}:${v}`)
            .join(", ") || "—"}
        </div>
      </section>
      <section className="bg-white p-4 rounded shadow">
        <h2 className="text-lg font-semibold mb-2">탐지 결과 ({findings.length})</h2>
        <FindingsTable findings={findings} />
      </section>
    </div>
  );
}
