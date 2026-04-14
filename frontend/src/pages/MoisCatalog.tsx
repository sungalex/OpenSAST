import { useEffect, useState } from "react";
import { MoisItem, api } from "../api/client";

export default function MoisCatalogPage() {
  const [items, setItems] = useState<MoisItem[]>([]);
  useEffect(() => {
    api.get<MoisItem[]>("/mois/items").then((r) => setItems(r.data));
  }, []);
  return (
    <section className="bg-white p-4 rounded shadow">
      <h2 className="text-xl font-semibold mb-4">
        행안부 구현단계 49개 보안약점
      </h2>
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left border-b bg-slate-100">
            <th className="py-2 px-2">ID</th>
            <th className="py-2 px-2">항목명</th>
            <th className="py-2 px-2">분류</th>
            <th className="py-2 px-2">CWE</th>
            <th className="py-2 px-2">심각도</th>
            <th className="py-2 px-2">주 엔진</th>
          </tr>
        </thead>
        <tbody>
          {items.map((i) => (
            <tr key={i.id} className="border-b">
              <td className="py-2 px-2 font-mono text-xs">{i.id}</td>
              <td className="py-2 px-2">{i.name_kr}</td>
              <td className="py-2 px-2">{i.category}</td>
              <td className="py-2 px-2 font-mono text-xs">
                {i.cwe_ids.join(", ")}
              </td>
              <td className="py-2 px-2">{i.severity}</td>
              <td className="py-2 px-2">{i.primary_engines.join(", ")}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
