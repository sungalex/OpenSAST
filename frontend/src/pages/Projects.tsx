import { FormEvent, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { Project, Scan, api } from "../api/client";

type SourceMode = "path" | "upload" | "git";

export default function ProjectsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");

  const [mode, setMode] = useState<SourceMode>("path");
  const [scanPath, setScanPath] = useState("");
  const [gitUrl, setGitUrl] = useState("");
  const [gitBranch, setGitBranch] = useState("");
  const [archive, setArchive] = useState<File | null>(null);
  const [languageHint, setLanguageHint] = useState("");
  const [secondPass, setSecondPass] = useState(true);
  const [triage, setTriage] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const archiveInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    api.get<Project[]>("/projects").then((r) => setProjects(r.data));
  }, []);

  useEffect(() => {
    if (selectedId == null) return;
    api
      .get<Scan[]>(`/scans/project/${selectedId}`)
      .then((r) => setScans(r.data));
  }, [selectedId]);

  async function createProject(e: FormEvent) {
    e.preventDefault();
    if (!newName.trim()) return;
    const { data } = await api.post<Project>("/projects", {
      name: newName.trim(),
      description: newDesc.trim(),
    });
    setProjects([data, ...projects]);
    setNewName("");
    setNewDesc("");
    setSelectedId(data.id);
  }

  async function queueScan(e: FormEvent) {
    e.preventDefault();
    if (!selectedId) return;
    setError(null);
    setBusy(true);
    try {
      let created: Scan;
      if (mode === "path") {
        if (!scanPath.trim()) throw new Error("서버 경로를 입력하세요");
        const { data } = await api.post<Scan>("/scans", {
          project_id: selectedId,
          source_path: scanPath.trim(),
          language_hint: languageHint || null,
          enable_second_pass: secondPass,
          enable_triage: triage,
        });
        created = data;
        setScanPath("");
      } else if (mode === "git") {
        if (!gitUrl.trim()) throw new Error("Git URL 을 입력하세요");
        const { data } = await api.post<Scan>("/scans/git", {
          project_id: selectedId,
          git_url: gitUrl.trim(),
          branch: gitBranch.trim() || null,
          language_hint: languageHint || null,
          enable_second_pass: secondPass,
          enable_triage: triage,
        });
        created = data;
        setGitUrl("");
        setGitBranch("");
      } else {
        if (!archive) throw new Error("업로드할 .zip 파일을 선택하세요");
        const form = new FormData();
        form.append("project_id", String(selectedId));
        form.append("archive", archive);
        if (languageHint) form.append("language_hint", languageHint);
        form.append("enable_second_pass", String(secondPass));
        form.append("enable_triage", String(triage));
        const { data } = await api.post<Scan>("/scans/upload", form, {
          headers: { "Content-Type": "multipart/form-data" },
        });
        created = data;
        setArchive(null);
        if (archiveInputRef.current) archiveInputRef.current.value = "";
      }
      setScans([created, ...scans]);
    } catch (err: any) {
      setError(
        err?.response?.data?.detail?.toString?.() ??
          err?.message ??
          "스캔 요청 실패"
      );
    } finally {
      setBusy(false);
    }
  }

  const Tab = ({ m, label }: { m: SourceMode; label: string }) => (
    <button
      type="button"
      onClick={() => setMode(m)}
      className={`px-3 py-1 text-sm border-b-2 ${
        mode === m
          ? "border-brand-accent text-brand-accent font-semibold"
          : "border-transparent text-slate-500 hover:text-slate-700"
      }`}
    >
      {label}
    </button>
  );

  return (
    <div className="grid grid-cols-12 gap-6">
      <section className="col-span-4 bg-white p-4 rounded shadow">
        <h2 className="text-lg font-semibold mb-2">프로젝트</h2>
        <form onSubmit={createProject} className="space-y-2 mb-4">
          <input
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            placeholder="신규 프로젝트 이름"
            className="w-full rounded border px-2 py-1"
          />
          <input
            value={newDesc}
            onChange={(e) => setNewDesc(e.target.value)}
            placeholder="설명 (선택)"
            className="w-full rounded border px-2 py-1"
          />
          <button className="w-full bg-brand-accent text-white px-3 py-1 rounded">
            생성
          </button>
        </form>
        <ul className="divide-y">
          {projects.map((p) => (
            <li
              key={p.id}
              className={`py-2 ${
                selectedId === p.id
                  ? "font-semibold text-brand-accent"
                  : ""
              }`}
            >
              <div className="flex justify-between items-center">
                <button
                  className="text-left flex-1"
                  onClick={() => setSelectedId(p.id)}
                >
                  {p.name}
                </button>
                <Link
                  to={`/projects/${p.id}`}
                  className="text-[10px] text-brand-accent underline"
                >
                  상세
                </Link>
              </div>
              <div className="text-xs text-slate-500 truncate">
                {p.description || p.repo_url || "—"}
              </div>
            </li>
          ))}
        </ul>
      </section>

      <section className="col-span-8 bg-white p-4 rounded shadow">
        <h2 className="text-lg font-semibold mb-2">스캔</h2>
        {selectedId ? (
          <>
            <div className="flex gap-1 border-b mb-3">
              <Tab m="path" label="서버 경로" />
              <Tab m="upload" label="ZIP 업로드" />
              <Tab m="git" label="Git URL" />
            </div>

            <form onSubmit={queueScan} className="space-y-3 mb-4">
              {mode === "path" && (
                <div>
                  <label className="text-xs text-slate-500">
                    api/worker 컨테이너 내에서 접근 가능한 절대 경로. <br />
                    Docker 기본 구성에서는 <code>/var/aisast-work/sources/…</code>{" "}
                    또는 호스트에서 바인드 마운트한 경로를 사용하세요.
                  </label>
                  <input
                    value={scanPath}
                    onChange={(e) => setScanPath(e.target.value)}
                    placeholder="/var/aisast-work/sources/my-project"
                    className="w-full rounded border px-2 py-1 font-mono text-sm"
                  />
                </div>
              )}

              {mode === "upload" && (
                <div>
                  <label className="text-xs text-slate-500 block mb-1">
                    소스코드 디렉터리를 <b>.zip</b> 으로 압축해 업로드 (최대 500MB).
                  </label>
                  <input
                    ref={archiveInputRef}
                    type="file"
                    accept=".zip,application/zip"
                    onChange={(e) =>
                      setArchive(e.target.files?.[0] ?? null)
                    }
                    className="block w-full text-sm"
                  />
                  {archive && (
                    <p className="text-xs text-slate-600 mt-1">
                      선택됨: {archive.name} (
                      {(archive.size / 1024 / 1024).toFixed(1)} MB)
                    </p>
                  )}
                </div>
              )}

              {mode === "git" && (
                <div className="space-y-2">
                  <label className="text-xs text-slate-500">
                    공개 저장소 URL 또는 토큰 포함 URL. <br />
                    예:{" "}
                    <code>https://github.com/OWASP/NodeGoat.git</code>
                  </label>
                  <input
                    value={gitUrl}
                    onChange={(e) => setGitUrl(e.target.value)}
                    placeholder="https://github.com/..."
                    className="w-full rounded border px-2 py-1 font-mono text-sm"
                  />
                  <input
                    value={gitBranch}
                    onChange={(e) => setGitBranch(e.target.value)}
                    placeholder="브랜치 (선택, 기본: 기본 브랜치)"
                    className="w-full rounded border px-2 py-1 font-mono text-sm"
                  />
                </div>
              )}

              <div className="grid grid-cols-3 gap-2 text-sm">
                <input
                  value={languageHint}
                  onChange={(e) => setLanguageHint(e.target.value)}
                  placeholder="언어 힌트 (예: java)"
                  className="rounded border px-2 py-1"
                />
                <label className="flex items-center gap-1">
                  <input
                    type="checkbox"
                    checked={secondPass}
                    onChange={(e) => setSecondPass(e.target.checked)}
                  />
                  2차 Pass
                </label>
                <label className="flex items-center gap-1">
                  <input
                    type="checkbox"
                    checked={triage}
                    onChange={(e) => setTriage(e.target.checked)}
                  />
                  LLM Triage
                </label>
              </div>

              {error && (
                <p className="text-red-600 text-xs whitespace-pre-wrap">
                  {error}
                </p>
              )}

              <button
                type="submit"
                disabled={busy}
                className="bg-brand-accent text-white px-4 py-2 rounded disabled:opacity-50"
              >
                {busy ? "요청 중…" : "스캔 시작"}
              </button>
            </form>

            <table className="w-full text-sm">
              <thead>
                <tr className="text-left border-b">
                  <th className="py-1">스캔 ID</th>
                  <th>상태</th>
                  <th>경로</th>
                  <th>시작</th>
                  <th>리포트</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((s) => (
                  <tr key={s.id} className="border-b">
                    <td className="py-1">
                      <Link
                        to={`/scans/${s.id}`}
                        className="text-brand-accent hover:underline font-mono"
                      >
                        {s.id}
                      </Link>
                    </td>
                    <td>{s.status}</td>
                    <td className="truncate max-w-xs font-mono text-xs">
                      {s.source_path}
                    </td>
                    <td className="text-xs">{s.started_at ?? "-"}</td>
                    <td className="space-x-2">
                      <a
                        className="text-xs underline"
                        href={`/api/reports/${s.id}/sarif`}
                        target="_blank"
                      >
                        SARIF
                      </a>
                      <a
                        className="text-xs underline"
                        href={`/api/reports/${s.id}/excel`}
                        target="_blank"
                      >
                        Excel
                      </a>
                      <a
                        className="text-xs underline"
                        href={`/api/reports/${s.id}/html`}
                        target="_blank"
                      >
                        HTML
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        ) : (
          <p className="text-slate-500">좌측에서 프로젝트를 선택하세요.</p>
        )}
      </section>
    </div>
  );
}
