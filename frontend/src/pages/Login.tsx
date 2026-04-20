import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { useAuthStore } from "../store/auth";

export default function LoginPage() {
  const navigate = useNavigate();
  const setToken = useAuthStore((s) => s.setToken);
  const [email, setEmail] = useState("admin@opensast.local");
  const [password, setPassword] = useState("opensast-admin");
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const { data } = await api.post("/auth/login", { email, password });
      setToken(data.access_token, data.role);
      navigate("/projects");
    } catch {
      setError("로그인 실패: 이메일 또는 비밀번호를 확인하세요.");
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center">
      <form
        onSubmit={handleSubmit}
        className="bg-white shadow-md rounded-lg p-8 w-96 space-y-4"
      >
        <h1 className="text-2xl font-bold text-brand">OpenSAST 로그인</h1>
        <p className="text-sm text-slate-500">
          행안부 49개 보안약점 진단 시스템
        </p>
        <p className="text-xs text-slate-400 bg-slate-50 border border-slate-200 rounded p-2">
          최초 관리자 계정: <code>admin@opensast.local</code> /{" "}
          <code>opensast-admin</code>
          <br />
          (운영 환경에서는 <code>OPENSAST_BOOTSTRAP_ADMIN_*</code> 환경변수로 변경)
        </p>
        <label className="block">
          <span className="text-sm">이메일</span>
          <input
            type="email"
            className="mt-1 block w-full rounded border px-3 py-2"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </label>
        <label className="block">
          <span className="text-sm">비밀번호</span>
          <input
            type="password"
            className="mt-1 block w-full rounded border px-3 py-2"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </label>
        {error && <p className="text-red-600 text-sm">{error}</p>}
        <button
          type="submit"
          className="w-full bg-brand-accent text-white rounded py-2 hover:bg-blue-700"
        >
          로그인
        </button>
      </form>
    </div>
  );
}
