import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { useAuthStore } from "./store/auth";
import LoginPage from "./pages/Login";
import ProjectsPage from "./pages/Projects";
import ScanDetailPage from "./pages/ScanDetail";
import MoisCatalogPage from "./pages/MoisCatalog";

function Protected({ children }: { children: JSX.Element }) {
  const token = useAuthStore((s) => s.token);
  return token ? children : <Navigate to="/login" replace />;
}

function Shell({ children }: { children: JSX.Element }) {
  const logout = useAuthStore((s) => s.logout);
  return (
    <div className="min-h-screen flex flex-col">
      <header className="bg-brand text-white px-6 py-4 flex justify-between items-center">
        <div className="flex items-center gap-6">
          <span className="text-xl font-bold">aiSAST</span>
          <nav className="flex gap-4 text-sm">
            <NavLink to="/projects" className="hover:underline">프로젝트</NavLink>
            <NavLink to="/mois" className="hover:underline">49개 항목</NavLink>
          </nav>
        </div>
        <button
          className="text-sm bg-slate-700 px-3 py-1 rounded hover:bg-slate-600"
          onClick={logout}
        >
          로그아웃
        </button>
      </header>
      <main className="flex-1 p-6">{children}</main>
      <footer className="text-xs text-slate-500 text-center py-4">
        행안부 소프트웨어 보안약점 진단가이드(2021) 기반
      </footer>
    </div>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/projects"
        element={
          <Protected>
            <Shell>
              <ProjectsPage />
            </Shell>
          </Protected>
        }
      />
      <Route
        path="/scans/:scanId"
        element={
          <Protected>
            <Shell>
              <ScanDetailPage />
            </Shell>
          </Protected>
        }
      />
      <Route
        path="/mois"
        element={
          <Protected>
            <Shell>
              <MoisCatalogPage />
            </Shell>
          </Protected>
        }
      />
      <Route path="*" element={<Navigate to="/projects" replace />} />
    </Routes>
  );
}
