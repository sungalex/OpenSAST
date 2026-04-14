import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { useAuthStore } from "./store/auth";
import LoginPage from "./pages/Login";
import DashboardPage from "./pages/Dashboard";
import ProjectsPage from "./pages/Projects";
import ProjectDetailPage from "./pages/ProjectDetail";
import IssueSearchPage from "./pages/IssueSearch";
import RuleSetsPage from "./pages/RuleSets";
import AuditLogPage from "./pages/AuditLog";
import ScanDetailPage from "./pages/ScanDetail";
import MoisCatalogPage from "./pages/MoisCatalog";

function Protected({ children }: { children: JSX.Element }) {
  const token = useAuthStore((s) => s.token);
  return token ? children : <Navigate to="/login" replace />;
}

function AdminOnly({ children }: { children: JSX.Element }) {
  const role = useAuthStore((s) => s.role);
  return role === "admin" ? children : <Navigate to="/dashboard" replace />;
}

function NavItem({ to, label }: { to: string; label: string }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        `px-3 py-1 rounded text-sm transition-colors ${
          isActive
            ? "bg-white text-brand font-semibold"
            : "text-slate-200 hover:text-white hover:bg-slate-700"
        }`
      }
    >
      {label}
    </NavLink>
  );
}

function Shell({ children }: { children: JSX.Element }) {
  const logout = useAuthStore((s) => s.logout);
  const role = useAuthStore((s) => s.role);
  return (
    <div className="min-h-screen flex flex-col">
      <header className="bg-brand text-white px-6 py-3 flex justify-between items-center shadow-md">
        <div className="flex items-center gap-6">
          <span className="text-xl font-bold tracking-tight">aiSAST</span>
          <nav className="flex gap-1">
            <NavItem to="/dashboard" label="대시보드" />
            <NavItem to="/issues" label="이슈 검색" />
            <NavItem to="/projects" label="프로젝트" />
            <NavItem to="/rule-sets" label="체커 그룹" />
            <NavItem to="/mois" label="49개 항목" />
            {role === "admin" && <NavItem to="/audit" label="감사 로그" />}
          </nav>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-slate-300">role={role}</span>
          <button
            className="text-sm bg-slate-700 px-3 py-1 rounded hover:bg-slate-600"
            onClick={logout}
          >
            로그아웃
          </button>
        </div>
      </header>
      <main className="flex-1 p-6 max-w-screen-2xl mx-auto w-full">
        {children}
      </main>
      <footer className="text-xs text-slate-500 text-center py-3 border-t">
        aiSAST · 행안부 49개 보안약점 진단 · Apache-2.0
      </footer>
    </div>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/dashboard"
        element={
          <Protected>
            <Shell>
              <DashboardPage />
            </Shell>
          </Protected>
        }
      />
      <Route
        path="/issues"
        element={
          <Protected>
            <Shell>
              <IssueSearchPage />
            </Shell>
          </Protected>
        }
      />
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
        path="/projects/:projectId"
        element={
          <Protected>
            <Shell>
              <ProjectDetailPage />
            </Shell>
          </Protected>
        }
      />
      <Route
        path="/rule-sets"
        element={
          <Protected>
            <Shell>
              <RuleSetsPage />
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
      <Route
        path="/audit"
        element={
          <Protected>
            <AdminOnly>
              <Shell>
                <AuditLogPage />
              </Shell>
            </AdminOnly>
          </Protected>
        }
      />
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}
