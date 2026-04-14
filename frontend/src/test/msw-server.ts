import { setupServer } from "msw/node";
import { http, HttpResponse } from "msw";

const ADMIN_TOKEN = "test-jwt-token-fake";

export const handlers = [
  // 인증
  http.post("/api/auth/login", async ({ request }) => {
    const body = (await request.json()) as { email: string; password: string };
    if (
      body.email === "admin@aisast.local" &&
      body.password === "aisast-admin"
    ) {
      return HttpResponse.json({
        access_token: ADMIN_TOKEN,
        token_type: "bearer",
        role: "admin",
      });
    }
    return HttpResponse.json({ detail: "invalid credentials" }, { status: 401 });
  }),

  // 대시보드
  http.get("/api/dashboard/overview", () =>
    HttpResponse.json({
      totals: {
        projects: 2,
        scans: 5,
        findings: 42,
        high: 7,
        medium: 20,
        low: 15,
      },
      status_counts: { new: 30, confirmed: 10, excluded: 2 },
      latest_scan: {
        id: "abc123def456",
        project_id: 1,
        status: "completed",
        created_at: "2026-04-15T10:00:00Z",
      },
    })
  ),
  http.get("/api/dashboard/trends", () =>
    HttpResponse.json({
      days: 30,
      timeline: [
        { date: "2026-04-13", scans: 1, findings: 10 },
        { date: "2026-04-14", scans: 2, findings: 20 },
        { date: "2026-04-15", scans: 2, findings: 12 },
      ],
    })
  ),
  http.get("/api/dashboard/top-rules", () =>
    HttpResponse.json({
      top: [
        { rule_id: "mois-sr1-1-sql", engine: "opengrep", count: 12 },
        { rule_id: "mois-sr1-3-xss", engine: "opengrep", count: 8 },
        { rule_id: "B324", engine: "bandit", count: 4 },
      ],
    })
  ),
  http.get("/api/dashboard/mois-coverage", () =>
    HttpResponse.json({
      total_items: 49,
      covered_items: 3,
      coverage_ratio: 0.061,
      items: [
        {
          mois_id: "SR1-1",
          name_kr: "SQL 삽입",
          category: "입력데이터 검증 및 표현",
          severity: "HIGH",
          count: 12,
          covered: true,
        },
        {
          mois_id: "SR3-1",
          name_kr: "TOCTOU",
          category: "시간 및 상태",
          severity: "MEDIUM",
          count: 0,
          covered: false,
        },
      ],
    })
  ),
  http.get("/api/dashboard/category-distribution", () =>
    HttpResponse.json({
      categories: [
        { name: "입력데이터 검증 및 표현", count: 20 },
        { name: "보안기능", count: 12 },
      ],
    })
  ),

  // 프로젝트
  http.get("/api/projects", () =>
    HttpResponse.json([
      {
        id: 1,
        name: "test-proj",
        description: "msw fixture",
        repo_url: "",
        default_language: "python",
        created_at: "2026-04-15T00:00:00Z",
      },
    ])
  ),
  http.post("/api/projects", async ({ request }) => {
    const body = (await request.json()) as { name: string };
    return HttpResponse.json(
      {
        id: 2,
        name: body.name,
        description: "",
        repo_url: "",
        default_language: null,
        created_at: "2026-04-15T01:00:00Z",
      },
      { status: 201 }
    );
  }),

  // RuleSets
  http.get("/api/rule-sets", () =>
    HttpResponse.json([
      {
        id: 1,
        name: "default-strict",
        description: "default",
        enabled_engines: ["opengrep", "bandit"],
        include_rules: [],
        exclude_rules: [],
        min_severity: "MEDIUM",
        is_default: true,
      },
    ])
  ),
  http.post("/api/rule-sets", async ({ request }) => {
    const body = (await request.json()) as Record<string, unknown>;
    return HttpResponse.json(
      { id: 99, ...body },
      { status: 201 }
    );
  }),

  // Findings 검색 + 자연어
  http.get("/api/findings/search", ({ request }) => {
    const url = new URL(request.url);
    const sev = url.searchParams.getAll("severity");
    const all = [
      {
        id: 1,
        scan_id: "abc",
        rule_id: "mois-sr1-1-sql",
        engine: "opengrep",
        severity: "HIGH",
        message: "SQL 삽입 탐지",
        file_path: "src/db.py",
        start_line: 10,
        end_line: 10,
        cwe_ids: ["CWE-89"],
        mois_id: "SR1-1",
        category: "입력데이터 검증 및 표현",
        language: "python",
        snippet: 'cursor.execute(f"... {x}")',
        status: "new",
        status_reason: null,
        reviewed_by: null,
        triage: null,
        references: [
          { standard: "CWE", id: "CWE-89", title: "CWE-89", url: "" },
          { standard: "OWASP-2021", id: "A03", title: "Injection", url: "" },
        ],
      },
      {
        id: 2,
        scan_id: "abc",
        rule_id: "mois-sr2-4-md5",
        engine: "bandit",
        severity: "MEDIUM",
        message: "weak hash",
        file_path: "src/util.py",
        start_line: 5,
        end_line: 5,
        cwe_ids: ["CWE-327"],
        mois_id: "SR2-4",
        category: "보안기능",
        language: "python",
        snippet: null,
        status: "new",
        status_reason: null,
        reviewed_by: null,
        triage: null,
        references: [
          { standard: "CWE", id: "CWE-327", title: "CWE-327", url: "" },
        ],
      },
    ];
    if (sev.length === 0) return HttpResponse.json(all);
    return HttpResponse.json(all.filter((f) => sev.includes(f.severity)));
  }),
  http.post("/api/findings/ask", async ({ request }) => {
    const body = (await request.json()) as { query: string };
    return HttpResponse.json([
      {
        id: 99,
        scan_id: "abc",
        rule_id: "mois-sr1-1-sql",
        engine: "opengrep",
        severity: "HIGH",
        message: `자연어 결과: ${body.query}`,
        file_path: "src/db.py",
        start_line: 1,
        end_line: 1,
        cwe_ids: ["CWE-89"],
        mois_id: "SR1-1",
        category: "입력데이터 검증 및 표현",
        language: "python",
        snippet: null,
        status: "new",
        status_reason: null,
        reviewed_by: null,
        triage: null,
        references: [],
      },
    ]);
  }),
  http.post("/api/findings/:id/status", async ({ params, request }) => {
    const body = (await request.json()) as { status: string; reason?: string };
    return HttpResponse.json({
      id: Number(params.id),
      scan_id: "abc",
      rule_id: "x",
      engine: "opengrep",
      severity: "HIGH",
      message: "x",
      file_path: "x.py",
      start_line: 1,
      end_line: 1,
      cwe_ids: [],
      mois_id: null,
      category: null,
      language: null,
      snippet: null,
      status: body.status,
      status_reason: body.reason ?? null,
      reviewed_by: 1,
      triage: null,
      references: [],
    });
  }),

  // 감사 로그
  http.get("/api/admin/audit", () =>
    HttpResponse.json([
      {
        id: 1,
        user_id: 1,
        action: "auth.login",
        target_type: "user",
        target_id: "1",
        detail: { ok: true },
        ip: "127.0.0.1",
        created_at: "2026-04-15T10:00:00Z",
      },
    ])
  ),
];

export const server = setupServer(...handlers);
