import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import FindingsTable from "./FindingsTable";
import { Finding } from "../api/client";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 1,
    scan_id: "s1",
    rule_id: "mois-sr1-1-sql",
    engine: "opengrep",
    severity: "HIGH",
    message: "SQL 삽입 탐지",
    file_path: "src/db.py",
    start_line: 42,
    end_line: 42,
    cwe_ids: ["CWE-89"],
    mois_id: "SR1-1",
    category: "입력데이터 검증 및 표현",
    language: "python",
    snippet: "cursor.execute(f\"SELECT {x}\")",
    status: "new",
    status_reason: null,
    reviewed_by: null,
    triage: null,
    references: [
      { standard: "CWE", id: "CWE-89", title: "CWE-89", url: "" },
      { standard: "OWASP-2021", id: "A03", title: "Injection", url: "" },
      { standard: "SANS-25", id: "#3", title: "SANS Top 25 #3", url: "" },
    ],
    ...overrides,
  };
}

describe("FindingsTable", () => {
  it("renders empty state when no findings", () => {
    render(<FindingsTable findings={[]} />);
    expect(screen.getByText("탐지 결과 없음")).toBeInTheDocument();
  });

  it("renders severity, status, mois, references badges", () => {
    render(<FindingsTable findings={[makeFinding()]} />);
    expect(screen.getByText("HIGH")).toBeInTheDocument();
    expect(screen.getByText("미확인")).toBeInTheDocument();
    expect(screen.getByText("SR1-1")).toBeInTheDocument();
    // 레퍼런스 배지 (CWE 는 id 자체로 표시)
    expect(screen.getByText("CWE-89")).toBeInTheDocument();
    expect(screen.getByText(/OWASP-2021/)).toBeInTheDocument();
  });

  it("expands row on click and shows snippet + references links", async () => {
    const user = userEvent.setup();
    render(<FindingsTable findings={[makeFinding()]} />);
    await user.click(screen.getByText("HIGH"));
    expect(screen.getByText(/cursor\.execute/)).toBeInTheDocument();
    // 펼친 후 레퍼런스 링크
    expect(screen.getByRole("link", { name: /CWE CWE-89/i })).toBeInTheDocument();
  });

  it("shows admin-only transition buttons when isAdmin=true", async () => {
    const user = userEvent.setup();
    render(<FindingsTable findings={[makeFinding()]} isAdmin />);
    await user.click(screen.getByText("HIGH"));
    // analyst 전이도 렌더되어야 함 (확인 / 수정 완료 / 제외 신청)
    const buttons = screen.getAllByRole("button");
    const labels = buttons.map((b) => b.textContent ?? "");
    expect(labels.some((l) => l.includes("확인") && !l.includes("admin"))).toBe(
      true
    );
    expect(labels.some((l) => l.includes("제외 신청"))).toBe(true);
    // admin 전용: new → excluded ("(admin)" 라벨 포함)
    const adminLabels = labels.filter((l) => l.includes("admin"));
    expect(adminLabels.length).toBeGreaterThan(0);
  });

  it("hides admin transitions when isAdmin=false", async () => {
    const user = userEvent.setup();
    render(<FindingsTable findings={[makeFinding()]} />);
    await user.click(screen.getByText("HIGH"));
    const buttons = screen.queryAllByRole("button");
    const labels = buttons.map((b) => b.textContent ?? "");
    // (admin) 표시가 있는 버튼이 하나도 없어야 함
    const adminOnly = labels.filter((l) => l.includes("admin"));
    expect(adminOnly.length).toBe(0);
  });
});
