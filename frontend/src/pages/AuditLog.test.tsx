import { describe, expect, it } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import AuditLogPage from "./AuditLog";
import { loginAsAdmin, renderWithRouter } from "../test/test-utils";

describe("AuditLogPage", () => {
  it("renders audit log entries from API", async () => {
    loginAsAdmin();
    renderWithRouter(<AuditLogPage />);
    expect(screen.getByRole("heading", { name: /감사 로그/ })).toBeInTheDocument();
    // 고유 텍스트 (IP) 로 row 존재를 검증 — 드롭다운 옵션과 텍스트 충돌 회피
    await waitFor(() => {
      expect(screen.getByText("127.0.0.1")).toBeInTheDocument();
    });
    // 'auth.login' 은 select option 과 row 둘 다에서 등장할 수 있음
    const occurrences = screen.getAllByText("auth.login");
    expect(occurrences.length).toBeGreaterThanOrEqual(1);
  });
});
