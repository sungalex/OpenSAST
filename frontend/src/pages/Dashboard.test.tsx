import { describe, expect, it } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import DashboardPage from "./Dashboard";
import { loginAsAdmin, renderWithRouter } from "../test/test-utils";

describe("DashboardPage", () => {
  it("renders cards with totals from API", async () => {
    loginAsAdmin();
    renderWithRouter(<DashboardPage />);

    // 처음에는 로딩 상태
    expect(screen.getByText(/대시보드 로딩 중/)).toBeInTheDocument();

    // overview 응답 후 카드 값
    await waitFor(() => {
      expect(screen.getByText("프로젝트")).toBeInTheDocument();
      expect(screen.getByText("2")).toBeInTheDocument(); // projects
      expect(screen.getByText("42")).toBeInTheDocument(); // findings
      expect(screen.getByText("7")).toBeInTheDocument(); // HIGH
    });
  });

  it("renders MOIS coverage table with seeded items", async () => {
    loginAsAdmin();
    renderWithRouter(<DashboardPage />);
    await waitFor(() => {
      expect(screen.getByText("MOIS 49개 항목 커버리지")).toBeInTheDocument();
      expect(screen.getByText("SR1-1")).toBeInTheDocument();
      expect(screen.getByText("SR3-1")).toBeInTheDocument();
    });
  });

  it("renders TOP rules table", async () => {
    loginAsAdmin();
    renderWithRouter(<DashboardPage />);
    await waitFor(() => {
      expect(screen.getByText("TOP 10 룰")).toBeInTheDocument();
    });
  });
});
