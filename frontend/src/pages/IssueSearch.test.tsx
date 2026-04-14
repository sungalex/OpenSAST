import { describe, expect, it } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import IssueSearchPage from "./IssueSearch";
import { loginAsAdmin, renderWithRouter } from "../test/test-utils";

describe("IssueSearchPage", () => {
  it("renders advanced filter form", () => {
    loginAsAdmin();
    renderWithRouter(<IssueSearchPage />);
    expect(screen.getByText("Advanced Issue Filter")).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/src\/.+\/.*\.py/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /검색 실행/ })).toBeInTheDocument();
  });

  it("submits form and shows MSW-mocked results", async () => {
    loginAsAdmin();
    const user = userEvent.setup();
    renderWithRouter(<IssueSearchPage />);

    await user.click(screen.getByRole("button", { name: /검색 실행/ }));
    // FindingsTable collapsed 행에는 rule_id 와 file_path 가 표시되므로 이걸로 검증
    await waitFor(() => {
      expect(screen.getByText("mois-sr1-1-sql")).toBeInTheDocument();
      expect(screen.getByText("mois-sr2-4-md5")).toBeInTheDocument();
    });
  });

  it("renders NL search box", () => {
    loginAsAdmin();
    renderWithRouter(<IssueSearchPage />);
    expect(
      screen.getByText(/자연어 이슈 검색/)
    ).toBeInTheDocument();
  });
});
