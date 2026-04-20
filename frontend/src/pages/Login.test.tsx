import { describe, expect, it } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import LoginPage from "./Login";
import { loginAsAdmin, logout, renderWithRouter } from "../test/test-utils";
import { useAuthStore } from "../store/auth";

describe("LoginPage", () => {
  it("renders login form with default values", () => {
    logout();
    renderWithRouter(<LoginPage />);
    expect(
      screen.getByRole("heading", { name: /OpenSAST 로그인/i })
    ).toBeInTheDocument();
    const email = screen.getByLabelText(/이메일/i) as HTMLInputElement;
    expect(email.value).toBe("admin@opensast.local");
  });

  it("logs in successfully and stores token", async () => {
    logout();
    const user = userEvent.setup();
    renderWithRouter(<LoginPage />);
    await user.click(screen.getByRole("button", { name: "로그인" }));
    await waitFor(() => {
      expect(useAuthStore.getState().token).toBe("test-jwt-token-fake");
      expect(useAuthStore.getState().role).toBe("admin");
    });
  });

  it("shows error on wrong password", async () => {
    logout();
    const user = userEvent.setup();
    renderWithRouter(<LoginPage />);
    const pw = screen.getByLabelText(/비밀번호/i);
    await user.clear(pw);
    await user.type(pw, "WRONG");
    await user.click(screen.getByRole("button", { name: "로그인" }));
    expect(
      await screen.findByText(/로그인 실패/)
    ).toBeInTheDocument();
  });
});
