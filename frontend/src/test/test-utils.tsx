import { ReactElement } from "react";
import { MemoryRouter } from "react-router-dom";
import { render, RenderOptions } from "@testing-library/react";
import { useAuthStore } from "../store/auth";

export function renderWithRouter(
  ui: ReactElement,
  { route = "/", ...options }: { route?: string } & RenderOptions = {}
) {
  return render(
    <MemoryRouter initialEntries={[route]}>{ui}</MemoryRouter>,
    options
  );
}

export function loginAsAdmin() {
  useAuthStore.setState({ token: "test-jwt-token-fake", role: "admin" });
}

export function logout() {
  useAuthStore.setState({ token: null, role: null });
}
