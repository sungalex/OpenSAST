import { describe, expect, it } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import NlSearchBox from "./NlSearchBox";
import { loginAsAdmin, renderWithRouter } from "../test/test-utils";

describe("NlSearchBox", () => {
  it("submits query and renders results from API", async () => {
    loginAsAdmin();
    const user = userEvent.setup();
    renderWithRouter(<NlSearchBox />);

    const input = screen.getByPlaceholderText(/예:/);
    await user.type(input, "SQL 삽입 보여줘");
    await user.click(screen.getByRole("button", { name: "검색" }));

    await waitFor(() => {
      expect(
        screen.getByText(/자연어 결과: SQL 삽입 보여줘/)
      ).toBeInTheDocument();
    });
  });

  it("does nothing on empty submit", async () => {
    loginAsAdmin();
    const user = userEvent.setup();
    renderWithRouter(<NlSearchBox />);
    await user.click(screen.getByRole("button", { name: "검색" }));
    expect(screen.queryByText(/자연어 결과/)).not.toBeInTheDocument();
  });
});
