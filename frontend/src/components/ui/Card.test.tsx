import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { Panel, StatCard } from "./Card";

describe("StatCard", () => {
  it("renders label, value, hint", () => {
    render(<StatCard label="총 이슈" value={42} hint="오늘 기준" />);
    expect(screen.getByText("총 이슈")).toBeInTheDocument();
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByText("오늘 기준")).toBeInTheDocument();
  });

  it("applies high tone class", () => {
    render(<StatCard label="HIGH" value={5} tone="high" />);
    const value = screen.getByText("5");
    expect(value.className).toMatch(/red/);
  });
});

describe("Panel", () => {
  it("renders title and children", () => {
    render(
      <Panel title="대시보드">
        <p>본문</p>
      </Panel>
    );
    expect(screen.getByRole("heading", { name: "대시보드" })).toBeInTheDocument();
    expect(screen.getByText("본문")).toBeInTheDocument();
  });

  it("renders action node", () => {
    render(
      <Panel title="t" action={<button>버튼</button>}>
        <span />
      </Panel>
    );
    expect(screen.getByRole("button", { name: "버튼" })).toBeInTheDocument();
  });
});
