import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { Badge, severityTone, statusLabel, statusTone } from "./Badge";

describe("Badge", () => {
  it("renders children", () => {
    render(<Badge>HIGH</Badge>);
    expect(screen.getByText("HIGH")).toBeInTheDocument();
  });

  it("applies tone class", () => {
    render(<Badge tone="high">x</Badge>);
    const el = screen.getByText("x");
    expect(el.className).toMatch(/red/);
  });
});

describe("severityTone", () => {
  it("maps severities", () => {
    expect(severityTone("HIGH")).toBe("high");
    expect(severityTone("MEDIUM")).toBe("medium");
    expect(severityTone("LOW")).toBe("low");
    expect(severityTone("UNKNOWN")).toBe("neutral");
  });
});

describe("statusTone", () => {
  it("maps statuses to tones", () => {
    expect(statusTone("new")).toBe("neutral");
    expect(statusTone("confirmed")).toBe("warn");
    expect(statusTone("excluded")).toBe("ok");
    expect(statusTone("rejected")).toBe("high");
    expect(statusTone("fixed")).toBe("ok");
  });
});

describe("statusLabel", () => {
  it("translates statuses to Korean", () => {
    expect(statusLabel("new")).toBe("미확인");
    expect(statusLabel("confirmed")).toBe("확인");
    expect(statusLabel("exclusion_requested")).toBe("제외 신청");
    expect(statusLabel("excluded")).toBe("제외");
    expect(statusLabel("fixed")).toBe("수정 완료");
    expect(statusLabel("rejected")).toBe("거부");
    expect(statusLabel("unknown")).toBe("unknown");
  });
});
