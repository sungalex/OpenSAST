import "@testing-library/jest-dom/vitest";
import { afterAll, afterEach, beforeAll } from "vitest";
import { server } from "./msw-server";

// MSW 라이프사이클
beforeAll(() => server.listen({ onUnhandledRequest: "warn" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

// recharts 가 ResizeObserver 를 사용하므로 jsdom polyfill
class ResizeObserverMock {
  observe() {}
  unobserve() {}
  disconnect() {}
}
// @ts-expect-error: jsdom 에 ResizeObserver 가 없음
globalThis.ResizeObserver = ResizeObserverMock;

// matchMedia (Tailwind 일부 컴포넌트가 사용)
Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  }),
});

// localStorage 클린업 (zustand persist)
beforeAll(() => {
  window.localStorage.clear();
});
