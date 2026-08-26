---
paths:
  - "frontend/src/**/*.ts"
  - "frontend/src/**/*.tsx"
  - "frontend/*.ts"
  - "frontend/*.js"
  - "frontend/*.json"
---

# 프론트엔드 (React + TypeScript + Tailwind + Vite)

## 게이트

```bash
cd frontend && npm test && npx tsc -b --noEmit
```

CI 는 ubuntu · macOS · Windows 세 곳에서 **동일하게** 통과해야 한다.

## 규약

- ESLint + Prettier 설정은 `frontend/` 안에 있다. 라인 길이·포맷을 임의로 바꾸지 않는다.
- API URL·타임아웃을 컴포넌트에 하드코딩하지 않는다.
- **진단 결과를 화면에서 임의로 감추지 않는다.** 필터는 사용자가 명시적으로 건
  것만 유효하다. 백엔드가 `ScanResult.notes` 에 남긴 축소 사실(2차 Pass 생략,
  triage 상한)은 화면에도 드러나야 한다.
- 새 의존성은 이유를 남긴다 — 번들 크기와 공급망 위험. 이 저장소는 SAST 도구라
  스스로가 예시가 된다.
- 백엔드 응답 스키마를 바꿔야 하면 프론트에서 우회하지 말고 API 쪽에 요청한다.

## 진행 중인 방향 (ROADMAP v0.7)

React Query 도입 · `ErrorBoundary` + toast · 다크모드(`darkMode: 'class'`) ·
a11y(`aria-label`/`role`/키보드) · i18next(한·영, `name_en` 활용) ·
`shiki` 코드 뷰어(±20줄 컨텍스트) · side-by-side diff · `ScanDetail` 의 SSE 전환.
