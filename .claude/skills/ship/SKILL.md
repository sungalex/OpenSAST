---
name: ship
description: 변경을 브랜치 → PR → squash merge 로 내보낸다. master 직접 조작을 막고, GitGuardian·self-SAST·CI 차단에 대응한다.
argument-hint: [브랜치명 또는 PR 주제]
disable-model-invocation: true
allowed-tools: Bash(git status *) Bash(git diff *) Bash(git switch *) Bash(git add *) Bash(git commit *) Bash(git push *) Bash(git log *) Bash(gh pr *) Bash(gh api *) Bash(.venv/bin/python -m pytest *) Read Grep Glob
---

# 배포 절차 (브랜치 → PR → squash merge)

주제: $ARGUMENTS

## 절대 규칙

1. **`master` 를 직접 조작하지 않는다.** 커밋도, 푸시도, rebase 도.
2. **`pytest` 전량 통과 전에는 PR 을 만들지 않는다.**
3. **`--force` 푸시 금지.** 필요해 보이면 멈추고 이유를 보고한다.
4. **이력이 꼬이면 되살리지 말고 브랜치를 지우고 새로 만든다.**
5. **여러 파일 rename 이 섞인 변경은 파일 전달 대신 패치 한 장**(`git diff > NNNN.patch`)으로.

## 순서

```bash
git status --short
git branch --show-current                     # master 면 즉시 브랜치를 판다
git switch -c <feat|fix|docs|test|ci|chore|refactor|perf>/<주제>

.venv/bin/python -m pytest -q --tb=short      # 필수. 실패하면 여기서 중단
cd frontend && npm test && npx tsc -b --noEmit # 프론트 변경 시

git add -A
git commit -m "<type>(<scope>): <설명>"        # Conventional Commits
git push -u origin HEAD

gh pr create --fill
gh pr checks --watch
```

## PR 본문에 넣을 것

- 변경의 **목적과 영향**
- 관련 이슈 (`Closes #123`)
- security-auditor 리뷰 결과 요약
- 동작이 바뀐 항목 (예: 역할 권한 정정) — 릴리스 노트에도 들어간다

## 체크가 막혔을 때

| 차단 | 대응 |
|---|---|
| **GitGuardian** | 예외로 덮지 말고 **리터럴 자체를 없앤다.** 테스트 자격증명은 `tests/_credentials.py` 런타임 생성. 의도된 취약 픽스처만 `.gitguardian.yaml` 에 **경로 예외**로 두고, 탐지기 단위 비활성화는 하지 않는다. GitHub App 체크는 대시보드를 보므로 **저장소 파일과 대시보드(Settings > Secrets detection > Filepath exclusions) 양쪽**을 맞춰야 한다 |
| **self-SAST HIGH** | security-auditor 에게 정탐/오탐 판정 요청. 억제로 덮지 않는다 |
| **CI 실패** | qa-verifier 에게. 테스트를 느슨하게 만들어 통과시키지 않는다 |
| **리뷰 미승인** | 최소 1명 승인 필요 |

## 머지

```bash
gh pr merge --squash --delete-branch
git switch master && git pull
```

## 릴리스라면

1. 버전은 `pyproject.toml` 만 바꾼다 (현재 0.5.0)
2. `docs/guide/changelog.md` 갱신
3. `docs/ROADMAP.md` 완료 항목을 §7 로 한 줄 이관하고 본문에서 삭제
4. 릴리스 노트에 **동작이 바뀐 항목**을 반드시 명시
