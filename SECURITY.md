# Security Policy / 보안 정책

## Supported Versions / 지원 버전

| Version | Supported |
|---------|-----------|
| 0.4.x   | Yes       |
| < 0.4   | No        |

현재 최신 마이너 버전(0.4.x)만 보안 패치를 제공합니다.
Only the latest minor release (0.4.x) receives security patches.

---

## Reporting a Vulnerability / 취약점 신고

보안 취약점을 발견하셨다면 **공개 이슈를 생성하지 마시고** 아래 채널을 통해 비공개로 제보해주세요.

If you discover a security vulnerability, please **do NOT open a public issue**. Instead, report it through one of the following channels:

1. **Email / 이메일**: [security@opensast.dev](mailto:security@opensast.dev)
2. **GitHub Security Advisories**: [Report a vulnerability](https://github.com/sungalex/OpenSAST/security/advisories/new)

### 신고 시 포함할 정보 / What to Include

- 취약점에 대한 상세 설명 (Description of the vulnerability)
- 재현 단계 (Steps to reproduce)
- 영향 범위 (Impact assessment)
- 가능하다면 수정 제안 (Suggested fix, if any)

---

## Response Timeline / 대응 일정

| Stage | Timeline |
|-------|----------|
| 접수 확인 (Acknowledgment) | 72시간 이내 (within 72 hours) |
| 초기 분석 (Initial assessment) | 7일 이내 (within 7 days) |
| 패치 목표 (Patch target) | 30일 이내 (within 30 days) |
| 공개 (Disclosure) | 패치 배포 후 (after patch release) |

긴급도가 높은 취약점(CVSS 9.0+)은 가능한 한 빠르게 대응합니다.
Critical vulnerabilities (CVSS 9.0+) will be prioritized and addressed as quickly as possible.

---

## Scope / 범위

보안 정책이 적용되는 범위는 다음과 같습니다:

The security policy covers the following components:

| Component | Scope |
|-----------|-------|
| 코어 코드 (Core code) | `opensast/` Python 패키지 전체 |
| 분석 룰 (Rules) | `rules/` 디렉토리의 Opengrep YAML 룰 |
| API | FastAPI 기반 REST API 엔드포인트 |
| 프론트엔드 (Frontend) | `frontend/` React 웹 UI |
| Docker 이미지 (Docker images) | 공식 Dockerfile 및 docker-compose 설정 |
| CI/CD | GitHub Actions 워크플로우 설정 |

### 범위 외 항목 / Out of Scope

- 서드파티 분석 엔진 자체의 취약점 (Semgrep, CodeQL, SpotBugs, Bandit, ESLint, gosec)
  - 해당 프로젝트에 직접 신고해주세요 (Please report to the respective projects)
- 사용자 환경의 설정 오류 (Misconfiguration in user environments)
- 프로덕션 배포 인프라 관련 이슈 (Production deployment infrastructure)

---

## Acknowledgments / 감사

보안 취약점을 책임감 있게 제보해주신 분들께 감사드립니다. 요청 시 SECURITY.md 또는 릴리스 노트에 크레딧을 표기합니다.

We appreciate responsible disclosure. Contributors will be credited in release notes upon request.
