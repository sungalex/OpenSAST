# 데이터베이스

> 이 문서는 `docs/USER_GUIDE.md`(1,926줄 단일 파일)를 독자별로 분할한 것이다
> ([ADR-0003](../adr/0003-documentation-architecture.md)).

> **정본 주의**
>
> **스키마의 정본은 `opensast/db/models.py` 와 `alembic/versions/` 다.**
> 아래 설명은 개요이며, 컬럼 단위 사실은 코드를 보라.

---

## 데이터베이스 스키마

`opensast/db/models.py` (SQLAlchemy 2.0 Declarative):

| 테이블 | 주요 컬럼 | 관계 |
|--------|----------|------|
| `users` | `id`, `email`(unique), `hashed_password`, `role`, `is_active` | — |
| `projects` | `id`, `name`(unique), `description`, `repo_url`, `default_language`, `owner_id` | 1:N `scans` |
| `scans` | `id`(12자 hex), `project_id`, `source_path`, `status`, `error`, `started_at`, `finished_at`, `engine_stats`(JSON), `mois_coverage`(JSON) | 1:N `findings` |
| `findings` | `id`, `scan_id`, `finding_hash`, `rule_id`, `engine`, `message`, `severity`, `file_path`, `start_line`, `end_line`, `cwe_ids`(JSON), `mois_id`, `category`, `language`, `snippet`, `raw`(JSON) | 1:1 `triage` |
| `triage_records` | `id`, `finding_id`(unique), `verdict`, `fp_probability`, `rationale`, `recommended_fix`, `patched_code`, `model` | — |

스키마는 `startup` 이벤트에서 `Base.metadata.create_all()` 로 자동 생성된다. 운영
배포 시에는 Alembic 마이그레이션으로 전환하는 것을 권장한다.

> **v0.5.0 복합 인덱스**: Finding(`scan_id+severity`, `scan_id+mois_id`,
> `scan_id+status`), Scan(`project_id+status`, `started_at DESC`),
> AuditLog(`action+created_at`), SuppressionRule(`project_id+kind`) 총 7개
> 복합 인덱스가 추가되어 대규모 데이터 조회 성능이 개선되었다.

---
