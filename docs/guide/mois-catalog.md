# MOIS 49개 항목 카탈로그

> 이 문서는 `docs/USER_GUIDE.md`(1,926줄 단일 파일)를 독자별로 분할한 것이다
> ([ADR-0007](../adr/0007-documentation-architecture.md)).

---

## MOIS 49개 항목 카탈로그

`opensast/mois/catalog.py`가 **단일 소스**다. 7개 상위 분류와 49개 항목을 정확히 포함한다.

| 분류 | 개수 | 대표 항목 |
|------|------|----------|
| 입력데이터 검증 및 표현 | 18 | SQL 삽입(SR1-1), XSS(SR1-3), 명령어 삽입(SR1-4), SSRF(SR1-11), 역직렬화(SR1-18) |
| 보안기능 | 12 | 하드코드 비밀(SR2-6), 취약한 암호(SR2-4), 인증서 검증 결여(SR2-11) |
| 시간 및 상태 | 2 | TOCTOU(SR3-1), 종료되지 않는 반복(SR3-2) |
| 에러처리 | 3 | 오류메시지 정보노출(SR4-1) |
| 코드오류 | 7 | Null 참조(SR5-1), 자원 누수(SR5-2), Use-After-Free(SR5-3) |
| 캡슐화 | 5 | 디버그 코드 잔존(SR6-2) |
| API 오용 | 2 | DNS 기반 보안 결정(SR7-1), 취약한 API 사용(SR7-2) |

### 조회 API

```python
from opensast.mois.catalog import MOIS_ITEMS, get_item, items_for_cwe

get_item("SR1-1")            # SQL 삽입 항목
items_for_cwe("CWE-89")      # CWE로 역조회 (정수 "89" 도 허용)
```

- 전체 목록은 CLI `opensast list-mois` 또는 API `GET /api/mois/items` 에서도 조회 가능.
- 카탈로그 무결성은 `ensure_49_items()` 헬퍼와 `tests/test_mois_catalog.py`가 보장한다.

---
