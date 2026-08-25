# 리포트 포맷

> 이 문서는 `docs/USER_GUIDE.md`(1,926줄 단일 파일)를 독자별로 분할한 것이다
> ([ADR-0007](../adr/0007-documentation-architecture.md)).

---

## 리포트 포맷

`opensast/reports/__init__.py::build_reports()` 가 한 번에 4가지 아티팩트를 만든다.

| 포맷 | 구현 | 용도 |
|------|------|------|
| **SARIF 2.1.0** | `reports/sarif.py::build_sarif` | 도구 간 상호 운용 |
| **HTML** | `reports/html.py::build_html` + `templates/report.html.j2` | 웹 인터랙티브 리포트 |
| **Excel** | `reports/excel.py::build_excel` | 감리용 3시트 (진단요약/상세결과/49개항목) |
| **PDF** | `reports/pdf.py::build_pdf` | WeasyPrint 기반, 라이브러리 부재 시 HTML 폴백 |

### HTML 섹션

1. 스캔 메타데이터 (ID, 대상, 기간, 상태)
2. 심각도별 건수
3. **49개 항목 커버리지 표** (MOIS ID · 항목명 · 분류 · 탐지 건수)
4. 각 Finding 상세 (심각도 배지, MOIS/CWE, 위치, 코드 스니펫, LLM 판정/조치 방안/수정 코드)

### Excel 시트

- **진단요약**: 스캔 메타
- **상세결과**: 심각도·MOIS·분류·CWE·파일·라인·엔진·룰·메시지·LLM 판정·오탐확률·조치방안
- **49개항목**: 전체 49개 행(0 건 포함), 적합/부적합 열

---
