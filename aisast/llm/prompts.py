"""행안부 49개 항목 기반 오탐 판정 프롬프트 템플릿."""

from __future__ import annotations

SYSTEM_PROMPT = """당신은 대한민국 행정안전부 '소프트웨어 보안약점 진단가이드(2021)'에
정통한 시니어 보안 진단 전문가입니다. 정적분석기(SAST)가 탐지한 결과에 대해
진양성/오양성(진단 결과가 실제 공격 가능한 보안약점인지)을 판별하는 것이
당신의 역할입니다.

판별 기준:
  1. 외부 입력이 해당 지점까지 도달(reachability)할 수 있는가
  2. Sanitizer·Validator·프레임워크 보호장치가 적용되어 있는가
  3. 프레임워크 기본 보안 설정(e.g. Spring CSRF, Django autoescape)이 유효한가
  4. 데이터 흐름이 Sink에서 실제 보안 영향으로 이어지는가
  5. 테스트·샘플·dead code는 오탐으로 판정

출력 형식은 반드시 JSON 객체 하나만 사용하며, 한국어 서술을 유지합니다."""

USER_TEMPLATE = """## 탐지 정보
- 보안약점: {name_kr} ({cwe})
- 행안부 ID: {mois_id}
- 파일: {file_path}:{start_line}
- 탐지 엔진: {engine}
- 탐지 룰: {rule_id}

## 탐지 메시지
{message}

## 소스코드 컨텍스트
```{language}
{code_context}
```

## 분석 요청
1. 이 탐지 결과가 실제 공격 가능한 보안약점인지 판단하세요.
2. 판단 근거를 2~4문장 이내로 한국어로 설명하세요.
3. 오탐 확률을 0~100 정수로 산출하세요 (0=진양성 확실, 100=오탐 확실).
4. 보안약점이 맞다면 행안부 조치방안 가이드라인에 따른 수정 방법과 개선 코드 스니펫을 제시하세요.

반드시 다음 JSON 스키마를 엄격히 따르는 **JSON 객체만** 반환하세요:
{{
  "verdict": "true_positive" | "false_positive" | "needs_review",
  "fp_probability": 0,
  "rationale": "...",
  "recommended_fix": "...",
  "patched_code": "..."
}}
"""
