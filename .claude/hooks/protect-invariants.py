#!/usr/bin/env python3
"""OpenSAST 저장소 불변식 보호 (PreToolUse: Edit|Write|MultiEdit|NotebookEdit).

CLAUDE.md 에 글로 적힌 규칙 중 '어겼을 때 되돌리기 어려운' 것만 기계적으로 막는다.
어떤 예외가 나더라도 조용히 통과시킨다 (fail-open) — 훅이 작업을 막아서는 안 된다.
"""
import json
import re
import sys

# (정규식, 사유, 결정)  결정: deny = 차단, ask = 사용자에게 확인
GUARDS = [
    (
        r"(^|/)tests/vulnerable-samples/",
        "tests/vulnerable-samples/ 는 탐지 룰 검증용으로 '의도적으로 취약한' 코드입니다. "
        "여기의 취약점은 수정 대상이 아니라 정탐 근거입니다. "
        "룰을 조여야 하는 상황이라면 rules/ 를 고치세요.",
        "deny",
    ),
    (
        r"(^|/)tests/test_engine_integration\.py$",
        "tests/test_engine_integration.py 는 의도적으로 취약한 픽스처를 담고 있습니다. "
        "탐지력의 근거이므로 '고치지' 않습니다.",
        "deny",
    ),
    (
        r"(^|/)alembic/versions/0001[^/]*\.py$",
        "Alembic 리비전 0001 은 동결된 명시적 DDL 입니다. 여기를 수정하거나 "
        "Base.metadata.create_all() 을 되돌리면 마이그레이션 체인 전체가 깨집니다. "
        "스키마 변경은 새 리비전으로만 하세요.",
        "deny",
    ),
    (
        r"(^|/)docs/reviews/",
        "docs/reviews/ 는 감사 시점에 동결된 문서입니다 (ADR-0007). 본문을 고치지 말고, "
        "정정이 필요하면 문서 상단 박스에 정정 사항만 덧붙이세요.",
        "ask",
    ),
    (
        r"(^|/)docs/adr/\d{4}-[^/]*\.md$",
        "ADR 은 원칙적으로 수정하지 않습니다 (ADR-0007). 결정이 바뀌면 새 ADR 을 쓰고 "
        "옛 ADR 의 Status 만 'Superseded by ADR-NNNN' 으로 바꿉니다. "
        "Status 전환이나 오탈자 수정이라면 진행해도 됩니다.",
        "ask",
    ),
    (
        r"(^|/)\.env$",
        ".env 에는 실제 시크릿이 들어 있습니다. 설정 항목을 추가하려면 .env.example 을 "
        "고치세요 (키와 설명만, 값은 넣지 않습니다).",
        "deny",
    ),
]


def target_paths(tool_input):
    out = []
    for key in ("file_path", "notebook_path", "path"):
        v = tool_input.get(key)
        if isinstance(v, str):
            out.append(v)
    for e in tool_input.get("edits", []) or []:
        if isinstance(e, dict) and isinstance(e.get("file_path"), str):
            out.append(e["file_path"])
    return out


def main():
    payload = json.load(sys.stdin)
    tool_input = payload.get("tool_input") or {}
    for path in target_paths(tool_input):
        norm = path.replace("\\", "/")
        for pattern, reason, decision in GUARDS:
            if re.search(pattern, norm):
                print(json.dumps({
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny" if decision == "deny" else "escalate",
                        "permissionDecisionReason": f"[OpenSAST 불변식] {reason}",
                    }
                }, ensure_ascii=False))
                return
    # 해당 없음 — 통상 권한 흐름으로


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass  # fail-open: 훅 오류가 작업을 막지 않는다
    sys.exit(0)
