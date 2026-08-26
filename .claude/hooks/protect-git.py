#!/usr/bin/env python3
"""master 직접 조작·강제 푸시 차단 (PreToolUse: Bash).

CLAUDE.md 의 'master 를 직접 조작하지 않는다 / --force 푸시 금지' 를 기계적으로 강제한다.
어떤 예외가 나더라도 조용히 통과시킨다 (fail-open).
"""
import json
import re
import subprocess
import sys

PROTECTED = {"master", "main"}


def current_branch(cwd):
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=cwd, capture_output=True, text=True, timeout=5,
        )
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception:
        return ""


def deny(reason):
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": f"[OpenSAST 워크플로] {reason}",
        }
    }, ensure_ascii=False))


def main():
    payload = json.load(sys.stdin)
    cmd = (payload.get("tool_input") or {}).get("command") or ""
    if "git" not in cmd:
        return
    cwd = payload.get("cwd") or "."

    if re.search(r"\bgit\s+push\b.*(--force\b|--force-with-lease\b|\s-f\b)", cmd):
        return deny(
            "--force 푸시는 금지되어 있습니다. 이력이 꼬였다면 되살리지 말고 "
            "브랜치를 지우고 깨끗한 브랜치를 새로 만드세요."
        )

    if re.search(r"\bgit\s+push\b[^|;&]*\b(origin\s+)?(master|main)\b", cmd):
        return deny(
            "master/main 으로 직접 푸시하지 않습니다. 브랜치 → PR → squash merge "
            "→ 브랜치 삭제 순서를 따르세요. (/ship 스킬 참고)"
        )

    # 명시적 refspec 없는 bare push 는 현재 브랜치를 밀어 올린다
    bare_push = bool(re.search(r"\bgit\s+push\b(\s+(-u|--set-upstream))?(\s+\w[\w./-]*)?\s*$", cmd))

    if bare_push or re.search(r"\bgit\s+(commit|merge|rebase|reset\s+--hard)\b", cmd):
        br = current_branch(cwd)
        if br in PROTECTED:
            return deny(
                f"현재 브랜치가 '{br}' 입니다. master/main 을 직접 조작하지 않습니다. "
                f"먼저 작업 브랜치를 만드세요: git switch -c feat/<주제> (/ship 스킬 참고)"
            )


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass  # fail-open
    sys.exit(0)
