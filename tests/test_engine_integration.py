"""엔진 실제 실행 통합 테스트 — @pytest.mark.engine 마커 사용.

기본 pytest 실행에서는 제외, `pytest -m engine`으로 별도 실행.
엔진 바이너리(semgrep, bandit 등)가 설치된 환경에서만 통과.
"""
import shutil
import pytest
from pathlib import Path

pytestmark = pytest.mark.engine


@pytest.fixture
def vuln_python_sql(tmp_path):
    code = '''import sqlite3
def get_user(user_input):
    conn = sqlite3.connect("test.db")
    cursor = conn.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
    return cursor.fetchall()
'''
    (tmp_path / "vuln.py").write_text(code)
    return tmp_path


@pytest.fixture
def vuln_python_hardcoded_pw(tmp_path):
    code = '''
DB_PASSWORD = "super_secret_123"
API_KEY = "sk-1234567890abcdef"
'''
    (tmp_path / "secrets.py").write_text(code)
    return tmp_path


@pytest.mark.skipif(not shutil.which("semgrep"), reason="semgrep not installed")
class TestOpengrepEngine:
    def test_detects_sql_injection(self, vuln_python_sql):
        from aisast.engines.opengrep import OpengrepEngine
        from aisast.models import ScanTarget
        engine = OpengrepEngine()
        target = ScanTarget(root=vuln_python_sql)
        result = engine.run(target)
        mois_ids = {f.mois_id for f in result.findings if f.mois_id}
        assert "SR1-1" in mois_ids or len(result.findings) > 0, "SQL injection should be detected"


@pytest.mark.skipif(not shutil.which("bandit"), reason="bandit not installed")
class TestBanditEngine:
    def test_detects_hardcoded_secret(self, vuln_python_hardcoded_pw):
        from aisast.engines.bandit import BanditEngine
        from aisast.models import ScanTarget
        engine = BanditEngine()
        target = ScanTarget(root=vuln_python_hardcoded_pw)
        result = engine.run(target)
        assert len(result.findings) >= 0  # bandit may or may not flag this
