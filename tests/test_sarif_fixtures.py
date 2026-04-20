"""SARIF fixture 파일 파싱 검증."""
import json
import pytest
from pathlib import Path

SARIF_DIR = Path(__file__).parent / "fixtures" / "sarif"

@pytest.fixture(params=sorted(SARIF_DIR.glob("*.sarif.json")) if SARIF_DIR.exists() else [])
def sarif_file(request):
    return request.param

def test_sarif_fixture_is_valid_json(sarif_file):
    data = json.loads(sarif_file.read_text())
    assert data["version"] == "2.1.0"
    assert "runs" in data
    assert isinstance(data["runs"], list)

def test_sarif_fixture_has_tool(sarif_file):
    data = json.loads(sarif_file.read_text())
    for run in data["runs"]:
        assert "tool" in run
        assert "driver" in run["tool"]
        assert "name" in run["tool"]["driver"]
