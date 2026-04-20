"""Typer CLI 명령 출력 검증."""

from __future__ import annotations

from typer.testing import CliRunner

from opensast.cli import app

runner = CliRunner()


def test_cli_help() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.stdout
    assert "list-mois" in result.stdout
    assert "engines" in result.stdout
    assert "init-db" in result.stdout
    assert "serve" in result.stdout
    assert "report" in result.stdout


def test_cli_list_mois_outputs_49() -> None:
    result = runner.invoke(app, ["list-mois"])
    assert result.exit_code == 0
    # Rich 테이블 출력에 SR1-1 ~ SR7-2 가 모두 보여야 함
    assert "SR1-1" in result.stdout
    assert "SR7-2" in result.stdout
    # 한국어 항목명도 포함
    assert "SQL" in result.stdout


def test_cli_engines_lists_all_known() -> None:
    result = runner.invoke(app, ["engines"])
    assert result.exit_code == 0
    for name in ("opengrep", "bandit", "eslint", "gosec", "spotbugs", "codeql"):
        assert name in result.stdout
