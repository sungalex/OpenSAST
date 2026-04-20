"""aiSAST CLI.

예시:
  $ opensast scan ./my-project --no-second-pass --no-triage
  $ opensast serve --host 0.0.0.0 --port 8000
  $ opensast init-db
  $ opensast list-mois
  $ opensast engines
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from opensast.config import get_settings
from opensast.db.base import Base
from opensast.db.session import init_engine
from opensast.engines.registry import available_engines
from opensast.mois.catalog import MOIS_ITEMS, ensure_49_items
from opensast.orchestrator.pipeline import ScanOptions, run_scan
from opensast.reports.sarif import build_sarif as build_sarif_from_rows
from opensast.sarif.normalize import findings_to_sarif
from opensast.utils.paths import safe_write_text

app = typer.Typer(
    help="aiSAST — 행안부 49개 구현단계 보안약점 진단 도구",
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    path: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    output: Path = typer.Option(
        Path("aisast-result.sarif"), "--output", "-o", help="SARIF 출력 경로"
    ),
    json_output: Optional[Path] = typer.Option(
        None, "--json", help="도메인 JSON 출력 경로 (선택)"
    ),
    second_pass: bool = typer.Option(
        True, "--second-pass/--no-second-pass", help="CodeQL/SpotBugs 심층 Pass"
    ),
    triage: bool = typer.Option(
        True, "--triage/--no-triage", help="LLM 기반 오탐 필터링"
    ),
    language: Optional[str] = typer.Option(None, "--language", help="언어 힌트"),
) -> None:
    """디렉터리를 스캔하고 SARIF 결과를 저장한다."""

    console.print(f"[bold green]aiSAST scanning[/] {path}")
    options = ScanOptions(
        enable_second_pass=second_pass,
        enable_triage=triage,
        language_hint=language,
    )
    result = run_scan(path, options=options)
    sarif = findings_to_sarif(result.findings, tool_name="aisast-cli")
    safe_write_text(output, json.dumps(sarif, ensure_ascii=False, indent=2))
    console.print(f"SARIF → [cyan]{output}[/]  ({len(result.findings)} findings)")
    if json_output:
        safe_write_text(
            json_output,
            json.dumps(result.as_dict(), ensure_ascii=False, indent=2),
        )
        console.print(f"JSON  → [cyan]{json_output}[/]")
    _print_summary(result.engine_stats, result.mois_coverage)


@app.command("list-mois")
def list_mois() -> None:
    """49개 항목 목록 출력."""

    ensure_49_items()
    table = Table(title="행안부 49개 구현단계 보안약점", show_lines=False)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("항목명(한)", style="white")
    table.add_column("분류", style="magenta")
    table.add_column("CWE", style="green")
    table.add_column("심각도", style="yellow")
    for item in MOIS_ITEMS:
        table.add_row(
            item.id,
            item.name_kr,
            item.category.value,
            ",".join(item.cwe_ids),
            item.severity.value,
        )
    console.print(table)


@app.command()
def engines() -> None:
    """설치되어 있는 엔진 바이너리 상태 확인."""

    table = Table(title="SAST 엔진 가용성")
    table.add_column("엔진", style="cyan")
    table.add_column("바이너리")
    table.add_column("상태", style="green")
    for info in available_engines():
        status = "[green]✓[/]" if info.available else "[red]✗[/]"
        table.add_row(info.name, info.binary, status)
    console.print(table)


@app.command("db-upgrade")
def db_upgrade(
    revision: str = typer.Argument("head", help="Alembic 리비전 (기본: head)"),
) -> None:
    """Alembic 마이그레이션 적용."""

    from alembic import command
    from alembic.config import Config as AlembicConfig

    cfg = AlembicConfig(str(get_settings().project_root / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", get_settings().database_url)
    command.upgrade(cfg, revision)
    console.print(f"[green]Alembic upgrade[/] → {revision}")


@app.command("init-db")
def init_db(
    seed_admin: bool = typer.Option(
        True, "--seed-admin/--no-seed-admin", help="부트스트랩 관리자 계정 자동 생성"
    ),
) -> None:
    """데이터베이스 스키마 생성 및 초기 관리자 계정 생성."""

    from opensast.db import repo
    from opensast.db.session import session_scope

    settings = get_settings()
    engine = init_engine(settings)
    Base.metadata.create_all(engine)
    console.print(f"[green]DB initialized[/]: {settings.database_url}")
    if seed_admin:
        with session_scope() as session:
            repo.ensure_bootstrap_admin(session, settings=settings)
        console.print(
            f"[yellow]Bootstrap admin[/]: {settings.bootstrap_admin_email} "
            f"(password from OPENSAST_BOOTSTRAP_ADMIN_PASSWORD)"
        )


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", "--host"),  # noqa: S104
    port: int = typer.Option(8000, "--port"),
    reload: bool = typer.Option(False, "--reload"),
) -> None:
    """FastAPI 서버 실행."""

    import uvicorn

    uvicorn.run("opensast.api.app:app", host=host, port=port, reload=reload)


@app.command()
def report(
    sarif_path: Path = typer.Argument(..., exists=True, file_okay=True),
    out_html: Path = typer.Option(Path("aisast-report.html"), "--html"),
    out_excel: Path = typer.Option(Path("aisast-report.xlsx"), "--excel"),
) -> None:
    """이미 생성된 SARIF 파일로부터 HTML/Excel 리포트 변환."""

    from opensast.db import models as dbm
    from opensast.reports.excel import build_excel
    from opensast.reports.html import build_html
    from opensast.sarif.normalize import findings_from_sarif
    from opensast.sarif.parser import parse_sarif

    doc = parse_sarif(sarif_path)
    findings = findings_from_sarif(doc)
    scan_stub = dbm.Scan(
        id="adhoc",
        project_id=0,
        source_path=str(sarif_path),
        status="completed",
    )
    rows: list[dbm.Finding] = []
    for f in findings:
        rows.append(
            dbm.Finding(
                scan_id="adhoc",
                finding_hash=f.finding_id,
                rule_id=f.rule_id,
                engine=f.engine,
                message=f.message,
                severity=f.severity.value,
                file_path=f.location.file_path,
                start_line=f.location.start_line,
                end_line=f.location.end_line,
                cwe_ids=list(f.cwe_ids),
                mois_id=f.mois_id,
                category=f.category,
                language=f.language,
                snippet=f.location.snippet,
                raw=f.raw,
            )
        )
    html = build_html(scan_stub, rows)
    excel = build_excel(scan_stub, rows)
    out_html.write_bytes(html)
    out_excel.write_bytes(excel)
    # Keep reference to internal helper so linters don't drop the import
    _ = build_sarif_from_rows  # noqa: F841
    console.print(f"HTML  → [cyan]{out_html}[/]")
    console.print(f"Excel → [cyan]{out_excel}[/]")


def _print_summary(engine_stats: dict[str, int], mois_coverage: dict[str, int]) -> None:
    if engine_stats:
        eng_table = Table(title="엔진별 탐지 건수")
        eng_table.add_column("엔진")
        eng_table.add_column("건수", justify="right")
        for k, v in sorted(engine_stats.items()):
            eng_table.add_row(k, str(v))
        console.print(eng_table)
    if mois_coverage:
        mois_table = Table(title="MOIS 항목별 탐지 건수")
        mois_table.add_column("MOIS ID")
        mois_table.add_column("건수", justify="right")
        for k, v in sorted(mois_coverage.items()):
            mois_table.add_row(k, str(v))
        console.print(mois_table)


if __name__ == "__main__":
    app()
