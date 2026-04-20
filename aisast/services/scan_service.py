"""Scan 큐잉·업로드·Git clone·diff·source viewer 서비스."""

from __future__ import annotations

import shutil
import uuid
import zipfile
from pathlib import Path

from fastapi import UploadFile, status
from sqlalchemy import select

from aisast.config import Settings, get_settings
from aisast.db import models, repo
from aisast.services.base import BaseService, ServiceError
from aisast.services.project_service import ProjectService
from aisast.utils.logging import get_logger
from aisast.utils.paths import ensure_dir

log = get_logger(__name__)

_MAX_UPLOAD_BYTES = 500 * 1024 * 1024
_ALLOWED_SUFFIXES = {".zip"}


class ScanService(BaseService):
    def __init__(self, session, actor=None, *, settings: Settings | None = None):
        super().__init__(session, actor)
        self.settings = settings or get_settings()

    # ---- 큐잉 --------------------------------------------------------
    def queue_from_path(
        self,
        *,
        project_id: int,
        source_path: str,
        language_hint: str | None,
        enable_second_pass: bool,
        enable_triage: bool,
    ) -> models.Scan:
        project = ProjectService(self.session, self.actor).get(project_id)
        scan_id = uuid.uuid4().hex[:12]
        repo.create_scan_record(
            self.session,
            scan_id=scan_id,
            project_id=project.id,
            source_path=source_path,
        )
        self._audit(
            "scan.queue",
            target_type="scan",
            target_id=scan_id,
            detail={"mode": "path", "path": source_path},
        )
        self.session.commit()
        from aisast.orchestrator.tasks import run_scan_task

        run_scan_task.delay(
            scan_id,
            source_path,
            enable_second_pass,
            enable_triage,
            language_hint,
        )
        scan = self.session.get(models.Scan, scan_id)
        assert scan is not None
        return scan

    def queue_from_upload(
        self,
        *,
        project_id: int,
        archive: UploadFile,
        language_hint: str | None,
        enable_second_pass: bool,
        enable_triage: bool,
    ) -> models.Scan:
        project = ProjectService(self.session, self.actor).get(project_id)
        self._validate_archive(archive)

        scan_id = uuid.uuid4().hex[:12]
        work_root = Path(self.settings.work_dir)
        scan_root = work_root / "sources" / scan_id
        archive_path = work_root / "uploads" / f"{scan_id}.zip"
        ensure_dir(scan_root)
        ensure_dir(archive_path.parent)

        total = self._stream_upload(archive, archive_path)
        log.info("scan %s uploaded %d bytes", scan_id, total)
        try:
            self._safe_extract_zip(archive_path, scan_root)
        except Exception as exc:
            shutil.rmtree(scan_root, ignore_errors=True)
            archive_path.unlink(missing_ok=True)
            raise ServiceError(
                f"zip 압축 해제 실패: {exc}",
                status_code=status.HTTP_400_BAD_REQUEST,
            ) from exc
        finally:
            archive_path.unlink(missing_ok=True)

        source_path = str(scan_root)
        repo.create_scan_record(
            self.session,
            scan_id=scan_id,
            project_id=project.id,
            source_path=source_path,
        )
        self._audit(
            "scan.queue",
            target_type="scan",
            target_id=scan_id,
            detail={"mode": "upload", "bytes": total},
        )
        self.session.commit()
        from aisast.orchestrator.tasks import run_scan_task

        run_scan_task.delay(
            scan_id, source_path, enable_second_pass, enable_triage, language_hint
        )
        scan = self.session.get(models.Scan, scan_id)
        assert scan is not None
        return scan

    def queue_from_git(
        self,
        *,
        project_id: int,
        git_url: str,
        branch: str | None,
        language_hint: str | None,
        enable_second_pass: bool,
        enable_triage: bool,
    ) -> models.Scan:
        project = ProjectService(self.session, self.actor).get(project_id)
        scan_id = uuid.uuid4().hex[:12]
        repo.create_scan_record(
            self.session,
            scan_id=scan_id,
            project_id=project.id,
            source_path=f"git:{git_url}@{branch or 'HEAD'}",
        )
        self._audit(
            "scan.queue",
            target_type="scan",
            target_id=scan_id,
            detail={"mode": "git", "url": git_url, "branch": branch},
        )
        self.session.commit()
        from aisast.orchestrator.tasks import clone_and_scan_task

        clone_and_scan_task.delay(
            scan_id,
            git_url,
            branch,
            enable_second_pass,
            enable_triage,
            language_hint,
        )
        scan = self.session.get(models.Scan, scan_id)
        assert scan is not None
        return scan

    # ---- 조회 --------------------------------------------------------
    def get(self, scan_id: str) -> models.Scan:
        scan = self.session.get(models.Scan, scan_id)
        if scan is None:
            raise ServiceError("scan not found", status_code=status.HTTP_404_NOT_FOUND)
        # 조직 스코핑: scan 이 속한 project 의 org_id 검증
        org_id = self.actor.organization_id if self.actor else None
        if org_id is not None:
            project = self.session.get(models.Project, scan.project_id)
            if project is None or project.organization_id != org_id:
                raise ServiceError("scan not found", status_code=status.HTTP_404_NOT_FOUND)
        return scan

    def list_for_project(self, project_id: int) -> list[models.Scan]:
        # project 접근 검증은 라우트에서 ProjectService.get 으로 수행
        return repo.list_scans_for_project(self.session, project_id)

    # ---- diff --------------------------------------------------------
    def diff(
        self, scan_id: str, *, base: str | None = None
    ) -> dict:
        head = self.get(scan_id)
        if base is None:
            prev = self.session.scalars(
                select(models.Scan)
                .where(
                    models.Scan.project_id == head.project_id,
                    models.Scan.id != head.id,
                    models.Scan.created_at < head.created_at,
                )
                .order_by(models.Scan.created_at.desc())
                .limit(1)
            ).first()
            base_scan_id = prev.id if prev else None
        else:
            base_scan_id = base

        head_rows = list(
            self.session.scalars(
                select(models.Finding).where(models.Finding.scan_id == head.id)
            )
        )
        base_rows: list[models.Finding] = []
        if base_scan_id:
            base_rows = list(
                self.session.scalars(
                    select(models.Finding).where(
                        models.Finding.scan_id == base_scan_id
                    )
                )
            )

        head_hashes = {h.finding_hash: h for h in head_rows}
        base_hashes = {b.finding_hash: b for b in base_rows}
        new_hashes = sorted(head_hashes.keys() - base_hashes.keys())
        resolved_hashes = sorted(base_hashes.keys() - head_hashes.keys())
        persistent = len(head_hashes.keys() & base_hashes.keys())

        new_list = [head_hashes[h] for h in new_hashes]
        resolved_list = [base_hashes[h] for h in resolved_hashes]
        summary = {
            "new": len(new_list),
            "resolved": len(resolved_list),
            "persistent": persistent,
            "new_high": sum(1 for f in new_list if f.severity == "HIGH"),
        }
        return {
            "base_scan_id": base_scan_id,
            "head_scan_id": head.id,
            "new": new_list,
            "resolved": resolved_list,
            "persistent": persistent,
            "summary": summary,
        }

    # ---- source viewer ----------------------------------------------
    def read_source(
        self, scan_id: str, *, path: str, max_bytes: int = 512 * 1024
    ) -> dict:
        scan = self.get(scan_id)
        root = Path(scan.source_path)
        if not root.exists() or not root.is_dir():
            raise ServiceError(
                "소스 디렉터리가 정리되어 더 이상 조회할 수 없습니다",
                status_code=status.HTTP_410_GONE,
            )
        candidate = (root / path).resolve()
        root_resolved = root.resolve()
        if not str(candidate).startswith(str(root_resolved)):
            raise ServiceError(
                "경로가 소스 루트를 벗어납니다",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        if not candidate.exists() or not candidate.is_file():
            raise ServiceError(
                "file not found", status_code=status.HTTP_404_NOT_FOUND
            )
        size = candidate.stat().st_size
        if size > max_bytes:
            return {
                "path": str(candidate.relative_to(root_resolved)),
                "truncated": True,
                "size": size,
                "content": candidate.read_bytes()[:max_bytes].decode(
                    "utf-8", errors="replace"
                ),
            }
        return {
            "path": str(candidate.relative_to(root_resolved)),
            "truncated": False,
            "size": size,
            "content": candidate.read_text(encoding="utf-8", errors="replace"),
        }

    # ---- 내부 헬퍼 ---------------------------------------------------
    @staticmethod
    def _validate_archive(archive: UploadFile) -> None:
        name = (archive.filename or "").lower()
        suffix = Path(name).suffix
        if suffix not in _ALLOWED_SUFFIXES:
            raise ServiceError(
                f"지원하지 않는 형식: {suffix or '없음'} — .zip 만 가능",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

    @staticmethod
    def _stream_upload(archive: UploadFile, dest: Path) -> int:
        total = 0
        chunk_size = 1024 * 1024
        with dest.open("wb") as f:
            while True:
                chunk = archive.file.read(chunk_size)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_UPLOAD_BYTES:
                    dest.unlink(missing_ok=True)
                    raise ServiceError(
                        f"업로드 크기 제한 초과 ({_MAX_UPLOAD_BYTES} bytes)",
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    )
                f.write(chunk)
        return total

    @staticmethod
    def _safe_extract_zip(archive_path: Path, dest_dir: Path) -> None:
        dest_resolved = dest_dir.resolve()
        with zipfile.ZipFile(archive_path) as zf:
            for member in zf.infolist():
                member_path = (dest_dir / member.filename).resolve()
                if not str(member_path).startswith(str(dest_resolved)):
                    raise ValueError(
                        f"zip 엔트리가 대상 경로를 벗어납니다: {member.filename}"
                    )
            zf.extractall(dest_dir)
