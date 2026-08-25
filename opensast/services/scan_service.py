"""Scan 큐잉·업로드·Git clone·diff·source viewer 서비스.

보안 관련 불변식 세 가지를 이 계층에서 강제한다.

1. **스캔 실행은 쓰기 역할만** — `viewer` 는 스캔을 큐잉할 수 없다
   (ARCHITECTURE §4.3 RBAC 표).
2. **경로 스캔은 허용 루트 안에서만** — 임의 `source_path` 를 받아 워커 호스트의
   `/etc` 같은 경로를 스캔하고 소스 뷰어로 읽어내는 경로를 차단한다.
3. **경로 봉쇄는 `Path.is_relative_to()` 로만** — 문자열 접두사 비교는
   `/work/sources/ab` 루트에서 `/work/sources/abcd` 를 통과시킨다.
"""

from __future__ import annotations

import shutil
import uuid
import zipfile
from pathlib import Path

from fastapi import UploadFile, status
from sqlalchemy import select

from opensast.config import Settings, get_settings
from opensast.db import models, repo
from opensast.services.base import BaseService, ServiceError
from opensast.services.project_service import ProjectService
from opensast.utils.logging import get_logger
from opensast.utils.paths import ensure_dir

log = get_logger(__name__)

_ALLOWED_SUFFIXES = {".zip"}

#: 스캔을 큐잉할 수 있는 역할 — viewer 제외
_SCAN_ROLES = ("admin", "analyst")

#: ZIP 최대 압축 확대율. 이 배수를 넘으면 zip bomb 으로 간주하고 거부한다.
_MAX_ZIP_EXPANSION_RATIO = 100
#: 압축 해제 후 총 크기 상한 (압축률이 낮은 대용량 아카이브 방어)
_MAX_ZIP_UNCOMPRESSED_BYTES = 4 * 1024 * 1024 * 1024  # 4 GiB


class ScanService(BaseService):
    def __init__(self, session, actor, *, settings: Settings | None = None):
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
        self.actor.require_role(*_SCAN_ROLES)
        project = ProjectService(self.session, self.actor).get(project_id)
        resolved = self._validate_source_path(source_path)
        scan_id = uuid.uuid4().hex[:12]
        repo.create_scan_record(
            self.session,
            scan_id=scan_id,
            project_id=project.id,
            source_path=str(resolved),
        )
        self._audit(
            "scan.queue",
            target_type="scan",
            target_id=scan_id,
            detail={"mode": "path", "path": str(resolved)},
        )
        self.session.commit()
        from opensast.orchestrator.tasks import run_scan_task

        run_scan_task.delay(
            scan_id,
            str(resolved),
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
        self.actor.require_role(*_SCAN_ROLES)
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
        except ServiceError:
            shutil.rmtree(scan_root, ignore_errors=True)
            archive_path.unlink(missing_ok=True)
            raise
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
        from opensast.orchestrator.tasks import run_scan_task

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
        self.actor.require_role(*_SCAN_ROLES)
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
        from opensast.orchestrator.tasks import clone_and_scan_task

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
        # 조직 스코핑: scan 이 속한 project 의 org_id 검증 (system 컨텍스트는 우회)
        if not self.actor.is_system:
            project = self.session.get(models.Project, scan.project_id)
            if project is None:
                raise ServiceError(
                    "scan not found", status_code=status.HTTP_404_NOT_FOUND
                )
            self._assert_org(project, label="scan")
        return scan

    def list_for_project(self, project_id: int) -> list[models.Scan]:
        # 프로젝트 접근 권한을 여기서 검증한다 — 라우트에 의존하지 않는다.
        ProjectService(self.session, self.actor).get(project_id)
        return repo.list_scans_for_project(self.session, project_id)

    def status_snapshot(self, scan_id: str) -> dict:
        """SSE 스트리밍용 경량 상태 조회 (권한 검증 포함)."""

        scan = self.get(scan_id)
        return {
            "scan_id": scan.id,
            "status": scan.status,
            "error": scan.error,
        }

    # ---- diff --------------------------------------------------------
    def diff(self, scan_id: str, *, base: str | None = None) -> dict:
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
            # 명시적 base 도 동일한 접근 검증을 거친다 (교차 조직 diff 차단)
            base_scan_id = self.get(base).id

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
        root_resolved = root.resolve()
        candidate = (root_resolved / path).resolve()
        if not _is_contained(candidate, root_resolved):
            raise ServiceError(
                "경로가 소스 루트를 벗어납니다",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        if candidate.is_symlink():
            raise ServiceError(
                "심볼릭 링크는 조회할 수 없습니다",
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
    def _validate_source_path(self, source_path: str) -> Path:
        """경로 스캔 대상이 허용 루트 안에 있는지 검증한다.

        허용 루트는 `settings.scan_allowed_source_roots` 이며 기본값은
        `work_dir` 하나다. 즉 기본 구성에서는 업로드·clone 으로 만들어진 작업
        디렉터리만 스캔할 수 있고, 워커 호스트의 임의 경로는 거부된다.
        """

        raw = (source_path or "").strip()
        if not raw:
            raise ServiceError("source_path is required")
        candidate = Path(raw).expanduser()
        if not candidate.is_absolute():
            candidate = (Path(self.settings.work_dir) / candidate)
        candidate = candidate.resolve()

        allowed = self.settings.allowed_source_roots()
        if not any(_is_contained(candidate, root) for root in allowed):
            log.warning(
                "rejected out-of-scope scan path %s (actor=%s)",
                candidate,
                self.actor.user_id,
            )
            self._audit(
                "scan.path_rejected",
                target_type="scan",
                detail={"path": str(candidate)},
            )
            self.session.commit()
            raise ServiceError(
                "허용되지 않은 스캔 경로입니다. "
                "OPENSAST_SCAN_ALLOWED_SOURCE_ROOTS 에 등록된 디렉터리 하위만 "
                "스캔할 수 있습니다.",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        if not candidate.exists() or not candidate.is_dir():
            raise ServiceError(
                "source_path 가 존재하지 않거나 디렉터리가 아닙니다",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        return candidate

    @staticmethod
    def _validate_archive(archive: UploadFile) -> None:
        name = (archive.filename or "").lower()
        suffix = Path(name).suffix
        if suffix not in _ALLOWED_SUFFIXES:
            raise ServiceError(
                f"지원하지 않는 형식: {suffix or '없음'} — .zip 만 가능",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

    def _stream_upload(self, archive: UploadFile, dest: Path) -> int:
        limit = self.settings.max_upload_bytes
        total = 0
        chunk_size = 1024 * 1024
        with dest.open("wb") as f:
            while True:
                chunk = archive.file.read(chunk_size)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    f.close()
                    dest.unlink(missing_ok=True)
                    raise ServiceError(
                        f"업로드 크기 제한 초과 ({limit} bytes)",
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    )
                f.write(chunk)
        return total

    @staticmethod
    def _safe_extract_zip(archive_path: Path, dest_dir: Path) -> None:
        """경로 탈출과 zip bomb 을 모두 막으면서 압축을 해제한다."""

        dest_resolved = dest_dir.resolve()
        compressed_total = 0
        uncompressed_total = 0
        with zipfile.ZipFile(archive_path) as zf:
            for member in zf.infolist():
                member_path = (dest_resolved / member.filename).resolve()
                if not _is_contained(member_path, dest_resolved):
                    raise ServiceError(
                        f"zip 엔트리가 대상 경로를 벗어납니다: {member.filename}",
                        status_code=status.HTTP_400_BAD_REQUEST,
                    )
                compressed_total += member.compress_size
                uncompressed_total += member.file_size
            if uncompressed_total > _MAX_ZIP_UNCOMPRESSED_BYTES:
                raise ServiceError(
                    "압축 해제 후 크기가 상한을 초과합니다 "
                    f"({uncompressed_total} > {_MAX_ZIP_UNCOMPRESSED_BYTES} bytes)",
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                )
            if (
                compressed_total > 0
                and uncompressed_total / compressed_total > _MAX_ZIP_EXPANSION_RATIO
            ):
                raise ServiceError(
                    "압축 확대율이 비정상적으로 높습니다 (zip bomb 의심)",
                    status_code=status.HTTP_400_BAD_REQUEST,
                )
            zf.extractall(dest_dir)


def _is_contained(candidate: Path, root: Path) -> bool:
    """`candidate` 가 `root` 하위(또는 root 자신)인지 판정한다.

    문자열 접두사 비교(`startswith`)는 형제 디렉터리를 통과시키므로 쓰지 않는다.
    """

    try:
        return candidate == root or candidate.is_relative_to(root)
    except (ValueError, OSError):
        return False
