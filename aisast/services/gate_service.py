"""CI/CD 빌드 게이트 정책·판정 서비스."""

from __future__ import annotations

from fastapi import status
from sqlalchemy import select

from aisast.db import models
from aisast.services.base import BaseService, ServiceError


class GateService(BaseService):
    def _verify_project_access(self, project_id: int) -> models.Project:
        """프로젝트 존재 + 조직 스코핑 검증."""
        project = self.session.get(models.Project, project_id)
        if project is None:
            raise ServiceError(
                "project not found", status_code=status.HTTP_404_NOT_FOUND
            )
        org_id = self.actor.organization_id if self.actor else None
        if org_id is not None and project.organization_id != org_id:
            raise ServiceError(
                "project not found", status_code=status.HTTP_404_NOT_FOUND
            )
        return project

    def upsert_policy(
        self,
        *,
        project_id: int,
        max_high: int,
        max_medium: int,
        max_low: int,
        max_new_high: int,
        block_on_triage_fp_below: int,
        enabled: bool,
    ) -> models.GatePolicy:
        self.actor.require_role("admin")
        self._verify_project_access(project_id)
        existing = self.session.scalar(
            select(models.GatePolicy).where(
                models.GatePolicy.project_id == project_id
            )
        )
        if existing:
            for f, v in (
                ("max_high", max_high),
                ("max_medium", max_medium),
                ("max_low", max_low),
                ("max_new_high", max_new_high),
                ("block_on_triage_fp_below", block_on_triage_fp_below),
                ("enabled", enabled),
            ):
                setattr(existing, f, v)
            self._audit(
                "gate.policy_update",
                target_type="project",
                target_id=project_id,
                detail={"max_high": max_high, "max_medium": max_medium},
            )
            self.session.commit()
            self.session.refresh(existing)
            return existing
        row = models.GatePolicy(
            project_id=project_id,
            max_high=max_high,
            max_medium=max_medium,
            max_low=max_low,
            max_new_high=max_new_high,
            block_on_triage_fp_below=block_on_triage_fp_below,
            enabled=enabled,
        )
        self.session.add(row)
        self._audit(
            "gate.policy_create",
            target_type="project",
            target_id=project_id,
            detail={"max_high": max_high},
        )
        self.session.commit()
        self.session.refresh(row)
        return row

    def get_policy(self, project_id: int) -> models.GatePolicy:
        self._verify_project_access(project_id)
        row = self.session.scalar(
            select(models.GatePolicy).where(
                models.GatePolicy.project_id == project_id
            )
        )
        if row is None:
            raise ServiceError("no policy", status_code=status.HTTP_404_NOT_FOUND)
        return row

    def check(
        self,
        *,
        project_id: int,
        scan_id: str | None,
        base_scan_id: str | None,
    ) -> dict:
        self._verify_project_access(project_id)
        policy = self.session.scalar(
            select(models.GatePolicy).where(
                models.GatePolicy.project_id == project_id
            )
        )
        if policy is None or not policy.enabled:
            return {
                "passed": True,
                "reasons": ["no policy / disabled"],
                "counts": {},
                "new_high": 0,
            }
        if scan_id:
            scan = self.session.get(models.Scan, scan_id)
        else:
            scan = self.session.scalar(
                select(models.Scan)
                .where(
                    models.Scan.project_id == project_id,
                    models.Scan.status == "completed",
                )
                .order_by(models.Scan.created_at.desc())
                .limit(1)
            )
        if scan is None:
            raise ServiceError(
                "no completed scan to check",
                status_code=status.HTTP_404_NOT_FOUND,
            )
        findings = list(
            self.session.scalars(
                select(models.Finding).where(
                    models.Finding.scan_id == scan.id,
                    models.Finding.status != "excluded",
                )
            )
        )
        counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        reasons: list[str] = []
        if counts["HIGH"] > policy.max_high:
            reasons.append(f"HIGH {counts['HIGH']} > 임계값 {policy.max_high}")
        if counts["MEDIUM"] > policy.max_medium:
            reasons.append(f"MEDIUM {counts['MEDIUM']} > 임계값 {policy.max_medium}")
        if counts["LOW"] > policy.max_low:
            reasons.append(f"LOW {counts['LOW']} > 임계값 {policy.max_low}")
        new_high = 0
        if base_scan_id:
            base_hashes = {
                r.finding_hash
                for r in self.session.scalars(
                    select(models.Finding).where(
                        models.Finding.scan_id == base_scan_id
                    )
                )
            }
            new_high = sum(
                1
                for f in findings
                if f.severity == "HIGH" and f.finding_hash not in base_hashes
            )
            if new_high > policy.max_new_high:
                reasons.append(f"신규 HIGH {new_high} > 임계값 {policy.max_new_high}")
        passed = not reasons
        self._audit(
            "gate.check",
            target_type="project",
            target_id=project_id,
            detail={"passed": passed, "counts": counts, "new_high": new_high},
        )
        self.session.commit()
        return {
            "passed": passed,
            "reasons": reasons if reasons else ["within thresholds"],
            "counts": counts,
            "new_high": new_high,
        }
