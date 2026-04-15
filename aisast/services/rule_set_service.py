"""체커 그룹(RuleSet) CRUD 서비스."""

from __future__ import annotations

from fastapi import status
from sqlalchemy import select

from aisast.db import models
from aisast.services.base import BaseService, ServiceError


class RuleSetService(BaseService):
    def list_all(self) -> list[models.RuleSet]:
        return list(self.session.scalars(select(models.RuleSet).order_by(models.RuleSet.id)))

    def get(self, rule_set_id: int) -> models.RuleSet:
        row = self.session.get(models.RuleSet, rule_set_id)
        if row is None:
            raise ServiceError("rule set not found", status_code=status.HTTP_404_NOT_FOUND)
        return row

    def create(
        self,
        *,
        name: str,
        description: str = "",
        enabled_engines: list[str],
        include_rules: list[str],
        exclude_rules: list[str],
        min_severity: str = "LOW",
        is_default: bool = False,
    ) -> models.RuleSet:
        self.actor.require_role("admin")
        if self.session.scalar(
            select(models.RuleSet).where(models.RuleSet.name == name)
        ):
            raise ServiceError(
                "rule set name exists", status_code=status.HTTP_409_CONFLICT
            )
        if is_default:
            for existing in self.session.scalars(
                select(models.RuleSet).where(models.RuleSet.is_default.is_(True))
            ):
                existing.is_default = False
        row = models.RuleSet(
            name=name,
            description=description,
            enabled_engines=enabled_engines,
            include_rules=include_rules,
            exclude_rules=exclude_rules,
            min_severity=min_severity.upper(),
            is_default=is_default,
        )
        self.session.add(row)
        self._audit(
            "rule_set.create",
            target_type="rule_set",
            target_id=None,
            detail={"name": name, "engines": enabled_engines},
        )
        self.session.commit()
        self.session.refresh(row)
        return row

    def delete(self, rule_set_id: int) -> None:
        self.actor.require_role("admin")
        row = self.get(rule_set_id)
        if row.is_default:
            raise ServiceError(
                "cannot delete default rule set",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        self.session.delete(row)
        self._audit(
            "rule_set.delete",
            target_type="rule_set",
            target_id=rule_set_id,
            detail={"name": row.name},
        )
        self.session.commit()
