"""행안부 49개 항목 조회 라우트."""

from __future__ import annotations

from fastapi import APIRouter

from aisast.api.schemas import MoisItemOut
from aisast.mois.catalog import MOIS_ITEMS

router = APIRouter(prefix="/api/mois", tags=["mois"])


@router.get("/items", response_model=list[MoisItemOut])
def list_items() -> list[MoisItemOut]:
    return [
        MoisItemOut(
            id=item.id,
            name_kr=item.name_kr,
            name_en=item.name_en,
            category=item.category.value,
            cwe_ids=list(item.cwe_ids),
            severity=item.severity.value,
            primary_engines=list(item.primary_engines),
            secondary_engines=list(item.secondary_engines),
            description=item.description,
        )
        for item in MOIS_ITEMS
    ]
