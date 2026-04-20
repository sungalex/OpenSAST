"""행안부 49개 항목 조회 라우트."""

from __future__ import annotations

from fastapi import APIRouter

from opensast.api.schemas import MoisItemOut, ReferenceOut
from opensast.mois.catalog import MOIS_ITEMS
from opensast.mois.references import references_for_cwes

router = APIRouter(prefix="/api/mois", tags=["mois"])


@router.get("/items", response_model=list[MoisItemOut])
def list_items() -> list[MoisItemOut]:
    out: list[MoisItemOut] = []
    for item in MOIS_ITEMS:
        refs = references_for_cwes(item.cwe_ids)
        out.append(
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
                references=[ReferenceOut(**r.as_dict()) for r in refs],
            )
        )
    return out
