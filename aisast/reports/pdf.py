"""WeasyPrint 기반 PDF 리포트 렌더러.

WeasyPrint는 시스템 라이브러리(cairo 등)에 의존하므로, 임포트 실패 시 원본
HTML을 그대로 반환하여 API가 500을 내지 않도록 한다. 운영 환경에서는
docker-compose의 `api` 서비스에서 libpango/libcairo 설치를 보장한다.
"""

from __future__ import annotations

from aisast.utils.logging import get_logger

log = get_logger(__name__)


def build_pdf(html_bytes: bytes) -> bytes:
    try:
        from weasyprint import HTML  # type: ignore

        return HTML(string=html_bytes.decode("utf-8")).write_pdf()
    except Exception as exc:  # pragma: no cover - optional runtime dep
        log.warning("WeasyPrint unavailable, returning raw HTML: %s", exc)
        return html_bytes
