"""Finding 저장 멱등성 — (scan_id, finding_hash) 유니크 인덱스.

Celery 재시도가 같은 스캔을 다시 실행해도 Finding 이 중복 삽입되지 않도록
DB 차원에서 못 박는다. 기존 중복 행은 가장 낮은 id 만 남기고 제거한다.

제약(CONSTRAINT) 대신 **유니크 인덱스**를 쓰는 이유: SQLite 에는 ALTER TABLE ADD
CONSTRAINT 가 없어 alembic 이 테이블을 통째로 복사·재생성하는데, 그 과정에서
기존 인덱스와 이름이 충돌한다. 유니크 인덱스는 두 백엔드 모두에서 in-place 로
생성되며 강제력은 동일하다.

Revision ID: 0004
Revises: 0003
"""
import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

INDEX_NAME = "uq_findings_scan_hash"


def upgrade() -> None:
    conn = op.get_bind()
    # 기존 중복 정리 — 같은 (scan_id, finding_hash) 중 최소 id 만 보존
    conn.execute(
        sa.text(
            """
            DELETE FROM findings
             WHERE id NOT IN (
                   SELECT MIN(id) FROM findings
                    GROUP BY scan_id, finding_hash
             )
            """
        )
    )
    existing = {ix["name"] for ix in sa.inspect(conn).get_indexes("findings")}
    if INDEX_NAME not in existing:
        op.create_index(
            INDEX_NAME, "findings", ["scan_id", "finding_hash"], unique=True
        )


def downgrade() -> None:
    op.drop_index(INDEX_NAME, table_name="findings")
