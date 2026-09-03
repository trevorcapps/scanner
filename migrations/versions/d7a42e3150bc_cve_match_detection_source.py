"""record CVE match detection source

Revision ID: d7a42e3150bc
Revises: c4e8a1d5f209
Create Date: 2026-09-03 12:45:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = 'd7a42e3150bc'
down_revision = 'c4e8a1d5f209'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('cve_matches', sa.Column('detection_source', sa.Text(), nullable=True))


def downgrade():
    op.drop_column('cve_matches', 'detection_source')
