"""auth scan: system_info_json on asset_os_details

Revision ID: b1f3a7c92e04
Revises: fefa81e13b76
Create Date: 2026-09-03 01:20:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b1f3a7c92e04'
down_revision = 'fefa81e13b76'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('asset_os_details', sa.Column('system_info_json', sa.Text(), nullable=True))


def downgrade():
    op.drop_column('asset_os_details', 'system_info_json')
