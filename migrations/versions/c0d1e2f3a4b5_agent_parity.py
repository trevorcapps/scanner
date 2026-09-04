"""agent parity: patch state, service health, rollout rings

Revision ID: c0d1e2f3a4b5
Revises: b9c0d1e2f3a4
Create Date: 2026-09-04 02:20:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = 'c0d1e2f3a4b5'
down_revision = 'b9c0d1e2f3a4'
branch_labels = None
depends_on = None

_COLS = [
    ('host_platform', sa.String(16)),
    ('telemetry_schema_version', sa.Integer()),
    ('reboot_required', sa.String(12)),
    ('pending_updates', sa.Integer()),
    ('security_updates', sa.Integer()),
    ('patch_status_json', sa.Text()),
    ('service_health_json', sa.Text()),
    ('uptime_seconds', sa.Integer()),
    ('upgrade_status', sa.String(16)),
    ('capability_health_json', sa.Text()),
]


def upgrade():
    with op.batch_alter_table('agents') as batch:
        for name, type_ in _COLS:
            batch.add_column(sa.Column(name, type_, nullable=True))
        batch.add_column(sa.Column('rollout_ring', sa.String(16), nullable=False,
                                   server_default='stable'))


def downgrade():
    with op.batch_alter_table('agents') as batch:
        batch.drop_column('rollout_ring')
        for name, _ in reversed(_COLS):
            batch.drop_column(name)
