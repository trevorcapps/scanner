"""software observations + asset timeline

Revision ID: b9c0d1e2f3a4
Revises: a8b9c0d1e2f3
Create Date: 2026-09-04 02:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = 'b9c0d1e2f3a4'
down_revision = 'a8b9c0d1e2f3'
branch_labels = None
depends_on = None

_RLS = ('software_observations', 'asset_timeline_events')


def upgrade():
    op.create_table(
        'software_observations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('asset_id', sa.Integer(), nullable=False),
        sa.Column('ip', sa.Text(), nullable=True),
        sa.Column('package_name', sa.Text(), nullable=False),
        sa.Column('package_version', sa.Text(), nullable=True),
        sa.Column('cpe', sa.Text(), nullable=True),
        sa.Column('source', sa.String(24), nullable=True),
        sa.Column('job_id', sa.String(36), nullable=True),
        sa.Column('first_seen', sa.Text(), nullable=False),
        sa.Column('last_seen', sa.Text(), nullable=False),
        sa.Column('removed_at', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_software_observations_organization_id', 'software_observations', ['organization_id'])
    op.create_index('ix_software_observations_asset_id', 'software_observations', ['asset_id'])
    op.create_index('ix_software_observations_ip', 'software_observations', ['ip'])
    op.create_index('ix_software_obs_asset_pkg', 'software_observations', ['asset_id', 'package_name'])

    op.create_table(
        'asset_timeline_events',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('asset_id', sa.Integer(), nullable=False),
        sa.Column('kind', sa.String(32), nullable=False),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('from_value', sa.Text(), nullable=True),
        sa.Column('to_value', sa.Text(), nullable=True),
        sa.Column('source', sa.String(24), nullable=True),
        sa.Column('job_id', sa.String(36), nullable=True),
        sa.Column('report_id', sa.Integer(), nullable=True),
        sa.Column('detail_json', sa.Text(), nullable=True),
        sa.Column('created_at', sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_asset_timeline_events_organization_id', 'asset_timeline_events', ['organization_id'])
    op.create_index('ix_asset_timeline_events_asset_id', 'asset_timeline_events', ['asset_id'])
    op.create_index('ix_asset_timeline_asset_at', 'asset_timeline_events', ['asset_id', 'created_at'])

    if op.get_bind().dialect.name == 'postgresql':
        for table in _RLS:
            op.execute(f'ALTER TABLE {table} ENABLE ROW LEVEL SECURITY')
            op.execute(
                f"CREATE POLICY tenant_isolation ON {table} "
                f"USING (organization_id = NULLIF(current_setting('artemis.current_org', true), '')::int) "
                f"WITH CHECK (organization_id = NULLIF(current_setting('artemis.current_org', true), '')::int)"
            )


def downgrade():
    if op.get_bind().dialect.name == 'postgresql':
        for table in _RLS:
            op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON {table}')
    op.drop_table('asset_timeline_events')
    op.drop_table('software_observations')
