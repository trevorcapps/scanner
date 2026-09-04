"""discovery scopes

Revision ID: a8b9c0d1e2f3
Revises: f7a8b9c0d1e2
Create Date: 2026-09-04 01:40:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = 'a8b9c0d1e2f3'
down_revision = 'f7a8b9c0d1e2'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'discovery_scopes',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(128), nullable=False),
        sa.Column('cidrs_json', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('exclusions_json', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('engine_pool', sa.String(64), nullable=True),
        sa.Column('cron_expression', sa.Text(), nullable=True),
        sa.Column('next_run', sa.Text(), nullable=True),
        sa.Column('max_hosts', sa.Integer(), nullable=False, server_default='1024'),
        sa.Column('enabled', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('approval_state', sa.String(16), nullable=False, server_default='pending'),
        sa.Column('approved_by', sa.Integer(), nullable=True),
        sa.Column('approved_at', sa.Text(), nullable=True),
        sa.Column('created_at', sa.Text(), nullable=False),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.Column('last_run', sa.Text(), nullable=True),
        sa.Column('last_status', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('organization_id', 'name', name='uq_discovery_scope_org_name'),
    )
    op.create_index('ix_discovery_scopes_organization_id', 'discovery_scopes', ['organization_id'])

    if op.get_bind().dialect.name == 'postgresql':
        op.execute('ALTER TABLE discovery_scopes ENABLE ROW LEVEL SECURITY')
        op.execute(
            "CREATE POLICY tenant_isolation ON discovery_scopes "
            "USING (organization_id = NULLIF(current_setting('artemis.current_org', true), '')::int) "
            "WITH CHECK (organization_id = NULLIF(current_setting('artemis.current_org', true), '')::int)"
        )


def downgrade():
    if op.get_bind().dialect.name == 'postgresql':
        op.execute('DROP POLICY IF EXISTS tenant_isolation ON discovery_scopes')
    op.drop_index('ix_discovery_scopes_organization_id', table_name='discovery_scopes')
    op.drop_table('discovery_scopes')
