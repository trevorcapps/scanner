"""patch campaigns

Revision ID: a4b5c6d7e8f9
Revises: f3a4b5c6d7e8
Create Date: 2026-09-04 03:55:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = 'a4b5c6d7e8f9'
down_revision = 'f3a4b5c6d7e8'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'patch_campaigns',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(128), nullable=False),
        sa.Column('starter_id', sa.String(64), nullable=True),
        sa.Column('content_id', sa.Integer(), nullable=True),
        sa.Column('status', sa.String(16), nullable=False, server_default='planned'),
        sa.Column('candidate_ids_json', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('excluded_ids_json', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('canary_ids_json', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('batch_size', sa.Integer(), nullable=False, server_default='10'),
        sa.Column('pause_between_batches', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('max_fail_percentage', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('coordinate_reboot', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('maintenance_window_id', sa.Integer(), nullable=True),
        sa.Column('variables_json', sa.Text(), nullable=True),
        sa.Column('per_host_json', sa.Text(), nullable=True),
        sa.Column('parent_job_id', sa.String(36), nullable=True),
        sa.Column('created_at', sa.Text(), nullable=False),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.Column('started_at', sa.Text(), nullable=True),
        sa.Column('completed_at', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_patch_campaigns_organization_id', 'patch_campaigns', ['organization_id'])
    op.create_index('ix_patch_campaigns_status', 'patch_campaigns', ['status'])

    if op.get_bind().dialect.name == 'postgresql':
        op.execute('ALTER TABLE patch_campaigns ENABLE ROW LEVEL SECURITY')
        op.execute(
            "CREATE POLICY tenant_isolation ON patch_campaigns "
            "USING (organization_id = NULLIF(current_setting('artemis.current_org', true), '')::int) "
            "WITH CHECK (organization_id = NULLIF(current_setting('artemis.current_org', true), '')::int)"
        )


def downgrade():
    if op.get_bind().dialect.name == 'postgresql':
        op.execute('DROP POLICY IF EXISTS tenant_isolation ON patch_campaigns')
    op.drop_table('patch_campaigns')
