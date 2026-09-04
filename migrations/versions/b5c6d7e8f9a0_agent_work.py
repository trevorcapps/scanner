"""signed agent work channel

Revision ID: b5c6d7e8f9a0
Revises: a4b5c6d7e8f9
Create Date: 2026-09-04 04:20:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = 'b5c6d7e8f9a0'
down_revision = 'a4b5c6d7e8f9'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'agent_work',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('agent_id', sa.Integer(), nullable=False),
        sa.Column('job_id', sa.String(36), nullable=True),
        sa.Column('kind', sa.String(24), nullable=False),
        sa.Column('status', sa.String(12), nullable=False, server_default='queued'),
        sa.Column('content_digest', sa.String(64), nullable=True),
        sa.Column('payload_json', sa.Text(), nullable=False),
        sa.Column('signature', sa.String(64), nullable=False),
        sa.Column('created_at', sa.Text(), nullable=False),
        sa.Column('delivered_at', sa.Text(), nullable=True),
        sa.Column('completed_at', sa.Text(), nullable=True),
        sa.Column('expires_at', sa.Text(), nullable=False),
        sa.Column('result_json', sa.Text(), nullable=True),
        sa.Column('reject_reason', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['job_id'], ['scan_jobs.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_agent_work_organization_id', 'agent_work', ['organization_id'])
    op.create_index('ix_agent_work_agent_id', 'agent_work', ['agent_id'])
    op.create_index('ix_agent_work_job_id', 'agent_work', ['job_id'])
    op.create_index('ix_agent_work_status', 'agent_work', ['status'])

    if op.get_bind().dialect.name == 'postgresql':
        op.execute('ALTER TABLE agent_work ENABLE ROW LEVEL SECURITY')
        op.execute(
            "CREATE POLICY tenant_isolation ON agent_work "
            "USING (organization_id = NULLIF(current_setting('artemis.current_org', true), '')::int) "
            "WITH CHECK (organization_id = NULLIF(current_setting('artemis.current_org', true), '')::int)"
        )


def downgrade():
    if op.get_bind().dialect.name == 'postgresql':
        op.execute('DROP POLICY IF EXISTS tenant_isolation ON agent_work')
    op.drop_table('agent_work')
