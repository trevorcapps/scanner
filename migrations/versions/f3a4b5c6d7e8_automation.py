"""ansible automation: content, execution environments, runs, windows

Revision ID: f3a4b5c6d7e8
Revises: e2f3a4b5c6d7
Create Date: 2026-09-04 03:35:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = 'f3a4b5c6d7e8'
down_revision = 'e2f3a4b5c6d7'
branch_labels = None
depends_on = None

_RLS = ('automation_content', 'execution_environments', 'maintenance_windows', 'automation_runs')


def upgrade():
    op.create_table(
        'automation_content',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('digest', sa.String(64), nullable=False),
        sa.Column('kind', sa.String(16), nullable=False, server_default='playbook'),
        sa.Column('filename', sa.Text(), nullable=True),
        sa.Column('size_bytes', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('sealed_body', sa.Text(), nullable=False),
        sa.Column('syntax_ok', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('lint_summary_json', sa.Text(), nullable=True),
        sa.Column('created_at', sa.Text(), nullable=False),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('organization_id', 'digest', name='uq_automation_content_org_digest'),
    )
    op.create_index('ix_automation_content_organization_id', 'automation_content', ['organization_id'])
    op.create_index('ix_automation_content_digest', 'automation_content', ['digest'])

    op.create_table(
        'execution_environments',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(128), nullable=False),
        sa.Column('image', sa.Text(), nullable=False),
        sa.Column('ansible_core_version', sa.String(32), nullable=True),
        sa.Column('runner_version', sa.String(32), nullable=True),
        sa.Column('collections_json', sa.Text(), nullable=True),
        sa.Column('is_default', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('organization_id', 'name', name='uq_exec_env_org_name'),
    )
    op.create_index('ix_execution_environments_organization_id', 'execution_environments',
                    ['organization_id'])

    op.create_table(
        'maintenance_windows',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(128), nullable=False),
        sa.Column('timezone', sa.String(64), nullable=False, server_default='UTC'),
        sa.Column('window_start', sa.String(5), nullable=True),
        sa.Column('window_end', sa.String(5), nullable=True),
        sa.Column('days_json', sa.Text(), nullable=True),
        sa.Column('created_at', sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_maintenance_windows_organization_id', 'maintenance_windows', ['organization_id'])

    op.create_table(
        'automation_runs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('job_id', sa.String(36), nullable=False),
        sa.Column('content_id', sa.Integer(), nullable=False),
        sa.Column('content_digest', sa.String(64), nullable=False),
        sa.Column('execution_environment_id', sa.Integer(), nullable=True),
        sa.Column('variables_json', sa.Text(), nullable=True),
        sa.Column('credential_refs_json', sa.Text(), nullable=True),
        sa.Column('target_snapshot_json', sa.Text(), nullable=False),
        sa.Column('check_mode', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('serial', sa.Integer(), nullable=True),
        sa.Column('max_fail_percentage', sa.Integer(), nullable=True),
        sa.Column('launch_options_json', sa.Text(), nullable=True),
        sa.Column('launched_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['job_id'], ['scan_jobs.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['content_id'], ['automation_content.id'], ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_automation_runs_organization_id', 'automation_runs', ['organization_id'])
    op.create_index('ix_automation_runs_job_id', 'automation_runs', ['job_id'])

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
    op.drop_table('automation_runs')
    op.drop_table('maintenance_windows')
    op.drop_table('execution_environments')
    op.drop_table('automation_content')
