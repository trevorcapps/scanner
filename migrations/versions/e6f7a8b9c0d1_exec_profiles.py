"""scan execution profiles + schedule missed-run policy

Revision ID: e6f7a8b9c0d1
Revises: d5e6f7a8b9c0
Create Date: 2026-09-04 00:45:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = 'e6f7a8b9c0d1'
down_revision = 'd5e6f7a8b9c0'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'scan_execution_profiles',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.Text(), nullable=False),
        sa.Column('version', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('is_current', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('timezone', sa.String(length=64), nullable=False, server_default='UTC'),
        sa.Column('window_start', sa.String(length=5), nullable=True),
        sa.Column('window_end', sa.String(length=5), nullable=True),
        sa.Column('window_days_json', sa.Text(), nullable=True),
        sa.Column('max_hosts', sa.Integer(), nullable=False, server_default='256'),
        sa.Column('excluded_targets_json', sa.Text(), nullable=True),
        sa.Column('scanner_rate', sa.Integer(), nullable=True),
        sa.Column('concurrency', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('credential_ids_json', sa.Text(), nullable=True),
        sa.Column('engine_pool', sa.String(length=64), nullable=True),
        sa.Column('retry_count', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('notify_json', sa.Text(), nullable=True),
        sa.Column('created_at', sa.Text(), nullable=False),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('organization_id', 'name', 'version', name='uq_exec_profile_org_name_ver'),
    )
    op.create_index('ix_scan_execution_profiles_organization_id', 'scan_execution_profiles',
                    ['organization_id'])

    recreate = 'always' if op.get_bind().dialect.name == 'sqlite' else 'auto'
    with op.batch_alter_table('scheduled_scans', recreate=recreate) as batch:
        batch.add_column(sa.Column('execution_profile_id', sa.Integer(), nullable=True))
        batch.add_column(sa.Column('missed_run_policy', sa.String(length=16),
                                   nullable=False, server_default='skip'))
        batch.add_column(sa.Column('last_occurrence_key', sa.String(length=128), nullable=True))
        batch.create_foreign_key('fk_scheduled_scans_exec_profile', 'scan_execution_profiles',
                                 ['execution_profile_id'], ['id'], ondelete='SET NULL')
    op.create_index('ix_scheduled_scans_execution_profile_id', 'scheduled_scans',
                    ['execution_profile_id'])

    with op.batch_alter_table('scan_history') as batch:
        batch.add_column(sa.Column('baseline_json', sa.Text(), nullable=True))

    if op.get_bind().dialect.name == 'postgresql':
        op.execute('ALTER TABLE scan_execution_profiles ENABLE ROW LEVEL SECURITY')
        op.execute(
            "CREATE POLICY tenant_isolation ON scan_execution_profiles "
            "USING (organization_id = NULLIF(current_setting('artemis.current_org', true), '')::int) "
            "WITH CHECK (organization_id = NULLIF(current_setting('artemis.current_org', true), '')::int)"
        )


def downgrade():
    if op.get_bind().dialect.name == 'postgresql':
        op.execute('DROP POLICY IF EXISTS tenant_isolation ON scan_execution_profiles')

    with op.batch_alter_table('scan_history') as batch:
        batch.drop_column('baseline_json')

    op.drop_index('ix_scheduled_scans_execution_profile_id', table_name='scheduled_scans')
    recreate = 'always' if op.get_bind().dialect.name == 'sqlite' else 'auto'
    with op.batch_alter_table('scheduled_scans', recreate=recreate) as batch:
        batch.drop_constraint('fk_scheduled_scans_exec_profile', type_='foreignkey')
        batch.drop_column('last_occurrence_key')
        batch.drop_column('missed_run_policy')
        batch.drop_column('execution_profile_id')

    op.drop_index('ix_scan_execution_profiles_organization_id', table_name='scan_execution_profiles')
    op.drop_table('scan_execution_profiles')
