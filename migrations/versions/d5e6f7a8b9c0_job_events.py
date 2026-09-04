"""job_events + ScanJob durability columns

Revision ID: d5e6f7a8b9c0
Revises: c4d5e6f7a8b9
Create Date: 2026-09-04 00:15:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = 'd5e6f7a8b9c0'
down_revision = 'c4d5e6f7a8b9'
branch_labels = None
depends_on = None


def upgrade():
    recreate = 'always' if op.get_bind().dialect.name == 'sqlite' else 'auto'
    with op.batch_alter_table('scan_jobs', recreate=recreate) as batch:
        batch.add_column(sa.Column('progress_current', sa.Integer(), nullable=False, server_default='0'))
        batch.add_column(sa.Column('progress_total', sa.Integer(), nullable=True))
        batch.add_column(sa.Column('parent_job_id', sa.String(length=36), nullable=True))
        batch.add_column(sa.Column('idempotency_key', sa.String(length=128), nullable=True))
        batch.add_column(sa.Column('lease_expires_at', sa.Text(), nullable=True))
        batch.add_column(sa.Column('retention_until', sa.Text(), nullable=True))
        batch.create_foreign_key('fk_scan_jobs_parent', 'scan_jobs',
                                 ['parent_job_id'], ['id'], ondelete='CASCADE')
    op.create_index('ix_scan_jobs_parent_job_id', 'scan_jobs', ['parent_job_id'])
    op.create_index('ix_scan_jobs_idempotency_key', 'scan_jobs', ['idempotency_key'])

    op.create_table(
        'job_events',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('job_id', sa.String(length=36), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('seq', sa.Integer(), nullable=False),
        sa.Column('kind', sa.String(length=16), nullable=False),
        sa.Column('message', sa.Text(), nullable=True),
        sa.Column('level', sa.String(length=8), nullable=True),
        sa.Column('progress_current', sa.Integer(), nullable=True),
        sa.Column('progress_total', sa.Integer(), nullable=True),
        sa.Column('data_json', sa.Text(), nullable=True),
        sa.Column('created_at', sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(['job_id'], ['scan_jobs.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_job_events_job_id', 'job_events', ['job_id'])
    op.create_index('ix_job_events_organization_id', 'job_events', ['organization_id'])
    op.create_index('ix_job_events_job_seq', 'job_events', ['job_id', 'seq'])

    if op.get_bind().dialect.name == 'postgresql':
        op.execute('ALTER TABLE job_events ENABLE ROW LEVEL SECURITY')
        op.execute(
            "CREATE POLICY tenant_isolation ON job_events "
            "USING (organization_id = NULLIF(current_setting('artemis.current_org', true), '')::int) "
            "WITH CHECK (organization_id = NULLIF(current_setting('artemis.current_org', true), '')::int)"
        )


def downgrade():
    if op.get_bind().dialect.name == 'postgresql':
        op.execute('DROP POLICY IF EXISTS tenant_isolation ON job_events')
    op.drop_index('ix_job_events_job_seq', table_name='job_events')
    op.drop_index('ix_job_events_organization_id', table_name='job_events')
    op.drop_index('ix_job_events_job_id', table_name='job_events')
    op.drop_table('job_events')

    op.drop_index('ix_scan_jobs_idempotency_key', table_name='scan_jobs')
    op.drop_index('ix_scan_jobs_parent_job_id', table_name='scan_jobs')
    recreate = 'always' if op.get_bind().dialect.name == 'sqlite' else 'auto'
    with op.batch_alter_table('scan_jobs', recreate=recreate) as batch:
        batch.drop_constraint('fk_scan_jobs_parent', type_='foreignkey')
        batch.drop_column('retention_until')
        batch.drop_column('lease_expires_at')
        batch.drop_column('idempotency_key')
        batch.drop_column('parent_job_id')
        batch.drop_column('progress_total')
        batch.drop_column('progress_current')
