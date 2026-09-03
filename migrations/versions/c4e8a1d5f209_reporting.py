"""executive reporting: reports, report_schedules, risk_snapshots

Revision ID: c4e8a1d5f209
Revises: b1f3a7c92e04
Create Date: 2026-09-03 03:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c4e8a1d5f209'
down_revision = 'b1f3a7c92e04'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'reports',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('title', sa.Text(), nullable=False),
        sa.Column('kind', sa.Text(), nullable=True),
        sa.Column('fmt', sa.Text(), nullable=True),
        sa.Column('scope_json', sa.Text(), nullable=True),
        sa.Column('status', sa.Text(), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('file_path', sa.Text(), nullable=True),
        sa.Column('size_bytes', sa.Integer(), nullable=True),
        sa.Column('summary_json', sa.Text(), nullable=True),
        sa.Column('generated_by', sa.Integer(), nullable=True),
        sa.Column('schedule_id', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_reports_created_at', 'reports', ['created_at'])

    op.create_table(
        'report_schedules',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.Text(), nullable=False),
        sa.Column('kind', sa.Text(), nullable=True),
        sa.Column('fmt', sa.Text(), nullable=True),
        sa.Column('scope_json', sa.Text(), nullable=True),
        sa.Column('cron_expression', sa.Text(), nullable=False),
        sa.Column('recipients', sa.Text(), nullable=True),
        sa.Column('enabled', sa.Integer(), nullable=True),
        sa.Column('last_run', sa.Text(), nullable=True),
        sa.Column('next_run', sa.Text(), nullable=True),
        sa.Column('last_status', sa.Text(), nullable=True),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.Text(), nullable=True),
        sa.Column('updated_at', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'risk_snapshots',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('snapshot_date', sa.Text(), nullable=True),
        sa.Column('assets', sa.Integer(), nullable=True),
        sa.Column('affected_hosts', sa.Integer(), nullable=True),
        sa.Column('critical', sa.Integer(), nullable=True),
        sa.Column('high', sa.Integer(), nullable=True),
        sa.Column('medium', sa.Integer(), nullable=True),
        sa.Column('low', sa.Integer(), nullable=True),
        sa.Column('info', sa.Integer(), nullable=True),
        sa.Column('exploitable', sa.Integer(), nullable=True),
        sa.Column('total_findings', sa.Integer(), nullable=True),
        sa.Column('unique_cves', sa.Integer(), nullable=True),
        sa.Column('risk_score', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('snapshot_date'),
    )


def downgrade():
    op.drop_table('risk_snapshots')
    op.drop_table('report_schedules')
    op.drop_index('idx_reports_created_at', table_name='reports')
    op.drop_table('reports')
