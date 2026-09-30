"""P5-A: metadata-only shell sessions and exclusive operator leases.

Revision ID: c6d7e8f9a0b1
Revises: b5c6d7e8f9a0
"""
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa

revision = 'c6d7e8f9a0b1'
down_revision = 'b5c6d7e8f9a0'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('agent_shell_sessions', sa.Column('source', sa.Text()))
    op.add_column('agent_shell_sessions', sa.Column('close_reason', sa.String(64)))
    # Old processes must be stopped before this migration. End their leases;
    # transcript contents are deliberately discarded, including during rollback.
    ended_at = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    op.execute("UPDATE agent_shell_sessions SET status='closed', close_reason='transport_migration', "
               f"closed_at=COALESCE(closed_at, '{ended_at}') "
               "WHERE status IN ('requested', 'running', 'closing')")
    op.drop_table('agent_shell_inputs')
    op.drop_table('agent_shell_outputs')
    op.create_index('uq_agent_shell_active_lease', 'agent_shell_sessions',
                    ['organization_id', 'agent_id'], unique=True,
                    postgresql_where=sa.text("status IN ('requested', 'running', 'closing')"),
                    sqlite_where=sa.text("status IN ('requested', 'running', 'closing')"))


def downgrade():
    op.drop_index('uq_agent_shell_active_lease', table_name='agent_shell_sessions')
    for table in ('agent_shell_inputs', 'agent_shell_outputs'):
        op.create_table(table,
                        sa.Column('id', sa.Integer(), primary_key=True),
                        sa.Column('session_id', sa.String(36),
                                  sa.ForeignKey('agent_shell_sessions.id', ondelete='CASCADE'), nullable=False),
                        sa.Column('data_b64', sa.Text(), nullable=False),
                        sa.Column('created_at', sa.Text(), nullable=False))
        op.create_index(f'ix_{table}_session_id', table, ['session_id'])
    op.drop_column('agent_shell_sessions', 'close_reason')
    op.drop_column('agent_shell_sessions', 'source')
