"""agent remote shell sessions

Revision ID: e24f91ab607d
Revises: d7a42e3150bc
Create Date: 2026-09-03 15:10:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = 'e24f91ab607d'
down_revision = 'd7a42e3150bc'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('agents', sa.Column('capabilities_json', sa.Text(), nullable=True))
    op.create_table(
        'agent_shell_sessions',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('agent_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('status', sa.String(length=24), nullable=False),
        sa.Column('cols', sa.Integer(), nullable=False),
        sa.Column('rows', sa.Integer(), nullable=False),
        sa.Column('output_bytes', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.Text(), nullable=False),
        sa.Column('started_at', sa.Text(), nullable=True),
        sa.Column('last_activity_at', sa.Text(), nullable=False),
        sa.Column('last_agent_poll_at', sa.Text(), nullable=True),
        sa.Column('expires_at', sa.Text(), nullable=False),
        sa.Column('closed_at', sa.Text(), nullable=True),
        sa.Column('exit_code', sa.Integer(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_agent_shell_sessions_agent_id', 'agent_shell_sessions', ['agent_id'])
    op.create_index('ix_agent_shell_sessions_status', 'agent_shell_sessions', ['status'])
    op.create_index('ix_agent_shell_sessions_user_id', 'agent_shell_sessions', ['user_id'])

    op.create_table(
        'agent_shell_inputs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('session_id', sa.String(length=36), nullable=False),
        sa.Column('data_b64', sa.Text(), nullable=False),
        sa.Column('created_at', sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(['session_id'], ['agent_shell_sessions.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_agent_shell_inputs_session_id', 'agent_shell_inputs', ['session_id'])

    op.create_table(
        'agent_shell_outputs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('session_id', sa.String(length=36), nullable=False),
        sa.Column('data_b64', sa.Text(), nullable=False),
        sa.Column('created_at', sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(['session_id'], ['agent_shell_sessions.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_agent_shell_outputs_session_id', 'agent_shell_outputs', ['session_id'])


def downgrade():
    op.drop_index('ix_agent_shell_outputs_session_id', table_name='agent_shell_outputs')
    op.drop_table('agent_shell_outputs')
    op.drop_index('ix_agent_shell_inputs_session_id', table_name='agent_shell_inputs')
    op.drop_table('agent_shell_inputs')
    op.drop_index('ix_agent_shell_sessions_user_id', table_name='agent_shell_sessions')
    op.drop_index('ix_agent_shell_sessions_status', table_name='agent_shell_sessions')
    op.drop_index('ix_agent_shell_sessions_agent_id', table_name='agent_shell_sessions')
    op.drop_table('agent_shell_sessions')
    op.drop_column('agents', 'capabilities_json')
