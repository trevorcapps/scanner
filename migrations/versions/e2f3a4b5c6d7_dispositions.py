"""dispositions + suppression rules

Revision ID: e2f3a4b5c6d7
Revises: d1e2f3a4b5c6
Create Date: 2026-09-04 03:10:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = 'e2f3a4b5c6d7'
down_revision = 'd1e2f3a4b5c6'
branch_labels = None
depends_on = None

_RLS = ('dispositions', 'suppression_rules')


def upgrade():
    op.create_table(
        'dispositions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('disposition_type', sa.String(24), nullable=False),
        sa.Column('scope', sa.String(16), nullable=False),
        sa.Column('target_id', sa.Integer(), nullable=True),
        sa.Column('fingerprint', sa.String(64), nullable=True),
        sa.Column('definition_id', sa.String(128), nullable=True),
        sa.Column('rationale', sa.Text(), nullable=False),
        sa.Column('evidence_json', sa.Text(), nullable=True),
        sa.Column('requested_by', sa.Integer(), nullable=True),
        sa.Column('approved_by', sa.Integer(), nullable=True),
        sa.Column('status', sa.String(16), nullable=False, server_default='pending'),
        sa.Column('created_at', sa.Text(), nullable=False),
        sa.Column('approved_at', sa.Text(), nullable=True),
        sa.Column('expires_at', sa.Text(), nullable=True),
        sa.Column('review_date', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_dispositions_organization_id', 'dispositions', ['organization_id'])
    op.create_index('ix_dispositions_fingerprint', 'dispositions', ['fingerprint'])
    op.create_index('ix_dispositions_definition_id', 'dispositions', ['definition_id'])
    op.create_index('ix_dispositions_status', 'dispositions', ['status'])

    op.create_table(
        'suppression_rules',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.Text(), nullable=False),
        sa.Column('definition_id', sa.String(128), nullable=True),
        sa.Column('fingerprint', sa.String(64), nullable=True),
        sa.Column('ip_pattern', sa.Text(), nullable=True),
        sa.Column('component_pattern', sa.Text(), nullable=True),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('disposition_id', sa.Integer(), nullable=True),
        sa.Column('enabled', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.Text(), nullable=False),
        sa.Column('expires_at', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['disposition_id'], ['dispositions.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_suppression_rules_organization_id', 'suppression_rules', ['organization_id'])
    op.create_index('ix_suppression_rules_definition_id', 'suppression_rules', ['definition_id'])
    op.create_index('ix_suppression_rules_fingerprint', 'suppression_rules', ['fingerprint'])

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
    op.drop_table('suppression_rules')
    op.drop_table('dispositions')
