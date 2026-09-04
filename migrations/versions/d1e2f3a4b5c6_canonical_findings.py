"""canonical findings: definitions + occurrences + observations

Revision ID: d1e2f3a4b5c6
Revises: c0d1e2f3a4b5
Create Date: 2026-09-04 02:45:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = 'd1e2f3a4b5c6'
down_revision = 'c0d1e2f3a4b5'
branch_labels = None
depends_on = None

_RLS = ('finding_occurrences', 'finding_observations')


def upgrade():
    op.create_table(
        'vulnerability_definitions',
        sa.Column('id', sa.String(128), nullable=False),
        sa.Column('kind', sa.String(16), nullable=False),
        sa.Column('title', sa.Text(), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(16), nullable=True),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('cvss_vector', sa.Text(), nullable=True),
        sa.Column('cwe_id', sa.String(32), nullable=True),
        sa.Column('published_date', sa.Text(), nullable=True),
        sa.Column('references_json', sa.Text(), nullable=True),
        sa.Column('epss_score', sa.Float(), nullable=True),
        sa.Column('epss_percentile', sa.Float(), nullable=True),
        sa.Column('epss_model_date', sa.Text(), nullable=True),
        sa.Column('kev', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('kev_date_added', sa.Text(), nullable=True),
        sa.Column('kev_due_date', sa.Text(), nullable=True),
        sa.Column('kev_ransomware', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('kev_required_action', sa.Text(), nullable=True),
        sa.Column('exploit_maturity', sa.String(16), nullable=False, server_default='none'),
        sa.Column('exploit_evidence_json', sa.Text(), nullable=True),
        sa.Column('updated_at', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'finding_occurrences',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('fingerprint', sa.String(64), nullable=False),
        sa.Column('definition_id', sa.String(128), nullable=False),
        sa.Column('asset_id', sa.Integer(), nullable=True),
        sa.Column('ip', sa.Text(), nullable=True),
        sa.Column('port', sa.Integer(), nullable=True),
        sa.Column('protocol', sa.String(8), nullable=True),
        sa.Column('component', sa.Text(), nullable=True),
        sa.Column('status', sa.String(16), nullable=False, server_default='open'),
        sa.Column('first_seen', sa.Text(), nullable=False),
        sa.Column('last_seen', sa.Text(), nullable=False),
        sa.Column('resolved_at', sa.Text(), nullable=True),
        sa.Column('reopened_at', sa.Text(), nullable=True),
        sa.Column('sources_json', sa.Text(), nullable=True),
        sa.Column('priority_score', sa.Float(), nullable=True),
        sa.Column('priority_factors_json', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['definition_id'], ['vulnerability_definitions.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('organization_id', 'fingerprint', name='uq_finding_occ_org_fp'),
    )
    for col in ('organization_id', 'fingerprint', 'definition_id', 'asset_id', 'ip', 'status'):
        op.create_index(f'ix_finding_occurrences_{col}', 'finding_occurrences', [col])

    op.create_table(
        'finding_observations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('occurrence_id', sa.Integer(), nullable=False),
        sa.Column('source', sa.String(16), nullable=False),
        sa.Column('job_id', sa.String(36), nullable=True),
        sa.Column('observed_at', sa.Text(), nullable=False),
        sa.Column('present', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('severity', sa.String(16), nullable=True),
        sa.Column('matched_at', sa.Text(), nullable=True),
        sa.Column('evidence_json', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['occurrence_id'], ['finding_occurrences.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_finding_observations_organization_id', 'finding_observations', ['organization_id'])
    op.create_index('ix_finding_observations_occurrence_id', 'finding_observations', ['occurrence_id'])
    op.create_index('ix_finding_obs_occ_at', 'finding_observations', ['occurrence_id', 'observed_at'])

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
    op.drop_table('finding_observations')
    op.drop_table('finding_occurrences')
    op.drop_table('vulnerability_definitions')
