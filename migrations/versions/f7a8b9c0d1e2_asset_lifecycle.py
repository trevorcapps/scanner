"""asset business context / lifecycle + tags + groups

Revision ID: f7a8b9c0d1e2
Revises: e6f7a8b9c0d1
Create Date: 2026-09-04 01:15:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = 'f7a8b9c0d1e2'
down_revision = 'e6f7a8b9c0d1'
branch_labels = None
depends_on = None

_RLS_TABLES = ('asset_tags', 'asset_groups', 'asset_group_members', 'asset_review_events')


def upgrade():
    is_pg = op.get_bind().dialect.name == 'postgresql'

    with op.batch_alter_table('assets') as batch:
        batch.add_column(sa.Column('criticality', sa.String(16), nullable=False, server_default='unknown'))
        batch.add_column(sa.Column('environment', sa.String(32), nullable=True))
        batch.add_column(sa.Column('business_owner', sa.Text(), nullable=True))
        batch.add_column(sa.Column('business_team', sa.Text(), nullable=True))
        batch.add_column(sa.Column('external_id', sa.Text(), nullable=True))
        batch.add_column(sa.Column('notes', sa.Text(), nullable=True))
        batch.add_column(sa.Column('manual_fields_json', sa.Text(), nullable=True))
        batch.add_column(sa.Column('lifecycle', sa.String(16), nullable=False, server_default='discovered'))
        batch.add_column(sa.Column('decommission_reason', sa.Text(), nullable=True))
        batch.add_column(sa.Column('decommissioned_at', sa.Text(), nullable=True))
        batch.add_column(sa.Column('first_seen_source', sa.String(32), nullable=True))
        batch.add_column(sa.Column('last_seen_source', sa.String(32), nullable=True))

    # Existing rows have been seen by a scan and are considered active.
    op.execute("UPDATE assets SET lifecycle = 'active' WHERE lifecycle = 'discovered'")

    op.create_table(
        'asset_tags',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(64), nullable=False),
        sa.Column('color', sa.String(16), nullable=True),
        sa.Column('created_at', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('organization_id', 'name', name='uq_asset_tag_org_name'),
    )
    op.create_index('ix_asset_tags_organization_id', 'asset_tags', ['organization_id'])

    op.create_table(
        'asset_tag_links',
        sa.Column('asset_id', sa.Integer(), nullable=False),
        sa.Column('tag_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['tag_id'], ['asset_tags.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('asset_id', 'tag_id'),
    )

    op.create_table(
        'asset_groups',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(128), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('kind', sa.String(8), nullable=False, server_default='static'),
        sa.Column('filter_json', sa.Text(), nullable=True),
        sa.Column('created_at', sa.Text(), nullable=True),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('organization_id', 'name', name='uq_asset_group_org_name'),
    )
    op.create_index('ix_asset_groups_organization_id', 'asset_groups', ['organization_id'])

    op.create_table(
        'asset_group_members',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('group_id', sa.Integer(), nullable=False),
        sa.Column('asset_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['group_id'], ['asset_groups.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('group_id', 'asset_id', name='uq_asset_group_member'),
    )
    op.create_index('ix_asset_group_members_organization_id', 'asset_group_members', ['organization_id'])
    op.create_index('ix_asset_group_members_group_id', 'asset_group_members', ['group_id'])
    op.create_index('ix_asset_group_members_asset_id', 'asset_group_members', ['asset_id'])

    op.create_table(
        'asset_review_events',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('asset_id', sa.Integer(), nullable=False),
        sa.Column('kind', sa.String(32), nullable=False),
        sa.Column('detail_json', sa.Text(), nullable=True),
        sa.Column('created_at', sa.Text(), nullable=False),
        sa.Column('resolved_at', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_asset_review_events_organization_id', 'asset_review_events', ['organization_id'])
    op.create_index('ix_asset_review_events_asset_id', 'asset_review_events', ['asset_id'])

    if is_pg:
        for table in _RLS_TABLES:
            op.execute(f'ALTER TABLE {table} ENABLE ROW LEVEL SECURITY')
            op.execute(
                f"CREATE POLICY tenant_isolation ON {table} "
                f"USING (organization_id = NULLIF(current_setting('artemis.current_org', true), '')::int) "
                f"WITH CHECK (organization_id = NULLIF(current_setting('artemis.current_org', true), '')::int)"
            )


def downgrade():
    if op.get_bind().dialect.name == 'postgresql':
        for table in _RLS_TABLES:
            op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON {table}')

    op.drop_table('asset_review_events')
    op.drop_table('asset_group_members')
    op.drop_table('asset_groups')
    op.drop_table('asset_tag_links')
    op.drop_table('asset_tags')

    with op.batch_alter_table('assets') as batch:
        for col in ('last_seen_source', 'first_seen_source', 'decommissioned_at',
                    'decommission_reason', 'lifecycle', 'manual_fields_json', 'notes',
                    'external_id', 'business_team', 'business_owner', 'environment', 'criticality'):
            batch.drop_column(col)
