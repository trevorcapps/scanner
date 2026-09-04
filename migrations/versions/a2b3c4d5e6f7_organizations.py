"""organizations, memberships, invitations; platform_admin; api key org binding

Revision ID: a2b3c4d5e6f7
Revises: f1a2b3c4d5e6
Create Date: 2026-09-03 22:15:00.000000

Expand/backfill/contract:
  1. create org tables, add users.platform_admin, add api_keys.organization_id (nullable)
  2. create the Default organization, a membership for every user (seeded from
     users.role), promote the earliest user to platform_admin, and bind every
     API key to Default
  3. make api_keys.organization_id NOT NULL
"""

import sqlalchemy as sa
from alembic import op

revision = 'a2b3c4d5e6f7'
down_revision = 'f1a2b3c4d5e6'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'organizations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('slug', sa.String(length=64), nullable=False),
        sa.Column('name', sa.Text(), nullable=False),
        sa.Column('is_default', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('slug'),
    )
    op.create_table(
        'organization_memberships',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('role', sa.String(length=16), nullable=False, server_default='analyst'),
        sa.Column('created_at', sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('organization_id', 'user_id', name='uq_org_membership'),
    )
    op.create_index('ix_organization_memberships_organization_id', 'organization_memberships', ['organization_id'])
    op.create_index('ix_organization_memberships_user_id', 'organization_memberships', ['user_id'])

    op.create_table(
        'organization_invitations',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('email', sa.Text(), nullable=False),
        sa.Column('role', sa.String(length=16), nullable=False, server_default='analyst'),
        sa.Column('token', sa.String(length=64), nullable=False),
        sa.Column('invited_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.Text(), nullable=False),
        sa.Column('expires_at', sa.Text(), nullable=False),
        sa.Column('accepted_at', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token'),
    )
    op.create_index('ix_organization_invitations_organization_id', 'organization_invitations', ['organization_id'])

    with op.batch_alter_table('users') as batch:
        batch.add_column(sa.Column('platform_admin', sa.Integer(), nullable=False, server_default='0'))
    with op.batch_alter_table('api_keys') as batch:
        batch.add_column(sa.Column('organization_id', sa.Integer(), nullable=True))
        batch.create_foreign_key(
            'fk_api_keys_organization', 'organizations', ['organization_id'], ['id'], ondelete='CASCADE'
        )
    op.create_index('ix_api_keys_organization_id', 'api_keys', ['organization_id'])

    # ---- backfill --------------------------------------------------------
    now = sa.func.now()
    bind = op.get_bind()
    iso = '2026-09-03T00:00:00Z'

    bind.execute(sa.text(
        "INSERT INTO organizations (slug, name, is_default, created_at) "
        "VALUES ('default', 'Default', 1, :ts)"
    ), {'ts': iso})
    org_id = bind.execute(sa.text(
        "SELECT id FROM organizations WHERE slug = 'default'"
    )).scalar()

    users = list(bind.execute(sa.text("SELECT id, role FROM users ORDER BY id")))
    for index, row in enumerate(users):
        role = row.role if row.role in ('admin', 'analyst', 'readonly') else 'analyst'
        bind.execute(sa.text(
            "INSERT INTO organization_memberships (organization_id, user_id, role, created_at) "
            "VALUES (:o, :u, :r, :ts)"
        ), {'o': org_id, 'u': row.id, 'r': role, 'ts': iso})
        if index == 0:
            bind.execute(sa.text("UPDATE users SET platform_admin = 1 WHERE id = :u"), {'u': row.id})

    bind.execute(sa.text("UPDATE api_keys SET organization_id = :o WHERE organization_id IS NULL"),
                 {'o': org_id})

    # ---- contract -------------------------------------------------------
    # recreate='always' so SQLite actually rewrites the table with the new
    # NOT NULL constraint (a bare ALTER is a no-op there).
    with op.batch_alter_table('api_keys', recreate='always') as batch:
        batch.alter_column('organization_id', existing_type=sa.Integer(), nullable=False)

    _ = now  # silence lint if unused on some dialects


def downgrade():
    op.drop_index('ix_api_keys_organization_id', table_name='api_keys')
    with op.batch_alter_table('api_keys') as batch:
        batch.drop_constraint('fk_api_keys_organization', type_='foreignkey')
        batch.drop_column('organization_id')
    with op.batch_alter_table('users') as batch:
        batch.drop_column('platform_admin')

    op.drop_index('ix_organization_invitations_organization_id', table_name='organization_invitations')
    op.drop_table('organization_invitations')
    op.drop_index('ix_organization_memberships_user_id', table_name='organization_memberships')
    op.drop_index('ix_organization_memberships_organization_id', table_name='organization_memberships')
    op.drop_table('organization_memberships')
    op.drop_table('organizations')
