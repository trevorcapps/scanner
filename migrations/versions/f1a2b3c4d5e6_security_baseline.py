"""security baseline: audit_events + encrypted credential secrets

Revision ID: f1a2b3c4d5e6
Revises: e24f91ab607d
Create Date: 2026-09-03 21:30:00.000000

Expand/backfill/contract for the credential secret columns:
  1. add secret_enc / private_key_enc / key_kind
  2. seal existing plaintext password and any readable key_path file
  3. drop the plaintext password column

Backfill requires ARTEMIS_ENCRYPTION_KEY to be configured when credential rows
exist; the migration fails loudly otherwise rather than silently losing secrets.
"""

import os

import sqlalchemy as sa
from alembic import op

revision = 'f1a2b3c4d5e6'
down_revision = 'e24f91ab607d'
branch_labels = None
depends_on = None


def _audit_table():
    op.create_table(
        'audit_events',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.Text(), nullable=False),
        sa.Column('action', sa.String(length=64), nullable=False),
        sa.Column('outcome', sa.String(length=16), nullable=False, server_default='success'),
        sa.Column('actor_user_id', sa.Integer(), nullable=True),
        sa.Column('actor_label', sa.Text(), nullable=True),
        sa.Column('actor_kind', sa.String(length=16), nullable=True),
        sa.Column('source_ip', sa.Text(), nullable=True),
        sa.Column('target_type', sa.String(length=32), nullable=True),
        sa.Column('target_id', sa.Text(), nullable=True),
        sa.Column('request_id', sa.Text(), nullable=True),
        sa.Column('organization_id', sa.Integer(), nullable=True),
        sa.Column('detail_json', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    for col in ('created_at', 'action', 'actor_user_id',
                'target_type', 'target_id', 'request_id', 'organization_id'):
        op.create_index(f'ix_audit_events_{col}', 'audit_events', [col])


def upgrade():
    _audit_table()

    op.add_column('credentials', sa.Column('secret_enc', sa.Text(), nullable=True))
    op.add_column('credentials', sa.Column('private_key_enc', sa.Text(), nullable=True))
    op.add_column('credentials', sa.Column('key_kind', sa.Text(), nullable=True))

    bind = op.get_bind()
    rows = list(bind.execute(sa.text(
        'SELECT id, cred_type, key_path, password FROM credentials'
    )))

    if rows:
        from artemis.services import crypto_service

        if not crypto_service.is_configured():
            raise RuntimeError(
                "Cannot encrypt %d existing credential(s): set ARTEMIS_ENCRYPTION_KEY "
                "before running this migration." % len(rows)
            )

        for row in rows:
            secret_enc = crypto_service.seal(row.password) if row.password else None
            private_key_enc = None
            if row.key_path and os.path.isfile(row.key_path):
                try:
                    with open(row.key_path) as handle:
                        private_key_enc = crypto_service.seal(handle.read())
                except OSError:
                    private_key_enc = None
            bind.execute(
                sa.text(
                    'UPDATE credentials SET secret_enc = :s, private_key_enc = :k WHERE id = :i'
                ),
                {'s': secret_enc, 'k': private_key_enc, 'i': row.id},
            )

            # Verify decryptability before we drop the plaintext.
            if secret_enc:
                assert crypto_service.open_envelope(secret_enc) == row.password

    with op.batch_alter_table('credentials') as batch:
        batch.drop_column('password')


def downgrade():
    op.add_column('credentials', sa.Column('password', sa.Text(), nullable=True))

    bind = op.get_bind()
    rows = list(bind.execute(sa.text(
        'SELECT id, secret_enc FROM credentials WHERE secret_enc IS NOT NULL'
    )))
    if rows:
        from artemis.services import crypto_service

        for row in rows:
            try:
                plaintext = crypto_service.open_envelope(row.secret_enc)
            except Exception:
                plaintext = None
            bind.execute(
                sa.text('UPDATE credentials SET password = :p WHERE id = :i'),
                {'p': plaintext, 'i': row.id},
            )

    with op.batch_alter_table('credentials') as batch:
        batch.drop_column('key_kind')
        batch.drop_column('private_key_enc')
        batch.drop_column('secret_enc')

    for col in ('created_at', 'action', 'actor_user_id',
                'target_type', 'target_id', 'request_id', 'organization_id'):
        op.drop_index(f'ix_audit_events_{col}', table_name='audit_events')
    op.drop_table('audit_events')
