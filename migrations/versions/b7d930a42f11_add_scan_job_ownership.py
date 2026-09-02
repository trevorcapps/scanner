"""add scan job ownership constraints

Revision ID: b7d930a42f11
Revises: 6766db20a99d
Create Date: 2026-09-02 07:18:00
"""

from alembic import op


revision = 'b7d930a42f11'
down_revision = '6766db20a99d'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('scan_jobs', schema=None) as batch_op:
        batch_op.create_foreign_key(
            'fk_scan_jobs_requested_by_users',
            'users',
            ['requested_by'],
            ['id'],
            ondelete='SET NULL',
        )
        batch_op.create_foreign_key(
            'fk_scan_jobs_site_id_sites',
            'sites',
            ['site_id'],
            ['id'],
            ondelete='SET NULL',
        )


def downgrade():
    with op.batch_alter_table('scan_jobs', schema=None) as batch_op:
        batch_op.drop_constraint('fk_scan_jobs_site_id_sites', type_='foreignkey')
        batch_op.drop_constraint('fk_scan_jobs_requested_by_users', type_='foreignkey')
