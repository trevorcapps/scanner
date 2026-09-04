"""tenant columns: organization_id on every tenant-owned table

Revision ID: b3c4d5e6f7a8
Revises: a2b3c4d5e6f7
Create Date: 2026-09-03 22:45:00.000000

Expand / backfill / contract for ~20 tables:
  1. add nullable organization_id
  2. backfill every row to the Default organization
  3. make it NOT NULL, index it, and re-scope the globally-unique keys
     (asset IP, site name, credential name, ...) to (organization_id, key)
"""

import sqlalchemy as sa
from alembic import op

revision = 'b3c4d5e6f7a8'
down_revision = 'a2b3c4d5e6f7'
branch_labels = None
depends_on = None

SIMPLE_TABLES = [
    'scans', 'assets', 'vulnerabilities', 'fingerprints', 'credentials',
    'cve_matches', 'installed_software', 'asset_os_details', 'scheduled_scans',
    'scan_history', 'agents', 'agent_reports', 'agent_data', 'sites',
    'site_scans', 'scan_jobs', 'risk_snapshots', 'webhooks', 'webhook_deliveries',
    'reports', 'report_schedules', 'agent_shell_sessions',
]

# table -> (old multi-col unique cols, new composite cols, new name)
MULTI_UNIQUE_SWAPS = [
    ('vulnerabilities', ['ip', 'port', 'protocol', 'vuln_id'],
     ['organization_id', 'ip', 'port', 'protocol', 'vuln_id'], 'uq_vuln_org_ip_port_proto_id'),
    ('fingerprints', ['ip', 'port', 'protocol', 'signature_id'],
     ['organization_id', 'ip', 'port', 'protocol', 'signature_id'], 'uq_fp_org_ip_port_proto_sig'),
    ('cve_matches', ['ip', 'cve_id'],
     ['organization_id', 'ip', 'cve_id'], 'uq_cve_match_org_ip_cve'),
    ('installed_software', ['ip', 'package_name'],
     ['organization_id', 'ip', 'package_name'], 'uq_sw_org_ip_pkg'),
]

COLUMN_UNIQUE_SWAPS = [
    ('assets', 'ip', 'uq_asset_org_ip'),
    ('asset_os_details', 'ip', 'uq_asset_os_org_ip'),
    ('agent_data', 'ip', 'uq_agent_data_org_ip'),
    ('credentials', 'name', 'uq_credential_org_name'),
    ('sites', 'name', 'uq_site_org_name'),
    ('risk_snapshots', 'snapshot_date', 'uq_risk_snapshot_org_date'),
]


def _is_sqlite():
    return op.get_bind().dialect.name == 'sqlite'


def _batch(table):
    # SQLite cannot ALTER columns / constraints in place; every other backend
    # can, and forcing a recreate there breaks FK dependencies.
    return op.batch_alter_table(table, recreate='always' if _is_sqlite() else 'auto')


def _uniques(insp, table):
    return {tuple(uc['column_names']): uc['name'] for uc in insp.get_unique_constraints(table)}


def _drop_index_if_exists(insp, table, name):
    if any(ix['name'] == name for ix in insp.get_indexes(table)):
        op.drop_index(name, table_name=table)


def _default_org_id(bind):
    return bind.execute(sa.text("SELECT id FROM organizations WHERE slug = 'default'")).scalar()


def upgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)
    org_id = _default_org_id(bind)
    if org_id is None:
        raise RuntimeError("Default organization missing; run migration a2b3c4d5e6f7 first")

    for table in SIMPLE_TABLES:
        with op.batch_alter_table(table) as batch:
            batch.add_column(sa.Column('organization_id', sa.Integer(), nullable=True))
        bind.execute(sa.text(f"UPDATE {table} SET organization_id = :o"), {'o': org_id})

    for table in SIMPLE_TABLES:
        with _batch(table) as batch:
            batch.alter_column('organization_id', existing_type=sa.Integer(), nullable=False)
            batch.create_foreign_key(
                f'fk_{table}_organization', 'organizations',
                ['organization_id'], ['id'], ondelete='CASCADE',
            )
        op.create_index(f'ix_{table}_organization_id', table, ['organization_id'])

    for table, old_cols, new_cols, new_name in MULTI_UNIQUE_SWAPS:
        old_name = _uniques(insp, table).get(tuple(old_cols))
        with _batch(table) as batch:
            if old_name:
                batch.drop_constraint(old_name, type_='unique')
            batch.create_unique_constraint(new_name, new_cols)

    # agent_data.ip carried a UNIQUE index (index=True + unique=True); it is now
    # a plain index, with uniqueness moving to (organization_id, ip).
    _drop_index_if_exists(insp, 'agent_data', 'ix_agent_data_ip')

    for table, col, new_name in COLUMN_UNIQUE_SWAPS:
        old_name = _uniques(insp, table).get((col,))
        with _batch(table) as batch:
            if old_name:
                batch.drop_constraint(old_name, type_='unique')
            batch.create_unique_constraint(new_name, ['organization_id', col])

    op.create_index('ix_agent_data_ip', 'agent_data', ['ip'])


def downgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)

    _drop_index_if_exists(insp, 'agent_data', 'ix_agent_data_ip')

    for table, col, new_name in COLUMN_UNIQUE_SWAPS:
        exists = _uniques(insp, table).get(('organization_id', col))
        with _batch(table) as batch:
            if exists:
                batch.drop_constraint(exists, type_='unique')
            batch.create_unique_constraint(f'{table}_{col}_key', [col])

    op.create_index('ix_agent_data_ip', 'agent_data', ['ip'], unique=True)

    for table, old_cols, new_cols, new_name in MULTI_UNIQUE_SWAPS:
        exists = _uniques(insp, table).get(tuple(new_cols))
        with _batch(table) as batch:
            if exists:
                batch.drop_constraint(exists, type_='unique')
            batch.create_unique_constraint(f'uq_{table}_legacy', old_cols)

    for table in SIMPLE_TABLES:
        op.drop_index(f'ix_{table}_organization_id', table_name=table)
        with _batch(table) as batch:
            batch.drop_constraint(f'fk_{table}_organization', type_='foreignkey')
            batch.drop_column('organization_id')
