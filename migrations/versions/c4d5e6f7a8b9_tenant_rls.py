"""PostgreSQL row-level security policies for tenant tables (defense in depth)

Revision ID: c4d5e6f7a8b9
Revises: b3c4d5e6f7a8
Create Date: 2026-09-03 23:30:00.000000

Adds an ``organization_id = current_setting('artemis.current_org')`` RLS policy
to every tenant table and ENABLEs RLS. It is intentionally **not FORCEd**: the
default single-role deployment connects as the table owner, who bypasses RLS, so
these policies are inert until an operator runs the app as a dedicated
restricted role (documented in docs/ARCHITECTURE.md) and sets
ARTEMIS_ENABLE_RLS=1. Application-level scoping via artemis.services.tenant is
the primary control.

No-op on SQLite.
"""

from alembic import op

revision = 'c4d5e6f7a8b9'
down_revision = 'b3c4d5e6f7a8'
branch_labels = None
depends_on = None

TENANT_TABLES = [
    'scans', 'assets', 'vulnerabilities', 'fingerprints', 'credentials',
    'cve_matches', 'installed_software', 'asset_os_details', 'scheduled_scans',
    'scan_history', 'agents', 'agent_reports', 'agent_data', 'sites',
    'site_scans', 'scan_jobs', 'risk_snapshots', 'webhooks', 'webhook_deliveries',
    'reports', 'report_schedules', 'agent_shell_sessions',
]

_USING = (
    "organization_id = NULLIF(current_setting('artemis.current_org', true), '')::int"
)


def upgrade():
    if op.get_bind().dialect.name != 'postgresql':
        return
    for table in TENANT_TABLES:
        op.execute(f'ALTER TABLE {table} ENABLE ROW LEVEL SECURITY')
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING ({_USING}) WITH CHECK ({_USING})"
        )


def downgrade():
    if op.get_bind().dialect.name != 'postgresql':
        return
    for table in TENANT_TABLES:
        op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON {table}')
        op.execute(f'ALTER TABLE {table} DISABLE ROW LEVEL SECURITY')
