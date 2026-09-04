"""Reports API — read-only SQL console, executive report generation & delivery."""

import json
import os
import re
import time
import logging
from datetime import datetime, timezone

from flask import Blueprint, current_app, request, send_file, g
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from artemis.extensions import db
from artemis.models.report import Report, ReportSchedule
from artemis.services.auth_service import login_required, role_required

logger = logging.getLogger(__name__)

reports_bp = Blueprint('reports', __name__)

_ALLOWED_PREFIXES = ('SELECT', 'PRAGMA', 'EXPLAIN', 'WITH', 'TABLE')
_DANGEROUS = ('INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER', 'CREATE', 'REPLACE',
              'ATTACH', 'DETACH', 'REINDEX', 'VACUUM', 'GRANT', 'REVOKE', 'COPY',
              'TRUNCATE', 'MERGE', 'CALL', 'DO', 'SET', 'COMMENT')
_MAX_ROWS = 1000

_KINDS = ('executive', 'technical', 'full')
_FORMATS = ('pdf', 'html')
_BRANDING_KEYS = ('report_org_name', 'report_logo', 'report_accent_color',
                  'report_footer', 'report_confidentiality')
_SMTP_KEYS = ('smtp_host', 'smtp_port', 'smtp_username', 'smtp_from', 'smtp_security')


def _uid():
    return getattr(getattr(g, 'current_user', None), 'id', None)


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


# --------------------------------------------------------------------------- #
# Read-only SQL console
# --------------------------------------------------------------------------- #

@reports_bp.route('/sql', methods=['POST'])
def api_sql_query():
    """
    ---
    post:
      summary: Run a read-only SQL query against the Postgres system of record
      description: >
        SELECT-only. The NVD/CPE/ExploitDB feed cache lives in a separate SQLite
        database and is not queryable here.
      tags: [Reports]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                query: {type: string}
      responses:
        200: {description: Result set (capped at 1000 rows)}
        400: {description: Rejected or invalid query}
      security: [{bearerAuth: []}]
    """
    data = request.get_json(silent=True)
    if not data or not data.get('query') or not data['query'].strip():
        return {'error': 'Query is required'}, 400

    query = data['query'].strip()

    normalized = re.sub(r'--.*$', '', query, flags=re.MULTILINE)
    normalized = re.sub(r'/\*.*?\*/', '', normalized, flags=re.DOTALL)
    normalized = normalized.strip().rstrip(';').upper()

    if ';' in normalized:
        return {'error': 'Multiple statements are not allowed.'}, 400
    if not any(normalized.startswith(p) for p in _ALLOWED_PREFIXES):
        return {'error': 'Only SELECT queries are allowed (read-only mode).'}, 400
    for kw in _DANGEROUS:
        if re.search(r'\b' + kw + r'\b', normalized):
            return {'error': f'{kw} statements are not allowed (read-only mode).'}, 400

    try:
        start = time.monotonic()
        with db.engine.connect() as conn:
            conn = conn.execution_options(postgresql_readonly=True)
            try:
                conn.exec_driver_sql("SET statement_timeout = 15000")
            except SQLAlchemyError:
                pass  # sqlite (tests) has no statement_timeout
            result = conn.execute(text(query))
            columns = list(result.keys())
            rows_raw = result.fetchmany(_MAX_ROWS + 1)
        elapsed = round((time.monotonic() - start) * 1000, 1)
        truncated = len(rows_raw) > _MAX_ROWS
        rows = [list(r) for r in rows_raw[:_MAX_ROWS]]

        return {
            'columns': columns,
            'rows': rows,
            'count': len(rows),
            'time_ms': elapsed,
            'truncated': truncated,
        }
    except SQLAlchemyError as e:
        return {'error': str(getattr(e, 'orig', e))}, 400
    except Exception as e:
        logger.error(f"SQL query error: {e}")
        return {'error': str(e)}, 500


# --------------------------------------------------------------------------- #
# Report generation & history
# --------------------------------------------------------------------------- #

@reports_bp.route('/reports', methods=['GET'])
@login_required
def list_reports():
    """
    ---
    get:
      summary: Generated report history
      tags: [Reports]
      responses: {200: {description: List of reports}}
      security: [{bearerAuth: []}]
    """
    rows = Report.query.order_by(Report.id.desc()).limit(200).all()
    return {'reports': [r.to_dict() for r in rows]}


@reports_bp.route('/reports', methods=['POST'])
@login_required
def create_report():
    """
    ---
    post:
      summary: Generate an executive / technical report
      tags: [Reports]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                kind: {type: string, enum: [executive, technical, full]}
                format: {type: string, enum: [pdf, html]}
                scope:
                  type: object
                  description: >
                    {"type":"environment"} | {"type":"site","id":N} |
                    {"type":"filter","min_severity":"high","device_type":"server","subnet":"10.0.0.0/24"}
      responses:
        201: {description: Report generated}
        400: {description: Invalid request}
        501: {description: PDF export unavailable}
      security: [{bearerAuth: []}]
    """
    from artemis.services.executive_report_service import build_report

    data = request.get_json(silent=True) or {}
    kind = (data.get('kind') or 'executive').lower()
    fmt = (data.get('format') or 'pdf').lower()
    scope = data.get('scope') or {'type': 'environment'}

    if kind not in _KINDS:
        return {'error': f'kind must be one of {", ".join(_KINDS)}'}, 400
    if fmt not in _FORMATS:
        return {'error': f'format must be one of {", ".join(_FORMATS)}'}, 400
    if not isinstance(scope, dict) or scope.get('type') not in ('environment', 'site', 'filter'):
        return {'error': 'scope.type must be environment, site or filter'}, 400

    rec = build_report(scope, kind=kind, fmt=fmt, generated_by=_uid())
    if rec.status != 'ready':
        code = 501 if 'WeasyPrint' in (rec.error or '') else 500
        return {'error': rec.error or 'Report generation failed', 'report': rec.to_dict()}, code
    return {'report': rec.to_dict()}, 201


@reports_bp.route('/reports/<int:report_id>', methods=['GET'])
@login_required
def get_report(report_id):
    """
    ---
    get:
      summary: Report metadata
      tags: [Reports]
      parameters: [{in: path, name: report_id, required: true, schema: {type: integer}}]
      responses: {200: {description: Report}, 404: {description: Not found}}
      security: [{bearerAuth: []}]
    """
    from artemis.services.tenant import scoped_get
    rec = scoped_get(Report, report_id)
    if not rec:
        return {'error': 'Not found'}, 404
    return {'report': rec.to_dict()}


@reports_bp.route('/reports/<int:report_id>/download', methods=['GET'])
@login_required
def download_report(report_id):
    """
    ---
    get:
      summary: Download the generated report file
      tags: [Reports]
      parameters: [{in: path, name: report_id, required: true, schema: {type: integer}}]
      responses: {200: {description: File}, 404: {description: Not found}}
      security: [{bearerAuth: []}]
    """
    from artemis.services.tenant import current_org_id, scoped_get
    rec = scoped_get(Report, report_id)
    if not rec or not rec.file_path or not os.path.isfile(rec.file_path):
        return {'error': 'Report file not available'}, 404
    # Defence in depth: the file must live under this org's artifact directory.
    org_dir = os.path.realpath(os.path.join(current_app.config['REPORTS_DIR'], f"org-{current_org_id()}"))
    if not os.path.realpath(rec.file_path).startswith(org_dir + os.sep):
        return {'error': 'Report file not available'}, 404
    mimetype = 'application/pdf' if rec.fmt == 'pdf' else 'text/html'
    dl = f"{re.sub(r'[^A-Za-z0-9._-]+', '-', rec.title)}.{rec.fmt}"
    from artemis.services import audit_service
    audit_service.record(
        audit_service.EXPORT, target_type='report', target_id=report_id,
        detail={'format': rec.fmt, 'title': rec.title}, commit=True,
    )
    return send_file(rec.file_path, mimetype=mimetype, as_attachment=True, download_name=dl)


@reports_bp.route('/reports/<int:report_id>', methods=['DELETE'])
@role_required('admin')
def delete_report(report_id):
    """
    ---
    delete:
      summary: Delete a generated report (and its file)
      tags: [Reports]
      parameters: [{in: path, name: report_id, required: true, schema: {type: integer}}]
      responses: {200: {description: Deleted}}
      security: [{bearerAuth: []}]
    """
    rec = db.session.get(Report, report_id)
    if not rec:
        return {'error': 'Not found'}, 404
    if rec.file_path and os.path.isfile(rec.file_path):
        try:
            os.remove(rec.file_path)
        except OSError:
            pass
    db.session.delete(rec)
    db.session.commit()
    return {'success': True}


@reports_bp.route('/reports/trends', methods=['GET'])
@login_required
def report_trends():
    """
    ---
    get:
      summary: Daily environment risk snapshots (trajectory data)
      tags: [Reports]
      parameters: [{in: query, name: days, schema: {type: integer, default: 90}}]
      responses: {200: {description: Series}}
      security: [{bearerAuth: []}]
    """
    from artemis.services.risk_snapshot_service import get_snapshots
    try:
        days = max(2, min(365, int(request.args.get('days', 90))))
    except (TypeError, ValueError):
        days = 90
    return {'days': days, 'series': get_snapshots(days=days)}


@reports_bp.route('/reports/snapshot', methods=['POST'])
@role_required('admin')
def capture_snapshot_now():
    """
    ---
    post:
      summary: Capture today's risk snapshot immediately (overwrites today's row)
      tags: [Reports]
      responses: {200: {description: Snapshot}}
      security: [{bearerAuth: []}]
    """
    from artemis.services.risk_snapshot_service import capture_snapshot
    row = capture_snapshot(force=True)
    return {'snapshot': row.to_dict()}


# --------------------------------------------------------------------------- #
# Branding & SMTP settings
# --------------------------------------------------------------------------- #

@reports_bp.route('/reports/branding', methods=['GET'])
@login_required
def get_branding_api():
    """
    ---
    get:
      summary: Report branding settings
      tags: [Reports]
      responses: {200: {description: Branding}}
      security: [{bearerAuth: []}]
    """
    from artemis.services.auth_scan_service import get_setting
    return {k: get_setting(k, '') or '' for k in _BRANDING_KEYS}


@reports_bp.route('/reports/branding', methods=['PUT'])
@role_required('admin')
def set_branding_api():
    """
    ---
    put:
      summary: Update report branding settings
      tags: [Reports]
      requestBody:
        content: {application/json: {schema: {type: object}}}
      responses: {200: {description: Saved}}
      security: [{bearerAuth: []}]
    """
    from artemis.services.auth_scan_service import set_setting
    data = request.get_json(silent=True) or {}
    for k in _BRANDING_KEYS:
        if k in data:
            set_setting(k, str(data[k] or ''))
    return {'success': True}


@reports_bp.route('/reports/smtp', methods=['GET'])
@role_required('admin')
def get_smtp_api():
    """
    ---
    get:
      summary: SMTP settings (password redacted)
      tags: [Reports]
      responses: {200: {description: SMTP config}}
      security: [{bearerAuth: []}]
    """
    from artemis.services.auth_scan_service import get_setting
    out = {k: get_setting(k, '') or '' for k in _SMTP_KEYS}
    out['smtp_password_set'] = bool(get_setting('smtp_password', ''))
    return out


@reports_bp.route('/reports/smtp', methods=['PUT'])
@role_required('admin')
def set_smtp_api():
    """
    ---
    put:
      summary: Update SMTP settings
      tags: [Reports]
      requestBody:
        content: {application/json: {schema: {type: object}}}
      responses: {200: {description: Saved}}
      security: [{bearerAuth: []}]
    """
    from artemis.services.auth_scan_service import set_setting
    data = request.get_json(silent=True) or {}
    for k in _SMTP_KEYS:
        if k in data:
            set_setting(k, str(data[k] or ''))
    if data.get('smtp_password'):
        set_setting('smtp_password', str(data['smtp_password']))
    elif data.get('smtp_password_clear'):
        set_setting('smtp_password', '')
    return {'success': True}


@reports_bp.route('/reports/test-email', methods=['POST'])
@role_required('admin')
def test_email_api():
    """
    ---
    post:
      summary: Send a test email with the current SMTP settings
      tags: [Reports]
      requestBody:
        content: {application/json: {schema: {type: object, properties: {recipient: {type: string}}}}}
      responses: {200: {description: Sent}, 400: {description: Failed}}
      security: [{bearerAuth: []}]
    """
    from artemis.services.email_service import send_test_email
    data = request.get_json(silent=True) or {}
    recipient = (data.get('recipient') or '').strip()
    if not recipient:
        return {'error': 'recipient is required'}, 400
    try:
        send_test_email(recipient)
        return {'success': True}
    except Exception as e:
        return {'error': str(e)}, 400


# --------------------------------------------------------------------------- #
# Scheduled reports
# --------------------------------------------------------------------------- #

def _validate_schedule(data):
    from croniter import croniter
    name = (data.get('name') or '').strip()
    if not name:
        return None, 'name is required'
    kind = (data.get('kind') or 'executive').lower()
    fmt = (data.get('format') or 'pdf').lower()
    cron = (data.get('cron_expression') or '').strip()
    if kind not in _KINDS:
        return None, f'kind must be one of {", ".join(_KINDS)}'
    if fmt not in _FORMATS:
        return None, f'format must be one of {", ".join(_FORMATS)}'
    if not croniter.is_valid(cron):
        return None, 'cron_expression is not a valid 5-field cron'
    scope = data.get('scope') or {'type': 'environment'}
    if not isinstance(scope, dict) or scope.get('type') not in ('environment', 'site', 'filter'):
        return None, 'scope.type must be environment, site or filter'
    recipients = data.get('recipients')
    if isinstance(recipients, list):
        recipients = ', '.join(r.strip() for r in recipients if r.strip())
    return {
        'name': name, 'kind': kind, 'fmt': fmt, 'cron': cron,
        'scope': scope, 'recipients': (recipients or '').strip(),
        'enabled': 1 if data.get('enabled', True) else 0,
    }, None


@reports_bp.route('/report-schedules', methods=['GET'])
@login_required
def list_report_schedules():
    """
    ---
    get:
      summary: List scheduled reports
      tags: [Reports]
      responses: {200: {description: Schedules}}
      security: [{bearerAuth: []}]
    """
    rows = ReportSchedule.query.order_by(ReportSchedule.id.desc()).all()
    return {'schedules': [r.to_dict() for r in rows]}


@reports_bp.route('/report-schedules', methods=['POST'])
@role_required('admin')
def create_report_schedule():
    """
    ---
    post:
      summary: Create a scheduled report
      tags: [Reports]
      requestBody:
        content: {application/json: {schema: {type: object}}}
      responses: {201: {description: Created}, 400: {description: Invalid}}
      security: [{bearerAuth: []}]
    """
    from artemis.services.report_schedule_runner import next_cron
    v, err = _validate_schedule(request.get_json(silent=True) or {})
    if err:
        return {'error': err}, 400
    row = ReportSchedule(
        name=v['name'], kind=v['kind'], fmt=v['fmt'], cron_expression=v['cron'],
        scope_json=json.dumps(v['scope']), recipients=v['recipients'], enabled=v['enabled'],
        created_at=_now(), updated_at=_now(), next_run=next_cron(v['cron']),
    )
    db.session.add(row)
    db.session.commit()
    return {'schedule': row.to_dict()}, 201


@reports_bp.route('/report-schedules/<int:sid>', methods=['PUT'])
@role_required('admin')
def update_report_schedule(sid):
    """
    ---
    put:
      summary: Update a scheduled report
      tags: [Reports]
      parameters: [{in: path, name: sid, required: true, schema: {type: integer}}]
      responses: {200: {description: Updated}, 404: {description: Not found}}
      security: [{bearerAuth: []}]
    """
    from artemis.services.report_schedule_runner import next_cron
    row = db.session.get(ReportSchedule, sid)
    if not row:
        return {'error': 'Not found'}, 404
    v, err = _validate_schedule(request.get_json(silent=True) or {})
    if err:
        return {'error': err}, 400
    row.name, row.kind, row.fmt = v['name'], v['kind'], v['fmt']
    row.cron_expression = v['cron']
    row.scope_json = json.dumps(v['scope'])
    row.recipients = v['recipients']
    row.enabled = v['enabled']
    row.next_run = next_cron(v['cron']) if row.enabled else None
    row.updated_at = _now()
    db.session.commit()
    return {'schedule': row.to_dict()}


@reports_bp.route('/report-schedules/<int:sid>', methods=['DELETE'])
@role_required('admin')
def delete_report_schedule(sid):
    """
    ---
    delete:
      summary: Delete a scheduled report
      tags: [Reports]
      parameters: [{in: path, name: sid, required: true, schema: {type: integer}}]
      responses: {200: {description: Deleted}}
      security: [{bearerAuth: []}]
    """
    row = db.session.get(ReportSchedule, sid)
    if not row:
        return {'error': 'Not found'}, 404
    db.session.delete(row)
    db.session.commit()
    return {'success': True}


@reports_bp.route('/report-schedules/<int:sid>/run', methods=['POST'])
@role_required('admin')
def run_report_schedule_now(sid):
    """
    ---
    post:
      summary: Generate + deliver a scheduled report immediately
      tags: [Reports]
      parameters: [{in: path, name: sid, required: true, schema: {type: integer}}]
      responses: {200: {description: Ran}, 404: {description: Not found}}
      security: [{bearerAuth: []}]
    """
    from artemis.services.report_schedule_runner import _run_one
    row = db.session.get(ReportSchedule, sid)
    if not row:
        return {'error': 'Not found'}, 404
    _run_one(row)
    row.last_run = _now()
    row.updated_at = _now()
    db.session.commit()
    return {'schedule': row.to_dict()}
