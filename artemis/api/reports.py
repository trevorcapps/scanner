"""Reports API blueprint — read-only SQL console and report endpoints."""

import re
import time
import logging

from flask import Blueprint, request
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from artemis.extensions import db

logger = logging.getLogger(__name__)

reports_bp = Blueprint('reports', __name__)

_ALLOWED_PREFIXES = ('SELECT', 'PRAGMA', 'EXPLAIN', 'WITH', 'TABLE')
_DANGEROUS = ('INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER', 'CREATE', 'REPLACE',
              'ATTACH', 'DETACH', 'REINDEX', 'VACUUM', 'GRANT', 'REVOKE', 'COPY',
              'TRUNCATE', 'MERGE', 'CALL', 'DO', 'SET', 'COMMENT')
_MAX_ROWS = 1000


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
