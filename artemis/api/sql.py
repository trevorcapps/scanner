"""SQL query API blueprint — read-only SQL access to scanner database."""

import re
import time
import sqlite3
import logging

from flask import Blueprint, request

logger = logging.getLogger(__name__)

sql_bp = Blueprint('sql', __name__)


def _get_db_path():
    from flask import current_app
    return current_app.config['DB_PATH']


@sql_bp.route('/sql', methods=['POST'])
def api_sql_query():
    """Execute a read-only SQL query against the scanner database."""
    data = request.get_json()
    if not data or not data.get('query'):
        return {'error': 'Query is required'}, 400

    query = data['query'].strip()
    if not query:
        return {'error': 'Query is required'}, 400

    # Validate read-only
    normalized = re.sub(r'--.*$', '', query, flags=re.MULTILINE)
    normalized = re.sub(r'/\*.*?\*/', '', normalized, flags=re.DOTALL)
    normalized = normalized.strip().upper()

    allowed_prefixes = ('SELECT', 'PRAGMA', 'EXPLAIN', 'WITH')
    if not any(normalized.startswith(p) for p in allowed_prefixes):
        return {'error': 'Only SELECT queries are allowed (read-only mode).'}, 400

    dangerous = ['INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER', 'CREATE', 'REPLACE',
                 'ATTACH', 'DETACH', 'REINDEX', 'VACUUM']
    for kw in dangerous:
        if re.search(r'\b' + kw + r'\b', normalized):
            return {'error': f'{kw} statements are not allowed (read-only mode).'}, 400

    try:
        start = time.monotonic()
        conn = sqlite3.connect(_get_db_path())
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(query)
        rows_raw = cursor.fetchmany(1000)
        columns = [desc[0] for desc in cursor.description] if cursor.description else []
        rows = [list(row) for row in rows_raw]
        elapsed = round((time.monotonic() - start) * 1000, 1)
        conn.close()

        return {
            'columns': columns,
            'rows': rows,
            'count': len(rows),
            'time_ms': elapsed,
            'truncated': len(rows_raw) == 1000
        }
    except sqlite3.Error as e:
        return {'error': str(e)}, 400
    except Exception as e:
        logger.error(f"SQL query error: {e}")
        return {'error': str(e)}, 500
