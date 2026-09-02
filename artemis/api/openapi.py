"""OpenAPI 3 spec generation + Swagger UI.

The spec is built by introspecting the registered ``/api/v1`` URL rules and
reading a YAML block from each view function's docstring (``apispec``'s
``load_operations_from_docstring``). Routes without a YAML block still appear,
with a summary taken from the plain docstring.
"""

import re
import logging

from flask import Blueprint, current_app, jsonify

from apispec import APISpec
from apispec.yaml_utils import load_operations_from_docstring

logger = logging.getLogger(__name__)

docs_bp = Blueprint('docs', __name__)

_PATH_PARAM = re.compile(r'<(?:[^:<>]+:)?([^<>]+)>')
_SPEC_CACHE = {}


def _flask_path_to_openapi(rule):
    return _PATH_PARAM.sub(r'{\1}', rule)


def _path_params(rule):
    return _PATH_PARAM.findall(rule)


def _tag_for(path):
    # /api/v1/<resource>/... -> Resource
    parts = [p for p in path.split('/') if p and not p.startswith('{')]
    resource = parts[2] if len(parts) > 2 else 'Meta'
    return resource.replace('-', ' ').title().replace(' ', '')


_COMPONENT_SCHEMAS = {
    'Error': {
        'type': 'object',
        'properties': {'error': {'type': 'string'}},
    },
    'Pagination': {
        'type': 'object',
        'properties': {
            'page': {'type': 'integer'}, 'per_page': {'type': 'integer'},
            'total': {'type': 'integer'}, 'pages': {'type': 'integer'},
        },
    },
    'Asset': {
        'type': 'object',
        'properties': {
            'ip': {'type': 'string'}, 'hostname': {'type': 'string', 'nullable': True},
            'device_type': {'type': 'string', 'nullable': True},
            'os_name': {'type': 'string', 'nullable': True},
            'mac_address': {'type': 'string', 'nullable': True},
            'first_seen': {'type': 'string'}, 'last_seen': {'type': 'string'},
            'scan_count': {'type': 'integer'},
            'port_count': {'type': 'integer'},
            'vuln_counts': {'type': 'object'},
        },
    },
    'Scan': {
        'type': 'object',
        'properties': {
            'ip': {'type': 'string'}, 'protocol': {'type': 'string'},
            'port': {'type': 'integer'}, 'state': {'type': 'string'},
            'service': {'type': 'string'}, 'product': {'type': 'string'},
            'version': {'type': 'string'}, 'scan_date': {'type': 'string'},
        },
    },
    'Vulnerability': {
        'type': 'object',
        'properties': {
            'cve_id': {'type': 'string'}, 'vuln_name': {'type': 'string'},
            'severity': {'type': 'string'}, 'description': {'type': 'string'},
            'cvss_score': {'type': 'number', 'nullable': True},
            'has_exploit': {'type': 'boolean'},
            'detection_sources': {'type': 'array', 'items': {'type': 'string'}},
            'affected_assets': {'type': 'array', 'items': {'type': 'object'}},
        },
    },
    'Fingerprint': {
        'type': 'object',
        'properties': {
            'ip': {'type': 'string'}, 'port': {'type': 'integer'},
            'name': {'type': 'string'}, 'category': {'type': 'string'},
            'vendor': {'type': 'string'}, 'version': {'type': 'string', 'nullable': True},
            'confidence': {'type': 'integer'},
        },
    },
    'ScanJob': {
        'type': 'object',
        'properties': {
            'id': {'type': 'string'}, 'job_type': {'type': 'string'},
            'status': {'type': 'string'}, 'target': {'type': 'string'},
            'created_at': {'type': 'string'}, 'result': {'type': 'object', 'nullable': True},
        },
    },
    'Webhook': {
        'type': 'object',
        'properties': {
            'id': {'type': 'integer'}, 'url': {'type': 'string'},
            'events': {'type': 'array', 'items': {'type': 'string'}},
            'enabled': {'type': 'boolean'}, 'description': {'type': 'string'},
            'last_status': {'type': 'string', 'nullable': True},
            'last_delivery_at': {'type': 'string', 'nullable': True},
        },
    },
}


def build_spec(app):
    version = app.config.get('API_VERSION', '2.0.0')
    if version in _SPEC_CACHE:
        return _SPEC_CACHE[version]

    spec = APISpec(
        title='Artemis Scanner API',
        version=version,
        openapi_version='3.0.3',
        info={'description': 'Network vulnerability scanner & asset inventory. '
                            'Authenticate with a bearer JWT (`/api/v1/auth/login`) '
                            'or an `X-API-Key`. Agent endpoints use `X-Agent-Key`.'},
    )

    for name, schema in _COMPONENT_SCHEMAS.items():
        spec.components.schema(name, schema)

    spec.components.security_scheme('bearerAuth', {
        'type': 'http', 'scheme': 'bearer', 'bearerFormat': 'JWT'})
    spec.components.security_scheme('apiKeyAuth', {
        'type': 'apiKey', 'in': 'header', 'name': 'X-API-Key'})
    spec.components.security_scheme('agentKeyAuth', {
        'type': 'apiKey', 'in': 'header', 'name': 'X-Agent-Key'})

    seen = {}
    for rule in app.url_map.iter_rules():
        if not rule.rule.startswith('/api/v1/'):
            continue
        if rule.rule.endswith(('/openapi.json', '/docs')):
            continue
        view = app.view_functions.get(rule.endpoint)
        if view is None:
            continue

        oapi_path = _flask_path_to_openapi(rule.rule)
        methods = sorted(m.lower() for m in (rule.methods or set())
                         if m not in ('HEAD', 'OPTIONS'))

        ops = load_operations_from_docstring(view.__doc__ or '') or {}
        if not ops:
            summary = (view.__doc__ or '').strip().splitlines()[0].strip() if view.__doc__ else rule.endpoint
            ops = {m: {'summary': summary, 'tags': [_tag_for(oapi_path)],
                       'responses': {'200': {'description': 'OK'}}}
                   for m in methods}

        # Fill in path params + a sane default tag/response for each operation.
        for m, op in ops.items():
            op.setdefault('tags', [_tag_for(oapi_path)])
            op.setdefault('responses', {'200': {'description': 'OK'}})
            params = op.setdefault('parameters', [])
            have = {(p.get('name'), p.get('in')) for p in params}
            for pname in _path_params(rule.rule):
                if (pname, 'path') not in have:
                    params.append({'in': 'path', 'name': pname, 'required': True,
                                   'schema': {'type': 'string'}})

        merged = seen.setdefault(oapi_path, {})
        merged.update(ops)

    for path, operations in sorted(seen.items()):
        try:
            spec.path(path=path, operations=operations)
        except Exception as e:  # pragma: no cover - defensive
            logger.warning(f"OpenAPI: could not add {path}: {e}")

    doc = spec.to_dict()
    doc.setdefault('security', [{'bearerAuth': []}, {'apiKeyAuth': []}])
    _SPEC_CACHE[version] = doc
    return doc


@docs_bp.route('/openapi.json')
def openapi_json():
    """
    ---
    get:
      summary: This OpenAPI document
      tags: [Meta]
      responses:
        200: {description: OpenAPI 3 spec}
    """
    return jsonify(build_spec(current_app._get_current_object()))


_SWAGGER_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Artemis API</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.17.14/swagger-ui.min.css">
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.17.14/swagger-ui-bundle.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.17.14/swagger-ui-standalone-preset.min.js"></script>
<script>
window.onload = function () {
  window.ui = SwaggerUIBundle({
    url: '/api/v1/openapi.json',
    dom_id: '#swagger-ui',
    deepLinking: true,
    persistAuthorization: true,
    presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
    layout: 'StandaloneLayout',
  });
};
</script>
</body>
</html>"""


@docs_bp.route('/health')
def health():
    """
    ---
    get:
      summary: Liveness / dependency health
      tags: [Meta]
      responses:
        200: {description: All dependencies reachable}
        503: {description: A dependency is down}
    """
    from artemis.extensions import db
    from sqlalchemy import text as _text

    checks = {}
    ok = True

    try:
        db.session.execute(_text('SELECT 1'))
        checks['database'] = 'ok'
    except Exception as e:
        checks['database'] = f'error: {e}'
        ok = False

    cache = current_app.config.get('NVD_CACHE_PATH')
    if cache and cache != ':memory:':
        import os
        checks['nvd_cache'] = 'ok' if os.path.isfile(cache) else 'missing'
    else:
        checks['nvd_cache'] = 'n/a'

    broker = current_app.config.get('CELERY_BROKER_URL', '')
    if broker.startswith('redis'):
        try:
            import redis
            redis.from_url(broker).ping()
            checks['redis'] = 'ok'
        except Exception as e:
            checks['redis'] = f'error: {e}'
            ok = False
    else:
        checks['redis'] = 'eager'

    body = {'status': 'ok' if ok else 'degraded',
            'version': current_app.config.get('API_VERSION', '2.0.0'),
            'checks': checks}
    return (body, 200) if ok else (body, 503)


@docs_bp.route('/docs')
def swagger_ui():
    """
    ---
    get:
      summary: Swagger UI for the API
      tags: [Meta]
      responses:
        200: {description: HTML page}
    """
    return _SWAGGER_HTML
