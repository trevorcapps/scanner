"""Uniform error envelope for every /api response.

Shape: ``{"error": <message>, "code": <machine slug>, "request_id": <id>}``
with the matching HTTP status. Non-API routes keep Flask's default handling.
"""

import logging

from flask import g, jsonify, request
from werkzeug.exceptions import HTTPException

logger = logging.getLogger("artemis.api")

_CODES = {
    400: 'bad_request', 401: 'unauthorized', 403: 'forbidden', 404: 'not_found',
    405: 'method_not_allowed', 409: 'conflict', 413: 'payload_too_large',
    422: 'unprocessable', 429: 'rate_limited', 500: 'internal_error',
}


def _is_api():
    return request.path.startswith(('/api/', '/agent/'))


def _envelope(status, message, code=None):
    body = {
        'error': message,
        'code': code or _CODES.get(status, 'error'),
        'request_id': getattr(g, 'request_id', None),
    }
    response = jsonify(body)
    response.status_code = status
    return response


def register_error_handlers(app):
    @app.errorhandler(HTTPException)
    def _http_exc(exc):
        if not _is_api():
            return exc
        # A handler already produced a JSON body (e.g. rate limiter) — keep it.
        if exc.response is not None and exc.response.mimetype == 'application/json':
            return exc.response
        return _envelope(exc.code or 500, exc.description or exc.name)

    @app.errorhandler(404)
    def _not_found(exc):
        if not _is_api():
            return exc
        return _envelope(404, 'Resource not found')

    @app.errorhandler(Exception)
    def _unhandled(exc):
        if not _is_api():
            raise exc
        logger.exception('unhandled error on %s %s', request.method, request.path)
        return _envelope(500, 'Internal server error')
