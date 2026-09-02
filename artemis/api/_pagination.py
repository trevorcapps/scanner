"""Shared list-response helpers for the /api/v1 blueprints."""

from flask import request

DEFAULT_PER_PAGE = 50
MAX_PER_PAGE = 200


def page_args():
    """Read ``page`` / ``per_page`` from the query string, clamped."""
    try:
        page = max(1, int(request.args.get('page', 1)))
    except (TypeError, ValueError):
        page = 1
    try:
        per_page = int(request.args.get('per_page', DEFAULT_PER_PAGE))
    except (TypeError, ValueError):
        per_page = DEFAULT_PER_PAGE
    per_page = max(1, min(per_page, MAX_PER_PAGE))
    return page, per_page


def paginate(query, serializer=lambda o: o.to_dict(), key='data'):
    """Run a SQLAlchemy ``query`` for the current page and wrap the result.

    Returns ``{<key>: [...], 'pagination': {...}}``.
    """
    page, per_page = page_args()
    total = query.order_by(None).count()
    items = query.limit(per_page).offset((page - 1) * per_page).all()
    return {
        key: [serializer(i) for i in items],
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': (total + per_page - 1) // per_page if per_page else 0,
        },
    }


def paginate_list(items, serializer=lambda o: o, key='data'):
    """Same envelope for an in-memory list (used where the query is not ORM)."""
    page, per_page = page_args()
    total = len(items)
    start = (page - 1) * per_page
    window = items[start:start + per_page]
    return {
        key: [serializer(i) for i in window],
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': (total + per_page - 1) // per_page if per_page else 0,
        },
    }
