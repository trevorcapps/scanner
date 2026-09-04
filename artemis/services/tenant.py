"""The tenant query/write boundary.

Rules (enforced from Phase 1.3 onward):
  * Reads of a tenant-owned model go through ``scoped(Model)``.
  * Writes never set ``organization_id`` by hand — a ``before_flush`` hook stamps
    it from the active request's organization (or the Default organization
    outside a request, e.g. background jobs and tests).
  * ``current_org_id()`` raises when no context can be resolved, so a missing
    context fails closed rather than leaking across tenants.
"""

import logging

from flask import g, has_request_context
from sqlalchemy import event, inspect

from artemis.extensions import db
from artemis.models._tenant import TenantMixin

logger = logging.getLogger(__name__)


class TenantContextError(RuntimeError):
    pass


def current_org_id(required=True):
    org_id = getattr(g, 'organization_id', None) if has_request_context() else None
    if org_id is None:
        org_id = getattr(_fallback, 'org_id', None)
    if org_id is None and required:
        raise TenantContextError('no active organization for this operation')
    return org_id


class _Fallback:
    """Explicit org id for code that runs outside a request (Celery, CLI, tests)."""
    org_id = None


_fallback = _Fallback()


class use_organization:  # noqa: N801 - context-manager naming
    def __init__(self, org_id):
        self.org_id = org_id
        self._prev = None

    def __enter__(self):
        self._prev = _fallback.org_id
        _fallback.org_id = self.org_id
        return self

    def __exit__(self, *exc):
        _fallback.org_id = self._prev
        return False


def _default_org():
    from artemis.models.organization import Organization
    return (Organization.query.filter_by(is_default=1).first()
            or Organization.query.order_by(Organization.id).first())


def scoped(model):
    """A query pre-filtered to the active organization."""
    return model.query.filter(model.organization_id == current_org_id())


def scoped_get(model, pk):
    obj = db.session.get(model, pk)
    if obj is None:
        return None
    if getattr(obj, 'organization_id', None) != current_org_id():
        return None
    return obj


@event.listens_for(db.session, 'before_flush')
def _stamp_organization(session, _flush_context, _instances):
    pending = [o for o in session.new
               if isinstance(o, TenantMixin) and getattr(o, 'organization_id', None) is None]
    if not pending:
        return

    org_id = current_org_id(required=False)
    default_org = None
    if org_id is None:
        default_org = _default_org()
        org_id = default_org.id if default_org is not None else None

    for obj in pending:
        if org_id is not None:
            obj.organization_id = org_id
        elif default_org is not None:
            obj.organization = default_org       # pending org, FK resolved at flush
        else:
            logger.warning(
                "tenant row %s flushed with no organization context",
                inspect(obj).mapper.class_.__name__,
            )
