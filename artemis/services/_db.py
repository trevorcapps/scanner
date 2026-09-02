"""Small SQLAlchemy helpers shared by the scan-pipeline services.

These services were converted from raw ``sqlite3`` (with ``INSERT OR REPLACE``)
to the ORM. ``upsert`` replaces that idiom in a backend-agnostic way; write
volume here is low (a handful of rows per scan) so a select-then-write is fine.
"""

from artemis.extensions import db


def upsert(model, match: dict, values: dict):
    """Insert or update a single row.

    Looks up ``model`` by the ``match`` column/value pairs. If found, assigns
    every ``values`` field onto it; otherwise creates a new instance from
    ``match | values``. The caller is responsible for ``db.session.commit()``
    (usually once after a batch).

    Returns the (attached, not-yet-committed) instance.
    """
    instance = model.query.filter_by(**match).first()
    if instance is None:
        instance = model(**{**match, **values})
        db.session.add(instance)
    else:
        for key, value in values.items():
            setattr(instance, key, value)
    return instance


def coalesce(new, current):
    """Return ``new`` unless it is ``None`` (mirrors SQL COALESCE for updates)."""
    return current if new is None else new
