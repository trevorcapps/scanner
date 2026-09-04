"""Scan execution profiles: versioned CRUD and time-window evaluation."""

import json
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, available_timezones

from croniter import croniter

from artemis.extensions import db
from artemis.models.scan_profile import MISSED_RUN_POLICIES, ScanExecutionProfile
from artemis.services.tenant import current_org_id, scoped

_TZ_NAMES = available_timezones()


def _now_iso():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def validate_cron(expr):
    try:
        croniter(expr, datetime.now(timezone.utc))
        return True
    except (ValueError, KeyError):
        return False


def validate_timezone(name):
    return name in _TZ_NAMES


def validate_missed_run_policy(policy):
    return policy in MISSED_RUN_POLICIES


def list_profiles(include_history=False):
    q = scoped(ScanExecutionProfile)
    if not include_history:
        q = q.filter(ScanExecutionProfile.is_current == 1)
    return q.order_by(ScanExecutionProfile.name, ScanExecutionProfile.version.desc()).all()


def get_profile(profile_id):
    from artemis.services.tenant import scoped_get
    return scoped_get(ScanExecutionProfile, profile_id)


def _fields(data):
    return dict(
        timezone=data.get('timezone', 'UTC'),
        window_start=data.get('window_start') or None,
        window_end=data.get('window_end') or None,
        window_days_json=json.dumps(data['window_days']) if data.get('window_days') is not None else None,
        max_hosts=int(data.get('max_hosts', 256)),
        excluded_targets_json=json.dumps(data.get('excluded_targets', [])),
        scanner_rate=data.get('scanner_rate'),
        concurrency=int(data.get('concurrency', 1)),
        credential_ids_json=json.dumps(data.get('credential_ids', [])),
        engine_pool=data.get('engine_pool') or None,
        retry_count=int(data.get('retry_count', 1)),
        notify_json=json.dumps(data.get('notify', {})),
    )


def create_profile(data, created_by=None):
    name = (data.get('name') or '').strip()
    if not name:
        raise ValueError('name is required')
    if not validate_timezone(data.get('timezone', 'UTC')):
        raise ValueError('unknown timezone')

    latest = (scoped(ScanExecutionProfile)
              .filter(ScanExecutionProfile.name == name)
              .order_by(ScanExecutionProfile.version.desc()).first())
    version = (latest.version + 1) if latest else 1
    if latest:
        latest.is_current = 0

    profile = ScanExecutionProfile(
        name=name, version=version, is_current=1,
        created_at=_now_iso(), created_by=created_by, **_fields(data),
    )
    db.session.add(profile)
    db.session.commit()
    return profile


def new_version(name, data, created_by=None):
    data = {**data, 'name': name}
    return create_profile(data, created_by=created_by)


def within_window(profile, when=None):
    """True if ``when`` (UTC) falls inside the profile's allowed window."""
    if profile is None or not (profile.window_start and profile.window_end):
        return True
    when = when or datetime.now(timezone.utc)
    try:
        local = when.astimezone(ZoneInfo(profile.timezone))
    except Exception:  # noqa: BLE001
        local = when

    days = profile.window_days
    if days is not None and local.weekday() not in days:
        return False

    start_h, start_m = (int(x) for x in profile.window_start.split(':'))
    end_h, end_m = (int(x) for x in profile.window_end.split(':'))
    start = local.replace(hour=start_h, minute=start_m, second=0, microsecond=0)
    end = local.replace(hour=end_h, minute=end_m, second=0, microsecond=0)
    if start <= end:
        return start <= local <= end
    # window wraps midnight
    return local >= start or local <= end


def resolve_scan_options(profile, base_options):
    """Merge a profile's execution settings into a scan-options dict."""
    opts = dict(base_options or {})
    if profile is None:
        return opts
    opts.setdefault('max_hosts', profile.max_hosts)
    if profile.scanner_rate:
        opts.setdefault('rate_limit', profile.scanner_rate)
    if profile.excluded_targets:
        opts['excluded_targets'] = profile.excluded_targets
    if profile.credential_ids and not opts.get('credential_ids'):
        opts['credential_ids'] = profile.credential_ids
    return opts
