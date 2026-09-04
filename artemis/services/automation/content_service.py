"""Accept, validate, and content-address automation content (P5-B/C).

Authorized operators are intentionally allowed command/shell modules; isolation
and audit are the boundary, not a module allowlist. Validation here is about
safety of *handling*: size limits, safe archive extraction, YAML parsing, and a
syntax-check / lint pass before dispatch.
"""

import hashlib
import io
import json
import logging
import os
import subprocess
import tarfile
import tempfile
import zipfile
from datetime import datetime, timezone

import yaml

from artemis.extensions import db
from artemis.models.automation import AutomationContent
from artemis.services import crypto_service
from artemis.services.tenant import current_org_id, scoped

logger = logging.getLogger(__name__)

MAX_CONTENT_BYTES = 2 * 1024 * 1024        # 2 MiB pasted / uploaded
MAX_EXPANDED_BYTES = 20 * 1024 * 1024      # bundle expands to at most 20 MiB
MAX_BUNDLE_MEMBERS = 500


class ContentError(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _safe_extract_names(names):
    for name in names:
        if name.startswith('/') or '..' in name.split('/'):
            raise ContentError(f'unsafe path in archive: {name}')


def _parse_yaml(text):
    try:
        docs = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        raise ContentError(f'invalid YAML: {exc}') from exc
    if not docs or not isinstance(docs[0], list):
        raise ContentError('a playbook must be a top-level YAML list of plays')
    return docs[0]


def _syntax_check(playbook_text):
    """`ansible-playbook --syntax-check` if available; a structural check otherwise."""
    plays = _parse_yaml(playbook_text)
    for play in plays:
        if not isinstance(play, dict):
            raise ContentError('each play must be a mapping')
        if 'hosts' not in play:
            raise ContentError("every play needs a 'hosts' key")

    try:
        import shutil
        if shutil.which('ansible-playbook'):
            with tempfile.NamedTemporaryFile('w', suffix='.yml', delete=False) as fh:
                fh.write(playbook_text)
                path = fh.name
            try:
                proc = subprocess.run(
                    ['ansible-playbook', '--syntax-check', '-i', 'localhost,', path],
                    capture_output=True, text=True, timeout=60,
                )
                if proc.returncode != 0:
                    raise ContentError(f'syntax check failed: {proc.stderr.strip()[:500]}')
            finally:
                os.unlink(path)
    except FileNotFoundError:
        pass
    return True


def _lint(playbook_text):
    try:
        import shutil
        if not shutil.which('ansible-lint'):
            return {'available': False}
        with tempfile.NamedTemporaryFile('w', suffix='.yml', delete=False) as fh:
            fh.write(playbook_text)
            path = fh.name
        try:
            proc = subprocess.run(['ansible-lint', '-q', '--nocolor', '-f', 'json', path],
                                  capture_output=True, text=True, timeout=90)
            issues = json.loads(proc.stdout or '[]') if proc.stdout.strip().startswith('[') else []
            return {'available': True, 'issue_count': len(issues),
                    'issues': issues[:50], 'passed': proc.returncode == 0}
        finally:
            os.unlink(path)
    except Exception as exc:  # noqa: BLE001
        logger.debug('lint failed: %s', exc)
        return {'available': False}


def _bundle_playbook(raw):
    """Extract a tar/zip bundle, return (playbook_text, member_count)."""
    total = 0
    playbook_text = None
    if zipfile.is_zipfile(io.BytesIO(raw)):
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            names = zf.namelist()
            _safe_extract_names(names)
            if len(names) > MAX_BUNDLE_MEMBERS:
                raise ContentError('bundle has too many members')
            for info in zf.infolist():
                total += info.file_size
                if total > MAX_EXPANDED_BYTES:
                    raise ContentError('bundle expands beyond the size limit')
                if info.filename.rsplit('/', 1)[-1] in ('playbook.yml', 'site.yml', 'main.yml'):
                    playbook_text = zf.read(info).decode('utf-8', 'replace')
    else:
        try:
            with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
                names = tf.getnames()
                _safe_extract_names(names)
                for member in tf.getmembers():
                    total += member.size
                    if total > MAX_EXPANDED_BYTES:
                        raise ContentError('bundle expands beyond the size limit')
                    if member.name.rsplit('/', 1)[-1] in ('playbook.yml', 'site.yml', 'main.yml'):
                        playbook_text = tf.extractfile(member).read().decode('utf-8', 'replace')
        except tarfile.TarError as exc:
            raise ContentError(f'unreadable bundle: {exc}') from exc
    if playbook_text is None:
        raise ContentError('bundle contains no playbook.yml / site.yml / main.yml')
    return playbook_text, len(names)


def accept_content(raw, *, kind='playbook', filename=None, created_by=None):
    """Validate and store content. Returns the AutomationContent row.

    Idempotent by digest: re-submitting identical content returns the existing row.
    """
    if not crypto_service.is_configured():
        raise ContentError('secret encryption not configured; cannot store automation content')
    if isinstance(raw, str):
        raw = raw.encode('utf-8')
    if len(raw) > MAX_CONTENT_BYTES:
        raise ContentError(f'content exceeds {MAX_CONTENT_BYTES} bytes')

    digest = _digest(raw)
    existing = scoped(AutomationContent).filter(AutomationContent.digest == digest).first()
    if existing:
        return existing

    if kind == 'bundle':
        playbook_text, _members = _bundle_playbook(raw)
    else:
        playbook_text = raw.decode('utf-8', 'replace')

    _syntax_check(playbook_text)
    lint = _lint(playbook_text)

    content = AutomationContent(
        digest=digest, kind=kind, filename=filename, size_bytes=len(raw),
        sealed_body=crypto_service.seal(playbook_text),
        syntax_ok=1, lint_summary_json=json.dumps(lint),
        created_at=_now(), created_by=created_by,
    )
    db.session.add(content)
    db.session.commit()
    return content
