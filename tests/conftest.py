"""Shared pytest fixtures.

`fake_scanner_bin` builds a throwaway executable and puts its directory first on
`PATH`, so scanner adapters that shell out to `nmap` / `nuclei` can be exercised
without the real binaries and without network access.
"""

import base64
import os
import stat
import textwrap

import pytest

# A deterministic key so credential-encryption paths run under test. Must be set
# before artemis.services.crypto_service first reads the environment.
os.environ.setdefault(
    "ARTEMIS_ENCRYPTION_KEY",
    base64.b64encode(b"artemis-test-key-000000000000000").decode(),
)


@pytest.fixture(autouse=True)
def _reset_security_singletons():
    from artemis.services import crypto_service, rate_limit_service

    crypto_service.reset_cache()
    rate_limit_service.reset_state()
    yield
    rate_limit_service.reset_state()


@pytest.fixture(autouse=True, scope="session")
def _seed_default_org_on_create_all():
    """Every `db.create_all()` in a test also seeds the Default organization, so
    tenant-owned rows created directly in a test's setUp get stamped."""
    from artemis.extensions import db

    original = db.create_all

    def patched(*args, **kwargs):
        original(*args, **kwargs)
        try:
            from artemis.models.organization import Organization
            if Organization.query.filter_by(is_default=1).first() is None:
                db.session.add(Organization(name="Default", slug="default", is_default=1))
                db.session.commit()
        except Exception:
            db.session.rollback()

    db.create_all = patched
    yield
    db.create_all = original


@pytest.fixture
def fake_scanner_bin(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")

    def _install(name, script):
        path = bindir / name
        path.write_text("#!/usr/bin/env bash\n" + textwrap.dedent(script))
        path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        return path

    return _install


@pytest.fixture
def fake_nuclei(fake_scanner_bin):
    """A stand-in nuclei: `-version` succeeds; a scan writes one JSONL finding
    to the path following `-output` and honours `ARTEMIS_FAKE_NUCLEI_SLEEP`."""
    return fake_scanner_bin(
        "nuclei",
        r"""
        if [[ "$1" == "-version" ]]; then echo "fake-nuclei 0.0.0"; exit 0; fi
        out=""
        while [[ $# -gt 0 ]]; do
            case "$1" in
                -output) out="$2"; shift 2 ;;
                *) shift ;;
            esac
        done
        sleep "${ARTEMIS_FAKE_NUCLEI_SLEEP:-0}"
        if [[ -n "$out" ]]; then
            printf '%s\n' '{"template-id":"fake-cve","info":{"name":"Fake Finding","severity":"high"},"host":"127.0.0.1","matched-at":"127.0.0.1:80"}' > "$out"
        fi
        exit 0
        """,
    )
