"""Shared pytest fixtures.

`fake_scanner_bin` builds a throwaway executable and puts its directory first on
`PATH`, so scanner adapters that shell out to `nmap` / `nuclei` can be exercised
without the real binaries and without network access.
"""

import os
import stat
import textwrap

import pytest


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
