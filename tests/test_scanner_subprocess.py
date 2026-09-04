"""Scanner adapters drive a real child process. These use the fake-binary
fixtures so the subprocess contract (argv, output parsing) is covered without
the real nmap/nuclei or any network. Process-group termination on cancel is
hardened and tested in Phase 2."""

import subprocess

import pytest

from artemis.scanners import nuclei_scanner
from artemis.utils.dns import ScanError


def test_nuclei_missing_binary_raises(monkeypatch):
    monkeypatch.setattr(nuclei_scanner, "check_nuclei_installed", lambda: False)
    with pytest.raises(ScanError):
        nuclei_scanner.vuln_scan("127.0.0.1")


def test_nuclei_rejects_invalid_target(fake_nuclei):
    with pytest.raises(ScanError):
        nuclei_scanner.vuln_scan("not a target")


def test_nuclei_parses_jsonl_output(fake_nuclei):
    lines = []
    results = nuclei_scanner.vuln_scan("127.0.0.1", log_callback=lines.append)

    assert len(results) == 1
    assert results[0]["template-id"] == "fake-cve"
    assert any("nuclei" in line.lower() for line in lines)


def test_fake_binary_version_check(fake_nuclei):
    out = subprocess.run(["nuclei", "-version"], capture_output=True, text=True, timeout=5)
    assert out.returncode == 0
    assert "fake-nuclei" in out.stdout
