"""
Endpoint fingerprinting engine for Cerebus scanner.

Combines multiple detection techniques to identify what's actually
running on a scanned endpoint:
  - HTTP header analysis
  - HTML body pattern matching
  - Favicon hash matching (MMH3)
  - TLS certificate inspection
  - Service banner / CPE parsing
  - Default page / error page detection
  - Protocol-level handshakes via fingerprintx
"""

from fingerprint.engine import FingerprintEngine, FingerprintResult
from fingerprint.fpx import (
    scan_targets as fpx_scan_targets,
    scan_host as fpx_scan_host,
    check_installed as fpx_check_installed,
    FpxResult,
)

__all__ = [
    'FingerprintEngine', 'FingerprintResult',
    'fpx_scan_targets', 'fpx_scan_host', 'fpx_check_installed', 'FpxResult',
]
