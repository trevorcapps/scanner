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
"""

from fingerprint.engine import FingerprintEngine, FingerprintResult

__all__ = ['FingerprintEngine', 'FingerprintResult']
