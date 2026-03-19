"""SSH authenticated scanner — wraps auth_scan.py."""

import sys
import os
import logging

logger = logging.getLogger(__name__)

# Add parent scanner directory to path so auth_scan can be imported
_scanner_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _scanner_dir not in sys.path:
    sys.path.insert(0, _scanner_dir)

from auth_scan import run_authenticated_scan, ssh_connect  # noqa: E402

__all__ = ['run_authenticated_scan', 'ssh_connect']
