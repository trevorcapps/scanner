"""NVD feed sync & enrichment service — wraps nvd_feeds.py and cpe_dict.py."""

import sys
import os
import logging

logger = logging.getLogger(__name__)

# Add parent scanner directory to path
_scanner_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _scanner_dir not in sys.path:
    sys.path.insert(0, _scanner_dir)

from nvd_feeds import sync_nvd_database, get_nvd_sync_status, init_nvd_tables  # noqa: E402
from cpe_dict import init_cpe_tables, sync_cpe_dictionary  # noqa: E402
from exploit_ref import ensure_exploit_db, enrich_cves_with_exploits, lookup_exploits  # noqa: E402

__all__ = [
    'sync_nvd_database', 'get_nvd_sync_status', 'init_nvd_tables',
    'init_cpe_tables', 'sync_cpe_dictionary',
    'ensure_exploit_db', 'enrich_cves_with_exploits', 'lookup_exploits',
]
