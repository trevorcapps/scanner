import io
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import exploit_ref
from nvd_feeds import get_nvd_sync_status, init_nvd_tables


class FeedCacheTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tempdir.name, 'feeds.sqlite')
        exploit_ref._ready_paths.clear()
        exploit_ref._attempted_paths.clear()

    def tearDown(self):
        self.tempdir.cleanup()

    def test_nvd_initialization_includes_feed_metadata(self):
        init_nvd_tables(self.db_path)

        self.assertEqual(
            get_nvd_sync_status(self.db_path),
            {'total_cves': 0, 'last_sync': None},
        )
        with sqlite3.connect(self.db_path) as conn:
            tables = {
                row[0] for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
        self.assertIn('settings', tables)
        self.assertIn('exploitdb_refs', tables)

    def test_exploitdb_csv_is_cached_and_queried_without_external_package(self):
        feed = (
            'id,file,description,date_published,author,type,platform,port,date_added,'
            'date_updated,verified,codes,tags,aliases,screenshot_url,application_url,source_url\n'
            '4242,path,Example,2026-01-01,A,remote,linux,0,2026-01-01,2026-01-01,1,'
            'CVE-2026-12345,,,https://example.test,,\n'
        ).encode()

        with patch('exploit_ref.urllib.request.urlopen', return_value=io.BytesIO(feed)):
            self.assertTrue(exploit_ref.ensure_exploit_db(self.db_path, force=True))

        result = exploit_ref.lookup_exploits('CVE-2026-12345', self.db_path)
        self.assertTrue(result['has_exploit'])
        self.assertEqual(result['exploit_ids'], ['4242'])
        self.assertEqual(result['exploit_urls'], ['https://www.exploit-db.com/exploits/4242'])


if __name__ == '__main__':
    unittest.main()
