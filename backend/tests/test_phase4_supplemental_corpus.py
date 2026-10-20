from __future__ import annotations
import hashlib, json, re, socket, unittest
from pathlib import Path
from unittest.mock import patch
from urllib import request
from urllib.parse import urlsplit
from services.email_parser import parse_email
ROOT = Path(__file__).resolve().parent / 'fixtures' / 'phase4_supplemental'
class SupplementalCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest=json.loads((ROOT/'manifest.json').read_text(encoding='utf-8'))
    def test_manifest_hashes_and_unique_ids(self):
        entries=self.manifest['fixtures']; ids=[x['id'] for x in entries]
        self.assertEqual(len(entries),8); self.assertEqual(len(ids),len(set(ids)))
        for item in entries:
            raw=(ROOT/item['file']).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(),item['sha256'])
            self.assertEqual(item['human_review_status'],'not_performed')
    def test_all_cases_parse_without_network_or_exceptions(self):
        with patch.object(socket,'getaddrinfo',side_effect=AssertionError('DNS called')), patch.object(socket,'create_connection',side_effect=AssertionError('socket opened')), patch.object(request,'urlopen',side_effect=AssertionError('HTTP called')):
            for item in self.manifest['fixtures']:
                with self.subTest(fixture=item['id']):
                    result=parse_email((ROOT/item['file']).read_bytes(),item['file'])
                    self.assertIn(result['parsing']['status'],{'COMPLETE','PARTIAL'})
                    self.assertIn('basic_information',result)
    def test_embedded_urls_are_inert(self):
        for item in self.manifest['fixtures']:
            raw=(ROOT/item['file']).read_text(encoding='utf-8')
            for candidate in re.findall(r'https?://[^\s<>"\\]+',raw):
                host=urlsplit(candidate.rstrip('.,;)')).hostname or ''
                self.assertTrue(host.endswith('.invalid'),(item['id'],host))
if __name__=='__main__': unittest.main()
