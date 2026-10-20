from __future__ import annotations

import hashlib
import json
import re
import socket
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib import request
from urllib.parse import urlsplit

from services.email_parser import parse_email


FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "phase4_step16"
MANIFEST_PATH = FIXTURE_DIR / "manifest.json"


class Phase4Step16FixtureCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    def test_manifest_ids_files_and_hashes_are_stable(self):
        entries = self.manifest["fixtures"]
        ids = [entry["id"] for entry in entries]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(entries), 8)
        for entry in entries:
            path = FIXTURE_DIR / entry["file"]
            self.assertTrue(path.is_file(), entry["id"])
            self.assertTrue(path.name.startswith(entry["id"]), entry["id"])
            self.assertEqual(
                hashlib.sha256(path.read_bytes()).hexdigest(),
                entry["sha256"],
                entry["id"],
            )
            self.assertTrue(entry["evidence"])
            self.assertTrue(entry["rationale"])
            self.assertTrue(entry["provenance"])
            self.assertEqual(entry["qa_review_status"], "PASS")
            self.assertEqual(entry["human_review_status"], "not_performed")

    def test_fixture_corpus_parses_offline_with_declared_expectations(self):
        entries = self.manifest["fixtures"]
        # Fail fast if the parser path starts resolving a host or making HTTP calls.
        with (
            patch.object(socket, "getaddrinfo", side_effect=AssertionError("network DNS called")),
            patch.object(socket, "create_connection", side_effect=AssertionError("network socket opened")),
            patch.object(request, "urlopen", side_effect=AssertionError("HTTP request made")),
        ):
            for entry in entries:
                with self.subTest(fixture=entry["id"]):
                    raw = (FIXTURE_DIR / entry["file"]).read_bytes()
                    result = parse_email(raw, entry["file"])
                    expected = entry["expected_parser"]
                    self.assertEqual(result["parsing"]["status"], expected["status"])
                    self.assertEqual(result["url_summary"]["unique_count"], expected["url_count"])
                    self.assertEqual(len(result["attachments"]), expected["attachment_count"])
                    self.assertEqual(
                        result["basic_information"]["from"] is not None,
                        expected["from_present"],
                    )
                    if "reported_authentication" in expected:
                        auth = result["authentication"]
                        self.assertEqual(auth["reported_results"], expected["reported_authentication"])
                        self.assertFalse(auth["authentication_results_trusted"])
                        self.assertFalse(auth["validation"]["reported_headers_trusted"])

    def test_fixture_corpus_has_no_obvious_secret_material(self):
        secret_patterns = (
            re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
            re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
            re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
            re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*[^\s]{12,}"),
        )
        for entry in self.manifest["fixtures"]:
            raw = (FIXTURE_DIR / entry["file"]).read_text(encoding="utf-8")
            for pattern in secret_patterns:
                self.assertIsNone(pattern.search(raw), f"possible secret in {entry['id']}: {pattern.pattern}")

    def test_indicator_hosts_in_fixture_corpus_are_inert_invalid_names(self):
        for entry in self.manifest["fixtures"]:
            raw = (FIXTURE_DIR / entry["file"]).read_text(encoding="utf-8")
            for candidate in re.findall(r"https?://[^\s<>]+", raw):
                host = urlsplit(candidate.rstrip(".,;)")).hostname or ""
                self.assertTrue(host.endswith(".invalid"), (entry["id"], host))


if __name__ == "__main__":
    unittest.main()
