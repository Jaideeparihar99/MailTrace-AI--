"""Regression tests for the private Phase 4 blind-review handoff."""
import csv
import hashlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from reconcile_phase4_blind_review import ReviewError, reconcile


def _packet(tmp_path, *, reviewer_label="benign_legitimate", adjudication=None):
    packet = tmp_path / "blind_packet"
    emails = packet / "review_emails"
    emails.mkdir(parents=True)
    case_id = "RV-ABC123"
    email_name = f"{case_id.lower()}.eml"
    email_bytes = b"From: reviewer@example.invalid\r\n\r\nSynthetic message.\r\n"
    (emails / email_name).write_bytes(email_bytes)
    manifest_path = tmp_path / "manifest.json"
    manifest_bytes = json.dumps({
        "corpus_id": "test-corpus",
        "taxonomy": [{"label": "benign_legitimate"}, {"label": "phishing"}],
        "fixtures": [{"id": "MT-F16-0001", "label": "benign_legitimate"}],
    }).encode()
    manifest_path.write_bytes(manifest_bytes)
    key_path = tmp_path / "maintainer_key.json"
    key_path.write_text(json.dumps({
        "independent_review_status": "PENDING",
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest().upper(),
        "cases": [{
            "review_case_id": case_id,
            "fixture_id": "MT-F16-0001",
            "source_sha256": "source-hash",
            "review_copy_sha256": hashlib.sha256(email_bytes).hexdigest(),
        }],
    }), encoding="utf-8")
    row = {
        "review_case_id": case_id,
        "email_file": f"review_emails/{email_name}",
        "reviewer_label": reviewer_label,
        "reviewer_severity": "NONE",
        "confidence": "HIGH",
        "evidence_notes": "Routine meeting coordination; no unsafe request.",
        "reviewer_id_or_role": "independent-soc-reviewer",
        "reviewer_relationship_to_author": "INDEPENDENT",
        "reviewed_at_utc": "2026-10-19T10:00:00Z",
        "review_status": "COMPLETE",
        "adjudicated_label": "",
        "adjudicator_id_or_role": "",
        "adjudication_notes": "",
        "adjudicated_at_utc": "",
    }
    if adjudication:
        row.update({
            "adjudicated_label": adjudication,
            "adjudicator_id_or_role": "second-independent-reviewer",
            "adjudication_notes": "Second reviewer examined the source evidence and documented the final class.",
            "adjudicated_at_utc": "2026-10-19T11:00:00Z",
        })
    sheet_path = packet / "review_sheet.csv"
    with sheet_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(row))
        writer.writeheader()
        writer.writerow(row)
    return sheet_path, key_path, manifest_path, emails / email_name


def test_complete_independent_review_validates_without_mutating_manifest(tmp_path):
    sheet, key, manifest, _ = _packet(tmp_path)
    original = manifest.read_bytes()

    result = reconcile(sheet, key, manifest)

    assert result["status"] == "REVIEW_VALIDATED"
    assert result["reviewed_count"] == 1
    assert result["cases"][0]["matches_author_label"] is True
    assert result["manifest_updated"] is False
    assert manifest.read_bytes() == original


def test_incomplete_review_is_not_reconciled(tmp_path):
    sheet, key, manifest, _ = _packet(tmp_path)
    with sheet.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
        fields = rows[0].keys()
    rows[0]["review_status"] = "PENDING"
    with sheet.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    with pytest.raises(ReviewError, match="review_status must be COMPLETE"):
        reconcile(sheet, key, manifest)


def test_label_disagreement_requires_second_person_adjudication(tmp_path):
    sheet, key, manifest, _ = _packet(tmp_path, reviewer_label="phishing")

    with pytest.raises(ReviewError, match="second-person adjudication"):
        reconcile(sheet, key, manifest)

    sheet, key, manifest, _ = _packet(tmp_path / "adjudicated", reviewer_label="phishing", adjudication="benign_legitimate")
    result = reconcile(sheet, key, manifest)
    assert result["cases"][0]["reviewer_label"] == "phishing"
    assert result["cases"][0]["final_review_label"] == "benign_legitimate"
    assert result["cases"][0]["adjudication"]["adjudicator"] == "second-independent-reviewer"


def test_changed_blinded_email_is_rejected(tmp_path):
    sheet, key, manifest, email_path = _packet(tmp_path)
    email_path.write_bytes(email_path.read_bytes() + b"tampered")

    with pytest.raises(ReviewError, match="content changed"):
        reconcile(sheet, key, manifest)
