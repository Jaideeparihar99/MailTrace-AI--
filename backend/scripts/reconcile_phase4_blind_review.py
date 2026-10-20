"""Validate and privately reconcile completed Phase 4 blind-review responses.

This script never edits fixture labels or the source manifest. It only creates a
maintainer-side reconciliation report after checking reviewer independence,
review-sheet completeness, packet hashes, and any disagreement adjudication.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
REVIEW_ROOT = BACKEND / "tests" / "fixtures" / "phase4_human_review"
PACKET = REVIEW_ROOT / "blind_packet"
MANIFEST = BACKEND / "tests" / "fixtures" / "phase4_step16" / "manifest.json"
KEY = REVIEW_ROOT / "maintainer_key.json"
SHEET = PACKET / "review_sheet.csv"
REPORT = REVIEW_ROOT / "reconciliation_report.json"
CONFIDENCE = {"LOW", "MEDIUM", "HIGH"}


class ReviewError(ValueError):
    """Raised when a submitted review cannot be safely reconciled."""


def _utc_timestamp(value: str, field: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReviewError(f"{field} must be an ISO-8601 UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ReviewError(f"{field} must include UTC timezone information")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def reconcile(sheet_path: Path = SHEET, key_path: Path = KEY,
              manifest_path: Path = MANIFEST) -> dict:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    key = json.loads(key_path.read_text(encoding="utf-8"))
    if key.get("independent_review_status") != "PENDING":
        raise ReviewError("Maintainer key is not in PENDING state; use the existing audit record")
    manifest_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest().upper()
    if manifest_digest != key.get("manifest_sha256"):
        raise ReviewError("Fixture manifest changed since the blind packet was prepared")
    taxonomy = {item["label"] for item in manifest.get("taxonomy", [])}
    key_cases = {item["review_case_id"]: item for item in key.get("cases", [])}
    if len(key_cases) != len(key.get("cases", [])) or not key_cases:
        raise ReviewError("Maintainer key has duplicate or missing review case IDs")

    with sheet_path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
        fields = set(reader.fieldnames or [])
    required = {
        "review_case_id", "email_file", "reviewer_label", "reviewer_severity",
        "confidence", "evidence_notes", "reviewer_id_or_role", "reviewer_relationship_to_author",
        "reviewed_at_utc", "review_status", "adjudicated_label", "adjudicator_id_or_role",
        "adjudication_notes", "adjudicated_at_utc",
    }
    if missing := required - fields:
        raise ReviewError("Review sheet is missing required columns: " + ", ".join(sorted(missing)))
    row_ids = [row.get("review_case_id", "").strip() for row in rows]
    if len(set(row_ids)) != len(row_ids) or set(row_ids) != set(key_cases):
        raise ReviewError("Review rows must match the maintainer key exactly, with no duplicates")

    manifest_by_id = {item["id"]: item for item in manifest["fixtures"]}
    packet_dir = sheet_path.parent.resolve()
    reviewed = []
    disagreements = []
    for row in rows:
        case_id = row["review_case_id"].strip()
        private = key_cases[case_id]
        if row["email_file"].strip() != f"review_emails/{case_id.lower()}.eml":
            raise ReviewError(f"{case_id}: submitted email path does not match packet")
        email_path = (packet_dir / row["email_file"]).resolve()
        if packet_dir not in email_path.parents or not email_path.is_file():
            raise ReviewError(f"{case_id}: review email is missing or outside the packet")
        digest = hashlib.sha256(email_path.read_bytes()).hexdigest()
        if digest != private.get("review_copy_sha256"):
            raise ReviewError(f"{case_id}: review email content changed after packet preparation")
        if row["review_status"].strip().upper() != "COMPLETE":
            raise ReviewError(f"{case_id}: review_status must be COMPLETE")
        label = row["reviewer_label"].strip()
        if label not in taxonomy:
            raise ReviewError(f"{case_id}: reviewer_label must match a documented taxonomy label")
        if row["reviewer_severity"].strip().upper() not in {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}:
            raise ReviewError(f"{case_id}: invalid reviewer_severity")
        if row["confidence"].strip().upper() not in CONFIDENCE:
            raise ReviewError(f"{case_id}: confidence must be LOW, MEDIUM, or HIGH")
        if not row["evidence_notes"].strip():
            raise ReviewError(f"{case_id}: evidence_notes cannot be empty")
        if not row["reviewer_id_or_role"].strip():
            raise ReviewError(f"{case_id}: reviewer_id_or_role cannot be empty")
        if row["reviewer_relationship_to_author"].strip().upper() != "INDEPENDENT":
            raise ReviewError(f"{case_id}: reviewer must attest relationship as INDEPENDENT")
        reviewed_at = _utc_timestamp(row["reviewed_at_utc"].strip(), "reviewed_at_utc")

        adjudicated = row["adjudicated_label"].strip()
        final_label = label
        adjudication = None
        if adjudicated:
            if adjudicated not in taxonomy:
                raise ReviewError(f"{case_id}: adjudicated_label is not in the taxonomy")
            adjudicator = row["adjudicator_id_or_role"].strip()
            if not adjudicator or adjudicator.casefold() == row["reviewer_id_or_role"].strip().casefold():
                raise ReviewError(f"{case_id}: adjudicator must be identified separately from the reviewer")
            if not row["adjudication_notes"].strip():
                raise ReviewError(f"{case_id}: adjudication_notes cannot be empty")
            adjudicated_at = _utc_timestamp(row["adjudicated_at_utc"].strip(), "adjudicated_at_utc")
            adjudication = {"label": adjudicated, "adjudicator": adjudicator,
                            "notes": row["adjudication_notes"].strip(), "at_utc": adjudicated_at}
            final_label = adjudicated

        fixture = manifest_by_id.get(private["fixture_id"])
        if not fixture:
            raise ReviewError(f"{case_id}: fixture in private key is absent from manifest")
        expected = fixture["label"]
        if final_label != expected and not adjudication:
            disagreements.append(case_id)
        reviewed.append({
            "review_case_id": case_id,
            "fixture_id": private["fixture_id"],
            "source_sha256": private["source_sha256"],
            "reviewer_label": label,
            "final_review_label": final_label,
            "expected_label": expected,
            "matches_author_label": final_label == expected,
            "reviewer_severity": row["reviewer_severity"].strip().upper(),
            "confidence": row["confidence"].strip().upper(),
            "evidence_notes": row["evidence_notes"].strip(),
            "reviewer_id_or_role": row["reviewer_id_or_role"].strip(),
            "reviewed_at_utc": reviewed_at,
            "adjudication": adjudication,
        })

    if disagreements:
        raise ReviewError(
            "Independent review disagrees with author labels for case(s): "
            + ", ".join(disagreements)
            + ". Obtain a second-person adjudication, fill adjudication fields, then rerun."
        )
    return {
        "schema_version": "1.0",
        "status": "REVIEW_VALIDATED",
        "corpus_id": manifest.get("corpus_id"),
        "manifest_sha256": manifest_digest,
        "reviewed_count": len(reviewed),
        "reviewer_count": len({item["reviewer_id_or_role"] for item in reviewed}),
        "reviewed_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "cases": reviewed,
        "manifest_updated": False,
        "note": "Validation does not itself authorize changing expected labels or human-review status.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sheet", type=Path, default=SHEET, help="Completed reviewer CSV")
    parser.add_argument("--key", type=Path, default=KEY, help=argparse.SUPPRESS)
    parser.add_argument("--manifest", type=Path, default=MANIFEST, help=argparse.SUPPRESS)
    parser.add_argument("--output", type=Path, default=REPORT, help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        result = reconcile(args.sheet, args.key, args.manifest)
    except (OSError, json.JSONDecodeError, ReviewError) as exc:
        raise SystemExit(f"Review not reconciled: {exc}") from exc
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Validated {result['reviewed_count']} independent review rows.")
    print(f"Private reconciliation report: {args.output}")
    print("Manifest labels remain unchanged; inspect and approve before updating them.")


if __name__ == "__main__":
    main()
