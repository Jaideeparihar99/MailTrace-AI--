"""Prepare a blinded, synthetic Phase 4 label-review packet without asserting review."""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
import re
import secrets

BACKEND = Path(__file__).resolve().parents[1]
FIXTURE_DIR = BACKEND / "tests" / "fixtures" / "phase4_step16"
MANIFEST_PATH = FIXTURE_DIR / "manifest.json"
REVIEW_ROOT = BACKEND / "tests" / "fixtures" / "phase4_human_review"
REVIEW_DIR = REVIEW_ROOT / "blind_packet"
EMAIL_DIR = REVIEW_DIR / "review_emails"
SHEET_PATH = REVIEW_DIR / "review_sheet.csv"
KEY_PATH = REVIEW_ROOT / "maintainer_key.json"
README_PATH = REVIEW_DIR / "README.md"


def main() -> None:
    manifest_bytes = MANIFEST_PATH.read_bytes()
    manifest = json.loads(manifest_bytes)
    fixtures = manifest.get("fixtures", [])
    if len(fixtures) != 8:
        raise SystemExit(f"Expected 8 primary fixtures; found {len(fixtures)}")
    if any(item.get("qa_review_status") != "PASS" for item in fixtures):
        raise SystemExit("All fixtures must have QA PASS before packaging")
    if any(item.get("human_review_status") == "reviewed" for item in fixtures):
        raise SystemExit("At least one fixture is already reviewed; reconcile the existing review record first")
    if any(path.exists() for path in (EMAIL_DIR, SHEET_PATH, KEY_PATH, README_PATH)):
        raise SystemExit("Review packet already exists; archive it before regenerating to preserve audit history")

    EMAIL_DIR.mkdir(parents=True)
    shuffled = list(fixtures)
    # Fresh random IDs/order prevent reviewers from inferring the manifest row from filenames.
    secrets.SystemRandom().shuffle(shuffled)
    rows = []
    key = {
        "purpose": "Maintainer-only mapping; do not share this file with blind reviewers.",
        "corpus_id": manifest.get("corpus_id"),
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest().upper(),
        "created_by_script": "backend/scripts/prepare_phase4_blind_review.py",
        "independent_review_status": "PENDING",
        "cases": [],
    }
    for fixture in shuffled:
        case_id = "RV-" + secrets.token_hex(5).upper()
        output_name = case_id.lower() + ".eml"
        raw = (FIXTURE_DIR / fixture["file"]).read_bytes()
        actual_digest = hashlib.sha256(raw).hexdigest()
        if actual_digest.lower() != fixture.get("sha256", "").lower():
            raise SystemExit(f"Fixture digest mismatch: {fixture['id']}")
        # Remove the fixture-number correlation in this synthetic review copy only.
        blinded = re.sub(rb"(?im)^Message-ID:[^\r\n]*", b"Message-ID: <review-copy@review.invalid>", raw, count=1)
        destination = EMAIL_DIR / output_name
        destination.write_bytes(blinded)
        rows.append({
            "review_case_id": case_id,
            "email_file": f"review_emails/{output_name}",
            "reviewer_label": "",
            "reviewer_severity": "",
            "confidence": "",
            "evidence_notes": "",
            "reviewer_id_or_role": "",
            "reviewer_relationship_to_author": "",
            "reviewed_at_utc": "",
            "review_status": "PENDING",
            "adjudicated_label": "",
            "adjudicator_id_or_role": "",
            "adjudication_notes": "",
            "adjudicated_at_utc": "",
        })
        key["cases"].append({
            "review_case_id": case_id,
            "fixture_id": fixture["id"],
            "source_file": fixture["file"],
            "expected_label": fixture["label"],
            "source_sha256": actual_digest,
            "review_copy_sha256": hashlib.sha256(blinded).hexdigest(),
        })

    fields = list(rows[0])
    with SHEET_PATH.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    KEY_PATH.write_text(json.dumps(key, indent=2) + "\n", encoding="utf-8")
    README_PATH.write_text(
        "# Blinded Phase 4 synthetic fixture review\n\n"
        "Status: **PENDING**. This packet is prepared for independent human adjudication; it is not evidence that any review has occurred.\n\n"
        "## Send only these items to the reviewer\n\n"
        "- `README.md`\n- `review_sheet.csv`\n- the `review_emails/` directory\n\n"
        "Do **not** share `maintainer_key.json`, the source manifest, the main repository, or `false_positive_trace.md`. The key contains the expected labels. The reviewer should be a person other than the fixture author and should classify each raw message before seeing any expected label.\n\n"
        "Each email is synthetic and uses inert `.invalid` domains. The body and other evidence are preserved; only filenames and the synthetic Message-ID were replaced to hide the original fixture IDs. Do not visit or resolve any URL.\n\n"
        "For every case, record a taxonomy label, severity, confidence, concrete evidence, reviewer role/identity, an INDEPENDENT relationship attestation, and UTC review time; set review_status to COMPLETE. Do not reveal expected labels until the reviewer has submitted the sheet. If review disagrees with the author label, a second person must complete the adjudication fields with rationale and UTC time.\n\n"
        "After the sheet is completed, the maintainer can run `python scripts/reconcile_phase4_blind_review.py` from backend/. The script verifies packet hashes and required fields, writes a private reconciliation report, and never changes the manifest.\n",
        encoding="utf-8",
    )
    print(f"Prepared {len(rows)} blinded synthetic cases in {REVIEW_DIR}")
    print("Independent review status remains PENDING; no label has been changed.")


if __name__ == "__main__":
    main()
