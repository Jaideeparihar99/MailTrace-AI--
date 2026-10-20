"""Build a metadata-only, source-grouped split manifest for MeAJOR.

This utility reads the existing normalized corpus, but never prints or writes
email text and never trains a model. It groups complete source families into
leave-one-source-out folds and checks exact normalized-text duplicates for
cross-source leakage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET = REPO_ROOT / "backend/data/email_ai/normalized/meajor_phishing_binary.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "backend/tests/fixtures/meajor_source_group_split.v1.json"
ALLOWED_LABELS = {"LEGITIMATE", "PHISHING"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(dataset: Path) -> dict[str, Any]:
    if not dataset.is_file():
        raise FileNotFoundError(f"Dataset not found: {dataset}")

    source_rows: Counter[str] = Counter()
    source_labels: dict[str, Counter[str]] = defaultdict(Counter)
    fingerprint_groups: dict[str, dict[str, Any]] = {}
    total_rows = 0

    with dataset.open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"Invalid JSONL at line {line_number}.") from error
            if not isinstance(row, dict):
                raise ValueError(f"JSONL line {line_number} must be an object.")

            text = str(row.get("text") or "").strip()
            label = str(row.get("label") or "").strip().upper()
            source = str(row.get("source") or "").strip().lower()
            if not text or label not in ALLOWED_LABELS or not source:
                raise ValueError(f"Invalid text/label/source fields at line {line_number}.")

            total_rows += 1
            source_rows[source] += 1
            source_labels[source][label] += 1

            # Deliberately conservative exact-content normalization. Do not
            # remove URLs, punctuation, headers, or other potentially relevant evidence.
            canonical_text = re.sub(r"\s+", " ", text).strip().casefold()
            fingerprint = hashlib.sha256(canonical_text.encode("utf-8")).hexdigest()
            group = fingerprint_groups.setdefault(
                fingerprint,
                {"rows": 0, "sources": set(), "labels": set()},
            )
            group["rows"] += 1
            group["sources"].add(source)
            group["labels"].add(label)

    if not source_rows:
        raise ValueError("No usable records found.")

    for source, counts in source_labels.items():
        if set(counts) != ALLOWED_LABELS:
            raise ValueError(f"Source group {source} does not contain both binary labels.")

    sources = sorted(source_rows)
    folds = []
    for held_out in sources:
        training_sources = [source for source in sources if source != held_out]
        folds.append(
            {
                "fold_id": f"holdout-{held_out}",
                "training_sources": training_sources,
                "holdout_source": held_out,
                "training_rows": sum(source_rows[source] for source in training_sources),
                "training_class_counts": dict(
                    sorted(
                        sum((source_labels[source] for source in training_sources), Counter()).items()
                    )
                ),
                "holdout_rows": source_rows[held_out],
                "holdout_class_counts": dict(sorted(source_labels[held_out].items())),
            }
        )

    duplicate_groups = [group for group in fingerprint_groups.values() if group["rows"] > 1]
    cross_source_groups = [group for group in duplicate_groups if len(group["sources"]) > 1]
    conflicting_label_groups = [group for group in duplicate_groups if len(group["labels"]) > 1]

    try:
        dataset_path = dataset.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        dataset_path = str(dataset.resolve())

    return {
        "schema_version": "1.0",
        "manifest_id": "mailtrace-meajor-source-grouped-splits-v1",
        "dataset_path": dataset_path,
        "dataset_sha256": sha256_file(dataset),
        "dataset_rows": total_rows,
        "group_field": "source",
        "strategy": "three-fold leave-one-source-out; every row from a source stays together",
        "sources": {
            source: {
                "rows": source_rows[source],
                "class_counts": dict(sorted(source_labels[source].items())),
            }
            for source in sources
        },
        "exact_normalized_text_duplicate_audit": {
            "normalization": "Unicode casefold plus whitespace collapse; punctuation and evidence-bearing components preserved",
            "duplicate_groups": len(duplicate_groups),
            "duplicate_rows_beyond_first": sum(group["rows"] - 1 for group in duplicate_groups),
            "conflicting_label_groups": len(conflicting_label_groups),
            "cross_source_duplicate_groups": len(cross_source_groups),
            "cross_source_duplicate_rows": sum(group["rows"] - 1 for group in cross_source_groups),
        },
        "folds": folds,
        "training_performed": False,
        "limitations": [
            "Source-disjoint folds prevent source-family overlap but are not a temporal evaluation.",
            "Near-duplicate similarity and campaign identity are not available as explicit group fields and were not fully audited.",
            "Source labels remain proxy labels; this split does not make them human-adjudicated ground truth.",
            "This manifest contains only aggregate metadata and no message text or per-message identifiers.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    manifest = build_manifest(args.dataset)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        "SOURCE_GROUP_SPLIT_MANIFEST",
        json.dumps(
            {
                "output": str(args.output),
                "rows": manifest["dataset_rows"],
                "sources": len(manifest["sources"]),
                "folds": len(manifest["folds"]),
                "cross_source_duplicate_groups": manifest["exact_normalized_text_duplicate_audit"]["cross_source_duplicate_groups"],
                "training_performed": False,
            },
            sort_keys=True,
        ),
    )


if __name__ == "__main__":
    main()
