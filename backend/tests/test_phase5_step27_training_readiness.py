import hashlib
import json
from pathlib import Path
import pytest
from services.email_ai.training_readiness import require_training_approval, split_labeled_rows
from services.email_ai.model import train_model
from services.email_ai import calibrate_phishing_l3 as calibration
from services.email_ai.evaluate_phishing_l3_sources import evaluate_source_holdouts, _assert_no_cross_source_duplicate_leakage
from services.email_ai.feature_pipeline import _near_duplicate_pairs

def _approval(dataset, **overrides):
    digest = hashlib.sha256(dataset.read_bytes()).hexdigest()
    record = {
        "approved_for_training": True,
        "dataset_sha256": digest,
        "dataset_components": [{"component_id": "normalized-dataset", "source": "synthetic-test", "path": dataset.name, "sha256": digest}],
        "reviewer": "independent-review-board",
        "approval_date": "2026-10-19",
    }
    for key, status, reviewer, scope in (
        ("license_review", "APPROVED", "rights-reviewer", "Training and derivative-model use as expressly permitted by the test fixture"),
        ("label_review", "ADJUDICATED", "independent-label-reviewer", "Independent adjudication of synthetic test labels"),
        ("privacy_review", "APPROVED", "privacy-reviewer", "Synthetic test data; no personal data; test retention scope"),
    ):
        evidence = dataset.parent / f"{key}-evidence.txt"
        evidence.write_text(f"Synthetic test evidence for {key}\n", encoding="utf-8")
        evidence_hash = hashlib.sha256(evidence.read_bytes()).hexdigest()
        record[key] = {
            "status": status,
            "reviewer": reviewer,
            "review_date": "2026-10-19",
            "scope": scope,
            "evidence_path": evidence.name,
            "evidence_sha256": evidence_hash,
        }
        if key == "label_review":
            record[key].update({"independent": True, "reviewed_count": 8, "reconciliation_sha256": evidence_hash})
    record.update(overrides)
    return record

def test_training_fails_closed_when_approval_manifest_missing(tmp_path):
    data = tmp_path / "dataset.jsonl"; data.write_text('{"text":"x","label":"PHISHING"}\n', encoding="utf-8")
    with pytest.raises(RuntimeError, match="TRAINING_BLOCKED.*missing"):
        require_training_approval(data, tmp_path / "missing.json")

def test_training_approval_is_bound_to_exact_dataset_bytes(tmp_path):
    data = tmp_path / "dataset.jsonl"; data.write_text('{"text":"x","label":"PHISHING"}\n', encoding="utf-8")
    approval = tmp_path / "approval.json"; record = _approval(data); record["dataset_sha256"] = "0" * 64
    approval.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(RuntimeError, match="sha256 does not match"):
        require_training_approval(data, approval)

def test_training_requires_independent_label_adjudication(tmp_path):
    data = tmp_path / "dataset.jsonl"; data.write_text('{"text":"x","label":"PHISHING"}\n', encoding="utf-8")
    approval = tmp_path / "approval.json"; record = _approval(data); record["label_review"] = {"status":"APPROVED", "reviewer":"reviewer"}
    approval.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(RuntimeError, match="label_review must have status ADJUDICATED"):
        require_training_approval(data, approval)

def test_training_approval_accepts_complete_hash_bound_review_record(tmp_path):
    data = tmp_path / "dataset.jsonl"; data.write_text('{"text":"x","label":"PHISHING"}\n', encoding="utf-8")
    approval = tmp_path / "approval.json"; approval.write_text(json.dumps(_approval(data)), encoding="utf-8")
    result = require_training_approval(data, approval)
    assert result["dataset_sha256"] == hashlib.sha256(data.read_bytes()).hexdigest()

def test_grouped_training_partitions_keep_each_source_together_and_fit_only_train():
    rows=[]
    for source in range(9):
        rows.append({"text":f"legitimate unique message orchard {source}","label":"LEGITIMATE","source":f"source-{source}"})
        rows.append({"text":f"phishing unique message comet {source}","label":"PHISHING","source":f"source-{source}"})
    result=split_labeled_rows(rows, seed=27)
    owners={}
    for split, partition in result["splits"].items():
        assert {row["label"] for row in partition} == {"LEGITIMATE", "PHISHING"}
        for row in partition:
            source=row["source"]
            assert source not in owners or owners[source] == split
            owners[source]=split
    assert result["manifest"]["training_transform_policy"].startswith("TF-IDF and classifier fit on train")

def test_near_duplicate_detection_handles_large_exact_duplicate_buckets_without_quadratic_pairs():
    rows=[{"text":"repeated identical message token alpha beta gamma delta"} for _ in range(320)]
    assert list(_near_duplicate_pairs(rows)) == []


def test_malformed_approval_json_fails_closed(tmp_path):
    data = tmp_path / "dataset.jsonl"
    data.write_text('{"text":"x","label":"PHISHING"}\n', encoding="utf-8")
    approval = tmp_path / "approval.json"
    approval.write_text('{not-json', encoding="utf-8")
    with pytest.raises(RuntimeError, match="TRAINING_BLOCKED: invalid approval manifest"):
        require_training_approval(data, approval)


def test_approval_hash_must_be_well_formed_sha256(tmp_path):
    data = tmp_path / "dataset.jsonl"
    data.write_text('{"text":"x","label":"PHISHING"}\n', encoding="utf-8")
    approval = tmp_path / "approval.json"
    approval.write_text(json.dumps(_approval(data, dataset_sha256="not-a-hash")), encoding="utf-8")
    with pytest.raises(RuntimeError, match="64-character SHA-256"):
        require_training_approval(data, approval)


def test_invalid_approval_date_fails_closed(tmp_path):
    data = tmp_path / "dataset.jsonl"
    data.write_text('{"text":"x","label":"PHISHING"}\n', encoding="utf-8")
    approval = tmp_path / "approval.json"
    approval.write_text(json.dumps(_approval(data, approval_date="yesterday-ish")), encoding="utf-8")
    with pytest.raises(RuntimeError, match="valid ISO date"):
        require_training_approval(data, approval)


def test_dataset_mutation_invalidates_previously_valid_approval(tmp_path):
    data = tmp_path / "dataset.jsonl"
    data.write_text('{"text":"original","label":"PHISHING"}\n', encoding="utf-8")
    approval = tmp_path / "approval.json"
    approval.write_text(json.dumps(_approval(data)), encoding="utf-8")
    data.write_text('{"text":"modified","label":"PHISHING"}\n', encoding="utf-8")
    with pytest.raises(RuntimeError, match="sha256 does not match"):
        require_training_approval(data, approval)


def test_grouped_split_manifest_records_per_partition_class_counts():
    rows = []
    for source in range(9):
        rows.append({"text": f"legitimate unique message orchard {source}", "label": "LEGITIMATE", "source": f"source-{source}"})
        rows.append({"text": f"phishing unique message comet {source}", "label": "PHISHING", "source": f"source-{source}"})
    result = split_labeled_rows(rows, seed=2701)
    for name, partition in result["splits"].items():
        assert result["manifest"]["class_counts"][name] == {
            "LEGITIMATE": sum(row["label"] == "LEGITIMATE" for row in partition),
            "PHISHING": sum(row["label"] == "PHISHING" for row in partition),
        }


def test_campaign_and_thread_groups_never_cross_partitions():
    rows = []
    for source in range(9):
        rows.append({"text": f"legitimate distinct message meadow {source}", "label": "LEGITIMATE", "source": f"source-{source}", "campaign_id": f"campaign-{source}", "thread_id": f"thread-{source}"})
        rows.append({"text": f"phishing distinct message comet {source}", "label": "PHISHING", "source": f"source-{source}", "campaign_id": f"campaign-{source}", "thread_id": f"thread-{source}"})
    result = split_labeled_rows(rows, seed=88)
    for field in ("campaign_id", "thread_id"):
        owners = {}
        for split, partition in result["splits"].items():
            for row in partition:
                value = row[field]
                assert value not in owners or owners[value] == split
                owners[value] = split



def test_approval_requires_hash_bound_dataset_component_list(tmp_path):
    data = tmp_path / "dataset.jsonl"
    data.write_text('{"text":"x","label":"PHISHING"}\n', encoding="utf-8")
    approval = tmp_path / "approval.json"
    approval.write_text(json.dumps(_approval(data, dataset_components=[])), encoding="utf-8")
    with pytest.raises(RuntimeError, match="dataset_components must list"):
        require_training_approval(data, approval)


def test_approval_requires_existing_and_hash_bound_rights_evidence(tmp_path):
    data = tmp_path / "dataset.jsonl"
    data.write_text('{"text":"x","label":"PHISHING"}\n', encoding="utf-8")
    record = _approval(data)
    record["license_review"]["evidence_sha256"] = "0" * 64
    approval = tmp_path / "approval.json"
    approval.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(RuntimeError, match="license_review evidence SHA-256"):
        require_training_approval(data, approval)


def test_missing_privacy_approval_fails_closed(tmp_path):
    data = tmp_path / "dataset.jsonl"
    data.write_text('{"text":"x","label":"PHISHING"}\n', encoding="utf-8")
    approval = tmp_path / "approval.json"
    approval.write_text(json.dumps(_approval(data, privacy_review={"status": "PENDING", "reviewer": "privacy-reviewer"})), encoding="utf-8")
    with pytest.raises(RuntimeError, match="privacy_review must have status APPROVED"):
        require_training_approval(data, approval)


def test_label_review_requires_independence_and_reconciliation_evidence(tmp_path):
    data = tmp_path / "dataset.jsonl"
    data.write_text('{"text":"x","label":"PHISHING"}\n', encoding="utf-8")
    record = _approval(data)
    record["label_review"]["independent"] = False
    approval = tmp_path / "approval.json"
    approval.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(RuntimeError, match="label_review.independent"):
        require_training_approval(data, approval)


def test_partial_source_metadata_fails_closed():
    rows = []
    for source in range(9):
        rows.append({"text": f"legitimate distinct orchard {source}", "label": "LEGITIMATE", "source": f"source-{source}"})
        rows.append({"text": f"phishing distinct comet {source}", "label": "PHISHING", "source": f"source-{source}"})
    rows[-1].pop("source")
    with pytest.raises(ValueError, match="Source grouping metadata is incomplete"):
        split_labeled_rows(rows)


def test_fewer_than_three_source_groups_fails_closed():
    rows = []
    for source in range(2):
        rows.append({"text": f"legitimate distinct orchard {source}", "label": "LEGITIMATE", "source": f"source-{source}"})
        rows.append({"text": f"phishing distinct comet {source}", "label": "PHISHING", "source": f"source-{source}"})
    with pytest.raises(ValueError, match="At least three distinct source groups"):
        split_labeled_rows(rows)


def test_direct_model_training_rejects_rows_that_differ_from_approved_dataset(tmp_path):
    data = tmp_path / "dataset.jsonl"
    source_rows = []
    for source in range(4):
        source_rows.append({"text": f"legitimate original meadow {source}", "label": "LEGITIMATE", "source": f"source-{source}"})
        source_rows.append({"text": f"phishing original comet {source}", "label": "PHISHING", "source": f"source-{source}"})
    data.write_text("".join(json.dumps(row) + "\n" for row in source_rows), encoding="utf-8")
    approval = tmp_path / "approval.json"
    approval.write_text(json.dumps(_approval(data)), encoding="utf-8")
    tampered_rows = [dict(row, text=row["text"] + " altered") for row in source_rows]
    output = tmp_path / "must-not-be-created"
    with pytest.raises(RuntimeError, match="supplied training rows do not match"):
        train_model(tampered_rows, output, str(data), approval)
    assert not output.exists()


def test_direct_calibration_helper_fails_closed_without_approval(tmp_path):
    data = tmp_path / "missing-dataset.jsonl"
    with pytest.raises(RuntimeError, match="TRAINING_BLOCKED: dataset file missing"):
        calibration.fit_sigmoid_calibrator(["LEGITIMATE", "PHISHING"], [0.1, 0.9], dataset_path=data)


def test_direct_source_holdout_evaluator_fails_closed_without_approval(tmp_path):
    data = tmp_path / "missing-dataset.jsonl"
    with pytest.raises(RuntimeError, match="TRAINING_BLOCKED: dataset file missing"):
        evaluate_source_holdouts(data)



def test_training_split_rejects_absent_source_provenance():
    rows = []
    for source in range(9):
        rows.append({"text": f"legitimate unique meadow {source}", "label": "LEGITIMATE"})
        rows.append({"text": f"phishing unique comet {source}", "label": "PHISHING"})
    with pytest.raises(ValueError, match="Source grouping metadata is required"):
        split_labeled_rows(rows)


def test_source_holdout_rejects_cross_source_exact_duplicates():
    rows = [
        {"text": "urgent invoice account verification orchard meadow", "label": "LEGITIMATE", "source": "family-a"},
        {"text": "urgent invoice account verification orchard meadow", "label": "PHISHING", "source": "family-b"},
    ]
    with pytest.raises(ValueError, match="canonical exact duplicate"):
        _assert_no_cross_source_duplicate_leakage(rows)


def test_source_holdout_rejects_detected_cross_source_near_duplicates():
    base = "urgent invoice account verification payment reference orchard meadow confirm immediately"
    rows = [
        {"text": base, "label": "LEGITIMATE", "source": "family-a"},
        {"text": base + " please", "label": "PHISHING", "source": "family-b"},
    ]
    with pytest.raises(ValueError, match="detected near-duplicate pair"):
        _assert_no_cross_source_duplicate_leakage(rows)


def test_current_blind_review_packet_has_stable_blind_ids_and_all_rows_pending():
    import csv
    fixture_root = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "phase4_human_review"
    packet = fixture_root / "blind_packet"
    with (packet / "review_sheet.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    key = json.loads((fixture_root / "maintainer_key.json").read_text(encoding="utf-8"))
    ids = [row["review_case_id"].strip() for row in rows]
    assert len(rows) == 8
    assert all(ids) and len(set(ids)) == len(ids)
    assert set(ids) == {case["review_case_id"] for case in key["cases"]}
    assert all(row["review_status"] == "PENDING" for row in rows)
    assert all(not row["reviewer_label"].strip() and not row["reviewer_id_or_role"].strip() for row in rows)
    for row in rows:
        email_path = packet / row["email_file"]
        assert email_path.is_file()
        assert hashlib.sha256(email_path.read_bytes()).hexdigest() == key["cases"][ids.index(row["review_case_id"])]["review_copy_sha256"]


def test_near_duplicate_refined_bucket_fails_closed_instead_of_silent_skip(monkeypatch):
    from services.email_ai import feature_pipeline

    # Distinct text values all receive the same deterministic signature, forcing an
    # oversized primary bucket and an oversized refined bucket without exposing content.
    monkeypatch.setattr(feature_pipeline, "_simhash", lambda tokens: 0x1234567890ABCDEF)
    rows = [{"text": f"distinct message token alpha beta gamma {index}", "source": "trec5"}
            for index in range(251)]
    with pytest.raises(ValueError, match="refined SimHash bucket.*refusing to silently skip"):
        list(feature_pipeline._near_duplicate_pairs(rows))


def test_source_split_audit_is_deterministic_and_detects_cross_source_exact_duplicates(tmp_path):
    import json
    from scripts.audit_meajor_source_split import build_manifest

    dataset = tmp_path / "mini.jsonl"
    rows = [
        {"text": "same shared content", "label": "LEGITIMATE", "source": "trec5"},
        {"text": "different legitimate content", "label": "PHISHING", "source": "trec5"},
        {"text": "same shared content", "label": "LEGITIMATE", "source": "trec6"},
        {"text": "different phishing content", "label": "PHISHING", "source": "trec6"},
    ]
    dataset.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    first = build_manifest(dataset)
    second = build_manifest(dataset)
    assert first == second
    assert first["exact_normalized_text_duplicate_audit"]["cross_source_duplicate_groups"] == 1
    assert first["exact_normalized_text_duplicate_audit"]["cross_source_duplicate_rows"] == 1
    assert all(fold["holdout_source"] not in fold["training_sources"] for fold in first["folds"])


def test_source_split_audit_fails_closed_on_malformed_jsonl(tmp_path):
    from scripts.audit_meajor_source_split import build_manifest

    dataset = tmp_path / "malformed.jsonl"
    dataset.write_text('{"text":"ok","label":"LEGITIMATE","source":"trec5"}\nnot-json\n', encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid JSONL"):
        build_manifest(dataset)
