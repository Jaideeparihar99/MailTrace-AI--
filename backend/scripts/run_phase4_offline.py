"""Run the focused offline Phase 2â€“4 regression gate and compare Step 18 baseline."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parent
BASELINE_PATH = BACKEND / "tests" / "fixtures" / "phase4_step18" / "baseline.json"
MANIFEST_PATH = BACKEND / "tests" / "fixtures" / "phase4_step16" / "manifest.json"

FOCUSED_SUITES = [
    "tests/test_phase4_step16_fixture_corpus.py",
    "tests/test_phase4_blind_review_reconciliation.py",
    "tests/test_phase4_supplemental_corpus.py",
    "tests/test_email_ai_model_path_resolution.py",
    "tests/test_phase4_ml_only_risk_cap.py",
    "tests/test_phase4_step17_analysis_api.py",
    "tests/test_email_alerting_policy.py",
    "tests/test_false_positive_scoring.py",
    "tests/test_phase3_step11_header_mime_parsing.py",
    "tests/test_phase3_step12_url_extraction.py",
    "tests/test_phase3_step13_ioc_normalization.py",
    "tests/test_phase3_step14_explicit_states.py",
    "tests/test_phase3_step15_report_consistency.py",
    "tests/test_phase2_step10_gate.py",
    "tests/test_domain_alignment_evidence.py",
    "services/email_ai/test_intelligence_fusion.py",
]
POSITIVE_LABELS = {"phishing", "credential_harvesting", "bec_payment_change"}
NEGATIVE_LABELS = {"benign_legitimate", "authentication_edge_case"}
POSITIVE_VERDICTS = {"HIGH RISK", "CRITICAL"}
NEGATIVE_VERDICTS = {"LOW RISK"}
EVALUATION_POLICY = {
    "unit": "email",
    "positive_labels": sorted(POSITIVE_LABELS),
    "negative_labels": sorted(NEGATIVE_LABELS),
    "positive_verdicts": sorted(POSITIVE_VERDICTS),
    "negative_verdicts": sorted(NEGATIVE_VERDICTS),
    "inconclusive_labels_excluded_from_binary_metrics": ["suspicious_inconclusive", "malformed_email"],
}


def run(command: list[str], *, capture: bool = False):
    print("\n> " + subprocess.list2cmdline(command), flush=True)
    completed = subprocess.run(command, cwd=BACKEND, text=True,
                               stdout=subprocess.PIPE if capture else None,
                               stderr=subprocess.STDOUT if capture else None)
    if capture and completed.stdout:
        print(completed.stdout, end="", flush=True)
    if completed.returncode:
        raise SystemExit(completed.returncode)
    return completed.stdout or ""


def calculate_metrics(results: list[dict]) -> dict:
    tp = fp = tn = fn = excluded = 0
    for row in results:
        label, verdict = row["label"], row["verdict"]
        if label in POSITIVE_LABELS:
            if verdict in POSITIVE_VERDICTS:
                tp += 1
            elif verdict in NEGATIVE_VERDICTS:
                fn += 1
            else:
                excluded += 1
        elif label in NEGATIVE_LABELS:
            if verdict in POSITIVE_VERDICTS:
                fp += 1
            elif verdict in NEGATIVE_VERDICTS:
                tn += 1
            else:
                excluded += 1
        else:
            excluded += 1
    precision_denominator = tp + fp
    recall_denominator = tp + fn
    negative_denominator = tn + fp
    precision = tp / precision_denominator if precision_denominator else None
    recall = tp / recall_denominator if recall_denominator else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision is not None and recall is not None and precision + recall else None)
    fpr = fp / negative_denominator if negative_denominator else None
    return {
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
                             "binary_n": tp + fp + tn + fn, "excluded_or_inconclusive": excluded},
        "metrics": {
            "precision": {"numerator": tp, "denominator": precision_denominator, "value": precision},
            "recall": {"numerator": tp, "denominator": recall_denominator, "value": recall},
            "f1": {"value": f1},
            "false_positive_rate": {"numerator": fp, "denominator": negative_denominator, "value": fpr},
        },
    }


def main():
    baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    manifest_digest = hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest().upper()
    if manifest_digest != baseline["fixture_manifest_sha256"]:
        raise SystemExit("Fixture manifest changed; baseline comparison stopped. Review labels/outcomes before updating baseline.")

    with tempfile.TemporaryDirectory(prefix="mailtrace-phase4-pytest-") as pytest_temp:
        run([sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-ra", "-q",
             *FOCUSED_SUITES, "--basetemp", pytest_temp])
    output = run([sys.executable, "scripts/evaluate_phase4_step18.py"], capture=True)
    actual = json.loads(output)

    expected_runtime = baseline["runtime"]
    actual_runtime = {key: actual[key] for key in expected_runtime}
    actual_metrics = calculate_metrics(actual["results"])
    comparisons = {
        "corpus_id": (actual["corpus_id"], baseline["corpus_id"]),
        "fixture_count": (actual["fixture_count"], len(baseline["results"])),
        "evaluation_policy": (EVALUATION_POLICY, baseline["evaluation_policy"]),
        "runtime": (actual_runtime, expected_runtime),
        "results": (actual["results"], baseline["results"]),
        "confusion_matrix": (actual_metrics["confusion_matrix"], baseline["confusion_matrix"]),
        "metrics": (actual_metrics["metrics"], baseline["metrics"]),
    }
    mismatches = [name for name, (current, expected) in comparisons.items() if current != expected]
    if mismatches:
        for name in mismatches:
            current, expected = comparisons[name]
            print(f"\nBASELINE MISMATCH: {name}\nExpected: {json.dumps(expected, indent=2)}\n"
                  f"Actual:   {json.dumps(current, indent=2)}")
        raise SystemExit(1)

    print("\nOffline Phase 4 gate: PASS")
    print(f"Baseline {baseline['baseline_id']}: MATCH")
    print(f"Fixture metrics: TP={actual_metrics['confusion_matrix']['tp']} "
          f"FP={actual_metrics['confusion_matrix']['fp']} TN={actual_metrics['confusion_matrix']['tn']} "
          f"FN={actual_metrics['confusion_matrix']['fn']} "
          f"excluded/inconclusive={actual_metrics['confusion_matrix']['excluded_or_inconclusive']}")


if __name__ == "__main__":
    main()
