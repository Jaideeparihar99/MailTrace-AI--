from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
spec = spec_from_file_location("labeled_holdout_eval", Path(__file__).resolve().parents[1] / "scripts" / "evaluate_labeled_holdout.py")
mod = module_from_spec(spec)
spec.loader.exec_module(mod)
def test_metrics_are_correct_and_only_reviewed_rows_count():
    rows = [
        {"fixture_id":"1","expected_label":"phishing","predicted_label":"phishing","independent_review_status":"approved"},
        {"fixture_id":"2","expected_label":"benign","predicted_label":"phishing","independent_review_status":"reviewed"},
        {"fixture_id":"3","expected_label":"benign","predicted_label":"benign","independent_review_status":"adjudicated"},
        {"fixture_id":"4","expected_label":"phishing","predicted_label":"benign","independent_review_status":"approved"},
        {"fixture_id":"5","expected_label":"benign","predicted_label":"phishing","independent_review_status":"pending"},
    ]
    report, detail = mod.evaluate(rows)
    assert report["confusion_matrix"] == {"tp":1,"fp":1,"tn":1,"fn":1}
    assert report["precision"] == 0.5 and report["recall"] == 0.5
    assert report["f1"] == 0.5 and report["false_positive_rate"] == 0.5
    assert report["scored_independently_reviewed"] == 4
    assert report["excluded_unreviewed"] == 1
    assert detail[-1]["evaluation_status"] == "awaiting_independent_review"
def test_empty_holdout_metrics_are_null_not_fabricated():
    report, detail = mod.evaluate([])
    assert report["holdout_rows_received"] == 0
    assert report["precision"] is None and report["recall"] is None and report["f1"] is None
    assert report["false_positive_rate"] is None
    assert report["accuracy_claim_status"] == "UNVERIFIED"
