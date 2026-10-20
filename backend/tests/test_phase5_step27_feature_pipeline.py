from __future__ import annotations
import copy
import json
from pathlib import Path
import pytest
from services.email_ai.feature_pipeline import extract_features, feature_vector, grouped_split


def parsed(**overrides):
    result = {
        "basic_information": {"subject": " Re: Payment ", "from": "Alice <alice@example.invalid>", "reply_to": None, "return_path": None, "date": "Mon, 01 Jan 2024 10:00:00 +0000"},
        "body": {"text": "Please verify your account now! https://example.invalid/login", "html": "", "length": 60},
        "headers": {"from": "Alice", "subject": "Payment"},
        "urls": ["https://example.invalid/login"],
        "url_evidence": [{"comparison_url": "https://example.invalid/login"}],
        "authentication": {"spf": "FAIL", "dkim": "PASS", "dmarc": "FAIL", "authentication_results_trusted": False},
        "received_chain": [{"hop": 1}], "attachments": [], "parsing": {"status": "COMPLETE"},
    }
    result.update(overrides)
    return result


def test_empty_and_missing_content_are_explicit():
    out = extract_features({"basic_information": {}, "body": {}})
    f = out["normalized_features"]
    assert f["text_for_model"] == ""
    assert f["missingness"]["subject"] == "MISSING"
    assert f["missingness"]["body"] == "MISSING"
    assert f["categorical"]["spf_status"] == "MISSING"
    assert f["categorical"]["spf_status_available"] is False


def test_malformed_header_values_do_not_crash_and_are_not_trusted():
    source = parsed(basic_information={"subject": "\x00bad", "from": ["not", "a", "header"], "reply_to": 7, "return_path": None, "date": "not-a-date"}, authentication={"spf": "nonsense"})
    out = extract_features(source)
    assert out["normalized_features"]["categorical"]["message_date_trustworthy_format"] is False
    assert out["normalized_features"]["categorical"]["spf_status"] == "OTHER"
    assert out["normalized_features"]["categorical"]["authentication_results_trusted"] is False


def test_unicode_homoglyphs_and_invisible_controls_are_deterministic():
    source = parsed(basic_information={"subject": "Ñ€Ð°ypal\u200b", "from": None}, body={"text": "ï¼°ï¼¡ï¼¹ï¼°ï¼¡ï¼¬\u202e login", "html": "", "length": 20})
    first = extract_features(source)
    assert first == extract_features(source)
    assert first["normalized_features"]["subject_text"].endswith("ypal")
    assert first["normalized_features"]["lexical"]["contains_non_ascii"] is True
    assert first["normalized_features"]["lexical"]["contains_bidi_or_invisible_controls"] is True

    assert first["normalized_features"]["lexical"]["contains_bidi_or_invisible_controls"] is True
def test_real_unicode_homoglyph_is_preserved_and_detected():
    # Cyrillic small er (U+0440) visually resembles Latin p; retain the original evidence signal.
    source = parsed(basic_information={"subject": "\u0440ay\u0440al", "from": None}, body={"text": "hello", "html": "", "length": 5})
    out = extract_features(source)
    f = out["normalized_features"]
    assert f["subject_text"] == "\u0440ay\u0440al"
    assert f["lexical"]["contains_non_ascii"] is True


def test_authentication_trust_requires_an_explicit_boolean():
    source = parsed(authentication={"spf": "PASS", "dkim": "PASS", "dmarc": "PASS", "authentication_results_trusted": "false"})
    assert extract_features(source)["normalized_features"]["categorical"]["authentication_results_trusted"] is False


def test_feature_vector_rejects_unregistered_feature_names():
    out = extract_features(parsed())
    out["normalized_features"]["numeric"]["post_case_summary_length"] = 3
    with pytest.raises(ValueError, match="not in the .* allow-list"):
        feature_vector(out)


def test_html_only_message_uses_visible_text_not_markup():
    out = extract_features(parsed(body={"text": "", "html": "<html><head><title>hidden</title></head><body><p>Verify account</p><script>secret()</script></body></html>", "length": 100}))
    f = out["normalized_features"]
    assert f["categorical"]["body_source"] == "html"
    assert "verify account" in f["body_text"]
    assert "secret" not in f["body_text"]
    assert "hidden" not in f["body_text"]


def test_repeated_and_malformed_urls_are_counted_without_network_access():
    out = extract_features(parsed(urls=["https://a.invalid/x", "https://a.invalid/x", "malformed url"]))
    n = out["normalized_features"]["numeric"]
    assert n["url_count"] == 3
    assert n["url_host_count"] == 1
    assert n["url_invalid_host_count"] == 1


def test_long_input_is_truncated_and_evidence_is_unchanged():
    original = parsed(body={"text": "A" * 250_000, "html": "", "length": 250_000})
    before = copy.deepcopy(original)
    out = extract_features(original, max_text_chars=10_000)
    assert out["normalized_features"]["truncation"]["body"] is True
    assert len(out["normalized_features"]["body_text"]) <= 10_000
    assert original == before


def test_feature_vector_excludes_labels_and_rejects_leaking_feature_names():
    out = extract_features(parsed())
    out["label"] = "PHISHING"
    out["analyst_verdict"] = "MALICIOUS"
    assert "label" not in feature_vector(out)
    out["normalized_features"]["numeric"]["risk_score"] = 99
    with pytest.raises(ValueError, match="Forbidden"):
        feature_vector(out)


def test_reproducible_split_keeps_campaign_and_exact_duplicate_groups_together():
    rows = [
        {"text": "same body A", "label": "PHISHING", "campaign_id": "c1", "source": "s1"},
        {"text": "same body A", "label": "PHISHING", "campaign_id": "c1", "source": "s2"},
        {"text": "body B", "label": "LEGITIMATE", "campaign_id": "c2", "source": "s1"},
        {"text": "body C", "label": "LEGITIMATE", "campaign_id": "c3", "source": "s2"},
        {"text": "body D", "label": "PHISHING", "campaign_id": "c4", "source": "s3"},
        {"text": "body E", "label": "LEGITIMATE", "campaign_id": "c5", "source": "s4"},
        {"text": "body F", "label": "PHISHING", "campaign_id": "c6", "source": "s5"},
        {"text": "body G", "label": "LEGITIMATE", "campaign_id": "c7", "source": "s6"},
        {"text": "body H", "label": "PHISHING", "campaign_id": "c8", "source": "s7"},
    ]
    a = grouped_split(rows, seed=123, group_by_source=False, time_aware=False)
    b = grouped_split(rows, seed=123, group_by_source=False, time_aware=False)
    assert a["manifest"] == b["manifest"]
    memberships = {}
    for split_name, split_rows in a["splits"].items():
        for row in split_rows:
            memberships.setdefault(row["campaign_id"], set()).add(split_name)
            memberships.setdefault(row["text"], set()).add(split_name)
    assert all(len(value) == 1 for value in memberships.values())


def test_time_split_requires_trustworthy_timezone_aware_timestamps():
    rows = [{"text": f"body {i}", "campaign_id": f"c{i}", "timestamp": f"2024-01-{i:02d}T12:00:00+00:00"} for i in range(1, 10)]
    result = grouped_split(rows, time_aware=True, group_by_source=False)
    assert result["manifest"]["time_aware_used"] is True
    assert max(r["timestamp"] for r in result["splits"]["train"]) < min(r["timestamp"] for r in result["splits"]["test"])
    rows[0]["timestamp"] = "2024-01-01T12:00:00"
    result = grouped_split(rows, time_aware=True, group_by_source=False)
    assert result["manifest"]["time_aware_used"] is False


def test_temporal_split_fails_closed_when_a_group_spans_partition_boundaries():
    rows = [
        {"text": "campaign alpha old", "campaign_id": "alpha", "timestamp": "2024-01-01T00:00:00+00:00"},
        {"text": "campaign beta", "campaign_id": "beta", "timestamp": "2024-01-02T00:00:00+00:00"},
        {"text": "campaign gamma", "campaign_id": "gamma", "timestamp": "2024-01-03T00:00:00+00:00"},
        {"text": "campaign delta", "campaign_id": "delta", "timestamp": "2024-01-04T00:00:00+00:00"},
        {"text": "campaign epsilon", "campaign_id": "epsilon", "timestamp": "2024-01-05T00:00:00+00:00"},
        {"text": "campaign alpha new", "campaign_id": "alpha", "timestamp": "2024-01-09T00:00:00+00:00"},
    ]
    with pytest.raises(ValueError, match="timestamps overlap"):
        grouped_split(rows, group_by_source=False, time_aware=True)


def test_too_few_independent_groups_fails_closed():
    with pytest.raises(ValueError, match="3 independent groups"):
        grouped_split([{"text": "same"}, {"text": "same"}], group_by_source=False)


def test_schema_declares_target_and_leakage_exclusions():
    path = Path(__file__).parents[1] / "services" / "email_ai" / "feature_schema.v1.json"
    schema = json.loads(path.read_text(encoding="utf-8-sig"))
    assert schema["prediction_target"]["field"] == "label"
    assert "report summary" in schema["excluded_from_features"]

def test_schema_feature_names_match_runtime_allow_list():
    from services.email_ai.feature_pipeline import FEATURE_ALLOWLIST
    path = Path(__file__).parents[1] / "services" / "email_ai" / "feature_schema.v1.json"
    schema = json.loads(path.read_text(encoding="utf-8-sig"))
    declared = set().union(*(set(schema["features"][name]) for name in ("numeric", "categorical", "lexical")))
    assert declared == set(FEATURE_ALLOWLIST)


def test_source_grouping_keeps_each_source_in_one_partition():
    rows = [{"text": f"message {source}-{i}", "source": source, "campaign_id": f"{source}-c{i}"}
            for source in ("source-a", "source-b", "source-c") for i in range(3)]
    result = grouped_split(rows, group_by_source=True, time_aware=False)
    membership = {}
    for split_name, split_rows in result["splits"].items():
        for row in split_rows:
            membership.setdefault(row["source"], set()).add(split_name)
    assert all(len(splits) == 1 for splits in membership.values())
    assert result["manifest"]["group_by_source"] is True


def test_text_vectorizer_is_fitted_only_from_supplied_training_rows():
    from services.email_ai.feature_pipeline import fit_text_classifier
    train = [
        {"normalized_features": {"text_for_model": "routine meeting schedule"}},
        {"normalized_features": {"text_for_model": "invoice payment request"}},
        {"normalized_features": {"text_for_model": "weekly team update"}},
        {"normalized_features": {"text_for_model": "verify account credentials"}},
    ]
    model = fit_text_classifier(train, ["LEGITIMATE", "PHISHING", "LEGITIMATE", "PHISHING"], seed=27)
    vocabulary = model.named_steps["tfidf"].vocabulary_
    assert "testonlytoken" not in vocabulary
    # A dev/test-only token is not passed to fit and therefore cannot enter vocabulary.

def test_near_duplicate_texts_are_grouped_together():
    shared = "urgent invoice payment request from finance department please review the attached document before the end of today"
    rows = [
        {"text": shared, "campaign_id": "near-a"},
        {"text": shared.replace("attached document", "attached file"), "campaign_id": "near-b"},
        {"text": "a completely unrelated garden recipe about planting flowers in spring", "campaign_id": "unrelated-a"},
        {"text": "train timetable and railway platform announcement for tomorrow morning", "campaign_id": "unrelated-b"},
        {"text": "computer graphics lecture notes about matrices and vectors", "campaign_id": "unrelated-c"},
    ]
    result = grouped_split(rows, group_by_source=False, time_aware=False)
    membership = {}
    for split_name, split_rows in result["splits"].items():
        for row in split_rows:
            if row["campaign_id"].startswith("near-"):
                membership[row["campaign_id"]] = split_name
    assert membership["near-a"] == membership["near-b"]
