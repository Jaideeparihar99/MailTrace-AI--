from email.message import EmailMessage
import json
from pathlib import Path

from services.email_ai.intelligence_fusion import analyze_email_intelligence
from services.email_parser import parse_email


def _fusion(email=None, ai=None, forensic=None, ti=None, ip=None):
    return analyze_email_intelligence(
        email=email or {}, ai_result=ai or {"status": "MODEL_NOT_READY"},
        forensic=forensic, threat_intelligence=ti, ip_intelligence=ip,
    )


def _assert_auditable(result):
    ledger = result["score_ledger"]
    assert round(sum(row["contribution"] for row in ledger), 6) == result["unified_risk_score"]
    for row in ledger:
        assert row["reason_code"]
        assert row["detector_source"]
        assert isinstance(row["contribution"], float)
        if row["category"] in {"evidence_group"}:
            assert row["evidence_refs"]
        elif row["category"] != "fusion_policy":
            assert row["evidence_ref"]


def test_score_ledger_has_stable_reason_and_evidence_refs_and_reconciles():
    inputs = {
        "email": {"subject": "Verify your account", "body": "Enter your password immediately."},
        "ai": {"status": "MODEL_NOT_READY"},
    }
    first = _fusion(inputs["email"], inputs["ai"])
    second = _fusion(inputs["email"], inputs["ai"])
    _assert_auditable(first)
    assert [(r["reason_code"], r["evidence_ref"]) for r in first["evidence"]] == [
        (r["reason_code"], r["evidence_ref"]) for r in second["evidence"]
    ]
    assert [(r["reason_code"], r["evidence_ref"], r["contribution"]) for r in first["score_ledger"]] == [
        (r["reason_code"], r["evidence_ref"], r["contribution"]) for r in second["score_ledger"]
    ]
    assert 0 <= first["unified_risk_score"] <= 100
    assert 0 <= first["confidence"] <= 1


def test_bec_payment_change_lure_has_explainable_fraud_evidence():
    result = _fusion({
        "subject": "Updated bank details for the invoice",
        "body": "Please change the beneficiary and wire transfer the payment to our new bank account today.",
    })
    assert "financial_fraud_language" in {item["name"] for item in result["evidence"]}
    assert "MT-FUS-POLICY-INDEPENDENT_EVIDENCE_CAP" in {
        row["reason_code"] for row in result["score_ledger"]
    }
    _assert_auditable(result)


def test_authentication_failure_is_separate_from_benign_content_risk():
    result = _fusion({
        "subject": "Monthly newsletter",
        "body": "Here is the monthly community update.",
        "authentication_validation": {
            "spf": {"status": "FAIL"}, "dkim": {"status": "PASS"}, "dmarc": {"status": "PASS"},
            "independent_validation": True, "validated_domain": "example.com",
        },
    })
    assert "authentication_failure" in {item["name"] for item in result["evidence"]}
    assert result["unified_risk_score"] > 0
    assert result["confidence"] != result["unified_risk_score"]
    _assert_auditable(result)


def test_malformed_email_input_is_reported_without_fabricating_signals():
    parsed = parse_email(b"From: not-an-email@@example.com\r\nSubject: broken\r\n\r\nplain body", "malformed.eml")
    assert isinstance(parsed, dict)
    fused = _fusion({"subject": parsed.get("subject", ""), "body": parsed.get("body", {}).get("text", "")})
    assert 0 <= fused["unified_risk_score"] <= 100
    _assert_auditable(fused)


def test_promotional_auth_pass_baseline_remains_zero_and_auth_claims_are_distinct():
    auth = {name: {"status": "PASS"} for name in ("spf", "dkim", "dmarc")}
    result = _fusion({
        "sender": "updates@myntra.com", "subject": "It's LIVE! 3X Discounts",
        "body": "Offers may be revoked or suspended. Shop now. Unsubscribe.",
        "headers": {"List-Unsubscribe": "<https://track.myntra.com/unsubscribe>"},
        "urls": ["https://track.myntra.com/click"], "attachments": [],
        "authentication_validation": auth,
    }, forensic={"risk_score": 82, "findings": [{"severity": "MEDIUM", "title": "From and Return-Path domains differ"}]},
       ti={"matches": [], "matched_count": 0})
    assert result["unified_risk_score"] == 0
    assert result["risk_tier"] == "LOW"
    assert result["confidence"] == 0.275
    assert result["model_available"] is False
    assert result["confidence_components"]["model_support"] == 0.5
    _assert_auditable(result)


def test_stored_myntra_analysis_replays_to_low_risk_without_false_urgency():
    fixture = json.loads((Path(__file__).parent / "fixtures" / "myntra_promotional_record.json").read_text(encoding="utf-8"))
    result = analyze_email_intelligence(
        email=fixture["email"], ai_result=fixture["ai_result"],
        threat_intelligence=fixture["threat_intelligence"],
    )
    assert fixture["historical_observation"]["risk_score"] == 82
    assert result["unified_risk_score"] == 0
    assert result["risk_tier"] == "LOW"
    assert result["evidence"] == []
    assert result["model_available"] is False
    assert result["confidence"] == 0.275
    _assert_auditable(result)


def test_related_content_categories_share_one_evidence_group_and_bounded_uplift():
    result = _fusion({
        "subject": "Account notice",
        "body": "Your account will be suspended immediately. Verify your account and enter your password.",
    })
    rows = [row for row in result["score_ledger"] if row["category"] == "evidence_group"]
    related = next(row for row in rows if "credential_theft" in row["member_categories"])
    assert {"credential_theft", "social_engineering"}.issubset(set(related["member_categories"]))
    assert related["correlation_uplift"] <= 8
    assert result["fusion_metrics"]["independent_evidence_group_count"] == 1
    _assert_auditable(result)


def test_unrelated_content_categories_in_same_family_remain_independent():
    result = _fusion({
        "subject": "Account and invoice notice",
        "body": "Verify your account. Separately, wire transfer the invoice to a new beneficiary.",
    })
    groups = [row for row in result["score_ledger"] if row["category"] == "evidence_group"]
    intent_groups = [row for row in groups if row["correlation_group"].startswith("content_intent[")]
    assert any("credential_theft" in row["member_categories"] for row in intent_groups)
    assert any("fraud" in row["member_categories"] for row in intent_groups)
    assert result["fusion_metrics"]["independent_evidence_group_count"] >= 2
    _assert_auditable(result)


def test_authentication_score_cap_requires_all_independent_validated_checks():
    auth = {name: {"status": "PASS"} for name in ("spf", "dkim", "dmarc")}
    auth.update({"independent_validation": True, "validated_domain": "example.com"})
    finding = {"findings": [{"severity": "HIGH", "title": "Independent header anomaly"}]}
    result = _fusion({"authentication_validation": auth, "body": "Routine monthly update."}, forensic=finding)
    assert result["authentication"]["validation_completion"] == "COMPLETE"
    assert result["authentication"]["independent_validation"] is True
    assert result["unified_risk_score"] == 15
    assert "MT-FUS-POLICY-EVIDENCE_LIMITED_CAP" in {row["reason_code"] for row in result["score_ledger"]}
    incomplete = _fusion({"authentication_validation": {"spf": {"status": "PASS"}}}, forensic=finding)
    assert incomplete["authentication"]["validation_completion"] == "INCOMPLETE"
    assert incomplete["unified_risk_score"] > 15


def test_intelligence_availability_keeps_no_indicators_unavailable_and_error_distinct():
    assert _fusion({}, ti={"status": "no_iocs", "iocs": []})["intelligence_availability"]["status"] == "NO_INDICATORS"
    assert _fusion({}, ti=None)["intelligence_availability"]["status"] == "NOT_PROVIDED"
    assert _fusion({}, ti={"status": "error"})["intelligence_availability"]["status"] == "ERROR"
    assert _fusion({}, ti={"status": "no_matches", "coverage_status": "FRESH", "iocs": [{"ioc": "x"}], "matched_count": 0})["intelligence_availability"]["status"] == "CHECKED_NO_MATCHES"


def test_reported_authentication_pass_is_not_confused_with_independent_validation():
    result = _fusion(
        {"subject": "Routine note", "body": "Hello."},
        forensic={"authentication_analysis": {
            "reported_results": {"spf": "PASS", "dkim": "PASS", "dmarc": "PASS"},
            "authentication_results_trusted": False,
            "validation": {"spf": {"status": "UNVERIFIED_NO_TRUSTED_SMTP_IP"},
                           "dkim": {"status": "NOT_VALIDATED"}, "dmarc": {"status": "NOT_VALIDATED"},
                           "reported_headers_trusted": False},
        }},
    )
    assert result["authentication"]["checks"]["spf"]["reported_status"] == "PASS"
    assert result["authentication"]["checks"]["spf"]["validated_status"] == "UNVERIFIED_NO_TRUSTED_SMTP_IP"
    assert result["authentication"]["reported_results_trusted"] is False
    assert result["authentication"]["independent_validation"] is False


def test_api_fusion_failure_is_explicitly_degraded():
    from main import _resolve_final_email_score

    failed = _resolve_final_email_score({"status": "ERROR", "unified_risk_score": 0}, 22, 13)
    assert failed == {
        "score": 35, "source": "parser_rules_plus_ioc_fallback", "degraded": True,
        "fusion_status": "ERROR",
        "reason": "Fusion result was missing, failed, or invalid; parser plus IOC fallback was used.",
    }
    valid = _resolve_final_email_score({"status": "ANALYZED", "unified_risk_score": 17.4}, 90, 20)
    assert valid["score"] == 17
    assert valid["source"] == "intelligence_fusion"
    assert valid["degraded"] is False
