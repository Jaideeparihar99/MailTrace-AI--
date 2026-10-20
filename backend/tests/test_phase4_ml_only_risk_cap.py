from services.email_ai.intelligence_fusion import analyze_email_intelligence


def test_benign_risky_words_disclaimer_is_not_high_risk_with_ml_only_false_positive():
    result = analyze_email_intelligence(
        email={
            "sender": "compliance@example.invalid",
            "subject": "Quarterly fraud-prevention reminder",
            "body": (
                "Reminder: our fraud-prevention training discusses password safety and identity verification. "
                "The Compliance Desk will never ask you to send a password or one-time code by email. "
                "Do not use links in unexpected messages to verify an account. "
                "Please attend the scheduled training session in the internal learning portal you already use."
            ),
            "urls": [],
            "url_evidence": [],
            "attachments": [],
        },
        ai_result={
            "status": "MODEL_READY", "model_ready": True, "classification": "PHISHING",
            "model_probability": 0.6341296965, "calibrated_probability": 0.6341296965,
        },
        forensic={}, threat_intelligence={"iocs": [], "matches": {}}, ip_intelligence={},
    )
    assert result["unified_risk_score"] < 50
    assert result["risk_tier"] != "HIGH"
    assert any(x["component"] == "uncorroborated_ml_risk_cap" for x in result["score_breakdown"])
    assert round(sum(x["points"] for x in result["score_breakdown"]), 6) == result["unified_risk_score"]


def test_known_phishing_with_independent_url_evidence_remains_high_risk():
    result = analyze_email_intelligence(
        email={
            "sender": "notice@example.invalid",
            "subject": "Action required: service access review",
            "body": "Your fictional service access will be suspended immediately. Click here to verify the notice. Enter your password.",
            "urls": ["https://account-review.example.invalid/notice"],
            "advanced_url_intelligence": {"risk_score": 76, "verdict": "HIGH_CONFIDENCE_DECEPTIVE"},
            "attachments": [],
        },
        ai_result={"status": "MODEL_READY", "model_ready": True, "classification": "PHISHING", "model_probability": 0.7401, "calibrated_probability": 0.7401},
        forensic={}, threat_intelligence={"iocs": [], "matches": {}}, ip_intelligence={},
    )
    assert result["unified_risk_score"] >= 75
    assert result["risk_tier"] in {"HIGH", "CRITICAL"}
    assert result["fusion_metrics"]["independent_category_count"] >= 1
