"""Policy decisions and alert classification for the mail gateway workflow.

MailTrace returns a decision to a trusted gateway adapter. It does not move or
quarantine mail by itself; the adapter must apply the returned delivery action.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
from typing import Any


def verify_gateway_action_signature(
    event_id: str,
    payload: dict[str, Any],
    secret: str,
    supplied_signature: str,
) -> bool:
    """Verify a canonical receipt signature without accepting caller identity fields."""
    signed_payload = {"event_id": event_id, **payload}
    canonical = json.dumps(
        signed_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    expected = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    supplied = str(supplied_signature or "")
    if supplied.startswith("sha256="):
        supplied = supplied[7:]
    return hmac.compare_digest(supplied.lower(), expected)


def _attachment_scan_status(item: Any) -> str:
    if not isinstance(item, dict):
        return "UNKNOWN"
    scan = item.get("malware_scan")
    if not isinstance(scan, dict):
        return "UNKNOWN"
    return str(scan.get("status") or "UNKNOWN").strip().upper()


def build_mail_flow_decision(analysis: dict[str, Any]) -> dict[str, Any]:
    threat = analysis.get("threat_analysis", {})
    if not isinstance(threat, dict):
        threat = {}

    attachments = analysis.get("attachments", [])
    attachments = attachments if isinstance(attachments, list) else []
    scanner_confirmed_malware = any(
        isinstance(item, dict)
        and isinstance(item.get("malware_scan"), dict)
        and _attachment_scan_status(item) in {"INFECTED", "MALICIOUS"}
        and item["malware_scan"].get("malware_confirmed") is True
        and item["malware_scan"].get("engine") == "ClamAV"
        for item in attachments
    )
    raw_require_attachment_scan = os.getenv("MAILTRACE_REQUIRE_ATTACHMENT_SCAN", "true").strip().lower()
    if raw_require_attachment_scan not in {
        "1", "true", "yes", "on", "0", "false", "no", "off"
    }:
        raise RuntimeError("MAILTRACE_REQUIRE_ATTACHMENT_SCAN must be a boolean value.")
    require_attachment_scan = raw_require_attachment_scan in {"1", "true", "yes", "on"}
    unverified_attachment_scans = sum(
        1 for item in attachments
        if _attachment_scan_status(item) not in {"CLEAN", "INFECTED", "MALICIOUS"}
    )
    attachment_scan_incomplete = bool(
        require_attachment_scan and attachments and unverified_attachment_scans
    )

    score_invalid = False
    raw_score = threat.get("score")
    score_missing = "score" not in threat or raw_score is None
    if isinstance(raw_score, bool):
        score = 0
        score_invalid = True
    elif isinstance(raw_score, int):
        score = raw_score
    elif isinstance(raw_score, str) and raw_score.strip().isdecimal():
        score = int(raw_score.strip())
    else:
        score = 0
        score_invalid = True
    if not 0 <= score <= 100:
        score = 0
        score_invalid = True
    verdict = str(threat.get("verdict", "UNKNOWN") or "UNKNOWN").strip().upper()
    confidence = str(threat.get("confidence", "UNKNOWN") or "UNKNOWN").strip().upper()
    confidence_value = threat.get("confidence_value")
    evidence_confidence = threat.get("evidence_confidence")
    try:
        confidence_value = float(confidence_value)
        if isinstance(threat.get("confidence_value"), bool) or not math.isfinite(confidence_value):
            confidence_value = -1.0
    except (TypeError, ValueError):
        confidence_value = -1.0
    try:
        evidence_confidence = float(evidence_confidence)
        if isinstance(threat.get("evidence_confidence"), bool) or not math.isfinite(evidence_confidence):
            evidence_confidence = -1.0
    except (TypeError, ValueError):
        evidence_confidence = -1.0
    try:
        signal_count = int(threat.get("supporting_signal_count", 0))
        independent_evidence_count = int(threat.get("independent_evidence_count", 0))
    except (TypeError, ValueError):
        signal_count = 0
        independent_evidence_count = 0
    confidence_decision = str(threat.get("confidence_decision", "UNKNOWN") or "UNKNOWN").strip().upper()
    confidence_provenance_valid = (
        threat.get("confidence_basis") == "intelligence_fusion"
        and 0.0 <= confidence_value <= 1.0
        and 0.0 <= evidence_confidence <= 1.0
        and signal_count > 0
        and confidence_decision in {
            "HIGH_CONFIDENCE_THREAT",
            "CORROBORATED_THREAT",
            "LIKELY_LEGITIMATE",
            "SUSPICIOUS_REVIEW_REQUIRED",
        }
    )
    high_confidence_supported = (
        confidence_provenance_valid
        and confidence == "HIGH"
        and confidence_decision in {"HIGH_CONFIDENCE_THREAT", "CORROBORATED_THREAT"}
        and confidence_value >= 0.80
        and evidence_confidence >= 0.70
        and signal_count >= 5
        and independent_evidence_count >= 2
    )
    assessment_incomplete = (
        score_missing
        or score_invalid
        or verdict not in {"LOW RISK", "BENIGN", "LEGITIMATE", "MEDIUM", "SUSPICIOUS", "HIGH", "HIGH RISK", "CRITICAL"}
        or confidence not in {"LOW", "MEDIUM", "HIGH"}
        or not confidence_provenance_valid
        or confidence_decision == "INSUFFICIENT_EVIDENCE"
        or (confidence == "HIGH" and not high_confidence_supported)
        or attachment_scan_incomplete
    )

    mode = os.getenv("MAILTRACE_GATEWAY_ENFORCEMENT_MODE", "monitor_only").strip().lower()
    if mode not in {"monitor_only", "enforce"}:
        raise RuntimeError(
            "MAILTRACE_GATEWAY_ENFORCEMENT_MODE must be monitor_only or enforce."
        )
    try:
        quarantine_threshold = int(
            os.getenv("MAILTRACE_QUARANTINE_THRESHOLD", "85")
        )
    except ValueError as error:
        raise RuntimeError("MAILTRACE_QUARANTINE_THRESHOLD must be an integer from 50 to 100.") from error
    if not 50 <= quarantine_threshold <= 100:
        raise RuntimeError("MAILTRACE_QUARANTINE_THRESHOLD must be an integer from 50 to 100.")
    try:
        review_threshold = int(os.getenv("MAILTRACE_REVIEW_THRESHOLD", "40"))
    except ValueError as error:
        raise RuntimeError("MAILTRACE_REVIEW_THRESHOLD must be an integer from 0 to 99.") from error
    if not 0 <= review_threshold < quarantine_threshold:
        raise RuntimeError(
            "MAILTRACE_REVIEW_THRESHOLD must be from 0 to 99 and lower than MAILTRACE_QUARANTINE_THRESHOLD."
        )

    if score >= 90 or verdict == "CRITICAL":
        severity = "CRITICAL"
    elif score >= 70 or verdict in {"HIGH", "HIGH RISK"}:
        severity = "HIGH"
    elif score >= 40 or verdict == "SUSPICIOUS":
        severity = "MEDIUM"
    else:
        severity = "LOW"

    if scanner_confirmed_malware:
        severity = "HIGH"

    quarantine_recommended = high_confidence_supported and (
        verdict == "CRITICAL" or score >= quarantine_threshold
    )
    if scanner_confirmed_malware:
        recommended_action = "QUARANTINE"
        rationale = "ClamAV reported a malware signature in an attachment; quarantine the message and preserve the scanner result."
    elif attachment_scan_incomplete:
        recommended_action = "REVIEW"
        rationale = "Required malware scanning did not return a verified clean or infected verdict for every attachment; hold the message for review."
    elif assessment_incomplete:
        recommended_action = "REVIEW"
        rationale = "Threat assessment is incomplete or contains unsupported values; hold the message for review instead of allowing delivery."
    elif quarantine_recommended:
        recommended_action = "QUARANTINE"
        rationale = "High-risk threshold or critical verdict met with high confidence."
    elif (
        score_invalid
        or score >= review_threshold
        or verdict in {"SUSPICIOUS", "HIGH", "HIGH RISK", "CRITICAL"}
    ):
        # Uncertain or medium-risk messages must not silently become ALLOW. The
        # gateway holds them for review; SOC alerting remains limited to a
        # high-confidence threat or a trusted scanner-confirmed malware result.
        recommended_action = "REVIEW"
        rationale = (
            "The risk score was invalid; send the message to the configured review flow."
            if score_invalid
            else "The message has elevated or uncertain risk but does not meet the high-confidence quarantine threshold; send it to the configured review flow."
        )
    else:
        recommended_action = "ALLOW"
        rationale = "No configured review or quarantine threshold was met."

    fusion = analysis.get("intelligence_fusion", {})
    evidence = fusion.get("evidence", []) if isinstance(fusion, dict) else []
    category_labels = {
        "url": "A link is present; check its destination carefully before opening it.",
        "attachment": "An attachment is present; do not open it if you were not expecting it.",
        "malware_delivery": "The attachment has a potentially dangerous file type; do not open it.",
        "credential_theft": "The message may be trying to collect passwords or sign-in details.",
        "impersonation": "The sender or identity may be impersonating a person or organization.",
        "identity": "Sender identity indicators do not fully line up.",
        "fraud": "The message contains possible payment or invoice fraud indicators.",
        "social_engineering": "The message uses pressure or persuasion patterns commonly seen in scams.",
        "header_forensics": "Email routing or authentication headers contain anomalies.",
        "threat_intelligence": "An indicator matched available threat-intelligence data.",
        "infrastructure": "The sending infrastructure has elevated reputation risk.",
        "forensics": "Forensic checks raised a message-structure risk signal.",
        "ml": "Automated message classification raised a risk signal; review the supporting evidence.",
    }
    risk_indicators: list[str] = []
    if isinstance(evidence, list):
        for item in evidence:
            if not isinstance(item, dict):
                continue
            label = category_labels.get(str(item.get("category", "")).lower())
            if label and label not in risk_indicators:
                risk_indicators.append(label)
            if len(risk_indicators) >= 5:
                break
    if severity in {"HIGH", "CRITICAL"} and not risk_indicators:
        risk_indicators.append("The combined email risk assessment is high; analyst review is recommended.")

    is_risky = recommended_action in {"REVIEW", "QUARANTINE"}
    user_notification = None
    if is_risky:
        user_notification = {
            "title": (
                "Suspicious email — do not interact"
                if recommended_action == "QUARANTINE"
                else "Email needs a safety check"
            ),
            "summary": (
                "MailTrace found indicators that may be associated with phishing, impersonation, or fraud. This automated assessment is a warning, not proof of malicious intent."
                if recommended_action == "QUARANTINE"
                else "MailTrace could not complete a reliable risk assessment. Avoid links, attachments, payments, or credential requests until your organization clears the message."
                if assessment_incomplete
                else "MailTrace found signals that need review. Avoid links, attachments, payments, or credential requests until your organization clears the message."
            ),
            "why_risky": risk_indicators or ["The message needs security review before you act on it."],
            "next_steps": [
                "Do not click links, open attachments, reply, or send money or credentials.",
                "Verify the request with the sender using a separate, trusted contact method.",
                "Contact your security team if you already interacted with the message.",
            ],
        }

    return {
        "policy_version": "mailtrace-gateway-policy-v2",
        "severity": severity,
        "threat_score": score,
        "confidence": confidence,
        "recommended_action": recommended_action,
        "delivery_action": (
            recommended_action if mode == "enforce" else "MONITOR_ONLY"
        ),
        "enforcement_mode": mode.upper(),
        "gateway_must_apply_action": mode == "enforce",
        "quarantine_threshold": quarantine_threshold,
        "review_threshold": review_threshold,
        "attachment_scan_required": require_attachment_scan,
        "unverified_attachment_scan_count": unverified_attachment_scans,
        "rationale": rationale,
        "user_notification": user_notification,
    }


def should_create_alert(decision: dict[str, Any]) -> bool:
    """Only automatic high-risk quarantine decisions page the SOC."""
    return decision.get("recommended_action") == "QUARANTINE"
