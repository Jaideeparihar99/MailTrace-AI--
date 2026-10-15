import os
import hashlib
import hmac
import json
import pathlib
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from services.email_alerting import build_mail_flow_decision, should_create_alert


class EmailAlertingPolicyTests(unittest.TestCase):
    def decision(self, threat, *, mode="monitor_only"):
        confidence = str(threat.get("confidence", "UNKNOWN")).upper()
        provenance = {
            "confidence_basis": "intelligence_fusion",
            "confidence_value": 0.95 if confidence == "HIGH" else 0.70 if confidence == "MEDIUM" else 0.25,
            "evidence_confidence": 0.80 if confidence == "HIGH" else 0.50 if confidence == "MEDIUM" else 0.20,
            "supporting_signal_count": 5 if confidence == "HIGH" else 3,
            "independent_evidence_count": 2 if confidence == "HIGH" else 1,
            "confidence_decision": "HIGH_CONFIDENCE_THREAT" if confidence == "HIGH" and int(threat.get("score", 0) or 0) >= 85 else "LIKELY_LEGITIMATE" if confidence == "HIGH" else "SUSPICIOUS_REVIEW_REQUIRED",
        }
        threat = {**threat, **provenance}
        with patch.dict(os.environ, {
            "MAILTRACE_GATEWAY_ENFORCEMENT_MODE": mode,
            "MAILTRACE_REVIEW_THRESHOLD": "40",
            "MAILTRACE_QUARANTINE_THRESHOLD": "85",
        }, clear=False):
            return build_mail_flow_decision({"threat_analysis": threat})

    def test_low_risk_is_allowed_and_does_not_page_soc(self):
        result = self.decision({"score": 5, "verdict": "LOW", "confidence": "HIGH"})
        self.assertEqual(result["recommended_action"], "ALLOW")
        self.assertEqual(result["delivery_action"], "MONITOR_ONLY")
        self.assertFalse(should_create_alert(result))

    def test_medium_risk_is_reviewed_but_not_automatically_sent_to_soc(self):
        result = self.decision({"score": 55, "verdict": "SUSPICIOUS", "confidence": "MEDIUM"})
        self.assertEqual(result["recommended_action"], "REVIEW")
        self.assertEqual(result["delivery_action"], "MONITOR_ONLY")
        self.assertIsNotNone(result["user_notification"])
        self.assertFalse(should_create_alert(result))

    def test_high_confidence_risk_is_quarantined_and_creates_soc_alert(self):
        result = self.decision({"score": 90, "verdict": "HIGH", "confidence": "HIGH"}, mode="enforce")
        self.assertEqual(result["recommended_action"], "QUARANTINE")
        self.assertEqual(result["delivery_action"], "QUARANTINE")
        self.assertTrue(should_create_alert(result))

    def test_high_score_with_uncertain_confidence_is_review_not_quarantine(self):
        result = self.decision({"score": 95, "verdict": "HIGH", "confidence": "LOW"}, mode="enforce")
        self.assertEqual(result["recommended_action"], "REVIEW")
        self.assertEqual(result["delivery_action"], "REVIEW")
        self.assertFalse(should_create_alert(result))

    def test_malformed_score_fails_to_review_instead_of_allow(self):
        result = self.decision({"score": "not-a-score", "verdict": "UNKNOWN", "confidence": "UNKNOWN"})
        self.assertEqual(result["recommended_action"], "REVIEW")
        self.assertTrue("invalid" in result["rationale"] or "incomplete" in result["rationale"])

    def test_review_threshold_must_be_below_quarantine_threshold(self):
        with patch.dict(os.environ, {
            "MAILTRACE_REVIEW_THRESHOLD": "90",
            "MAILTRACE_QUARANTINE_THRESHOLD": "85",
        }, clear=False):
            with self.assertRaises(RuntimeError):
                build_mail_flow_decision({})

    def test_gateway_action_receipts_are_hash_chained_and_idempotent(self):
        import database.database as db

        original = db.DATABASE_PATH
        with tempfile.TemporaryDirectory(prefix="mailtrace-gateway-receipt-") as directory:
            db.DATABASE_PATH = pathlib.Path(directory) / "receipts.db"
            try:
                db.initialize_database()
                db.initialize_email_webhook_events()
                db.initialize_email_alerts()
                db.initialize_case_audit()
                delivery = db.begin_email_webhook_event("event-1", "fingerprint")
                decision = {
                    "recommended_action": "QUARANTINE",
                    "enforcement_mode": "ENFORCE",
                }
                self.assertTrue(db.complete_email_webhook_event(
                    "event-1", "INV-1", delivery["lease_token"], decision
                ))
                alert = db.create_email_alert(
                    "event-1", "INV-1", "HIGH", 90, "HIGH", "QUARANTINE", tenant_id="local"
                )

                first = db.record_email_gateway_action(
                    "event-1", "receipt-1", "QUARANTINE", "FAILED", reason_code="TEMP_UNAVAILABLE"
                )
                second = db.record_email_gateway_action(
                    "event-1", "receipt-2", "QUARANTINE", "APPLIED", gateway_message_id="gw-123"
                )
                duplicate = db.record_email_gateway_action(
                    "event-1", "receipt-2", "QUARANTINE", "APPLIED", gateway_message_id="gw-123"
                )
                mismatch = db.record_email_gateway_action(
                    "event-1", "receipt-3", "ALLOW", "APPLIED"
                )
                state = db.get_email_gateway_action_state("event-1")
                listed_alert = db.get_email_alerts()[0]
                case_audit_integrity = db.verify_case_audit_chain("local")
                valid_chain = db.verify_email_gateway_action_chain("event-1")
                connection = db.get_connection()
                try:
                    with self.assertRaises(Exception):
                        connection.execute(
                            "UPDATE email_gateway_action_receipts SET outcome='FAILED' WHERE id=1"
                        )
                    connection.execute("DROP TRIGGER trg_gateway_action_receipts_no_update")
                    connection.execute("UPDATE email_gateway_action_receipts SET event_hash=? WHERE id=1", ("f" * 64,))
                    connection.commit()
                finally:
                    connection.close()
                tampered_chain = db.verify_email_gateway_action_chain("event-1")
            finally:
                db.DATABASE_PATH = original

        self.assertEqual(first["status"], "recorded")
        self.assertEqual(second["status"], "recorded")
        self.assertEqual(first["receipt"]["previous_hash"], "0" * 64)
        self.assertEqual(second["receipt"]["previous_hash"], first["receipt"]["event_hash"])
        self.assertEqual(duplicate["status"], "duplicate")
        self.assertEqual(mismatch["status"], "action_mismatch")
        self.assertEqual(state["status"], "APPLIED")
        self.assertIsNotNone(alert["alert_id"])
        self.assertEqual(listed_alert["gateway_action_status"], "APPLIED")
        self.assertTrue(case_audit_integrity["valid"])
        self.assertTrue(valid_chain["valid"])
        self.assertEqual(valid_chain["verified_count"], 2)
        self.assertFalse(tampered_chain["valid"])
        self.assertEqual(tampered_chain["first_invalid_receipt_id"], 1)

    def test_gateway_receipt_signature_binds_event_and_payload(self):
        from services.email_alerting import verify_gateway_action_signature
        secret = "test-gateway-action-secret-with-32-characters"
        payload = {
            "timestamp": int(time.time()),
            "idempotency_key": "action-api-1",
            "action": "QUARANTINE",
            "outcome": "APPLIED",
            "gateway_message_id": "gateway-message-1",
        }
        signed = {"event_id": "event-api", **payload}
        canonical = json.dumps(signed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        signature = hmac.new(secret.encode(), canonical, hashlib.sha256).hexdigest()
        self.assertTrue(verify_gateway_action_signature("event-api", payload, secret, "sha256=" + signature))
        self.assertFalse(verify_gateway_action_signature("event-api", payload, secret, "0" * 64))
        self.assertFalse(verify_gateway_action_signature("different-event", payload, secret, signature))

    def test_signed_gateway_receipt_route_records_applied_action(self):
        import database.database as db
        import main

        original = db.DATABASE_PATH
        secret = "test-gateway-action-secret-with-32-characters"
        with tempfile.TemporaryDirectory(prefix="mailtrace-gateway-route-") as directory:
            db.DATABASE_PATH = pathlib.Path(directory) / "receipts.db"
            try:
                db.initialize_database()
                db.initialize_email_webhook_events()
                delivery = db.begin_email_webhook_event("route-event", "route-fingerprint")
                decision = {"recommended_action": "QUARANTINE", "enforcement_mode": "ENFORCE"}
                db.complete_email_webhook_event(
                    "route-event", "INV-ROUTE", delivery["lease_token"], decision
                )
                payload_data = {
                    "timestamp": int(time.time()),
                    "idempotency_key": "route-action-1",
                    "action": "QUARANTINE",
                    "outcome": "APPLIED",
                }
                signed = {"event_id": "route-event", **payload_data}
                canonical = json.dumps(signed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
                signature = hmac.new(secret.encode(), canonical, hashlib.sha256).hexdigest()
                request = SimpleNamespace(headers={"X-MailTrace-Signature": "sha256=" + signature})
                payload = main.GatewayActionReceipt(**payload_data)
                with patch.dict(os.environ, {"MAILTRACE_GATEWAY_ACK_SECRET": secret}):
                    result = main.acknowledge_gateway_action("route-event", payload, request)
            finally:
                db.DATABASE_PATH = original

        self.assertTrue(result["success"])
        self.assertFalse(result["duplicate"])
        self.assertEqual(result["gateway_action"]["status"], "APPLIED")


if __name__ == "__main__":
    unittest.main()
