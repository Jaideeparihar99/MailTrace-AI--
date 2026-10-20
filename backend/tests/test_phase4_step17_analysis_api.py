from __future__ import annotations

import asyncio
import json
from pathlib import Path
import socket
from urllib import request

import database.database as database
import pytest

main = None


FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "phase4_step16"
MANIFEST_PATH = FIXTURE_DIR / "manifest.json"


def _forensics_without_external_checks(*_args, **_kwargs):
    return {
        "ip_intelligence": {"candidates": []},
        "authentication_analysis": {
            "reported_results": {},
            "authentication_results_trusted": False,
            "validation": {
                "spf": {"status": "UNVERIFIED_NO_TRUSTED_SMTP_IP"},
                "dkim": {"status": "NOT_PRESENT"},
                "dmarc": {"status": "NOT_VALIDATED"},
                "reported_headers_trusted": False,
            },
        },
        "url_analysis": {"urls": []},
        "findings": [],
    }


def _local_integrity_receipt(**_kwargs):
    return {
        "integrity_anchor": {
            "created": True,
            "verified": True,
            "independent_verification": False,
            "provider_status": {"status": "LOCAL_TEST_ONLY"},
            "receipt": {"provider": "local", "trust_level": "LOCAL_TEST_ONLY"},
        },
        "retention": None,
    }


async def _asgi_request(method: str, path: str, *, body: bytes = b"", headers=()):
    sent = []
    receive_count = 0

    async def receive():
        nonlocal receive_count
        receive_count += 1
        if receive_count == 1:
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "root_path": "",
        "headers": list(headers) + [(b"host", b"mailtrace.test")],
        "client": ("127.0.0.1", 54341),
        "server": ("127.0.0.1", 80),
    }
    await main.app(scope, receive, send)
    start = next(message for message in sent if message["type"] == "http.response.start")
    response_body = b"".join(
        message.get("body", b"") for message in sent if message["type"] == "http.response.body"
    )
    return start["status"], response_body


def _multipart_email(filename: str, content: bytes) -> tuple[bytes, list[tuple[bytes, bytes]]]:
    boundary = b"----MailTraceStep17FixtureBoundary"
    body = (
        b"--" + boundary + b"\r\n"
        + b'Content-Disposition: form-data; name="file"; filename="' + filename.encode("ascii") + b'"\r\n'
        + b"Content-Type: message/rfc822\r\n\r\n"
        + content + b"\r\n--" + boundary + b"--\r\n"
    )
    content_type = b"multipart/form-data; boundary=" + boundary
    return body, [(b"content-type", content_type), (b"content-length", str(len(body)).encode("ascii"))]


def test_fixture_analysis_api_keeps_expected_risk_and_indicator_behavior(tmp_path, monkeypatch):
    global main

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "step17-analysis-api.db")
    import importlib

    main = importlib.import_module("main")
    monkeypatch.setattr(main, "analyze_email_forensics", _forensics_without_external_checks)
    monkeypatch.setattr(
        main,
        "analyze_email_ai",
        lambda **_kwargs: {
            "status": "MODEL_NOT_READY",
            "classification": "UNKNOWN",
            "model_probability": None,
            "calibrated_probability": None,
        },
    )
    monkeypatch.setattr(main, "get_threat_intelligence_source_status", lambda: {
        "coverage_status": "FRESH", "providers": {},
    })
    monkeypatch.setattr(main, "lookup_threat_intelligence_batch", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(main, "_build_evidence_governance", _local_integrity_receipt)
    database.initialize_database()

    def block_network(*_args, **_kwargs):
        raise AssertionError("offline API fixture test attempted network access")

    monkeypatch.setattr(socket, "getaddrinfo", block_network)
    monkeypatch.setattr(socket, "create_connection", block_network)
    monkeypatch.setattr(request, "urlopen", block_network)

    expected_minimum_scores = {
        "MT-F16-0001": 0,
        "MT-F16-0002": 0,
        "MT-F16-0003": 55,
        "MT-F16-0004": 65,
        "MT-F16-0005": 65,
        "MT-F16-0006": 0,
        "MT-F16-0007": 0,
        "MT-F16-0008": 0,
    }
    async def exercise_fixtures():
        for fixture in manifest["fixtures"]:
            sample = (FIXTURE_DIR / fixture["file"]).read_bytes()
            request_body, request_headers = _multipart_email(fixture["file"], sample)
            status_code, response_body = await _asgi_request(
                "POST", "/api/analyze-email", body=request_body, headers=request_headers,
            )
            response_text = response_body.decode("utf-8", errors="replace")
            assert status_code == 200, f"{fixture['id']}: {response_text}"
            payload = json.loads(response_text)
            assert payload.get("success") is True, fixture["id"]
            analysis = payload["analysis"]
            threat = analysis["threat_analysis"]
            score = threat["score"]
            assert isinstance(score, (int, float)), fixture["id"]
            assert 0 <= score <= 100, fixture["id"]
            assert score >= expected_minimum_scores[fixture["id"]], fixture["id"]
            assert threat.get("verdict") and threat.get("confidence") is not None, fixture["id"]
            if fixture["id"] == "MT-F16-0006":
                assert threat["verdict"] == "REVIEW REQUIRED (SUSPICIOUS IDENTITY MISMATCH)"
                assert threat["review_required"] is True
                assert threat["review_reasons"][0] in {"FROM_REPLY_TO_ORGANIZATIONAL_DOMAIN_MISMATCH", "FROM_REPLY_TO_DOMAIN_ALIGNMENT_UNVERIFIED"}
                assert any(item.get("title") == "From/Reply-To domain alignment concern" for item in threat["indicators"])
            if fixture["id"] in {"MT-F16-0003", "MT-F16-0004", "MT-F16-0005"}:
                # Model is intentionally unavailable in this offline gate; risk does not imply confidence.
                assert threat["confidence"] in {"LOW", "UNKNOWN"}
                assert threat.get("confidence_basis") in {"intelligence_fusion", "unavailable"}
            assert analysis["email_ai"]["status"] == "MODEL_NOT_READY", fixture["id"]
            assert analysis["url_summary"]["unique_count"] == len(analysis["urls"]), fixture["id"]
            assert analysis["url_summary"]["ioc_unique_count"] == analysis["threat_intelligence"]["ioc_summary"]["url"], fixture["id"]
            assert analysis["url_summary"]["counts_consistent"] is True, fixture["id"]
            live_enrichment = analysis["threat_intelligence"].get("live_provider_enrichment")
            assert live_enrichment is not None, "production email-analysis path must attach live provider status"
            assert live_enrichment["mode"] == "live_provider_enrichment"
            if live_enrichment["status"] == "not_configured":
                assert live_enrichment["evidence_ledger"] == []
            assert analysis["result_statuses"]["model_inference"]["status"] == "NOT_RUN", fixture["id"]

            if fixture["id"] == "MT-F16-0002":
                assert score <= 15, "benign compliance disclaimer must not become credential theft"
                assert "credential_harvesting_language" not in {
                    item["name"] for item in analysis["intelligence_fusion"]["evidence"]
                }
            if fixture["id"] in {"MT-F16-0003", "MT-F16-0004", "MT-F16-0005"}:
                assert score >= 55, f"labeled malicious fixture was not detected: {fixture['id']}"
            if fixture["id"] == "MT-F16-0008":
                auth = analysis["authentication"]
                assert auth["authentication_results_trusted"] is False
                assert auth["reported_results"] == {"spf": "PASS", "dkim": "PASS", "dmarc": "PASS"}
            if fixture["id"] == "MT-F16-0007":
                assert analysis["parsing"]["status"] == "PARTIAL"
                assert threat["verdict"] == "REVIEW REQUIRED (PARTIAL EMAIL PARSE)"
                assert threat["review_required"] is True
                assert "PARTIAL_EMAIL_PARSE" in threat["review_reasons"]

            detail_status, detail_body = await _asgi_request(
                "GET", f"/api/investigations/{payload['investigation_id']}",
            )
            assert detail_status == 200, fixture["id"]
            stored = json.loads(detail_body.decode("utf-8"))["investigation"]["analysis"]
            assert stored == analysis, f"persisted analysis diverged for {fixture['id']}"

    asyncio.run(exercise_fixtures())


@pytest.mark.parametrize("model_probability", [0.6341296965, 0.95])
def test_model_only_phishing_prediction_requires_analyst_review(tmp_path, monkeypatch, model_probability):
    """Uncorroborated model-only threat output is explicitly routed for review."""
    global main
    import importlib

    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "step20-model-only-api.db")
    main = importlib.import_module("main")
    monkeypatch.setattr(main, "analyze_email_forensics", _forensics_without_external_checks)
    monkeypatch.setattr(main, "analyze_email_ai", lambda **_kwargs: {
        "status": "MODEL_READY", "model_ready": True, "classification": "PHISHING",
        "model_probability": model_probability, "calibrated_probability": model_probability,
    })
    monkeypatch.setattr(main, "get_threat_intelligence_source_status", lambda: {
        "coverage_status": "FRESH", "providers": {},
    })
    monkeypatch.setattr(main, "lookup_threat_intelligence_batch", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(main, "_build_evidence_governance", _local_integrity_receipt)
    database.initialize_database()

    def block_network(*_args, **_kwargs):
        raise AssertionError("model-only false-positive API test attempted network access")

    monkeypatch.setattr(socket, "getaddrinfo", block_network)
    monkeypatch.setattr(socket, "create_connection", block_network)
    monkeypatch.setattr(request, "urlopen", block_network)

    async def analyze_fixture():
        fixture = next(item for item in json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))["fixtures"]
                       if item["id"] == "MT-F16-0002")
        sample = (FIXTURE_DIR / fixture["file"]).read_bytes()
        request_body, request_headers = _multipart_email(fixture["file"], sample)
        status_code, response_body = await _asgi_request(
            "POST", "/api/analyze-email", body=request_body, headers=request_headers,
        )
        assert status_code == 200, response_body.decode("utf-8", errors="replace")
        payload = json.loads(response_body)
        threat = payload["analysis"]["threat_analysis"]
        assert threat["verdict"] == "REVIEW REQUIRED (UNCONFIRMED MODEL SIGNAL)"
        assert threat["review_required"] is True
        assert "MODEL_THREAT_PREDICTION_UNCORROBORATED" in threat["review_reasons"]
        if model_probability < 0.70:
            assert threat["score"] < 50
        assert payload["analysis"]["email_ai"]["classification"] == "PHISHING"
        fusion = payload["analysis"]["intelligence_fusion"]
        assert fusion["fusion_metrics"]["independent_category_count"] == 0
        assert fusion["evidence"] and all(item["category"] == "ml" for item in fusion["evidence"])

    asyncio.run(analyze_fixture())
