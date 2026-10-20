"""Offline, reproducible Step 18 evaluation over the Phase 4 Step 16 fixtures."""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
from pathlib import Path
import socket
import sys
import tempfile
from urllib import request

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parent
FIXTURE_DIR = BACKEND / "tests" / "fixtures" / "phase4_step16"
sys.path.insert(0, str(BACKEND))

import database.database as database  # noqa: E402


def _forensics_without_external_checks(*_args, **_kwargs):
    return {
        "ip_intelligence": {"candidates": []},
        "authentication_analysis": {
            "reported_results": {}, "authentication_results_trusted": False,
            "validation": {"spf": {"status": "UNVERIFIED_NO_TRUSTED_SMTP_IP"},
                           "dkim": {"status": "NOT_PRESENT"},
                           "dmarc": {"status": "NOT_VALIDATED"},
                           "reported_headers_trusted": False},
        },
        "url_analysis": {"urls": []}, "findings": [],
    }


def _local_integrity_receipt(**_kwargs):
    return {"integrity_anchor": {"created": True, "verified": True,
            "independent_verification": False,
            "provider_status": {"status": "LOCAL_TEST_ONLY"},
            "receipt": {"provider": "local", "trust_level": "LOCAL_TEST_ONLY"}},
            "retention": None}


async def _asgi_request(app, method: str, path: str, *, body: bytes = b"", headers=()):
    sent = []
    received = False

    async def receive():
        nonlocal received
        if not received:
            received = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
             "http_version": "1.1", "method": method, "scheme": "http", "path": path,
             "raw_path": path.encode("ascii"), "query_string": b"", "root_path": "",
             "headers": list(headers) + [(b"host", b"mailtrace.test")],
             "client": ("127.0.0.1", 54341), "server": ("127.0.0.1", 80)}
    await app(scope, receive, send)
    start = next(item for item in sent if item["type"] == "http.response.start")
    response_body = b"".join(item.get("body", b"") for item in sent
                              if item["type"] == "http.response.body")
    return start["status"], response_body


def _multipart_email(filename: str, content: bytes):
    boundary = b"----MailTraceStep18FixtureBoundary"
    body = (b"--" + boundary + b"\r\n" +
            b'Content-Disposition: form-data; name="file"; filename="' + filename.encode("ascii") +
            b'"\r\nContent-Type: message/rfc822\r\n\r\n' + content +
            b"\r\n--" + boundary + b"--\r\n")
    return body, [(b"content-type", b"multipart/form-data; boundary=" + boundary),
                  (b"content-length", str(len(body)).encode("ascii"))]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--model-enabled", action="store_true",
        help="Run a separate diagnostic through the real local model; does not alter the default offline gate.",
    )
    parser.add_argument("--trace-fixture", default=None, help="Include detailed evidence ledger for one fixture ID.")
    args = parser.parse_args()
    model_enabled = bool(args.model_enabled)
    logging.disable(logging.INFO)
    manifest = json.loads((FIXTURE_DIR / "manifest.json").read_text(encoding="utf-8"))
    eligible = [item for item in manifest["fixtures"]
                if item.get("qa_review_status") == "PASS" and item.get("expected_parser")]
    if not eligible:
        raise SystemExit("No QA-reviewed fixtures with expected outcomes in manifest")

    with tempfile.TemporaryDirectory(prefix="mailtrace-step18-") as temp_dir:
        database.DATABASE_PATH = Path(temp_dir) / "evaluation.db"
        import main as api
        from unittest.mock import patch
        active_fixture = {"id": None}
        fusion_trace = {}
        original_fusion = api.analyze_email_intelligence
        def trace_fusion(*args, **kwargs):
            result = original_fusion(*args, **kwargs)
            if active_fixture["id"]:
                fusion_trace[active_fixture["id"]] = result
            return result
        api.analyze_email_intelligence = trace_fusion
        runtime_model_status = "NOT_CHECKED_FOR_STUBBED_OFFLINE_GATE"
        if model_enabled:
            from services.email_ai.inference import predict_email

            # Only the opt-in diagnostic requires the local model artifact.
            runtime_model_probe = predict_email({
                "subject": "Routine account notification",
                "body": "This is a harmless local model readiness probe.",
            })
            runtime_model_status = runtime_model_probe.get("status", "UNKNOWN")
            if runtime_model_status != "MODEL_READY":
                raise SystemExit(
                    "Model-enabled diagnostic requires a loadable local model; "
                    f"probe status={runtime_model_status}"
                )

        api.analyze_email_forensics = _forensics_without_external_checks
        if not model_enabled:
            api.analyze_email_ai = lambda **_kwargs: {
                "status": "MODEL_NOT_READY", "classification": "UNKNOWN",
                "model_probability": None, "calibrated_probability": None}
        api.get_threat_intelligence_source_status = lambda: {"coverage_status": "FRESH", "providers": {}}
        api.lookup_threat_intelligence_batch = lambda *_args, **_kwargs: {}
        api._build_evidence_governance = _local_integrity_receipt
        database.initialize_database()

        def block_network(*_args, **_kwargs):
            raise AssertionError("Offline evaluation attempted network access")

        rows = []

        async def run_all():
            for fixture in eligible:
                active_fixture["id"] = fixture["id"]
                raw = (FIXTURE_DIR / fixture["file"]).read_bytes()
                body, headers = _multipart_email(fixture["file"], raw)
                code, response = await _asgi_request(api.app, "POST", "/api/analyze-email",
                                                    body=body, headers=headers)
                if code != 200:
                    raise RuntimeError(f"{fixture['id']} API status {code}: {response[:300]!r}")
                payload = json.loads(response)
                analysis = payload["analysis"]
                threat = analysis["threat_analysis"]
                row = {"id": fixture["id"], "label": fixture["label"],
                       "verdict": threat.get("verdict"), "score": threat.get("score"),
                       "confidence": threat.get("confidence"),
                       "review_required": bool(threat.get("review_required", False)),
                       "review_reasons": threat.get("review_reasons", []),
                       "analysis_status": analysis.get("analysis_status", "COMPLETE"),
                       "parser_status": analysis.get("parsing", {}).get("status")}
                if model_enabled:
                    ai = analysis.get("email_ai", {})
                    row.update({
                        "model_status": ai.get("status"),
                        "model_classification": ai.get("classification"),
                        "model_probability": ai.get("model_probability"),
                        "positive_class": ai.get("positive_class", "PHISHING"),
                        "threshold": ai.get("threshold", 0.5),
                    })
                if args.trace_fixture == fixture["id"]:
                    row["trace"] = {
                        "risk_drivers": threat.get("risk_drivers"),
                        "score_breakdown": threat.get("score_breakdown"),
                        "score_ledger": threat.get("score_ledger"),
                        "fusion_metrics": threat.get("fusion_metrics"),
                        "evidence": threat.get("evidence"),
                        "fusion_groups": threat.get("fusion_group_details"),
                        "contradiction_analysis": threat.get("contradiction_analysis"),
                        "fusion_trace": fusion_trace.get(fixture["id"]),
                    }
                rows.append(row)

        with patch.object(socket, "getaddrinfo", block_network), \
             patch.object(socket, "create_connection", block_network), \
             patch.object(request, "urlopen", block_network):
            asyncio.run(run_all())

    output = {"corpus_id": manifest.get("corpus_id"), "fixture_count": len(rows),
              "application_version": api.app.version,
              "model_status": (
                  runtime_model_status if model_enabled
                  else "MODEL_NOT_REQUIRED_FOR_STUBBED_OFFLINE_GATE"
              ),
              "offline_evaluation_ai_mode": (
                  "REAL_LOCAL_MODEL_DIAGNOSTIC" if model_enabled else "STUBBED_MODEL_NOT_READY"
              ),
              "fusion_engine_version": api.FUSION_ENGINE_VERSION,
              "policy_version": "soc-fusion-policy-3.0",
              "post_fusion_disposition_policy_version": "phase4-review-routing-1.1",
              "network": "blocked", "results": rows}
    if model_enabled:
        positives = {"phishing", "credential_harvesting", "bec_payment_change"}
        negatives = {"benign_legitimate"}
        tp = fp = tn = fn = 0
        scored = 0
        for row in rows:
            label = row["label"]
            if label not in positives | negatives or row.get("model_status") != "MODEL_READY":
                continue
            scored += 1
            predicted_positive = (
                str(row.get("model_classification", "")).upper()
                == str(row.get("positive_class", "PHISHING")).upper()
            )
            actual_positive = label in positives
            if actual_positive and predicted_positive:
                tp += 1
            elif not actual_positive and predicted_positive:
                fp += 1
            elif not actual_positive and not predicted_positive:
                tn += 1
            else:
                fn += 1
        output["diagnostic_metrics"] = {
            "scope": "tiny synthetic corpus; labels not independently adjudicated",
            "binary_scored_samples": scored,
            "excluded_samples": len(rows) - scored,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": (tp / (tp + fp)) if tp + fp else None,
            "recall": (tp / (tp + fn)) if tp + fn else None,
            "false_positive_rate": (fp / (fp + tn)) if fp + tn else None,
            "not_a_production_accuracy_claim": True,
        }
    if args.trace_fixture and not any(row["id"] == args.trace_fixture for row in rows):
        raise SystemExit(f"Trace fixture not found in scored corpus: {args.trace_fixture}")
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
