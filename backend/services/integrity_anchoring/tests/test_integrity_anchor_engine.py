from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import tempfile
from dataclasses import replace

from services.integrity_anchoring import (
    IntegrityAnchorEngine,
    IntegrityAnchorError,
    LocalAnchorProvider,
    RFC3161Provider,
)


def _anchor(engine: IntegrityAnchorEngine, provider: str = "local"):
    return engine.create_anchor(
        evidence_id="EV-ANCHOR-1",
        evidence_sha256="a" * 64,
        terminal_event_hash="b" * 64,
        chain_anchor_digest="c" * 64,
        provider=provider,
        metadata={"purpose": "test only"},
    )


def test_anchor_receipt_survives_engine_restart_and_reverifies():
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "integrity-anchors.sqlite3"
        first = IntegrityAnchorEngine(
            providers={"local": LocalAnchorProvider()}, storage_path=path
        )
        receipt = _anchor(first)
        assert first.verify_anchor(receipt.anchor_id).valid

        restarted = IntegrityAnchorEngine(
            providers={"local": LocalAnchorProvider()}, storage_path=path
        )
        loaded = restarted.get_anchor(receipt.anchor_id)
        assert loaded.evidence_id == "EV-ANCHOR-1"
        assert loaded.commitment_sha256 == receipt.commitment_sha256
        assert restarted.verify_anchor(receipt.anchor_id).valid
        assert len(restarted.list_anchors(evidence_id="EV-ANCHOR-1")) == 1


def test_persisted_anchor_create_is_idempotent():
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "integrity-anchors.sqlite3"
        first = IntegrityAnchorEngine(
            providers={"local": LocalAnchorProvider()}, storage_path=path
        )
        first_receipt = _anchor(first)
        restarted = IntegrityAnchorEngine(
            providers={"local": LocalAnchorProvider()}, storage_path=path
        )
        second_receipt = _anchor(restarted)
        assert first_receipt.anchor_id == second_receipt.anchor_id
        assert len(restarted.list_anchors()) == 1


def test_mismatched_provider_receipt_is_rejected_before_persisting():
    class MismatchedEvidenceProvider(LocalAnchorProvider):
        name = "mismatched"

        def create(self, request):
            return replace(super().create(request), provider=self.name, evidence_id="EV-OTHER")

    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "integrity-anchors.sqlite3"
        engine = IntegrityAnchorEngine(
            providers={"mismatched": MismatchedEvidenceProvider()}, storage_path=path
        )
        try:
            _anchor(engine, "mismatched")
        except IntegrityAnchorError:
            pass
        else:
            raise AssertionError("Mismatched evidence receipt was accepted")
        assert engine.list_anchors() == []


def test_local_provider_is_never_reported_as_independent():
    with tempfile.TemporaryDirectory() as folder:
        engine = IntegrityAnchorEngine(
            providers={"local": LocalAnchorProvider()},
            storage_path=Path(folder) / "integrity-anchors.sqlite3",
        )
        state = engine.status()
        assert state["status"] == "LOCAL_TEST_ONLY"
        assert state["independent_anchor_configured"] is False
        assert state["providers"][0]["independent_trust_boundary"] is False
        assert state["storage"] == "SQLITE_DURABLE"


def test_rfc3161_without_real_builder_fails_closed():
    provider = RFC3161Provider(
        tsa_url="https://tsa.example.invalid/timestamp",
        request_transport=lambda raw: b"not-a-real-token",
        token_verifier=lambda token, digest, nonce: (True, datetime.now(timezone.utc).isoformat(), ()),
    )
    assert provider.is_configured is False
    with tempfile.TemporaryDirectory() as folder:
        engine = IntegrityAnchorEngine(
            providers={"rfc3161": provider},
            storage_path=Path(folder) / "integrity-anchors.sqlite3",
        )
        receipt = _anchor(engine, "rfc3161")
        assert receipt.status == "FAILED"
        assert receipt.anchored_at_utc is None
        assert engine.status()["independent_anchor_configured"] is False


def test_rfc3161_transport_receives_builder_der_not_ascii_digest():
    observed = {}
    def builder(request):
        observed["commitment"] = request.commitment_sha256
        return b"DER-TIMESTAMP-REQUEST"
    def transport(payload):
        observed["transport_payload"] = payload
        return b"TIMESTAMP-TOKEN"
    def verifier(token, digest, nonce):
        assert token == b"TIMESTAMP-TOKEN"
        assert digest == observed["commitment"]
        return True, datetime.now(timezone.utc).isoformat(), ()

    provider = RFC3161Provider(
        tsa_url="https://tsa.example.invalid/timestamp",
        request_transport=transport,
        token_verifier=verifier,
        request_builder=builder,
    )
    with tempfile.TemporaryDirectory() as folder:
        engine = IntegrityAnchorEngine(
            providers={"rfc3161": provider},
            storage_path=Path(folder) / "integrity-anchors.sqlite3",
        )
        receipt = _anchor(engine, "rfc3161")
        assert receipt.proof == b"TIMESTAMP-TOKEN"
        assert observed["transport_payload"] == b"DER-TIMESTAMP-REQUEST"
        verification = engine.verify_anchor(receipt.anchor_id)
        assert verification.valid
        assert verification.trust_level == "TSA_VERIFIED"
        persisted_receipt = engine.get_anchor(receipt.anchor_id)
        assert persisted_receipt.anchored_at_utc is not None
        assert persisted_receipt.verification_state == "VERIFIED"


if __name__ == "__main__":
    tests = [
        test_anchor_receipt_survives_engine_restart_and_reverifies,
        test_persisted_anchor_create_is_idempotent,
        test_local_provider_is_never_reported_as_independent,
        test_mismatched_provider_receipt_is_rejected_before_persisting,
        test_rfc3161_without_real_builder_fails_closed,
        test_rfc3161_transport_receives_builder_der_not_ascii_digest,
    ]
    failures = []
    for test in tests:
        try:
            test()
            print(f"PASS {test.__name__}")
        except Exception as exc:
            failures.append((test.__name__, type(exc).__name__, str(exc)))
            print(f"FAIL {test.__name__}: {type(exc).__name__}: {exc}")
    print(f"ANCHOR_TESTS={len(tests)}")
    print(f"ANCHOR_FAILS={len(failures)}")
    if failures:
        raise SystemExit(1)
    print("ANCHOR_TESTS=PASS")
