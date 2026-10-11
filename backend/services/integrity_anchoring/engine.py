from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
from pathlib import Path
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from .canonical import (
    canonical_commitment_payload,
    commitment_sha256,
)
from .models import (
    AnchorExport,
    AnchorReceipt,
    AnchorRequest,
    AnchorVerification,
)
from .providers import AnchorProvider
from .rules import (
    ANALYSIS_NAME,
    ANALYSIS_VERSION,
    MAX_EVIDENCE_ID_CHARS,
    MAX_METADATA_ITEMS,
    MAX_PROVIDER_NAME_CHARS,
    SUPPORTED_COMMITMENT_ALGORITHM,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_json(value: Any) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class IntegrityAnchorError(Exception):
    pass


class IntegrityAnchorEngine:
    """
    Independent integrity-anchoring orchestration layer.

    The engine receives an already-established custody commitment.
    It does not calculate or replace Evidence Custody's own chain.
    """

    def __init__(
        self,
        *,
        providers: dict[str, AnchorProvider] | None = None,
        storage_path: str | Path | None = None,
    ) -> None:
        self._providers = dict(providers or {})
        self._requests: dict[str, AnchorRequest] = {}
        self._receipts: dict[str, AnchorReceipt] = {}
        self.storage_path = Path(storage_path) if storage_path is not None else None
        self._guard = threading.RLock()
        if self.storage_path is not None:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            self._initialize_storage()
            self._refresh_from_storage()

    def _connect(self) -> sqlite3.Connection:
        if self.storage_path is None:
            raise IntegrityAnchorError("Durable anchor storage is not configured.")
        connection = sqlite3.connect(str(self.storage_path), timeout=15)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=15000")
        return connection

    def _initialize_storage(self) -> None:
        connection = None
        try:
            connection = self._connect()
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS integrity_anchors (
                    anchor_id TEXT PRIMARY KEY,
                    evidence_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    commitment_sha256 TEXT NOT NULL,
                    requested_at_utc TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    UNIQUE (evidence_id, provider, commitment_sha256)
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_integrity_anchors_evidence "
                "ON integrity_anchors(evidence_id, requested_at_utc)"
            )
            connection.commit()
        except sqlite3.DatabaseError as exc:
            raise IntegrityAnchorError(
                "Persisted integrity-anchor ledger could not be initialized."
            ) from exc
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _request_json(request: AnchorRequest) -> str:
        return json.dumps(asdict(request), sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    @staticmethod
    def _receipt_json(receipt: AnchorReceipt) -> str:
        payload = asdict(receipt)
        payload["proof"] = receipt.proof.hex() if receipt.proof is not None else None
        payload["verification_issues"] = list(receipt.verification_issues)
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    @staticmethod
    def _request_from_json(raw: str) -> AnchorRequest:
        payload = json.loads(raw)
        return AnchorRequest(**payload)

    @staticmethod
    def _receipt_from_json(raw: str) -> AnchorReceipt:
        payload = json.loads(raw)
        proof = payload.get("proof")
        payload["proof"] = bytes.fromhex(proof) if proof is not None else None
        payload["verification_issues"] = tuple(payload.get("verification_issues") or ())
        return AnchorReceipt(**payload)

    def _refresh_from_storage(self, connection: sqlite3.Connection | None = None) -> None:
        if self.storage_path is None:
            return
        owns_connection = connection is None
        active = connection or self._connect()
        try:
            rows = active.execute(
                "SELECT anchor_id, request_json, receipt_json FROM integrity_anchors"
            ).fetchall()
            requests: dict[str, AnchorRequest] = {}
            receipts: dict[str, AnchorReceipt] = {}
            for row in rows:
                anchor_id = str(row["anchor_id"])
                request = self._request_from_json(row["request_json"])
                receipt = self._receipt_from_json(row["receipt_json"])
                if request.anchor_id != anchor_id or receipt.anchor_id != anchor_id:
                    raise ValueError("Persisted anchor identifiers do not match the row key.")
                requests[anchor_id] = request
                receipts[anchor_id] = receipt
            self._requests = requests
            self._receipts = receipts
        except (sqlite3.DatabaseError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            raise IntegrityAnchorError(
                "Persisted integrity-anchor records are corrupt or unreadable."
            ) from exc
        finally:
            if owns_connection:
                active.close()

    def status(self) -> dict[str, Any]:
        """Report configured trust boundaries without conflating local proofs with independent anchors."""
        provider_rows = []
        for name, provider in sorted(self._providers.items()):
            trust_level = str(getattr(provider, "trust_level", "UNKNOWN"))
            independent = bool(getattr(provider, "independent_trust_boundary", trust_level != "LOCAL_TEST_ONLY"))
            configured = bool(getattr(provider, "is_configured", True))
            provider_rows.append({
                "name": name,
                "trust_level": trust_level,
                "configured": configured,
                "independent_trust_boundary": independent,
                "ready_for_independent_anchor": independent and configured,
            })
        external_ready = any(item["ready_for_independent_anchor"] for item in provider_rows)
        local_available = any(item["name"] == "local" for item in provider_rows)
        return {
            "status": "EXTERNAL_READY" if external_ready else ("LOCAL_TEST_ONLY" if local_available else "NOT_CONFIGURED"),
            "independent_anchor_configured": external_ready,
            "providers": provider_rows,
            "storage": "SQLITE_DURABLE" if self.storage_path is not None else "MEMORY_ONLY",
            "blockchain_ledger": "NOT_CONFIGURED",
        }

    # ---------------------------------------------------------
    # Provider management
    # ---------------------------------------------------------
    def register_provider(
        self,
        provider: AnchorProvider,
    ) -> None:
        if not isinstance(provider, AnchorProvider):
            raise TypeError(
                "provider must implement AnchorProvider."
            )

        if not provider.name:
            raise ValueError("Provider name is required.")

        if len(provider.name) > MAX_PROVIDER_NAME_CHARS:
            raise ValueError("Provider name is too long.")

        self._providers[provider.name] = provider

    def get_provider(
        self,
        provider_name: str,
    ) -> AnchorProvider:
        try:
            return self._providers[provider_name]
        except KeyError as exc:
            raise IntegrityAnchorError(
                f"Unknown anchor provider: {provider_name}"
            ) from exc

    # ---------------------------------------------------------
    # Anchor creation
    # ---------------------------------------------------------
    def create_anchor(
        self,
        *,
        evidence_id: str,
        evidence_sha256: str,
        terminal_event_hash: str,
        chain_anchor_digest: str,
        provider: str,
        manifest_sha256: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AnchorReceipt:
        if not evidence_id:
            raise ValueError("Evidence ID is required.")
        if len(evidence_id) > MAX_EVIDENCE_ID_CHARS:
            raise ValueError("Evidence ID is too long.")
        metadata = dict(metadata or {})
        if len(metadata) > MAX_METADATA_ITEMS:
            raise ValueError("Too many anchor metadata items.")

        commitment_payload = canonical_commitment_payload(
            evidence_id=evidence_id,
            evidence_sha256=evidence_sha256,
            terminal_event_hash=terminal_event_hash,
            chain_anchor_digest=chain_anchor_digest,
            manifest_sha256=manifest_sha256,
        )
        commitment = commitment_sha256(commitment_payload)
        anchor_provider = self.get_provider(provider)

        with self._guard:
            connection = self._connect() if self.storage_path is not None else None
            try:
                if connection is not None:
                    connection.execute("BEGIN IMMEDIATE")
                    self._refresh_from_storage(connection)
                for existing in self._receipts.values():
                    if (
                        existing.evidence_id == evidence_id
                        and existing.provider == provider
                        and existing.commitment_sha256 == commitment
                    ):
                        if connection is not None:
                            connection.commit()
                        return existing

                anchor_id = (
                    "anc_"
                    + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
                    + "_"
                    + secrets.token_hex(8)
                )
                request = AnchorRequest(
                    anchor_id=anchor_id,
                    evidence_id=evidence_id,
                    commitment_algorithm=SUPPORTED_COMMITMENT_ALGORITHM,
                    commitment_sha256=commitment,
                    commitment_payload=commitment_payload,
                    requested_at_utc=_utc_now(),
                    provider=provider,
                    nonce=secrets.token_hex(16),
                    metadata=metadata,
                )
                receipt = anchor_provider.create(request)
                if (
                    receipt.anchor_id != anchor_id
                    or receipt.evidence_id != evidence_id
                    or receipt.provider != provider
                    or receipt.commitment_algorithm != SUPPORTED_COMMITMENT_ALGORITHM
                    or receipt.commitment_sha256 != commitment
                ):
                    raise IntegrityAnchorError(
                        "Anchor provider returned a receipt that does not match the requested evidence commitment."
                    )
                if connection is not None:
                    connection.execute(
                        """INSERT INTO integrity_anchors
                        (anchor_id, evidence_id, provider, commitment_sha256, requested_at_utc, request_json, receipt_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (
                            anchor_id, evidence_id, provider, commitment, request.requested_at_utc,
                            self._request_json(request), self._receipt_json(receipt),
                        ),
                    )
                    connection.commit()
                self._requests[anchor_id] = request
                self._receipts[anchor_id] = receipt
                return receipt
            except Exception:
                if connection is not None:
                    connection.rollback()
                raise
            finally:
                if connection is not None:
                    connection.close()

    # ---------------------------------------------------------
    # Verification
    # ---------------------------------------------------------
    def verify_anchor(
        self,
        anchor_id: str,
    ) -> AnchorVerification:
        with self._guard:
            connection = self._connect() if self.storage_path is not None else None
            try:
                if connection is not None:
                    connection.execute("BEGIN IMMEDIATE")
                    self._refresh_from_storage(connection)
                if anchor_id not in self._requests:
                    raise IntegrityAnchorError(f"Unknown anchor: {anchor_id}")
                request = self._requests[anchor_id]
                receipt = self._receipts[anchor_id]
                provider = self.get_provider(request.provider)
                result = provider.verify(request, receipt)
                updated = AnchorReceipt(
                    **{
                        **asdict(receipt),
                        "status": "VERIFIED" if result.valid else receipt.status,
                        "anchored_at_utc": result.anchored_at_utc or receipt.anchored_at_utc,
                        "trust_level": result.trust_level,
                        "verification_state": "VERIFIED" if result.valid else "FAILED",
                        "verification_issues": result.issues,
                    }
                )
                self._receipts[anchor_id] = updated
                if connection is not None:
                    cursor = connection.execute(
                        "UPDATE integrity_anchors SET receipt_json=? WHERE anchor_id=?",
                        (self._receipt_json(updated), anchor_id),
                    )
                    if cursor.rowcount != 1:
                        raise IntegrityAnchorError("Anchor disappeared while verification was being stored.")
                    connection.commit()
                return result
            except Exception:
                if connection is not None:
                    connection.rollback()
                raise
            finally:
                if connection is not None:
                    connection.close()

    # ---------------------------------------------------------
    # Lookup
    # ---------------------------------------------------------
    def get_anchor(
        self,
        anchor_id: str,
    ) -> AnchorReceipt:
        with self._guard:
            self._refresh_from_storage()
        try:
            return self._receipts[anchor_id]
        except KeyError as exc:
            raise IntegrityAnchorError(
                f"Unknown anchor: {anchor_id}"
            ) from exc

    def list_anchors(
        self,
        *,
        evidence_id: str | None = None,
    ) -> list[AnchorReceipt]:
        with self._guard:
            self._refresh_from_storage()
        values = list(
            self._receipts.values()
        )

        if evidence_id is None:
            return values

        return [
            item
            for item in values
            if item.evidence_id == evidence_id
        ]

    # ---------------------------------------------------------
    # Proof export
    # ---------------------------------------------------------
    def export_anchor_proof(
        self,
        anchor_id: str,
    ) -> AnchorExport:
        with self._guard:
            self._refresh_from_storage()
        if anchor_id not in self._requests:
            raise IntegrityAnchorError(
                f"Unknown anchor: {anchor_id}"
            )

        request = self._requests[anchor_id]

        verification = self.verify_anchor(
            anchor_id
        )

        # verify_anchor() may replace the stored receipt with the
        # cryptographically-derived verification state. Always
        # re-read the canonical stored receipt after verification
        # so exported receipt state cannot become stale.
        receipt = self._receipts[anchor_id]

        request_dict = asdict(request)
        receipt_dict = asdict(receipt)
        verification_dict = asdict(verification)

        canonical = json.dumps(
            {
                "request": request_dict,
                "receipt": {
                    **receipt_dict,
                    "proof": (
                        receipt_dict["proof"].hex()
                        if isinstance(
                            receipt_dict["proof"],
                            bytes,
                        )
                        else receipt_dict["proof"]
                    ),
                },
                "verification": verification_dict,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")

        return AnchorExport(
            analysis={
                "name": ANALYSIS_NAME,
                "version": ANALYSIS_VERSION,
                "static_only": True,
            },
            request=request_dict,
            receipt={
                **receipt_dict,
                "proof": (
                    receipt_dict["proof"].hex()
                    if isinstance(
                        receipt_dict["proof"],
                        bytes,
                    )
                    else receipt_dict["proof"]
                ),
            },
            verification=verification_dict,
            export_integrity={
                "sha256": hashlib.sha256(
                    canonical
                ).hexdigest(),
                "sha512": hashlib.sha512(
                    canonical
                ).hexdigest(),
            },
        )
