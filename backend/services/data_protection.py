"""Authenticated encryption helpers for sensitive MailTrace data.

Production keys belong in a secret manager. A key ring permits staged rotation:
keep the old key available while records are re-encrypted under the active key.
"""

from __future__ import annotations

import base64
import json
import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


_TEXT_V1_PREFIX = "enc:v1:"
_TEXT_V2_PREFIX = "enc:v2:"
_EVIDENCE_V1_PREFIX = b"MAILTRACE-EVIDENCE-ENC-V1\0"
_EVIDENCE_V2_PREFIX = b"MAILTRACE-EVIDENCE-ENC-V2:"
_EVIDENCE_FILENAME_FIELD = "evidence_original_filename"
_SENSITIVE_INVESTIGATION_FIELDS = (
    "filename", "subject", "sender", "recipient", "smtp_recipient", "analysis_json",
)


def is_production() -> bool:
    return os.getenv("MAILTRACE_ENV", "development").strip().lower() in {"prod", "production"}


def _decode_key(encoded: str, label: str) -> bytes:
    try:
        value = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise RuntimeError(f"Encryption key '{label}' must be valid standard base64.") from exc
    if len(value) != 32:
        raise RuntimeError(f"Encryption key '{label}' must decode to exactly 32 bytes.")
    return value


def _keyring(*, required: bool = False) -> tuple[dict[str, bytes], str] | None:
    keys: dict[str, bytes] = {}
    legacy = os.getenv("MAILTRACE_DATA_ENCRYPTION_KEY", "").strip()
    if legacy:
        keys["legacy"] = _decode_key(legacy, "legacy")

    raw_ring = os.getenv("MAILTRACE_DATA_ENCRYPTION_KEYS_JSON", "").strip()
    if raw_ring:
        try:
            parsed = json.loads(raw_ring)
        except json.JSONDecodeError as exc:
            raise RuntimeError("MAILTRACE_DATA_ENCRYPTION_KEYS_JSON must be a JSON object.") from exc
        if not isinstance(parsed, dict) or not parsed:
            raise RuntimeError("MAILTRACE_DATA_ENCRYPTION_KEYS_JSON must contain key IDs and keys.")
        for key_id, encoded in parsed.items():
            key_id = str(key_id).strip()
            if not key_id or len(key_id) > 64 or not key_id.replace("-", "").replace("_", "").isalnum():
                raise RuntimeError("Encryption key IDs may contain only letters, digits, '_' and '-'.")
            if not isinstance(encoded, str):
                raise RuntimeError(f"Encryption key '{key_id}' must be a base64 string.")
            keys[key_id] = _decode_key(encoded, key_id)

    if not keys:
        if required or is_production():
            raise RuntimeError(
                "MAILTRACE_DATA_ENCRYPTION_KEY or MAILTRACE_DATA_ENCRYPTION_KEYS_JSON is required in production."
            )
        return None

    active_id = os.getenv("MAILTRACE_DATA_ENCRYPTION_KEY_ID", "").strip()
    if not active_id:
        if len(keys) != 1:
            raise RuntimeError("Set MAILTRACE_DATA_ENCRYPTION_KEY_ID when using an encryption key ring.")
        active_id = next(iter(keys))
    if active_id not in keys:
        raise RuntimeError("MAILTRACE_DATA_ENCRYPTION_KEY_ID must name a key in the configured key ring.")
    return keys, active_id


def require_data_encryption_key() -> None:
    _keyring(required=True)


def _select_key(key_id: str) -> bytes:
    ring = _keyring(required=True)
    assert ring is not None
    keys, _ = ring
    if key_id in keys:
        return keys[key_id]
    if len(keys) == 1:
        return next(iter(keys.values()))
    raise RuntimeError(f"Encryption key '{key_id}' is not configured.")


def _active_key() -> tuple[str, bytes] | None:
    ring = _keyring()
    if ring is None:
        return None
    keys, active_id = ring
    return active_id, keys[active_id]


def _text_key_id(value: str) -> str | None:
    if value.startswith(_TEXT_V2_PREFIX):
        return value[len(_TEXT_V2_PREFIX):].split(":", 1)[0]
    if value.startswith(_TEXT_V1_PREFIX):
        return "legacy"
    return None


def protect_sensitive_value(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    active = _active_key()
    if active is None:
        return value
    active_id, key = active
    existing_id = _text_key_id(value)
    if existing_id == active_id:
        return value
    plaintext = reveal_sensitive_value(value, field) if existing_id else value
    nonce = secrets.token_bytes(12)
    aad = f"mailtrace:investigations:{field}:v1".encode("ascii")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), aad)
    return f"{_TEXT_V2_PREFIX}{active_id}:" + base64.b64encode(nonce + ciphertext).decode("ascii")


def reveal_sensitive_value(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    key_id = _text_key_id(value)
    if key_id is None:
        return value
    key = _select_key(key_id)
    if value.startswith(_TEXT_V2_PREFIX):
        encoded = value[len(_TEXT_V2_PREFIX):].split(":", 1)[1]
    else:
        encoded = value[len(_TEXT_V1_PREFIX):]
    try:
        packed = base64.b64decode(encoded, validate=True)
        nonce, ciphertext = packed[:12], packed[12:]
        if len(nonce) != 12 or len(ciphertext) < 16:
            raise ValueError("Invalid encrypted field envelope.")
        aad = f"mailtrace:investigations:{field}:v1".encode("ascii")
        return AESGCM(key).decrypt(nonce, ciphertext, aad).decode("utf-8")
    except Exception as exc:
        raise RuntimeError(f"Unable to decrypt protected investigation field: {field}.") from exc


def protect_investigation_row(row: dict) -> dict:
    return {
        **row,
        **{
            field: reveal_sensitive_value(row.get(field), field)
            for field in _SENSITIVE_INVESTIGATION_FIELDS
            if field in row
        },
    }


def protect_evidence_filename(value: str | None) -> str | None:
    return protect_sensitive_value(value, _EVIDENCE_FILENAME_FIELD)


def reveal_evidence_filename(value: str | None) -> str | None:
    return reveal_sensitive_value(value, _EVIDENCE_FILENAME_FIELD)


def _evidence_envelope(data: bytes) -> tuple[str | None, int, int] | None:
    if data.startswith(_EVIDENCE_V1_PREFIX):
        return "legacy", len(_EVIDENCE_V1_PREFIX), len(_EVIDENCE_V1_PREFIX) + 12
    if data.startswith(_EVIDENCE_V2_PREFIX):
        boundary = data.find(b"\0", len(_EVIDENCE_V2_PREFIX))
        if boundary < 0:
            raise RuntimeError("Invalid encrypted evidence envelope.")
        key_id = data[len(_EVIDENCE_V2_PREFIX):boundary].decode("ascii")
        return key_id, boundary + 1, boundary + 13
    return None


def protect_evidence_bytes(data: bytes, evidence_id: str) -> bytes:
    active = _active_key()
    if active is None:
        return data
    active_id, key = active
    envelope = _evidence_envelope(data)
    if envelope and envelope[0] == active_id:
        return data
    plaintext = reveal_evidence_bytes(data, evidence_id) if envelope else data
    nonce = secrets.token_bytes(12)
    aad = f"mailtrace:evidence:{evidence_id}:v1".encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return _EVIDENCE_V2_PREFIX + active_id.encode("ascii") + b"\0" + nonce + ciphertext


def reveal_evidence_bytes(data: bytes, evidence_id: str) -> bytes:
    envelope = _evidence_envelope(data)
    if envelope is None:
        return data
    key_id, _, payload_offset = envelope
    key = _select_key(key_id or "legacy")
    nonce, ciphertext = data[payload_offset - 12:payload_offset], data[payload_offset:]
    if len(nonce) != 12 or len(ciphertext) < 16:
        raise RuntimeError("Invalid encrypted evidence envelope.")
    aad = f"mailtrace:evidence:{evidence_id}:v1".encode("utf-8")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:
        raise RuntimeError("Unable to decrypt preserved email evidence.") from exc
