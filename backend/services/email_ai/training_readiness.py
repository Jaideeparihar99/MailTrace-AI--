"""Fail-closed training approvals and grouped dataset partitions for MailTrace-AI."""
from __future__ import annotations
import hashlib, json, re
from datetime import date
from pathlib import Path
from typing import Any, Mapping

APPROVAL_FILENAME = "training_approval.json"
REQUIRED_APPROVALS = {"license_review": "APPROVED", "label_review": "ADJUDICATED", "privacy_review": "APPROVED"}

def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def _valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _validate_iso_date(value: Any, description: str) -> str:
    if not isinstance(value, str):
        raise RuntimeError(f"TRAINING_BLOCKED: {description} must be an ISO date (YYYY-MM-DD).")
    try:
        if date.fromisoformat(value).isoformat() != value:
            raise ValueError
    except ValueError as exc:
        raise RuntimeError(f"TRAINING_BLOCKED: {description} must be a valid ISO date (YYYY-MM-DD).") from exc
    return value


def _resolve_evidence_path(manifest_path: Path, value: Any, description: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"TRAINING_BLOCKED: {description} evidence_path is required.")
    path = Path(value)
    resolved = path.resolve() if path.is_absolute() else (manifest_path.parent / path).resolve()
    if not resolved.is_file():
        raise RuntimeError(f"TRAINING_BLOCKED: {description} evidence file is missing: {resolved}")
    return resolved


def require_training_approval(dataset_path: str | Path, approval_path: str | Path | None = None) -> dict[str, Any]:
    """Require hash-bound dataset components and evidence-backed rights, label, and privacy approvals."""
    dataset = Path(dataset_path).resolve()
    approval = Path(approval_path).resolve() if approval_path else (dataset.parent.parent / "metadata" / APPROVAL_FILENAME).resolve()
    if not dataset.is_file():
        raise RuntimeError(f"TRAINING_BLOCKED: dataset file missing: {dataset}")
    if not approval.is_file():
        raise RuntimeError(f"TRAINING_BLOCKED: approval manifest missing: {approval}. Obtain written source-rights approval, independent label adjudication, and privacy/retention approval before training.")
    try:
        record = json.loads(approval.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"TRAINING_BLOCKED: invalid approval manifest: {approval}") from exc
    if not isinstance(record, dict):
        raise RuntimeError("TRAINING_BLOCKED: approval manifest must be a JSON object.")
    if record.get("approved_for_training") is not True:
        raise RuntimeError("TRAINING_BLOCKED: approved_for_training must be explicitly true.")
    declared_hash = record.get("dataset_sha256")
    actual_hash = sha256_file(dataset)
    if not _valid_sha256(declared_hash):
        raise RuntimeError("TRAINING_BLOCKED: dataset_sha256 must be a lowercase 64-character SHA-256 hex digest.")
    if declared_hash != actual_hash:
        raise RuntimeError("TRAINING_BLOCKED: approval dataset_sha256 does not match the current dataset bytes.")
    if not isinstance(record.get("reviewer"), str) or not record["reviewer"].strip():
        raise RuntimeError("TRAINING_BLOCKED: named reviewer and approval_date are required.")
    approval_date = _validate_iso_date(record.get("approval_date"), "approval_date")

    components = record.get("dataset_components")
    if not isinstance(components, list) or not components:
        raise RuntimeError("TRAINING_BLOCKED: dataset_components must list every dataset component and its SHA-256.")
    component_paths = set()
    for index, component in enumerate(components):
        label = f"dataset_components[{index}]"
        if not isinstance(component, dict):
            raise RuntimeError(f"TRAINING_BLOCKED: {label} must be an object.")
        for field in ("component_id", "source", "path"):
            if not isinstance(component.get(field), str) or not component[field].strip():
                raise RuntimeError(f"TRAINING_BLOCKED: {label}.{field} is required.")
        component_path = _resolve_evidence_path(approval, component["path"], label)
        component_hash = component.get("sha256")
        if not _valid_sha256(component_hash):
            raise RuntimeError(f"TRAINING_BLOCKED: {label}.sha256 must be a lowercase 64-character SHA-256 hex digest.")
        if sha256_file(component_path) != component_hash:
            raise RuntimeError(f"TRAINING_BLOCKED: {label} SHA-256 does not match component bytes.")
        if component_path in component_paths:
            raise RuntimeError("TRAINING_BLOCKED: duplicate dataset component path.")
        component_paths.add(component_path)
    if dataset not in component_paths:
        raise RuntimeError("TRAINING_BLOCKED: dataset_components must include the exact approved dataset file.")

    evidence_hashes = {}
    for key, required_status in REQUIRED_APPROVALS.items():
        section = record.get(key)
        if not isinstance(section, dict) or section.get("status") != required_status:
            raise RuntimeError(f"TRAINING_BLOCKED: {key} must have status {required_status} from a named reviewer.")
        if not isinstance(section.get("reviewer"), str) or not section["reviewer"].strip():
            raise RuntimeError(f"TRAINING_BLOCKED: {key}.reviewer is required.")
        _validate_iso_date(section.get("review_date"), f"{key}.review_date")
        if not isinstance(section.get("scope"), str) or not section["scope"].strip():
            raise RuntimeError(f"TRAINING_BLOCKED: {key}.scope must describe the reviewed use and restrictions.")
        evidence_path = _resolve_evidence_path(approval, section.get("evidence_path"), key)
        declared_evidence_hash = section.get("evidence_sha256")
        actual_evidence_hash = sha256_file(evidence_path)
        if not _valid_sha256(declared_evidence_hash) or declared_evidence_hash != actual_evidence_hash:
            raise RuntimeError(f"TRAINING_BLOCKED: {key} evidence SHA-256 is missing, malformed, or mismatched.")
        evidence_hashes[key] = actual_evidence_hash
    label_review = record["label_review"]
    if label_review.get("independent") is not True:
        raise RuntimeError("TRAINING_BLOCKED: label_review.independent must be explicitly true.")
    reviewed_count = label_review.get("reviewed_count")
    if isinstance(reviewed_count, bool) or not isinstance(reviewed_count, int) or reviewed_count < 1:
        raise RuntimeError("TRAINING_BLOCKED: label_review.reviewed_count must be a positive integer.")
    if label_review.get("reconciliation_sha256") != evidence_hashes["label_review"]:
        raise RuntimeError("TRAINING_BLOCKED: label_review reconciliation hash must match its evidence file.")

    return {
        "approval_manifest": str(approval),
        "approval_manifest_sha256": hashlib.sha256(approval.read_bytes()).hexdigest(),
        "dataset_sha256": actual_hash,
        "dataset_component_count": len(components),
        "approval_evidence_sha256": evidence_hashes,
        "reviewer": record["reviewer"],
        "approval_date": approval_date,
    }

def load_grouped_training_rows(path: str | Path) -> list[dict[str, Any]]:
    """Load labeled JSONL while preserving only grouping/time metadata needed for splitting."""
    rows=[]
    allowed_meta=("source", "source_group", "campaign_id", "campaign", "thread_id", "conversation_id", "duplicate_group_id", "near_duplicate_group_id", "timestamp", "sent_at", "date", "email_date")
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip(): continue
            try: raw=json.loads(line)
            except json.JSONDecodeError as exc: raise ValueError(f"Invalid JSONL at line {line_number}.") from exc
            if not isinstance(raw, dict): raise ValueError(f"JSONL line {line_number} must be an object.")
            text=str(raw.get("text") or "").strip(); label=str(raw.get("label") or "").strip().upper()
            if not text or label not in {"LEGITIMATE", "PHISHING"}: continue
            row={"text":text,"label":label}
            for key in allowed_meta:
                value=raw.get(key)
                if value is not None and str(value).strip(): row[key]=value
            rows.append(row)
    if len(rows)<3: raise ValueError("At least three labeled records are required for grouped splitting.")
    if {row["label"] for row in rows}!={"LEGITIMATE","PHISHING"}: raise ValueError("Grouped dataset must contain both LEGITIMATE and PHISHING labels.")
    return rows

def split_labeled_rows(rows: list[Mapping[str, Any]], *, seed: int = 2701) -> dict[str, Any]:
    """Split by source/campaign/thread/exact and approximate near-duplicate groups; fail closed if any partition lacks both classes."""
    from .feature_pipeline import grouped_split
    source_values = []
    for index, row in enumerate(rows):
        primary = str(row.get("source_group") or "").strip()
        fallback = str(row.get("source") or "").strip()
        if primary and fallback and primary.casefold() != fallback.casefold():
            raise ValueError(f"Conflicting source and source_group identifiers at row {index}.")
        value = primary or fallback
        source_values.append(value)
    populated_sources = [value for value in source_values if value]
    if not populated_sources:
        raise ValueError("Source grouping metadata is required for training splits; no source-agnostic row split fallback is permitted.")
    if len(populated_sources) != len(rows):
        raise ValueError("Source grouping metadata is incomplete; every row must have a source/source_group identifier when source grouping is used.")
    if len({value.casefold() for value in populated_sources}) < 3:
        raise ValueError("At least three distinct source groups are required for source-isolated train/dev/test partitions; no fallback to row splitting is permitted.")
    result=grouped_split(rows, seed=seed, train_ratio=0.70, dev_ratio=0.15, test_ratio=0.15, group_by_source=True, time_aware=True)
    for name, partition in result["splits"].items():
        classes={str(row.get("label") or "").upper() for row in partition}
        if classes!={"LEGITIMATE","PHISHING"}:
            raise ValueError(f"Grouped {name} partition does not contain both classes; source/group isolation cannot safely support this split. No fallback to row-level splitting is permitted.")
    result["manifest"]["label_key"]="label"
    result["manifest"]["class_counts"] = {name: {label: sum(1 for row in partition if str(row.get("label") or "").upper() == label) for label in ("LEGITIMATE", "PHISHING")} for name, partition in result["splits"].items()}
    result["manifest"]["training_transform_policy"]="TF-IDF and classifier fit on train partition only; dev/test are transform-only"
    return result
