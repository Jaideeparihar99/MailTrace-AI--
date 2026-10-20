from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict

import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
)
from sklearn.pipeline import Pipeline

from .dataset import load_rows, validate_rows
from .training_readiness import require_training_approval, split_labeled_rows


MODEL_TYPE = "tfidf_logistic_regression"
MODEL_VERSION = "1.0.0"
RANDOM_STATE = 42


def build_pipeline() -> Pipeline:
    return Pipeline(
        steps=[
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    strip_accents="unicode",
                    ngram_range=(1, 2),
                    min_df=1,
                    max_df=0.995,
                    sublinear_tf=True,
                    max_features=60000,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=3000,
                    class_weight="balanced",
                    random_state=RANDOM_STATE,
                    solver="lbfgs",
                ),
            ),
        ]
    )


def dataset_sha256(
    rows: list[dict[str, Any]]
) -> str:

    canonical = json.dumps(
        rows,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(
        canonical
    ).hexdigest()


def train_model(
    rows: list[dict[str, Any]],
    output_dir: str | Path,
    dataset_path: str,
    approval_manifest: str | Path | None = None,
) -> Dict[str, Any]:

    approval = require_training_approval(dataset_path, approval_manifest)
    approved_rows = validate_rows(load_rows(dataset_path))["rows"]
    # Re-check after reading to catch a dataset replacement during the load window.
    approval = require_training_approval(dataset_path, approval_manifest)
    if dataset_sha256(approved_rows) != dataset_sha256(rows):
        raise RuntimeError("TRAINING_BLOCKED: supplied training rows do not match the hash-approved dataset content.")
    rows = approved_rows
    split_result = split_labeled_rows(rows, seed=RANDOM_STATE)
    train_rows = split_result["splits"]["train"]
    test_rows = split_result["splits"]["test"]
    x_train = [row["text"] for row in train_rows]
    y_train = [row["label"].upper() for row in train_rows]
    x_test = [row["text"] for row in test_rows]
    y_test = [row["label"].upper() for row in test_rows]
    labels = [row["label"].upper() for row in rows]

    pipeline = build_pipeline()
    pipeline.fit(x_train, y_train)
    predictions = pipeline.predict(x_test)

    accuracy = float(
        accuracy_score(
            y_test,
            predictions
        )
    )

    macro_f1 = float(
        f1_score(
            y_test,
            predictions,
            average="macro",
            zero_division=0,
        )
    )

    report = classification_report(
        y_test,
        predictions,
        output_dict=True,
        zero_division=0,
    )

    output = Path(output_dir)
    output.mkdir(
        parents=True,
        exist_ok=True
    )

    model_path = (
        output
        / "email_classifier.joblib"
    )

    manifest_path = (
        output
        / "manifest.json"
    )

    joblib.dump(
        pipeline,
        model_path
    )

    manifest = {
        "engine": "mailtrace-email-ai",
        "engine_version": "1.0.0",
        "model_type": MODEL_TYPE,
        "model_version": MODEL_VERSION,
        "artifact": model_path.name,
        "dataset_path": str(dataset_path),
        "dataset_sha256": dataset_sha256(rows),
        "training_samples": len(rows),
        "train_samples": len(x_train),
        "dev_samples": len(split_result["splits"]["dev"]),
        "test_samples": len(x_test),
        "split_manifest": split_result["manifest"],
        "training_approval": approval,
        "classes": sorted(set(labels)),
        "metrics": {
            "accuracy": accuracy,
            "macro_f1": macro_f1,
            "classification_report": report,
        },
        "random_state": RANDOM_STATE,
        "calibration_status": "UNCALIBRATED",
        "confidence_type": (
            "uncalibrated_model_probability"
        ),
        "production_ready": False,
        "production_readiness_reason": (
            "Representative reviewed dataset, "
            "calibration and independent validation "
            "are still required."
        ),
    }

    manifest_path.write_text(
        json.dumps(
            manifest,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

    return {
        "model_path": str(model_path),
        "manifest_path": str(manifest_path),
        "manifest": manifest,
    }