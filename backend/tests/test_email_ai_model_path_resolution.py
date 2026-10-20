from pathlib import Path

import pytest

from services.email_ai.inference import predict_email


BACKEND_ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = BACKEND_ROOT / "models" / "email_ai"
MODEL_ARTIFACTS_PRESENT = any((MODEL_DIR / name).is_file() for name in (
    "email_phishing_l3_calibrated_bundle.joblib",
    "email_classifier.joblib",
))


@pytest.mark.skipif(
    not MODEL_ARTIFACTS_PRESENT,
    reason=(
        "Model artifacts are local-only/ignored; provision an approved artifact "
        "to run this model-load smoke test."
    ),
)
def test_default_model_loads_when_started_from_repository_root(monkeypatch):
    repo_root = Path(__file__).resolve().parents[2]
    monkeypatch.chdir(repo_root)

    result = predict_email({
        "subject": "Urgent account verification",
        "body": "Please verify your account immediately using the link.",
    })

    assert result["status"] == "MODEL_READY", result
    assert result["model_ready"] is True
    assert result["classification"] in {"PHISHING", "LEGITIMATE"}
    assert 0.0 <= result["model_probability"] <= 1.0


def test_missing_explicit_model_directory_fails_closed(tmp_path):
    result = predict_email(
        {"subject": "hello", "body": "ordinary message"},
        model_dir=tmp_path / "does-not-exist",
    )

    assert result["status"] == "MODEL_NOT_READY"
    assert result["model_ready"] is False
