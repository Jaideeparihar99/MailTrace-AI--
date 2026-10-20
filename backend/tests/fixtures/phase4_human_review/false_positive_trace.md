# MT-F16-0002 model-enabled API-path false-positive trace

Status: **Model classification remains an apparent false positive against the synthetic author label; independent label review is pending. The API disposition is now review-required, not confirmed high risk.**

Verified 2026-10-19 with:

```powershell
.\venv\Scripts\python.exe scripts\evaluate_phase4_step18.py --model-enabled --trace-fixture MT-F16-0002
```

The evaluator used the real local model, parser, fusion and `/api/analyze-email` path. Reputation/forensic network services were stubbed and DNS/socket/HTTP were blocked.

Observed:

- Synthetic manifest label: `benign_legitimate` (not independently adjudicated).
- Model prediction: `PHISHING`; probability `0.6341296965`.
- Fusion evidence: one `ml` evidence item; independent evidence-group count `0`.
- Fused risk score: `49`; fusion decision: `SUSPICIOUS_REVIEW_REQUIRED`.
- API disposition: `REVIEW REQUIRED (UNCONFIRMED MODEL SIGNAL)`.
- Structured reason: `MODEL_THREAT_PREDICTION_UNCORROBORATED`.
- No independent URL/header/content/reputation evidence corroborated the model signal in this fixture run.

The previous trace recorded the pre-fix output (`HIGH RISK`, score 75). That output is stale and was caused by the former model-only scoring/verdict behavior. The current guard preserves the score and evidence for analyst review while preventing an uncorroborated model-only prediction from being presented as confirmed high risk. It does **not** fix the model classification or establish that the synthetic fixture label is correct. Keep the final disposition pending independent label adjudication and a larger holdout; do not tune to this one example alone.
