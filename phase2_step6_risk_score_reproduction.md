# Phase 2 Step 6 — Myntra Promotional Email Risk-Score Reproduction

**Date:** 2026-10-15 (Asia/Kolkata)
**Repository revision:** `b32748b` (`codex/phase1-audit-and-scoring-fixes`)
**Result:** Existing inline fusion test reproduced. The original raw Myntra email and full API result were not found, so this is not an end-to-end reproduction of the reported high-risk false positive.
**Scope:** Inspect first; run only the existing direct fusion unit case. No code, tests, dependencies, configuration, database, fixtures or runtime data were changed. The FastAPI application was not started.

## 1. Fixture search and provenance

Searched the repository for `myntra`, promotional references, sample/fixture names, `.eml`/`.msg` paths and saved reports. No original Myntra message, raw email fixture, persisted analysis report, or full API output was found. This agrees with the Step 1/4/5 reports that no `.eml`/`.msg` fixtures were available.

One existing test case is available at `backend/tests/test_false_positive_scoring.py::test_promotional_mail_with_passed_auth_does_not_escalate_on_generic_copy`. It constructs a dictionary inline and calls `analyze_email_intelligence` directly. It is a synthetic/unit-test input, not a raw MIME email and not a full parser/API run. The report below uses only those fields as supplied by that test; it does not infer missing message headers or real-world authentication results.

## 2. Reproduction steps and exact commands

**Environment observed:** Python 3.14.7, pytest 9.1.1, `tldextract` 5.4.0, using the existing `backend/venv`. No packages were installed. `PYTHONDONTWRITEBYTECODE=1` and pytest's cache provider was disabled. The test imports only the domain-alignment and fusion modules; it does not import `main`, initialize SQLite, parse an email, or make network/provider calls.

From the `backend` directory, the test command was:

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
.\venv\Scripts\python.exe -m pytest -p no:cacheprovider -q tests/test_false_positive_scoring.py::test_promotional_mail_with_passed_auth_does_not_escalate_on_generic_copy
```

Observed output:

```text
.                                                                        [100%]
1 passed in 6.51s
```

To capture the complete raw fusion object, the following read-only script was run from `backend` with `.
env\Scripts\python.exe -` (the payload is copied exactly from the existing test):

```python
import json
from services.email_ai.intelligence_fusion import analyze_email_intelligence

email = {
    "sender": "updates@myntra.com",
    "subject": "It's LIVE! 3X Discounts",
    "body": "Offers may be revoked or suspended. Shop now. Unsubscribe.",
    "headers": {"List-Unsubscribe": "<https://track.myntra.com/unsubscribe>"},
    "urls": ["https://track.myntra.com/click"],
    "attachments": [],
    "authentication_validation": {
        key: {"status": "PASS"} for key in ("spf", "dkim", "dmarc")
    },
}
ai_result = {"status": "MODEL_NOT_READY", "classification": "UNKNOWN"}
forensic = {
    "risk_score": 82,
    "findings": [{
        "severity": "MEDIUM",
        "title": "From and Return-Path domains differ",
    }],
}
threat_intelligence = {"matches": [], "matched_count": 0}
result = analyze_email_intelligence(
    email=email,
    ai_result=ai_result,
    forensic=forensic,
    threat_intelligence=threat_intelligence,
)
print(json.dumps(result, indent=2, sort_keys=True))
```

The same payload was analyzed twice. The objects matched exactly after removing `soc.analysis_timestamp`; both canonical JSON serializations had SHA-256 `ac7cff54d39bc9419640c5f7bbcf4b3adbe85d877d6b6f4a71aaa6a85e74158b`. The timestamp is expected to differ. This establishes deterministic output for this direct fusion input in this environment, not across Python/library versions or the full application.

## 3. Observed result

| Field | Observed value |
|---|---:|
| Fusion status | `ANALYZED` |
| `unified_risk_score` | **0.0 / 100** |
| Risk tier | `LOW` |
| Fusion decision | `INSUFFICIENT_EVIDENCE` |
| Fusion confidence | **0.5445** |
| Evidence confidence | 0.0 |
| Model probability | 0.0 (input status was `MODEL_NOT_READY`) |
| Signal/evidence count | 0 / 0 |
| Fusion score breakdown sum | 0.0 |
| SOC severity | `INFO` |
| Recommended disposition | `ANALYST_REVIEW_REQUIRED` |
| Parser/API verdict | **Not observed** — the test bypasses parser and API, so no `threat_analysis.verdict` was produced. |

The test assertion only requires score `<= 15`, no critical signals, no ML or urgency signal, and a reconciled breakdown. It does not assert an exact score, risk tier, confidence, API verdict, parser score, or UI output.

## 4. Input facts actually present

The inline test supplies the following values; these are test inputs, not authenticated properties of an original email:

- Sender: `updates@myntra.com`; sender domain is therefore `myntra.com` within the test dictionary.
- Return-Path: **not supplied**. The phrase “From and Return-Path domains differ” appears only as the title of a synthetic forensic finding.
- Authentication: the dictionary passed to fusion contains `spf`, `dkim`, and `dmarc` each as `{"status":"PASS"}`. The test does not provide raw `Authentication-Results`, proof of independent verification, alignment details, or a verifier run. Do not report these as real-message verified passes.
- Headers: only `List-Unsubscribe: <https://track.myntra.com/unsubscribe>` is supplied.
- URL list: `https://track.myntra.com/click` is supplied. No actual extraction occurred; both URLs are hard-coded test values.
- IOCs/TI: `matches=[]`, `matched_count=0`; this is an empty supplied mapping, not evidence that an external TI provider completed a live lookup.
- Forensic payload: `risk_score=82` and one `MEDIUM` finding whose title mentions From/Return-Path. It is hard-coded and not produced by running the forensic analyzer.
- Relay chain, source IP, geolocation, DNS, DKIM verification, SPF context, DMARC alignment and attachments: not actually analyzed in this test. The test supplies an empty attachment list; it supplies no relay/IP result.
- Model: explicitly `MODEL_NOT_READY`; no model inference was performed.

## 5. Signal-by-signal score ledger

No signal contributes any risk points in this fixture. There is no per-signal weight or penalty contribution because the signal builder returns an empty list.

| Candidate signal/evidence | Detector and current rule | Weight / contribution | Finding |
|---|---|---:|---|
| ML classification/probability | `intelligence_fusion.py::_ai_signal` (lines 149–170) rejects `MODEL_NOT_READY`. | No ML signal; 0 risk points. | Absent as expected. However, downstream confidence still uses numeric probability 0; see §6. |
| Urgency/social-engineering wording | `_content_signals` (lines 174–199): risk requires urgency AND a social-action phrase, and is suppressed when promotional context is detected. The subject/body and `List-Unsubscribe` meet promotional context. | No signal; 0 points. | Absent. This direct test does not reproduce a high score from this rule. |
| Authentication failure | `_header_signals` (lines 218–236): only FAIL/SOFTFAIL/PERMERROR statuses create a signal (base 70 plus 10 per failure, capped 100). Supplied values all say PASS. | No signal; 0 points. | No authentication penalty. The test does not verify those claims. |
| URL delivery | `_url_signals` (lines 239–252) reads `advanced_url_intelligence` or `url_intelligence`; it does not score the supplied `urls` list by itself. | No signal; 0 points. | URL list is present as an input but no URL-intelligence mapping is supplied. |
| Forensic finding | `_forensic_signals` (lines 324–340) requires a findings list and keeps only HIGH/CRITICAL entries; it also excludes titles/categories containing “return-path”. | No signal; 0 points. | The supplied finding is MEDIUM and mentions Return-Path; both conditions exclude it. The separate forensic `risk_score=82` is not consumed by this function. |
| Threat intelligence | `_ti_signals` (lines 342–359) needs mapping entries; only malicious verdicts create a positive signal. | No signal; 0 points. | `matches=[]`; no matches supplied. Provider completion/unavailability is not tested. |
| Identity/Reply-To | `_identity_signals` (lines 202–216) requires sender and Reply-To values. | No signal; 0 points. | No Reply-To supplied. |
| Attachments/IP | `_attachment_signals` and `_infrastructure_signals` (lines 255–322, 365–377). | No signal; 0 points. | Empty attachments; no IP-intelligence argument supplied. |
| Fusion formula | `_fuse` empty-signals branch (lines 444–455). Emits six zero components: weighted evidence, corroboration, convergence, severity, corroboration bonus, breadth. | **0.0 total.** | Breakdown reconciles exactly with `unified_risk_score=0.0`. No clamp or authentication-cap adjustment changes this zero. |

### Current final classification rules applied to this result

- `_decision` (`intelligence_fusion.py:539–548`) returns `INSUFFICIENT_EVIDENCE` because the model classification is UNKNOWN, risk is below the threat threshold, and no evidence supports a likely-legitimate decision.
- Risk tier is selected at 90/75/50 in `analyze_email_intelligence` (`:614`); 0 maps to LOW.
- `_soc_severity` (`:550–555`) maps 0 to INFO; `_recommended_disposition` (`:558–561`) maps this to analyst review.
- This is fusion output only. Main API code, parser fallback, database persistence and frontend verdict were not executed.

## 6. Confidence and data-quality behavior

Confidence is **independently calculated by fusion**, not copied from the test input. But the current formula gives misleading model support when the model is unavailable:

1. `_probability_from_ai` (`:149–156`) returns the numeric default 0.0 when all probability keys are absent, even when the status is MODEL_NOT_READY.
2. `_ai_signal` correctly skips this result, so there is no ML risk signal.
3. `analyze_email_intelligence` (`:577–582`) nevertheless computes `model_support = 0.50 + abs(0.0 - 0.50) × 0.98 = 0.99` and overall confidence `0.55 × 0.99 + 0.45 × 0.0 = 0.5445`.
4. Thus the reported confidence is formula-derived but uses a non-result placeholder as if it were an extreme model prediction. This is a confirmed confidence defect for this test input; it does not explain a high risk score here.
5. Data quality reports completeness 0.925 because the expected email fields are present in the supplied dictionary and the AI/forensic/TI arguments are mappings. `enrichment_available.ai_result=true` does not distinguish MODEL_NOT_READY from usable model inference; TI mapping presence does not mean provider coverage is complete.

## 7. Confirmed versus suspected causes

### Confirmed for the existing inline case

- The inline test passes, but its observed direct fusion score is exactly 0.0, tier LOW, no signals and no high-risk decision.
- The hard-coded forensic score 82 does not affect fusion because `_forensic_signals` reads only severe entries from `findings`, and the only supplied finding is MEDIUM and Return-Path-related.
- The hard-coded URL list does not affect fusion without an `advanced_url_intelligence`/`url_intelligence` result.
- Missing model output is excluded from risk signals but still inflates model-support confidence to 0.99; final confidence is 0.5445. The formula is source-verified and reproduced.
- The existing test is not a raw email and cannot establish SPF/DKIM/DMARC, URL extraction, TI provider, relay/IP or parser behavior.

### Suspected or unresolved for the reported high-risk false positive

- **No confirmed cause of the reported high-risk score can be assigned.** The original message, exact analysis response, app version, parser output and environment are missing.
- A higher score in the full pipeline could come from parser rules, forensic/URL enrichment, IOC scoring, or the API’s parser-plus-IOC fallback when fusion fails; those paths were not executed here.
- Current source contains separate parser, fusion and API score paths. That is a plausible route to inconsistent displayed scores, but it is not proof of what happened for the missing original email.
- Do not lower thresholds or suppress detection based on this incomplete reproduction. The present inline case did not yield a high risk score to begin with.

## 8. Warnings and blockers

- Original raw email, saved full report, and independent expected label/verdict: **not found**.
- Full API/parser/forensic analysis and top-level `threat_analysis.verdict`: **not reproduced**; no safe disposable DB/runtime or actual email fixture was available, and application startup was intentionally avoided.
- Actual verified authentication outcomes, DNS results, extracted IOCs, relay hops, sending IP and threat-provider coverage: **not available**.
- The input fixture asserts all three auth values PASS but does not carry `attempted`, `complete`, method, provenance or alignment. It cannot verify the authentication-cap contract.
- No warnings were printed by the isolated test command. No network/provider access, app startup, database access or file fixture parsing occurred.
- The existing unit test's `score <= 15` assertion is too broad to lock down this observed result or confidence behavior; exact regression expectations are outside this no-code-change step.

## 9. Complete raw fusion output captured

```json
{
  "adjusted_confidence": 0.5445,
  "attack_intent": [],
  "classification": "UNKNOWN",
  "confidence": 0.5445,
  "confidence_components": {
    "evidence_breadth": 0.0,
    "evidence_confidence": 0.0,
    "model_support": 0.99,
    "severe_evidence_support": 0.0
  },
  "confidence_penalty": 0,
  "contradiction_analysis": {
    "confidence_penalty": 0,
    "contradiction_count": 0,
    "contradictions": [],
    "highest_severity": "NONE",
    "independent_evidence_mean": 0,
    "severe_independent_categories": [],
    "strong_independent_categories": []
  },
  "critical_signal_count": 0,
  "critical_signals": [],
  "decision": "INSUFFICIENT_EVIDENCE",
  "engine": "mailtrace-ai-intelligence-fusion",
  "evidence": [],
  "evidence_confidence": 0.0,
  "evidence_count": 0,
  "explainability": {
    "convergence": "LIMITED_CORROBORATION",
    "independent_evidence_components": [],
    "reason": "Risk is derived from grouped evidence with convergence, correlation controls and corroboration; the score is not an ML probability.",
    "top_risk_drivers": []
  },
  "fusion_metrics": {
    "base_weighted_score": 0.0,
    "convergence_bonus": 0,
    "correlation_group_count": 0,
    "corroborated_category_count": 0,
    "corroboration_bonus": 0.0,
    "corroboration_strength": 0.0,
    "independent_category_count": 0,
    "severe_category_count": 0,
    "severe_strength": 0.0,
    "severity_bonus": 0.0
  },
  "governance": {
    "autonomous_destructive_action": false,
    "execution_side_effect": false,
    "human_review_required_for_destructive_response": true,
    "model_probability_is_separate_from_confidence": true,
    "persistence": false,
    "policy_version": "soc-fusion-policy-3.0",
    "read_only": true,
    "score_is_not_a_probability": true
  },
  "model_probability": 0.0,
  "raw_confidence": 0.5445,
  "risk_drivers": [],
  "risk_tier": "LOW",
  "score_breakdown": [
    {"component": "weighted_evidence", "points": 0.0, "source": "no evidence"},
    {"component": "corroboration", "points": 0.0, "source": "no corroborating evidence"},
    {"component": "convergence_bonus", "points": 0.0, "source": "no independent evidence"},
    {"component": "severity_bonus", "points": 0.0, "source": "no severe signals"},
    {"component": "corroboration_bonus", "points": 0.0, "source": "no corroborated categories"},
    {"component": "evidence_breadth_bonus", "points": 0.0, "source": "no evidence breadth"}
  ],
  "signal_count": 0,
  "soc": {
    "analysis_fingerprint": null,
    "analysis_timestamp": "2026-10-15T08:51:25.356463Z",
    "analyst_disposition": "UNRESOLVED",
    "correlation_groups": {},
    "data_quality": {
      "completeness": 0.925,
      "enrichment_available": {
        "ai_result": true,
        "forensic": true,
        "ip_intelligence": false,
        "threat_intelligence": true
      },
      "enrichment_count": 3,
      "missing_components": [],
      "present_components": ["subject", "body", "sender", "headers", "urls"]
    },
    "detection_count": 0,
    "mitre_attack_techniques": [],
    "policy_version": "soc-fusion-policy-3.0",
    "recommended_disposition": "ANALYST_REVIEW_REQUIRED",
    "schema_version": "3.0",
    "severity": "INFO"
  },
  "status": "ANALYZED",
  "unified_risk_score": 0.0,
  "version": "3.0.0"
}
```

## 10. Handoff

The existing inline fusion fixture is reproducible and deterministic for the isolated scorer: **0.0 / LOW / INSUFFICIENT_EVIDENCE, confidence 0.5445, zero signals**. This does not reproduce the reported full-app high-risk result. Do not proceed to Step 7 on the claim that the original false positive has been reproduced. First obtain the original `.eml`/`.msg` (or exact sanitized parsed input) and the full saved/API result containing the high score; then arrange the previously specified disposable DB/runtime before running the application pipeline. Until then, the exact blocker is missing original input and output, and no detection changes should be made based on this test alone.
