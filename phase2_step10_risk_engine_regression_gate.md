# Phase 2 Step 10 — Risk Engine Regression Gate

**Status: Phase Two regression gate complete.** The stored Myntra parsed message replays to LOW risk, score contributions are explainable, domain and URL/IOC rules are covered, the actual analysis API returns reconciled counts, and the full backend suite passes. Phase Three still requires explicit user approval. There is no representative labeled dataset, so production-level model or detector accuracy is not established. The original raw MIME and a visually rendered browser capture were unavailable; those limits are documented below.

## A. Score contract and audit schema

`backend/services/email_ai/intelligence_fusion.py` remains the canonical source for this module’s `unified_risk_score` (0–100), `risk_tier`, `decision`, and independently computed fusion `confidence` (0–1). The score is a rule-fusion risk index, not an ML probability. `model_probability`, `evidence_confidence`, `confidence`, authentication observations, and threat-intelligence availability are semantically different values. The API also has separate parser/IOC fallback scoring in `backend/main.py`; a full API run was not performed, so the fusion score must not be presented as proof that the top-level API always uses it.

This step adds `evidence[].reason_code` and a stable `evidence_ref` (truncated SHA-256 of detector ID, detector source and evidence text), plus `score_ledger[]`. Signal rows point to evidence and have zero standalone contribution; one group row carries each actual bounded risk contribution, and policy rows show adjustments. Thus a reviewer cannot mistake two correlated categories for two separate score additions. Existing `score_breakdown` remains for compatibility. The independent-evidence cap is an explicit row.

Example captured from a synthetic BEC/payment-change input:

```json
{
  "unified_risk_score": 85,
  "risk_tier": "HIGH",
  "confidence": 0.73821,
  "evidence_confidence": 0.697133,
  "decision": "SUSPICIOUS_REVIEW_REQUIRED",
  "score_ledger": [
    {
      "reason_code": "MT-FUS-FRAUD-FINANCIAL-FRAUD-LANGUAGE",
      "evidence_ref": "EVD-a182407955c8b5eb",
      "detector_source": "email_content",
      "raw_signal_score": 88.0,
      "contribution": 0.0
    },
    {
      "reason_code": "MT-FUS-GROUP-CONTENT_INTENT_FRAUD",
      "detector_source": "intelligence_fusion_policy",
      "group_score": 88.0,
      "category_weight": 1.25,
      "contribution": 88.0
    },
    {
      "reason_code": "MT-FUS-POLICY-INDEPENDENT_EVIDENCE_CAP",
      "detector_source": "intelligence_fusion_policy",
      "contribution": -3.0
    }
  ]
}
```

The evidence reference is reproducible for identical detector/source/evidence text. It is not a byte offset or a cryptographic commitment to the original email. Detector evidence strings are often summaries rather than exact message spans; the current output does not yet provide source MIME-part offsets for each fusion signal. Do not use an evidence ref alone as a source locator.

### Current formula (verified from source)

`_aggregate_categories` groups signals by category. Within a category it averages each signal score using local weights `category_weight × (0.70 + 0.30 × confidence) × (0.75 + 0.25 × reliability)`. Category confidence is the maximum signal confidence. `_effective_group_scores` merges categories within their configured family only when evidence tokens overlap by at least two meaningful terms. A merged score is its strongest category score plus 8% of the other category scores, with uplift capped at 8 points; group weight and confidence are the maximum of member categories. `_fuse` computes the weighted mean over these effective groups using `group_weight × (0.70 + 0.30 × group_confidence)`.

The pre-cap score is:

```text
0.62 × weighted_evidence_group_mean
+ 0.38 × mean(top four evidence-group scores >= 65; zero if none)
+ min(15, 3 × (independent_groups_at_least_55 - 1), floored at 0)
+ severity bonus (5 for >=4 groups >=80; else 2.5 for >=2)
+ corroboration bonus (2 for >=4 groups >=65; else 1 for >=2)
+ breadth bonus (2.5 for >=5 independent groups)
```

Independent groups exclude the model-only group and require score >=55; corroborated and severe groups use thresholds >=65 and >=80. The score is clamped 0–100 and capped at 75 with zero independent groups or 85 with one. The authentication cap requires independently validated provenance, a validated domain, all three SPF/DKIM/DMARC statuses equal to PASS, and no protected threat group. In practice the validator currently leaves DMARC as policy/lookup state, so this cap is intentionally difficult to satisfy. Tiers are CRITICAL >=90, HIGH >=75, MEDIUM >=50, else LOW; `_decision` also uses classification, confidence, evidence confidence and signal count.

Exact duplicate signal rows are removed by `(category, name, evidence)` in `_deduplicate_signals`. Same-family categories with evidence overlap are additionally merged into one bounded group. This is rule-based token overlap; it does not establish semantic equivalence for paraphrases, multilingual content, opaque URLs or detector summaries that omit the underlying IOC. Those cases remain a limitation.

Model availability is now explicit. An unavailable model supplies neutral model support 0.50 rather than treating placeholder probability 0.0 as a confident prediction; with zero evidence, the stored Myntra replay confidence is 0.275. Authentication output separately lists reported results, their trust flag, independently validated statuses, validation completeness and validated domain. TI output separates not provided, unavailable, error, partial coverage, no indicators, checked with no matches, matches found and unknown. The API also discloses fallback score source, degraded mode, fusion status and reason.

## B. Regression inventory and observed results

| Scenario | Regression/evidence | Outcome |
|---|---|---|
| Stored Myntra message | `test_stored_myntra_analysis_replays_to_low_risk_without_false_urgency` using `backend/tests/fixtures/myntra_promotional_record.json` | Pass: stored historical analysis was 82 / HIGH RISK with one urgency-pressure signal; current fusion replay is 0 / LOW with no signals and confidence 0.275. Fixture comes from parsed DB content; raw MIME is absent. |
| Inline promotional email with reported/pass auth input | `test_promotional_mail_with_passed_auth_does_not_escalate_on_generic_copy` | Pass: 0 / LOW; unavailable model is explicit and does not inflate confidence. Caller supplied test PASS statuses do not activate the trusted authentication cap without independent validation provenance. |
| Disclaimer wording | `test_disclaimer_urgency_words_do_not_add_parser_social_engineering_points` | Pass. |
| Quoted and negated urgency/credential wording | Step 8 parser/fusion regressions | Pass. |
| Obvious phishing; auth pass with malicious content | `test_phishing_sample_remains_high_risk_despite_authentication_passes`, `test_actionable_suspension_phishing_keeps_parser_and_fusion_evidence` | Pass: malicious content still creates strong credential/URL or actionable-urgency evidence despite passed auth input. |
| Credential-harvesting lure | `test_actionable_suspension_phishing_keeps_parser_and_fusion_evidence` | Pass: credential and actionable pressure signals present. |
| BEC/payment change | `test_bec_payment_change_lure_has_explainable_fraud_evidence` | Pass: financial-fraud signal present and ledger reconciles. |
| Malformed email | `test_malformed_email_input_is_reported_without_fabricating_signals`; domain malformed-address cases | Pass for tested malformed input. |
| Auth failure with benign content | `test_authentication_failure_is_separate_from_benign_content_risk` | Pass: authentication failure signal is present and separate from content evidence. |
| Domain policy and URL/IOC reconciliation | `test_domain_alignment_evidence.py` | Pass in focused run: exact/organizational/unrelated/malformed domains; PSL/IDN; MIME overlap; HTML-only URL and source locations. |
| Stable evidence IDs and score bound/reconciliation | `test_score_ledger_has_stable_reason_and_evidence_refs_and_reconciles` | Pass: identical input yields stable reason/evidence refs and points; risk 0–100, confidence 0–1, ledger sum equals canonical score. |
| Evidence-aware correlated scoring | `test_related_content_categories_share_one_evidence_group_and_bounded_uplift`, `test_unrelated_content_categories_in_same_family_remain_independent` | Pass: shared multi-token evidence merges; unrelated same-family evidence remains separate. |
| Auth provenance and TI availability | Step 10 auth/TI regressions | Pass: reported PASS does not become independently validated PASS; missing/partial/error/no-indicator/no-match states remain distinct. |
| API degraded fallback disclosure | `test_api_fusion_failure_is_explicitly_degraded` | Pass: fallback score source, fusion status, degraded flag and reason are returned by the score-resolution function. |
| HTTP API URL/IOC reconciliation | `test_analyze_email_api_reconciles_url_and_ioc_counts` | Pass through `POST /api/analyze-email` with disposable SQLite: 2 unique URLs, 3 occurrences, 2 URL IOCs, `counts_consistent=true`, fusion score source disclosed. |

These fixtures are hand-authored regression cases. They are not a representative labeled evaluation set. A dataset loader exists at `backend/services/email_ai/dataset.py`, but no labeled dataset file was found in the repository. Production-level precision, recall, calibration, and false-positive rates have not been established.

## C. Step 6 baseline comparison

Step 6 recorded a synthetic inline Myntra-like input at **0.0 / LOW**, confidence **0.5445**, zero signals. The repository database provides the actual prior result: `INV-98D48FB0B1` stored parsed content with **82 / HIGH RISK**, fusion score **82**, and one `social_engineering.urgency_pressure_pattern` signal. The same saved API result also had parser `rule_score=10` from a Return-Path mismatch between `myntra.com` and `myntramailers.myntra.com`; the PSL-aware domain policy now treats those as the same organizational domain. Two later saved runs show **0 / LOW**. Replaying the first record’s parsed body, subject, sender, auth-validation statuses and TI state through current fusion yields **0 / LOW**, no signals, confidence **0.275**, and `model_available=false`. This confirms correction for the stored parsed message and identifies both historical contributors. The raw MIME is absent, so relay/header parsing cannot be replayed from source bytes; current full HTTP endpoint behavior was not captured.

The saved record’s Authentication-Results reported SPF/DKIM/DMARC PASS, but `authentication_results_trusted=false`. Independent validation had SPF `UNVERIFIED_NO_TRUSTED_SMTP_IP`, DKIM `TEMPORARY_ERROR_OR_INVALID_KEY`, and DMARC `DNS_LOOKUP_ERROR`. TI status was `no_iocs` with coverage `NEVER_SYNCED`; that means no IOC lookup occurred, not that the message was safe. The archived record had no usable IOC match evidence.

Step 9’s multipart result was verified both in parser tests and through the actual HTTP endpoint using a disposable database: two unique URLs, three occurrences, and two URL IOCs. The UI reads `analysis.url_summary.unique_count` (falling back to `analysis.urls.length`) for its extracted-URL and URL-indicator displays, so those displays use the same count returned by the API; no browser-rendered screenshot was captured. Domain alignment policy is PSL-aware and focused cases pass; alignment is not treated as authentication or safety.

## D. Changed files and verification

Step 10 changes:

- `backend/services/email_ai/intelligence_fusion.py`: stable evidence refs, evidence-overlap grouping, bounded group contributions, model/auth/TI availability contracts, score ledger.
- `backend/services/email_forensics/authentication_analyzer.py`: explicit independent-validation provenance and validated domain.
- `backend/main.py`: disclosed fallback/degraded score source and generic error response without exception text.
- `backend/services/email_alerting.py` and `backend/tests/test_email_alerting_policy.py`: confidence-provenance-aware policy fixtures and accepted LOW verdict spelling.
- `backend/database/database.py` and `backend/tests/test_soc_case_claims.py`: an existing routing refresh now records a more urgent risk-priority escalation without changing the assigned analyst or extending an earlier SLA deadline; the production legacy-schema test now supplies a disposable test encryption key.
- `backend/pytest.ini`, `backend/conftest.py`: deterministic import mode and workspace-local temporary paths; background workers disabled in tests.
- `backend/tests/test_phase2_step10_gate.py`, `backend/tests/test_domain_alignment_evidence.py`, and `backend/tests/fixtures/myntra_promotional_record.json`: scoring, provenance, availability, fallback, domain/URL, HTTP count reconciliation, and stored-message regressions.
- `phase2_step10_risk_engine_regression_gate.md`: this handoff.

The working tree also contains the Step 8–9 implementation and reports listed in the earlier handoffs. Unrelated pre-existing `windowf` was left untouched. No sender/domain allowlist was added. Static review found the existing API fusion-error fallback `parser_rules_plus_ioc_fallback` in `backend/main.py`; because it changes score source when fusion fails and was not exercised here, it needs a dedicated failure-path regression. No new secrets were added. The ledger exposes detector evidence text, so downstream report access and retention policy still need review.

Full regression command, run from `backend` (outside the network-restricted sandbox so the local TestClient can create its socket pair):

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
.\venv\Scripts\python.exe -m pytest -p no:cacheprovider -q --basetemp=.pytest-tmp-phase2-final
```

Full suite result: **166 passed in 290.61s**. The actual HTTP API URL/IOC reconciliation test also passed independently (**1 passed in 3.46s**) before the full run. Gateway alerting policy: **9 passed**. The existing fusion smoke module passed with a **100 / CRITICAL** synthetic threat result. Python compilation passed for changed backend modules, `node --check frontend/script.js` passed, and `git diff --check` reported no whitespace errors. Pytest collection uses importlib mode, resolving the prior duplicate-module collision.

The original TestClient stall was caused by sandbox restrictions on local socket creation: the minimal FastAPI request hung inside Windows/Python 3.14 socket-pair setup in the sandbox and completed successfully outside it. Running outside the sandbox resolved that environment issue and allowed the full HTTP-related regression suite to run. The API analysis endpoint was additionally exercised using a disposable SQLite database and mocked enrichment state; the browser UI itself was not launched.

## E. Remaining blockers and required follow-up

1. The archived DB supplies parsed Myntra content and a saved report, but not original `.eml`/`.msg` bytes; raw MIME-level relay/authentication replay remains unavailable.
2. The actual API counts and UI data binding agree, but the browser UI was not launched for a visual render check.
3. Add message-part offsets or another source locator for each signal; the current stable evidence reference hashes a detector summary, not the original email span.
4. Use an independently labeled, sufficiently large dataset before making precision/recall or production-readiness claims. Current examples are not enough.

**Phase exit decision:** Phase Two regression gate complete. The required regression criteria pass: the stored parsed Myntra false positive is reproduced and corrected by tests; PSL-aware domain alignment is covered; parser, IOC and HTTP API URL counts reconcile; score-ledger outputs are bounded and auditable; and the complete backend suite passes. The report makes no production-level precision/recall claim. The raw MIME and a browser-rendered UI capture are unavailable limitations, not failed regression gates. Wait for explicit user approval before Phase Three.
