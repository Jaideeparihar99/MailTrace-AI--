# Phase 4, Step 20 — Regression Gate and Test Report

**Report date:** 2026-10-19
**Step 20 deliverable:** COMPLETE — current local regression gate and findings documented.
**Phase 4 exit:** **NO-GO / INCOMPLETE** — independent fixture-label adjudication and representative model evaluation remain outstanding.
**Scope:** Local synthetic-fixture validation only. This report does not claim production accuracy, security certification, or hosted CI success.

## A. Executive summary

The latest focused offline regression gate passes: **90 passed, 16 subtests passed**, and the result matches baseline `mailtrace-phase4-step20-offline-v4`. The full backend test suite passes: **537 passed, 1 opt-in live-geolocation test skipped, 16 subtests passed**. Network access was blocked by the evaluator during fixture scoring and the model-enabled diagnostic.

This review fixed two demonstrated disposition gaps. First, an uncorroborated model-only threat prediction now becomes `REVIEW REQUIRED (UNCONFIRMED MODEL SIGNAL)` rather than a confirmed high-risk disposition; the model score and evidence remain available to the analyst. Second, partial parsing now sets the structured `review_required=true` flag and `PARTIAL_EMAIL_PARSE` reason, matching its review-required verdict. The API regression test covers both moderate and high model probability cases.

I also implemented the reviewer handoff validator. It checks independent-review attestation, required labels/evidence, UTC timestamps, unique case IDs, and packet email hashes; label disagreements require a second named adjudicator with rationale. It writes a private report and never changes fixture labels. Four isolated tests cover complete review, incomplete review, disagreement/adjudication, and tampered packet content. The human review itself remains pending because an independent person must provide the decisions.

The model still predicts phishing for one synthetic benign fixture (MT-F16-0002, probability 0.6341). The product now routes it for human review; this is a mitigation, not a model-quality fix. Labels are not independently adjudicated and the corpus is tiny, so the Phase 4 exit gate remains **NO-GO**. A blinded review packet is prepared for an independent reviewer; its expected-label key is kept separate and ignored by Git.

## B. Test commands and observed results

| Check | Command / method | Result |
|---|---|---|
| Focused Phase 2–4 offline regression gate, evaluator and baseline comparison | `cd backend; .\\venv\\Scripts\\python.exe scripts\\run_phase4_offline.py` | **PASS** — 90 passed, 16 subtests passed; baseline v4 matched; exit 0 |
| Blind-review workflow tests | `cd backend; .\\venv\\Scripts\\python.exe -m pytest -q -ra tests\\test_phase4_blind_review_reconciliation.py` | **PASS** — 4 passed |
| Full backend suite | `cd backend; .\\venv\\Scripts\\python.exe -m pytest -q -ra --disable-warnings` | **PASS** — 537 passed, 1 opt-in live-geolocation test skipped, 16 subtests passed |
| Real local model + API/fusion diagnostic | `cd backend; .\\venv\\Scripts\\python.exe scripts\\evaluate_phase4_step18.py --model-enabled --trace-fixture MT-F16-0002` | **DIAGNOSTIC** — 8 synthetic fixtures; model ready; DNS/socket/HTTP blocked; TP=3, FP=1, TN=1, FN=0 over 5 binary-labelled cases |
| Blinded packet validation | `backend/tests/fixtures/phase4_human_review/blind_packet/` | **READY / PENDING REVIEW** — 8 anonymous fixture copies, reviewer sheet has no expected labels, 8 private key rows; key and reconciliation output are Git-ignored |
| Hosted GitHub Actions | Workflow is present; no remote is configured in this checkout | **NOT RUN** |
| Live reputation providers | No authorized provider credentials configured | **BLOCKED / NOT RUN** |

The single full-suite skip is intentional: `tests/test_phase5_step22_live_geolocation.py` requires explicit opt-in and provider approval. No test failure occurred in these runs. No hosted run, provider call, stress test, or cross-platform matrix was performed in this turn.

## C. Fixture, protocol, and baseline inventory

- Primary corpus: `mailtrace-phase4-step16-v1`, **8 synthetic `.eml` fixtures**, manifest at `backend/tests/fixtures/phase4_step16/manifest.json`.
- Manifest SHA-256: `D99AA0AD45D98A62286B1DBCA245930BF375CF45D2568E0E9EBA38391FCB6CE8` (the runner verifies it before evaluation).
- Classes: 2 benign; 1 each phishing, credential harvesting, BEC/payment change, suspicious/inconclusive, malformed email, and authentication edge case.
- Supplemental parser corpus: 8 synthetic fixtures under `backend/tests/fixtures/phase4_supplemental/`; parser regression data only, excluded from accuracy metrics.
- Baseline: `mailtrace-phase4-step20-offline-v4`, stored at `backend/tests/fixtures/phase4_step18/baseline.json`. It records verdict, score, confidence, parser/analysis status, and explicit review-required flags/reasons.
- Canonical runner: `backend/scripts/run_phase4_offline.py`; evaluator: `backend/scripts/evaluate_phase4_step18.py`.
- The canonical evaluator stubs the model path for deterministic policy regression. The separate `--model-enabled` diagnostic runs the local model and actual API/fusion path; all external network access is blocked.
- Reviewer submission validator: `backend/scripts/reconcile_phase4_blind_review.py`; four isolated tests are included in the focused runner. It never modifies labels or marks review complete.
- Labels and rationale were authored with the synthetic fixtures. Their fixture QA status is not independent human label adjudication.

### Blind-review packet

An independent reviewer packet is ready at `backend/tests/fixtures/phase4_human_review/blind_packet/`. Share only its `README.md`, `review_sheet.csv`, and `review_emails/` directory. Do not share `backend/tests/fixtures/phase4_human_review/maintainer_key.json`, the source manifest, or `false_positive_trace.md` before the reviewer records decisions. The packet contains no expected labels; the maintainer key stays outside it and is ignored by Git. Human review remains **PENDING** until an independent reviewer supplies signed/date-stamped decisions and disagreements are adjudicated.

## D. Confusion matrix and evaluation results

### Canonical deterministic policy baseline

The fixed verdict mapping counts `HIGH RISK`/`CRITICAL` as positive and `LOW RISK` as negative. Review-required, suspicious, partial, and inconclusive outcomes are excluded from binary classification, not treated as clean.

| | Predicted positive | Predicted negative |
|---|---:|---:|
| Actual positive | TP = 3 | FN = 0 |
| Actual negative | FP = 0 | TN = 3 |

Binary `n=6`; excluded/inconclusive `n=2`. Precision `3/3=100%`; recall `3/3=100%`; F1 `100%`; false-positive rate `0/3=0%`. These are **stubbed-AI verdict-policy fixture metrics**, not trained-model performance or production accuracy.

### Fresh model-enabled API-path diagnostic

| Fixture | Synthetic manifest label | Model classification (probability) | API verdict / score | Review required |
|---|---|---|---|---|
| MT-F16-0001 | benign | LEGITIMATE (0.4718) | LOW RISK / 29 | No |
| MT-F16-0002 | benign | PHISHING (0.6341) | REVIEW REQUIRED / 49 | Yes — uncorroborated model signal |
| MT-F16-0003 | phishing | PHISHING (0.7345) | HIGH RISK / 85 | No |
| MT-F16-0004 | credential harvesting | PHISHING (0.6907) | HIGH RISK / 85 | No |
| MT-F16-0005 | BEC/payment change | PHISHING (0.5491) | HIGH RISK / 85 | No |
| MT-F16-0006 | suspicious/inconclusive | PHISHING (0.5212) | REVIEW REQUIRED / 49 | Yes — identity alignment unverified |
| MT-F16-0007 | malformed | PHISHING (0.7279) | REVIEW REQUIRED / 75 | Yes — partial parse |
| MT-F16-0008 | authentication edge | LEGITIMATE (0.4924) | SUSPICIOUS / 31 | No |

For binary-labelled cases only (`n=5`: 3 positive, 2 benign), model-classification metrics are TP=3, FP=1, TN=1, FN=0; precision 75%, recall 100%, F1 about 85.7%, false-positive rate 50%. Three cases are excluded. The benign model false positive remains; the disposition safeguard routes it to review instead of asserting HIGH RISK. Since all labels are synthetic and unadjudicated, these numbers are diagnostic only and do not generalize.

## E. Fixes made and coverage

| Finding | Change | Verification |
|---|---|---|
| Model-only threat prediction could appear confirmed despite zero independent evidence | API emits `REVIEW REQUIRED (UNCONFIRMED MODEL SIGNAL)`, `review_required=true`, and `MODEL_THREAT_PREDICTION_UNCORROBORATED`; preserves score/evidence | API regression tests cover probability 0.634 and 0.95, and assert no independent corroboration |
| Partial parse verdict required review but structured flag was false | Sets `review_required=true` and `PARTIAL_EMAIL_PARSE` | Fresh evaluator output and focused/full suites |
| Step 18 evaluation did not export review disposition | Evaluator rows and baseline now include `review_required` and `review_reasons`; disposition policy version is 1.1 | Baseline v4 comparison passes |
| Review sheet exposed expected labels | Added anonymous packet/key separation and changed root notice to direct reviewers to the blinded packet | Packet validation: 8 samples, no expected-label column or label leakage detected |

Current test coverage includes parser/MIME, URL/IOC, explicit states, domain alignment, risk fusion, API outcome, alert policy, and fixture integrity. The full test suite passes locally. No claim is made that every production detector/provider failure mode is fully covered.

## F. Remaining gaps and phase decision

### Completed in this Step 20 review

- Current focused gate and full local suite run and pass.
- Metrics and denominators are reproduced from the fixed corpus and limitations are explicit.
- API review disposition for uncorroborated model-only signals and partial parsing is explicit and regression-tested.
- Review packet is prepared without exposing expected labels to the reviewer.
- Step 20 report is saved here and includes a clear NO-GO recommendation.

### Still incomplete / blocked

1. **Independent label adjudication:** pending a person other than the fixture author. The coding agent cannot truthfully complete this independent review.
2. **Model quality:** one of two benign binary fixtures still receives a phishing classification. Routing prevents a confirmed high-risk disposition without independent evidence, but does not eliminate the model false positive.
3. **Representative holdout evaluation:** only eight synthetic fixtures exist; this is far too small and narrow for reliable model metrics.
4. **Hosted CI:** cannot be verified until the intended repository remote is configured and workflow is triggered.
5. **Live reputation providers:** require authorized credentials and explicit provider testing; these were not available or exercised.
6. **Security scan limitations:** prior heuristic secret scans are not comprehensive for all Git history, binary files, excluded local backups, or personal data. No claim of full secret/privacy audit is made here.

### Prioritized next actions

1. Give the blinded packet to an independent reviewer; collect decisions, rationale, date, reviewer role, and disagreements before revealing expected labels.
2. Resolve disagreements through documented adjudication; preserve unresolved cases as inconclusive and version the labels.
3. Expand the safe, representative holdout and rerun the model-enabled API evaluation; analyze benign false positives before changing thresholds.
4. Configure the intended Git remote, run hosted CI, and review logs.
5. With authorized secrets, test provider success, timeout, rate-limit, invalid-key, and unavailable states without committing credentials.
6. Run a comprehensive history-aware secret/privacy audit before any release.

## Go / no-go recommendation

**Step 20 report and local regression gate: COMPLETE. Phase 4 exit: NO-GO / INCOMPLETE.** The local code/test/report and reviewer-validation workflow are reviewable and reproducible, but the Phase 4 acceptance claim cannot be completed responsibly until an independent person submits labels and a representative model holdout is available. Hosted CI and live provider validation remain unverified. Do not claim production accuracy or start Phase 5 on the basis of this report alone; the remaining work is listed above.
