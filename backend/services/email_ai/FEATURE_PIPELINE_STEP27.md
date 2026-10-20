# Step 27 - leakage-safe email feature pipeline

## Contract
The prediction target is the separately curated dataset label (current compatibility: provisional LEGITIMATE / PHISHING). It must not be inferred from parser verdicts. Raw evidence, normalized features, model output, and final risk score are separate. Model output and final risk score remain null during preprocessing.

## Use
Call extract_features(existing_parse_email_result). This reuses the existing parser output and does not invoke a second parser. The feature stage makes no network calls, does not visit URLs, does not execute attachments, and does not mutate the parser result. Defaults cap text at 200,000 characters, subject at 20,000 characters, and URLs at 500. Missingness and truncation are explicit. Model vectors use a strict allow-list synchronized with `feature_schema.v1.json`; unknown feature names fail closed. The authentication-results trust flag is true only when the parser supplies the boolean `true` (not a truthy string).

Example workflow:
1. Run the existing approved parser in its separately configured intake/investigation stage.
2. Call extract_features(parser_result) to build a deterministic feature record.
3. Keep dataset label and provenance in a separate row/sidecar, never in normalized_features.
4. Call grouped_split(dataset_rows, seed=2701) before any learned transformation. The split manifest includes dataset and per-split hashes, schema/pipeline and Python versions, ratios, requested grouping/time policies, near-duplicate settings, strategy, and counts.
5. Fit vectorizers/classifiers only on split['splits']['train']; evaluate on dev/test without fitting on them.

## Features and availability
- Text: normalized subject, plain body or visible HTML fallback, concatenated model text; missing and truncation flags.
- Numeric: bounded character/word counts; URL count, unique valid host count, malformed host count, query/@/punycode indicators; header, Received-hop and attachment counts.
- Categorical: subject/body/header/Received availability, header presence, body source, timestamp-format trustworthiness, reported SPF/DKIM/DMARC values and availability, authentication trust flag, parser status.
- Lexical: urgency/credential/financial terms, punctuation counts, uppercase ratio, IP-literal URL, non-ASCII and bidi/invisible-control indicators. These are heuristics, not verdicts.
- Provenance: each feature family names its source paths and deterministic transformation class.

## Split strategy
Campaign/thread/conversation/duplicate-group IDs are connected with normalized exact-text fingerprints so related records stay together. Source-level grouping is enabled when at least three distinct source values exist. If every record has a timezone-aware timestamp, groups are assigned chronologically; otherwise stable seeded SHA-256 ordering is used. Fewer than three independent groups fails closed. Near-duplicate candidates are generated locally using token-set SimHash bands, then joined when Jaccard similarity is at least 0.80. Explicit near_duplicate_group_id is also honored. Candidate buckets above 250 rows are skipped to bound worst-case work, so this is conservative approximate grouping, not a guarantee of semantic duplicate detection. When grouped time ranges overlap across train/dev/test boundaries, the temporal split fails closed rather than claiming a strict chronological holdout.

## Verification command
From the backend directory, run: `.\venv\Scripts\python.exe -m pytest -q tests\test_phase5_step27_feature_pipeline.py`
Existing parser regression command: `.\venv\Scripts\python.exe -m pytest -q tests\test_phase3_step11_header_mime_parsing.py tests\test_phase3_step12_url_extraction.py tests\test_phase3_step13_ioc_normalization.py`

## Learned transforms
The included scikit-learn Pipeline learns TF-IDF vocabulary during fit(). fit_text_classifier accepts only explicitly supplied training records and labels. Callers must pass the training partition only; never fit vocabulary, scaling, or selection on dev/test. scikit-learn is already an existing project dependency; no dependency was added.

## Step 26 constraints and unresolved concerns
Step 26 says MeAJOR and Enron-derived license/reuse status is unresolved, public labels are provisional/not independently reviewed, and campaign/near-duplicate audits are incomplete. This step does not authorize training or commercial reuse. The generic trainer, MeAJOR trainer, stable trainer, calibration entrypoint, and source-holdout evaluator now enforce the approval gate and grouped split contract; no row-level random-split fallback is permitted in those paths. Existing model artifacts were not retrained. Exact duplicates and detected near-duplicates are grouped, but missed near-duplicate/campaign overlap, source-specific artifacts, label noise, rights, and retention policy remain open. Reported Authentication-Results headers are untrusted evidence, not cryptographic validation.


## Authentication evidence boundary

Authentication-result features are evidence reported by the existing parser, not independently verified authentication facts. They must not be interpreted as proof of sender identity or message legitimacy. A result can be absent, malformed, attacker-controlled, or parsed from an untrusted header; the trust indicator only records the parser-provided trust flag and does not independently validate DNS, signatures, or DMARC alignment.


## Training and calibration readiness gate

All training, calibration, and source-holdout fitting paths must require a dataset-hash-bound approval JSON at `backend/data/email_ai/metadata/training_approval.json` (or an explicitly supplied manifest for the generic CLI). The v1 schema is `training_approval.schema.v1.json`. In addition to `approved_for_training: true`, the manifest must bind the exact dataset bytes and list every component path/source/SHA-256; each rights, label, and privacy decision must cite an existing evidence file whose SHA-256 is verified. Label approval requires explicit independent review, a positive reviewed count, and a reconciliation hash matching its evidence. The gate intentionally fails closed while MeAJOR/Enron rights, privacy/retention, or independent label review remain unresolved; it does not manufacture approval.

The legacy MeAJOR trainer, stable trainer, calibration entrypoint, and generic `train.py` now use grouped partition logic instead of random row splits. If the available source/campaign groups cannot place both binary classes in every required partition without overlap, the pipeline raises an error rather than falling back to row-level random splitting. TF-IDF is fitted through the model pipeline on the train partition only. The existing trained model files are not overwritten by this remediation.

## Continued remediation verification (2026-10-19)

- Fixed a real acceptance gap: `train_phishing_l3_stable.py` imported the approval checker and later referenced `approval` in its output manifest, but `main()` did not invoke the checker. The entrypoint now checks approval before creating output directories or fitting a model.
- Hardened approval validation: dataset must exist; SHA-256 must be lowercase 64-character hexadecimal and match the exact current bytes; `approval_date` must be a real ISO `YYYY-MM-DD` date; malformed JSON/object and missing approval fail closed.
- Grouped-split manifests now include per-partition `LEGITIMATE` and `PHISHING` class counts. Partition validation still fails closed if any partition lacks either class.
- Expanded readiness tests for malformed manifests, malformed hashes, invalid dates, dataset mutation invalidating a previous approval, per-partition class counts, and campaign/thread group isolation.
- Targeted Step 27 regression suite: **57 passed in 5.05 seconds**. Python compilation passed. Stable trainer smoke test exited nonzero with the expected `TRAINING_BLOCKED: approval manifest missing` message.
- External blockers remain: MeAJOR rights and Enron-derived reuse/privacy approvals are not documented as granted; the independent blind-review sheet still has **8/8 rows PENDING**. No approval manifest was created; no training/calibration was run.

## Step 27 continued blocker-resolution audit (2026-10-19)

- Fixed direct-call safety gaps: `model.train_model()` now reloads and validates the approved dataset and rejects caller-supplied rows that differ from its normalized content before splitting/fitting/output writes; calibration fitting and source-holdout evaluation helpers enforce the approval gate directly, not only from their CLI entrypoints.
- Source-isolated training splits now require source metadata on every row and at least three distinct source groups. Missing provenance, conflicting `source`/`source_group`, or fewer than three sources fails closed instead of silently downgrading to a row/hash split.
- Source-holdout evaluation audits canonical exact duplicates and detected near-duplicate pairs across source families before fitting; cross-source duplicates block the evaluation. Near-duplicate detection remains approximate and skips oversized refined buckets, so it is not a proof that no semantic duplicates exist.
- Added `training_approval.schema.v1.json`. The runtime gate additionally verifies component file hashes and hashes of actual evidence files for rights, independent label adjudication, and privacy/retention approval. No production approval manifest exists.
- The current normalized MeAJOR JSONL was streamed read-only: 106,290 records, zero malformed JSON lines, SHA-256 `c0fe5fef82ab284b74e19078b54dc4820de49ef29e7576731abff3c8ecaf3ac5`; labels 58,362 LEGITIMATE / 47,928 PHISHING. Source counts: trec5 47,365 (27,796 LEGITIMATE / 19,569 PHISHING), trec6 14,978 (11,188 / 3,790), trec7 43,947 (19,378 / 24,569). No campaign, thread, duplicate-group, or timestamp metadata fields were present. The split therefore cannot claim temporal isolation; it depends on source grouping plus text duplicate detection.
- The full current-dataset near-duplicate grouped-split run was attempted but did not return a verifiable result from the execution bridge; no split result is claimed. The prior Step 26 exact-duplicate audit remains the available evidence (28 groups / 31 extra rows under its normalization; no cross-source overlap found). A full near-duplicate/campaign audit across TREC sources and the separate public evaluation corpora remains open.
- Blind packet review CSV: 8 rows, 8 PENDING, 0 completed, 0 disputed, 0 invalid rows in the current packet. All 8 IDs are stable non-identifying `RV-...` values and map to the private key; all blinded email copies exist and match the recorded hashes. Reviewer labels and identities remain blank. Added explicit taxonomy rubric and packet-integrity regression test; packet preparation is not adjudication.
- Verification: Python compilation passed. Step 27 readiness tests: 25 passed in 1.94 seconds. Blind-review reconciler tests: 4 passed in 0.34 seconds. Full backend suite: 636 passed, 1 skipped, 16 subtests passed in 56.94 seconds. No training/calibration/artifact overwrite was run.

**Current disposition: STEP 27 BLOCKED.** The legal rights, privacy/retention, and independent label adjudication dependencies remain outstanding, and the full-dataset near-duplicate audit still lacks a verified result.

## Final verification addendum (2026-10-19, after all Step 27 code changes)

### Final verification evidence

- Python compilation passed for `training_readiness.py`, `model.py`, `train.py`, `train_phishing_l3.py`, `train_phishing_l3_stable.py`, `calibrate_phishing_l3.py`, `evaluate_phishing_l3_sources.py`, `feature_pipeline.py`, and the Step 27 readiness tests.
- Full backend suite: **636 passed, 1 skipped, 16 subtests passed in 36.78 seconds**; exit code 0.
- Final fail-closed CLI smoke checks passed for generic `train.py`, MeAJOR trainer, stable trainer, calibration entrypoint, and source-holdout evaluator. Each exited nonzero with the expected missing-approval block before training/evaluation.
- Final targeted suite before the post-load recheck hardening: **74 passed in 6.80 seconds** across Step 27 feature/readiness, blind-review reconciliation, parsing, URL/IOC, model-path and analysis-API tests. The final full suite above ran after the post-load recheck changes.
- Both `training_approval.schema.v1.json` and `feature_schema.v1.json` parse as valid JSON.

### Current dataset metadata and split limitations

The normalized MeAJOR JSONL was streamed without printing message text. It contains 106,290 records, zero malformed JSONL records, SHA-256 `c0fe5fef82ab284b74e19078b54dc4820de49ef29e7576731abff3c8ecaf3ac5`, with 58,362 LEGITIMATE and 47,928 PHISHING. Source counts and class counts are:

- `trec5`: 47,365 (27,796 LEGITIMATE; 19,569 PHISHING)
- `trec6`: 14,978 (11,188 LEGITIMATE; 3,790 PHISHING)
- `trec7`: 43,947 (19,378 LEGITIMATE; 24,569 PHISHING)

No campaign, thread, duplicate-group, or timestamp fields are present in this normalized dataset. Temporal isolation is therefore unavailable from current metadata. A full-dataset near-duplicate grouped-split execution was attempted but returned no verifiable result from the execution bridge; no successful split or near-duplicate coverage claim is made. The code now requires source metadata for training splits, requires at least three distinct source families, and blocks source-holdout evaluation if it detects cross-source exact or near-duplicate candidates. Approximate detection limitations remain.

### Rights / privacy / review evidence

- Added `STEP27_DATASET_RIGHTS_REVIEW_REQUEST.md` with source-by-source evidence, requested decision scope, and an explicit approval checklist. It is a prepared request only; no reviewer was contacted and no approval was received.
- MeAJOR Zenodo record 18471483 identifies Version 2.0 (February 2026), 108,685 source samples and component sources TREC-05/06/07, Nazario, and Nigerian Fraud. Its Rights > License field is blank in the reviewed record. The local corpus is derived from multiple components, so component-level rights remain unresolved.
- CMU's Enron page describes real historical corporate correspondence and asks users to be privacy-sensitive; the page also links to 2026 material raising authenticity/integrity concerns. No corpus-wide license or approved retention schedule was found in repository evidence.
- Nazario's reviewed notice is CC BY 4.0, but that notice alone does not resolve rights for other MeAJOR components or privacy/personality rights. SpamAssassin's official README says message-text copyright remains with original senders and warns against testing the corpus on a live system.
- The review packet has 8 unique non-identifying `RV-...` IDs, all matching the private key and the SHA-256 of each blinded email copy. Review status remains **8 PENDING, 0 COMPLETE, 0 DISPUTED, 0 invalid packet-integrity rows**. Reviewer and label fields are blank. The README now includes the exact fixture taxonomy rubric and instructions to leave uncertain cases inconclusive rather than force a verdict.
- The approval manifest remains absent. Evidence-backed gate checks now require a hash-verified dataset component list, exact current dataset hash, existing hashed evidence files for each rights/label/privacy decision, independent label review with a reconciliation hash, and ISO review dates. No real approval evidence was available.

### Final disposition

**STEP 27 BLOCKED.** All safe technical fixes were applied and the full backend suite passes. The mandatory blockers remain: written rights decisions for MeAJOR and its upstream components (including Enron-derived material), privacy/retention approval, independent adjudication of the eight blind-review rows, and a verifiable full-dataset near-duplicate audit. No training, calibration, model-artifact overwrite, approval-manifest creation, Git stage, or commit occurred. Workspace changes were preserved.
