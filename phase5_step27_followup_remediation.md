# MailTrace-AI ??? Step 27 Follow-up Remediation Report

**Report date:** 2026-10-19
**Workspace:** Local project checkout
**Execution method:** Local command bridge
**Overall status:** `PARTIALLY REMEDIATED ??? TRAINING BLOCKED PENDING EXTERNAL APPROVALS`

## Executive summary

The five Step 27 concerns were addressed in code, documentation, tests, and explicit fail-closed controls where the decision requires a rights holder, legal reviewer, or independent human label reviewer. Existing training/calibration code paths now use the grouped splitter instead of random row splits. A hash-bound approval gate prevents training, calibration, and source-holdout model fitting until dataset rights, independent label adjudication, and privacy/retention approvals are recorded. Near-duplicate candidate generation was strengthened and authentication-result semantics were clarified.

**No model was retrained and no existing model artifact was overwritten.** The Step 26 inventory says MeAJOR rights are unresolved, Enron-derived reuse is not cleared, and the blind-review packet is pending. These are real approval blockers; code cannot legitimately resolve them by inventing a license or pretending to be an independent reviewer.

## Concern-by-concern disposition

### 1. MeAJOR / Enron provenance, licensing, and label review

**Status: MITIGATED BY ENFORCEMENT; EXTERNAL APPROVAL STILL BLOCKED.**

The Step 26 inventory was read before changes. It records:

- MeAJOR / Zenodo record `18471483`: the reviewed Rights metadata does not declare a license; source-component terms remain unreconciled.
- Enron-derived messages: no corpus-wide license was identified in the reviewed CMU notice; privacy-sensitive historical correspondence requires careful handling.
- Nazario source component: Step 26 records CC BY 4.0 terms, including attribution/modification obligations where applicable.
- SpamAssassin: Step 26 records original sender copyright and no blanket message-content license.
- The eight-row blind-review packet is still pending; public-source labels are source proxies, not independently adjudicated project labels.

No external legal conclusion was asserted, no dataset was downloaded, and no source/license was changed. A new fail-closed approval contract requires a named reviewer, approval date, exact dataset SHA-256, rights status `APPROVED`, label status `ADJUDICATED`, and privacy status `APPROVED`. The gate does not infer any of these.

**Still required:** written rights-holder/legal review for each relevant component and derivative model use; a named independent reviewer must adjudicate the blind packet and record disagreements/reconciliation. Until then, MeAJOR training/calibration/evaluation model fitting remains blocked.

### 2. Legacy random row splits in training and calibration

**Status: CODE MIGRATION COMPLETE; RUNS BLOCKED UNTIL APPROVAL.**

The following entrypoints now use `split_labeled_rows()` and the Step 27 `grouped_split()` contract rather than `train_test_split`:

- `backend/services/email_ai/train_phishing_l3.py`
- `backend/services/email_ai/train_phishing_l3_stable.py`
- `backend/services/email_ai/calibrate_phishing_l3.py`
- `backend/services/email_ai/model.py` (called by `train.py`)

`backend/services/email_ai/evaluate_phishing_l3_sources.py` already uses leave-one-source-out folds; its CLI now also requires the same approval gate before fitting fold models. The generic CLI `backend/services/email_ai/train.py` requires an explicit or default approval manifest, and `model.train_model()` also checks approval so direct calls cannot bypass the gate.

Grouping retains source/source_group, campaign, thread, conversation, duplicate-group, near-duplicate-group, and trustworthy timestamp metadata. When the available groups cannot produce train/dev/test partitions with both binary classes while preserving group boundaries, the splitter fails closed; it does not fall back to random row splits. TF-IDF vocabulary/scaling-like learned text transforms remain inside the model Pipeline and are fitted only by `fit()` on the training partition. Grouped split metadata is included in model manifests.

**Data limitation:** the local MeAJOR inventory has only three named TREC source families and no trustworthy timestamp/campaign/thread fields documented in the normalized schema. Strict source isolation can therefore produce highly uneven partitions or a class-deficient partition; the pipeline intentionally rejects that case rather than making misleading metrics. A separate frozen, approved source/time/campaign holdout design is still needed for robust final validation.

### 3. Near-duplicate leakage

**Status: IMPROVED; APPROXIMATE DETECTION REMAINS A LIMITATION.**

`backend/services/email_ai/feature_pipeline.py` now collapses exact canonical duplicates to representatives before approximate candidate generation. Oversized SimHash buckets receive a second-band refinement instead of being discarded at the first size threshold. Similarity remains local-only, using token-set Jaccard threshold `0.80`; refined buckets still above the bound remain skipped to prevent unbounded quadratic work. The schema and docs state these limits explicitly.

This reduces avoidable candidate explosion and missed candidates from oversized first-pass buckets, but does **not** prove semantic duplicate absence. Paraphrases, templated campaigns, translations, image/attachment-only similarities, and very large refined buckets can still be missed. No email URLs are fetched and no attachment is executed.

### 4. Authentication results are evidence, not independent proof

**Status: DOCUMENTED AND TESTED.**

`feature_pipeline.py` treats `authentication_results_trusted` as true only when the existing parser supplies the Boolean value `true`; a truthy string such as `"false"` is not accepted. The feature schema and Step 27 docs now explicitly state that SPF/DKIM/DMARC values are parser-reported evidence and do not independently prove sender identity, signature validity, DNS state, alignment, or legitimacy. Preprocessing does not perform external DNS/signature verification.

### 5. Retraining and production readiness

**Status: CORRECTLY NOT PERFORMED.**

No training/calibration/evaluation model fit was executed because approvals are missing and Step 26 label review is pending. The approval gate was checked directly and returned:

`TRAINING_BLOCKED: approval manifest missing: data\email_ai\metadata\training_approval.json...`

No model binary or production manifest was overwritten. No production-readiness claim is made. Once approvals are complete, rerun the grouped split audit first, inspect class counts/group isolation, then train only if every partition passes validation; report independent holdout metrics and label denominators before considering deployment.

## Files changed in this remediation

- `backend/services/email_ai/training_readiness.py` ??? new dataset-hash-bound approval gate, grouped JSONL loader, grouped partition validation.
- `backend/services/email_ai/dataset.py` ??? preserve only allow-listed source/group/time metadata during row validation.
- `backend/services/email_ai/model.py` ??? remove internal random row split; use grouped partitions; require approval before fitting; record approval/split manifest.
- `backend/services/email_ai/train.py` ??? add `--approval-manifest`; require approval before training.
- `backend/services/email_ai/train_phishing_l3.py` ??? grouped partitions, approval gate, manifest provenance; removed random row splitting.
- `backend/services/email_ai/train_phishing_l3_stable.py` ??? grouped partitions, approval gate, manifest provenance; removed random row splitting.
- `backend/services/email_ai/calibrate_phishing_l3.py` ??? grouped partition indices, approval gate, manifest provenance; removed legacy split helper.
- `backend/services/email_ai/evaluate_phishing_l3_sources.py` ??? approval gate before fold model fitting.
- `backend/services/email_ai/feature_pipeline.py` ??? exact-duplicate representative collapse and oversized-bucket refinement.
- `backend/services/email_ai/feature_schema.v1.json` ??? authentication evidence boundary, duplicate detection limits, training gate contract.
- `backend/services/email_ai/FEATURE_PIPELINE_STEP27.md` ??? grouped training, approval gate, and authentication limitations documentation.
- `backend/tests/test_phase5_step27_training_readiness.py` ??? six tests for missing/mismatched approval, independent label status, source grouping, and oversized exact-duplicate buckets.
- `phase5_step27_followup_remediation.md` ??? this report.

Raw dataset files and model binaries were not modified. No external API, network download, URL fetch, or attachment execution was performed.

## Verification performed

### Passed

1. Python compilation for all modified Python modules and the new test module ??? **PASS**.
2. Combined targeted regression command ??? **51 passed in 4.37 seconds (final rerun; earlier rerun was 4.46 seconds)**:

```text
Set-Location -LiteralPath 'C:\Users\ritur\New folder\mailtrace\MailTrace-AI\backend'
.\venv\Scripts\python.exe -m pytest -q -p no:cacheprovider --basetemp='.pytest-step27-remediation-regression' tests\test_phase5_step27_feature_pipeline.py tests\test_phase5_step27_training_readiness.py tests\test_phase3_step11_header_mime_parsing.py tests\test_phase3_step12_url_extraction.py tests\test_phase3_step13_ioc_normalization.py tests\test_email_ai_model_path_resolution.py tests\test_phase4_step17_analysis_api.py
```

3. Focused feature/readiness tests ??? **25 passed in 1.71 seconds**.
4. Existing parser regression tests ??? **21 passed in 0.37 seconds**.
5. Static scan of the four target training/calibration modules ??? **zero `train_test_split()` calls remain; each calls `split_labeled_rows()`**.
6. Direct approval-gate check ??? **expected fail-closed result** because no approval manifest exists.

### Not run / intentionally blocked

- Model retraining and calibration: blocked pending source rights, independent label adjudication, and privacy approval.
- Performance or production-readiness claims: not made.
- Full repository test suite: not run; only targeted tests listed above were executed.

## Exact next actions after external approvals

1. Create `backend/data/email_ai/metadata/training_approval.json` only after the relevant reviewers sign off. The record must contain:
   - `approved_for_training: true`
   - `dataset_sha256` matching the exact current normalized dataset bytes
   - non-empty `reviewer` and `approval_date`
   - `license_review: {"status":"APPROVED","reviewer":"..."}`
   - `label_review: {"status":"ADJUDICATED","reviewer":"..."}`
   - `privacy_review: {"status":"APPROVED","reviewer":"..."}`
2. Re-run the Step 27 readiness and grouped split tests; review all per-partition class counts and source/campaign isolation.
3. If the split fails because three sources cannot support all required partitions, do not weaken grouping silently. Design an independently reviewed source-held-out evaluation plan and document its limits.
4. Run the approved grouped training/calibration entrypoint and preserve model artifacts as versioned, non-production-ready outputs until independent holdout validation passes.
5. Complete the blind-review reconciliation and update dataset inventory/review status only from actual reviewer decisions.

**Final disposition:** Step 27's split-path migration, safety controls, duplicate-detection improvement, authentication evidence boundary, and reporting are implemented and targeted tests pass. Legal/data rights and independent label adjudication remain external blockers; retraining remains disabled by design.

## Independent current-step verification addendum (2026-10-19)

- Re-read the Step 27 contract and Step 26 handoff; corrected a stale sentence in the Step 27 documentation that still described training entrypoints as using legacy row splits.
- Python compilation of the modified Step 27 Python modules and readiness tests passed.
- Independent targeted regression rerun: **51 passed in 4.56 seconds** across feature pipeline, training readiness, parser, URL/IOC, model path, and analysis API tests.
- Repository-wide scan of `backend/services/email_ai/*.py` found no `train_test_split(...)`, `random_split(...)`, `StratifiedShuffleSplit`, or `ShuffleSplit` references in that package.
- The approval manifest is still absent. The readiness test confirms missing approval fails closed; no approval was fabricated and no training/calibration was run.
- Step 27 remains **BLOCKED on external rights/privacy approval and independent label adjudication**. The full repository suite was not run. Numerous unrelated/pre-existing modified and untracked repository paths exist; this remediation did not stage or commit files.
## Continued remediation addendum (2026-10-19, independent re-check)

### Defect found and fixed

A deeper entrypoint audit found `train_phishing_l3_stable.py` imported `require_training_approval` but did not call it at the start of `main()`. Its later report construction referenced an `approval` variable that was never initialized. This meant the stable training entrypoint could begin training without the mandatory gate and then fail later. Added the approval check as the first action in `main()`, before output-directory creation, dataset loading, fitting, or artifact writes. A direct module smoke test now exits nonzero with `TRAINING_BLOCKED: approval manifest missing`.

### Additional hardening and tests

- Approval validator now requires an existing dataset file, a lowercase 64-character SHA-256 hex digest matching current dataset bytes, and a valid ISO `YYYY-MM-DD` approval date.
- Added fail-closed tests for malformed JSON, malformed hash, invalid approval date, and changed dataset bytes invalidating a previously valid approval.
- Grouped split manifest records per-partition class counts; both classes are still required in every partition.
- Added tests proving campaign/thread groups stay within a single partition.
- Re-ran Python compilation successfully.
- Latest targeted regression suite: **57 passed in 5.05 seconds** across feature pipeline, training readiness, header/MIME parsing, URL extraction, IOC normalization, model path resolution, and analysis API tests.
- Readiness test module now contains 12 tests; all pass. Static inspection confirms all six relevant training/model/calibration/source-evaluation entrypoints reference the approval gate.

### Verified external approval state

- `backend/data/email_ai/metadata/training_approval.json`: **absent**. No manifest was created.
- Blind review CSV: **8 rows; 8 PENDING; 0 completed**. No reviewer identity, label, timestamp, or adjudication was invented.
- Step 26 inventory states MeAJOR's reviewed Zenodo Rights metadata has no declared license and Enron has no corpus-wide license identified in the reviewed CMU notice; rights-holder/legal reuse approval remains unresolved. These are evidence of unresolved status, not grants of permission.
- No model training, calibration, or artifact overwrite occurred. The full repository suite was not run. Unrelated workspace modifications and untracked files were preserved; no reset, clean, stage, or commit was performed.

**Disposition remains: STEP 27 BLOCKED.** Technical gaps discovered during this continuation were fixed, but the mandatory rights/privacy and independent label-adjudication dependencies are still unresolved.

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


## Continued remediation and evidence closure ??? 2026-10-19

### Verified dataset facts

- Path: `backend/data/email_ai/normalized/meajor_phishing_binary.jsonl`
- Size: 258,888,367 bytes; 106,290 JSONL records; no malformed records in the existing full scan.
- Recomputed SHA-256: `c0fe5fef82ab284b74e19078b54dc4820de49ef29e7576731abff3c8ecaf3ac5` (matches the previously reported value).
- Source/class counts: trec5 47,365 (27,796 LEGITIMATE; 19,569 PHISHING); trec6 14,978 (11,188 LEGITIMATE; 3,790 PHISHING); trec7 43,947 (19,378 LEGITIMATE; 24,569 PHISHING).
- Exact canonical-text duplicate groups: 28; 31 excess rows; 0 conflicting-label groups; 0 cross-source exact duplicate groups / excess rows under casefold + whitespace-collapse normalization.
- Three leave-one-source-family-out partitions have both labels in train and holdout and do not include the held-out source in training. This is source isolation, not temporal/campaign isolation.

### Audit remains INCOMPLETE

Evidence files: `backend/data/email_ai/metadata/step27_full_dataset_leakage_audit.v1.json` and `.md`. The exact scan completed, but its existing builder retains fingerprint groups in process memory, so strict bounded-memory processing is not verified. Near-duplicate pair counts remain unknown: the previous helper silently omitted refined SimHash sub-buckets above 250 members without recording a count. This was remediated to raise `ValueError` on oversized refined buckets, with a regression test, but the full-dataset near-duplicate audit has not been rerun/completed. No near-duplicate clearance is claimed.

### Changes and verification

- `backend/services/email_ai/feature_pipeline.py`: fail closed on oversized refined near-duplicate candidate buckets instead of silently skipping them.
- `backend/tests/test_phase5_step27_training_readiness.py`: added oversized-bucket fail-closed test, deterministic source-split audit/cross-source exact-duplicate test, and malformed JSONL failure test.
- `backend/services/email_ai/STEP27_DATASET_RIGHTS_REVIEW_REQUEST.md`: expanded decision matrix to Nigerian Fraud and component-by-component rights/privacy/use decisions. Request remains unsent.
- `backend/tests/fixtures/phase4_human_review/blind_packet/INDEPENDENT_REVIEWER_HANDOFF.md` and `independent_review_response_template.json`: prepared secure handoff checklist and blank attestation response template; no labels or identities prefilled.
- Python compilation: exit 0, 0.26 seconds. Targeted Step 27/blind-review tests: 51 passed, exit 0, 3.03 seconds. Full backend suite: 639 passed, 1 skipped, 16 subtests passed, exit 0, 36.05 seconds.
- All five intended entry-point checks were run as modules with the correct generic-trainer `--input` argument. Generic trainer and MeAJOR/stable/calibration/source-holdout paths all rejected the missing approval manifest before fitting; generic trainer output directory was not created. No training or calibration occurred.
- JSON validation passed for the audit evidence, training approval schema, feature schema, and blank reviewer response template. `training_approval.json` remains absent.
- Git status reported 206 entries at final inspection. No files were staged or committed; no reset/clean/checkout or mass revert was run.

### Unresolved mandatory blockers

1. Complete a deterministic SQLite-backed bounded-memory full-dataset exact/near-duplicate audit, quantify every oversized bucket/candidate exclusion, and make the run fail closed on timeout or incomplete coverage. Current audit status is `INCOMPLETE`.
2. Obtain authentic scoped rights decisions for MeAJOR and TREC-05/06/07, Nazario, Nigerian Fraud, Enron-derived data, and SpamAssassin where used. No requests were sent and no legal decisions were fabricated.
3. Obtain authorized privacy/retention approval including lawful/appropriate basis, PII handling, access, retention/deletion, and derived-artifact treatment.
4. Obtain an independent human review of all eight blind cases with attestation, UTC timestamps, hash validation, and separate adjudication for disagreements. Status remains 0/8 complete.
5. Only after those are satisfied, validate real hash-bound evidence and exact dataset/component bytes and create the approval manifest; do not train or calibrate before that point.

**Status: STEP 27 BLOCKED. Step 28 has not been started.**
