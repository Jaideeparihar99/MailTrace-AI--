# Phase 5 — Step 26: Dataset Inventory, Label Taxonomy & Privacy

**Status:** Inventory and policy artifacts created; dataset is **not approved for new training or production validation**. No model training was run. The existing raw inputs were not edited, downloaded, or uploaded.

## Deliverables

- Machine-readable inventory: `backend/tests/fixtures/dataset_manifest.v1.json`
- Proposed taxonomy/labeling guide: `backend/tests/fixtures/LABELING_GUIDE_v1.md`
- Source-grouped split specification: `backend/tests/fixtures/meajor_source_group_split.v1.json`
- Reproducible metadata-only split audit: `backend/scripts/audit_meajor_source_split.py`
- Existing synthetic examples remain in `backend/tests/fixtures/phase4_step16/` and `backend/tests/fixtures/phase4_supplemental/`; no additional email samples were necessary.

## Repository and model workflow

The current model workflow is under `backend/services/email_ai/`: dataset loading/validation (`dataset.py`), binary phishing training (`train_phishing_l3.py`, `train_phishing_l3_stable.py`), calibration (`calibrate_phishing_l3.py`), and source evaluation. The current tracked interface is binary `LEGITIMATE`/`PHISHING`; it does not implement the five threat classes in the new guide. Training metadata names the normalized MeAJOR file and stores its digest, row counts, random seed, split sizes, and model artifact digest.

Existing training uses seeded stratified random row splits (approximately 70/15/15). That is repeatable, but it does not group by campaign, source, or conversation, so related messages can cross train/validation/test partitions. Separate leave-source-out evaluation artifacts exist and explicitly remain non-production-ready; they do not establish campaign-disjoint splits. Model manifests correctly say `production_ready: false` and require organization-specific validation.

## Inventory findings

| Asset | Local inventory | Provenance and labels | License/privacy status | Readiness |
|---|---|---|---|---|
| MeAJOR binary model corpus | Raw CSV 191,121,228 bytes; normalized JSONL 258,888,367 bytes. 108,685 input rows; 106,290 normalized rows. | Zenodo record 18471483. The local raw CSV MD5 matches the record's published checksum. Labels: 58,362 `LEGITIMATE` (54.91%) and 47,928 `PHISHING` (45.09%). Sources recorded: TREC-05/06/07. | Zenodo record describes entity-removal anonymization, but its reviewed Rights section does not declare a license; source-component rights are unresolved. Keep the data sensitive and local. | Existing model-training source, but block future training/commercial reuse until legal and data-quality review. |
| Phishing-specific provisional corpus | 2,982 raw files / 42,346,327 bytes; 2,981 prepared rows: 2,225 train, 556 dev, 200 holdout. | 481 Nazario phishing samples plus 2,500 Enron ham. All prepared labels are curator/source-folder labels, not project-human-reviewed. Split hashes show zero exact cross-split overlap. | Nazario corpus license file states CC BY 4.0, subject to attribution and other rights. Enron has no corpus-wide license identified in repository records; CMU asks users to be privacy-sensitive. No raw message redistribution. | Provisional evaluation only; class ratio 83.86% ham / 16.14% phishing, and no campaign-level audit is recorded. |
| SpamAssassin provisional corpus | 3,899 raw files / 21,105,874 bytes; 3,897 prepared rows: 2,958 train, 739 dev, 200 holdout. | `easy_ham` and `spam_2`; labels: 2,500 ham / 1,397 spam. All prepared rows marked not human-reviewed. Zero exact cross-split SHA-256 overlaps. | Source README says original senders retain copyright; no blanket message-content license identified. Full headers are present in the original corpus; keep offline and do not redistribute. | Provisional spam policy evaluation only; omits `hard_ham`, uses historical data, and has no campaign/thread audit. Spam is not equivalent to phishing. |
| Phase 4 Step 16 corpus | 8 synthetic `.eml` fixtures; manifest includes per-file SHA-256, rationale, and expected parser outputs. | Authored synthetic; 2 benign and one each phishing, credential harvesting, BEC/payment change, suspicious/inconclusive, malformed, and authentication edge case. | Existing README reports fictional `.invalid` values and no real mailbox content. Independent human review is not performed. | Small regression set only, not a representative classifier benchmark. Several labels describe parser/test conditions rather than threat classes. |
| Phase 4 supplemental corpus | 8 synthetic parser/normalization `.eml` fixtures. | Authored synthetic scenarios; separate scenario manifest. | `.invalid` domains; no third-party source documented. | Parser robustness only, not an accuracy dataset. |
| Phase 4 blind-review packet | 8 blinded copies of Step 16 fixtures. | Review sheet is pending and has no completed reviewer decisions. Maintainer key/revealing files are separated per README. | Synthetic per packet README; keep maintainer key restricted. | No independent label adjudication has occurred. |
| Phase 4 holdout file | `holdout.jsonl` contains 200 blank template rows; split metadata says `holdout_actual_sample_count: 0`. | No email content, labels, or actual holdout samples. | Template only. | Must not be counted as 200 evaluation examples. |
| Other local EMLs | 9 unlabelled samples: root forensic sample, backend test-data sample, three backend test samples, and four thread smoke samples. | Provenance/review is insufficient; filenames are not ground truth. | Potential identifiers or live indicators are not verified safe. Do not upload, visit, or train on these until separately reviewed and sanitized. | Excluded from labeled datasets and training. |
| Local model binaries | Three `.joblib` files (1,178,939; 1,179,365; and 19,578,736 bytes) plus JSON manifests. | Binary phishing classifier trained from MeAJOR; manifests identify versions 1.0.0/1.1.0 and source digest. | Local artifacts are Git-ignored. License obligations follow the training data and remain unresolved. | Existing experimental artifacts only; manifests mark them non-production-ready. |

All `backend/data/` datasets and `.joblib` files are local/Git-ignored in this checkout. The data workflow has raw and prepared corpus files, but the raw content is not part of a clean Git clone. The `.part` partial download and two quarantined suspect CSVs under `backend/data/email_ai/raw/` are not training inputs; keep quarantined and excluded until their source/integrity is reconciled. Aggregate storage and file counts are recorded in the JSON manifest; no sample bodies are included in either new artifact.

## Data-quality and leakage audit

1. **MeAJOR exact duplicates:** the normalization audit reports 2,394 duplicate rows removed and one invalid-label row skipped. A separate reproducible whitespace/case-normalized `text` fingerprint pass on the current 106,290-row normalized file found 28 duplicate groups / 31 extra duplicate rows, with no conflicting labels among those groups. None of those groups cross the TREC source groups. Deduplication is therefore not complete under this normalization policy, although the observed exact duplicate groups do not cross the source-grouped folds.
2. **Split leakage:** current model scripts use stratified random row splits. This can leak near-identical campaign messages or source-specific artifacts across partitions. I added a metadata-only three-fold leave-one-source-out split manifest: each TREC source is held out as a whole, and all rows from the other sources form that fold's training partition. It records class counts, dataset SHA-256, and duplicate audit results, without email content or per-message IDs. This blocks source-family overlap and the observed exact cross-source duplicates, but campaign/thread near-duplicate overlap remains unassessed. Existing cross-source evaluation results remain explicitly non-production-ready.
3. **Prepared evaluation corpora:** split SHA-256 overlap is zero in the phishing-specific and SpamAssassin prepared manifests. That only rules out exact raw-file duplicates across their splits; it does not rule out near duplicates, campaign overlap, topic overlap, or label noise.
4. **Label taxonomy mismatch:** MeAJOR is binary. Prepared public corpora use source-derived `ham`/`spam` or `ham`/`phishing` proxy labels. None provide a complete, project-adjudicated `BENIGN`, phishing/credential theft, BEC, spam, uncertain taxonomy. `ham` is not proof of benign intent; spam is not necessarily malicious.
5. **Class coverage/imbalance:** the synthetic corpus has one example for most threat classes. The phishing-specific corpus is heavily ham-dominant; SpamAssassin has only easy ham plus spam in the prepared set. BEC, multilingual enterprise, image/attachment, thread/campaign and current organization-specific cases are not well represented.
6. **Human review:** the 8-sample blind review packet is pending. The public-source prepared datasets explicitly say `not_human_reviewed`. No external or commercial benchmark should be described as independently adjudicated.
7. **Privacy/licensing:** the Enron corpus contains historical real corporate correspondence; SpamAssassin samples preserve original sender copyright; MeAJOR's record has no license declaration in its reviewed Rights metadata. Raw corpora and model binaries are excluded from Git, but repository ignore rules do not resolve reuse, retention, or licensing questions.
8. **Unlabelled samples:** nine local `.eml` files have inadequate provenance for training. Treat them as potentially sensitive/untrusted evidence and isolate them pending review.

## Follow-up completed for the requested pre-Step-27 actions

- **License review:** checked the publisher/maintainer records. MeAJOR's reviewed Zenodo Rights metadata has no declared license; Enron has no corpus-wide license in the reviewed CMU notice and is explicitly privacy-sensitive; SpamAssassin says message copyright remains with original senders; Nazario's license file specifies CC BY 4.0. These known terms are recorded in the manifest. This does not grant rights or clear commercial reuse. MeAJOR and Enron-derived use remain blocked pending written rights-holder/legal approval.
- **Blind review:** verified all 8 independent-review rows are pending and none are complete. The packet is prepared and blind; I did not fill it or act as a substitute independent reviewer. An independent person must complete it before reconciliation.
- **Leakage-resistant split:** ran `backend/scripts/audit_meajor_source_split.py` on the local normalized MeAJOR dataset. It wrote `backend/tests/fixtures/meajor_source_group_split.v1.json` with three leave-one-source-out folds, all 106,290 rows, class counts, dataset SHA-256, and zero exact normalized-text duplicate groups crossing source groups. No message text or per-message IDs are in the manifest. No model was trained.
- **Existing source-held-out result:** the prior local uncalibrated evaluation artifact (`backend/data/email_ai/metadata/source_holdout_all.json`) reports false-positive rates of 30.86% on TREC-05, 8.55% on TREC-06, and 14.57% on TREC-07. These are previously recorded results, not a fresh run; their variance reinforces that the current model is not ready for production use.

## Label taxonomy and handling rules

The proposed v1.0 guide in `backend/tests/fixtures/LABELING_GUIDE_v1.md` adds `BENIGN`, `PHISHING_CREDENTIAL_THEFT`, `PHISHING_OTHER`, `BEC`, `SPAM_UNSOLICITED`, and `UNCERTAIN_NEEDS_REVIEW`. One primary label is used for exclusive metrics; overlapping behaviors are recorded as secondary tags. BEC takes precedence when deceptive business transaction control is the central objective; credential phishing takes precedence when obtaining authentication secrets is central. Ambiguity stays uncertain. Parser malformedness and authentication edge cases remain orthogonal metadata, never threat labels.

## Privacy, retention, and handling

- Do not send raw or private email to public reputation, model, DNS, or enrichment services during labeling or dataset preparation.
- Keep raw inputs immutable and local. Write sanitized/normalized copies separately with a transformation log, hashes, access control, and a documented deletion/retention schedule.
- Never include message bodies, full addresses, live URLs, attachment bytes, tokens, or identifying notes in Git-tracked manifests/reports. The two new artifacts contain inventory metadata only.
- Keep raw public email corpora and ignored trained model binaries out of public Git. Public availability is not permission to redistribute or commercialize.
- The repository has no approved retention duration for raw public email artifacts; this remains a policy gap.

## Prioritized remediation

1. **Blocker — legal/source approval:** resolve MeAJOR/component rights and Enron reuse terms for commercial and derivative model use; record attribution/obligations for Nazario and SpamAssassin.
2. **Blocker — label adjudication:** have an independent reviewer adjudicate an initial stratified sample and disagreements; do not mark the Step 16 packet reviewed until reconciliation succeeds.
3. **High — leakage control:** canonicalize and deduplicate by normalized body/message fingerprints; add campaign/thread/source grouping and time-aware frozen holdout. Keep source/campaign groups intact across splits.
4. **High — taxonomy mapping:** map source labels only to provisional labels, add explicit unknown/uncertain handling, and build reviewed BEC and credential-theft labels from permitted/synthetic data.
5. **High — privacy control:** add a documented sanitization/PII scan and retention/deletion process before any real or public email is used beyond local evaluation.
6. **Medium — coverage:** expand benign hard negatives, modern phishing, BEC/payment change, spam, multilingual and MIME/attachment cases with provenance and reviewer status; balance by campaign rather than duplicating rows.
7. **Medium — reproducibility:** record exact dependency/runtime versions, source archive checksums, normalization code version, split-group IDs, and model manifest in a tracked non-sensitive evaluation packet.

## Verification and limitations

Read-only inventory scripts counted files/bytes, summarized manifests/labels without printing message bodies, checked the local MeAJOR archive MD5 against Zenodo, counted normalized text duplicates, compared prepared split SHA-256 sets, and inspected model/data workflow code. The new source split audit read normalized text locally only to compute hashes and aggregate counts; it emitted no message content. No training, evaluation run, email-body disclosure, dataset download, URL visit, or provider submission occurred in this follow-up. Campaign-level near-duplicate detection was not run for the two public evaluation corpora or across the TREC sources.

Primary source/license references reviewed: [MeAJOR Zenodo record](https://zenodo.org/records/18471483) (describes sources and anonymization; license field is not populated in the reviewed Rights section), [Nazario corpus CC BY 4.0 license](https://monkey.org/~jose/phishing/LICENSE.txt), [CMU Enron dataset notice](https://www.cs.cmu.edu/~enron/), and [SpamAssassin public corpus README](https://spamassassin.apache.org/old/publiccorpus/readme.html).

## Step 27 handoff

**Next action:** have an independent reviewer complete `backend/tests/fixtures/phase4_human_review/blind_packet/review_sheet.csv`, then reconcile from `backend/` with `.\venv\Scripts\python.exe scripts\reconcile_phase4_blind_review.py`. Obtain written rights approval for MeAJOR and Enron-derived data, then complete campaign/thread near-duplicate grouping before using these folds for model decisions. To regenerate the metadata-only grouped split after dataset changes, run from `backend/`: `.\venv\Scripts\python.exe scripts\audit_meajor_source_split.py`. Step 27's prompt was not supplied, so no training action is started here.
