# MailTrace-AI Step 27 - Dataset Rights and Privacy Decision Request

**Purpose:** obtain written, scoped decisions before training, calibration, model evaluation used for model selection, derivative-model distribution, or redistribution. This is a prepared request only; it has not been sent and no approval is implied.

## Evidence matrix

| Source/component | Verified evidence | Intended uses that need an explicit decision | Current status |
|---|---|---|---|
| MeAJOR, Zenodo record 18471483, Version 2.0 (published February 2026) | Record describes 108,685 anonymized samples sourced from TREC-05/06/07, Nazario, and Nigerian Fraud; its Rights section has no populated license. Local normalized JSONL is 106,290 rows. | Training/fine-tuning; modification and normalization; derivative model weights; commercial and non-commercial use; redistribution of data, embeddings, features, or weights; attribution; upstream component rights. | UNRESOLVED - obtain rights-holder/legal review for MeAJOR and each incorporated source component. |
| TREC-05 / TREC-06 / TREC-07 as represented inside MeAJOR | Local normalized rows carry source values trec5/trec6/trec7. The MeAJOR record identifies them as upstream datasets; separate component license/rights evidence is not recorded in the reviewed local inventory. | Same as above, separately per source component and version. | UNRESOLVED - identify authoritative upstream terms and ensure the MeAJOR publisher could grant the required rights. |
| Enron-derived ham corpus | CMU Enron page describes a real historical corporate email corpus, says it was originally made public during the FERC investigation, notes some redactions and asks users to be privacy-sensitive. No corpus-wide license was identified in the reviewed CMU notice. The CMU page currently also links to 2026 research raising authenticity/integrity concerns. | Training and derivative models; privacy/legitimate-interest or other legal basis; personal data handling; retention/deletion; access controls; redistribution of messages, features, embeddings, or weights; commercial and non-commercial use. | BLOCKED pending authorized legal/privacy decision and authenticity/data-quality review. |
| Nigerian Fraud component as represented inside MeAJOR | MeAJOR Zenodo record lists Nigerian Fraud as an upstream source. The reviewed local inventory does not independently establish the exact upstream release, rights-holder, license, or whether the publisher can authorize derivative-model uses. | Internal and commercial training; normalization and feature extraction; derivative weights/calibrators/embeddings; hosting/distribution; redistribution; attribution; privacy/PII and retention. | UNRESOLVED - identify the exact upstream version and obtain authoritative terms or scoped permission. |
| Nazario corpus component | The reviewed local license notice is CC BY 4.0. Attribution and change notices apply when sharing licensed material; the license does not automatically resolve privacy/personality rights or rights not held by the licensor. | Confirm license applies to the exact samples/version and intended model/data uses; attribution; change notices; redistribution terms; upstream rights. | VERIFIED for existence of CC BY 4.0 notice only; overall inclusion/use inside MeAJOR remains UNRESOLVED. |
| SpamAssassin public corpus (used by separate provisional corpus) | Official README says copyright in message text remains with original senders; full headers may be present and it warns not to test a live system with these messages. No blanket message-content license is identified in the reviewed README. | Training, derived weights, redistribution, privacy/PII, sender-specific rights, retention, attribution, and safe handling of live indicators. | UNRESOLVED for message-content reuse absent additional rights analysis/permission. |

## Decisions requested from the authorized rights-holder/legal reviewer

For each source/component and version, please attach the authoritative license, permission letter, terms of service, or written legal determination and mark each item `APPROVED`, `DENIED`, or `NEEDS_MORE_EVIDENCE`:

1. Internal non-commercial model training and evaluation.
2. Commercial training and evaluation.
3. Cleaning, normalization, deduplication, feature extraction, and other modifications.
4. Creation and internal use of derivative model weights, calibrators, embeddings, and aggregate statistics.
5. Commercial distribution or hosted use of derivative models.
6. Redistribution of raw/normalized emails, excerpts, extracted features, embeddings, model weights, or evaluation outputs.
7. Required attribution, copyright/license notices, change notices, downstream license terms, and source-specific restrictions.
8. Whether each upstream component's rights are covered by the dataset publisher's authority; identify exceptions or excluded components.
9. Permitted retention duration, storage location, access roles, sanitization requirements, deletion triggers, and incident handling for any personal or sensitive email content.
10. Any restriction based on privacy, confidentiality, personality/publicity rights, jurisdiction, or intended user population.

## Privacy and retention decision requested

The repository inventory says no approved retention duration is recorded for raw public email artifacts. A designated privacy/data-protection reviewer must document the lawful/appropriate purpose, minimum necessary data, sanitization/PII controls, access controls, retention schedule, deletion verification, and permitted use of derived artifacts. The Enron-derived material requires particular care because it contains real historical correspondence; public availability alone is not a privacy approval.

## Required evidence to attach

- Reviewer name/role and organization.
- Decision date in ISO `YYYY-MM-DD` format.
- Exact source/version and scope of use.
- Signed approval or authoritative evidence path, retained locally under access control.
- SHA-256 of each evidence file.
- Explicit conditions, exclusions, attribution requirements, retention/deletion terms, and expiry/re-review date if applicable.
- For label approval, the private reconciliation report hash, count reviewed, independent reviewer confirmation, and second-person adjudication record for any disagreements.

**Do not create `backend/data/email_ai/metadata/training_approval.json` until all required source rights, privacy/retention, and independent label review decisions are complete and the approval manifest can bind every dataset component and evidence file by SHA-256.**

## Official source records reviewed

- MeAJOR Zenodo record: https://zenodo.org/records/18471483
- CMU Enron dataset notice: https://www.cs.cmu.edu/~enron/
- Nazario CC BY 4.0 notice: https://monkey.org/~jose/phishing/LICENSE.txt
- SpamAssassin public corpus README: https://spamassassin.apache.org/old/publiccorpus/readme.html


## Component-by-component approval record (required; no blanket approval)

The reviewer must create a separate signed decision for **MeAJOR v2.0**, **TREC-05**, **TREC-06**, **TREC-07**, **Nazario**, **Nigerian Fraud**, any **Enron-derived** messages, and **SpamAssassin** if used by any separate provisional corpus. For each item record: exact source/version and file hash; rights-holder/licensor authority; internal non-commercial use; commercial use; normalization/feature extraction; training and evaluation; derivative weights/calibrators/embeddings; hosting/distribution; raw/derived data redistribution; attribution and downstream terms; privacy/legal basis; sensitive data/PII controls; access roles; retention duration; deletion and backup deletion; derived-artifact handling; integrity/authenticity caveats; conditions and expiry/re-review date. Use `APPROVED`, `DENIED`, or `NEEDS_MORE_EVIDENCE` for each decision and attach evidence SHA-256. `UNKNOWN`, a public URL, or a blank license field is not an approval or a legal conclusion.

## Human action / communication status

This request has **not** been sent. No authorized recipient, legal determination, privacy approval, or upstream permission has been verified in this workspace. A project owner must identify and send it to authorized dataset rights holders and the designated legal/privacy reviewers, then store the actual responses and hash-bound evidence under approved access control. The engineering agent cannot self-approve these decisions.
