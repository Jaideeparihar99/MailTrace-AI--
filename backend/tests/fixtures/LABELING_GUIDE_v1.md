# MailTrace-AI Email Labeling Guide — v1.0

**Status:** Proposed canonical taxonomy for future reviewed datasets. Existing corpora are not retroactively relabeled by this guide. Do not train or claim validated metrics from the taxonomy until a reviewer signs off on the policy and sample labels.

## Record schema

Each reviewed message should have one `primary_label`, zero or more `secondary_tags`, an evidence-backed rationale, and provenance/review metadata. Preserve the original raw input immutably; place any redacted/synthetic derivative in a separate derived-data area and link it to the raw item by an access-controlled identifier and cryptographic digest.

Required metadata: stable sample ID, source/provenance or `synthetic`/`unknown`, source license/permission state, raw and derived digests, acquisition date if known, sanitization status, primary label, secondary tags, evidence references, reviewer role/ID, review timestamp, confidence, adjudication status, and split/group IDs. Never store reviewer notes with unnecessary personal content.

## Primary labels

| Label | Apply when | Do not apply solely because |
|---|---|---|
| `BENIGN` | Available evidence supports a legitimate or expected message and there is no persuasive malicious or unsolicited-abuse intent. | SPF/DKIM/DMARC passes, familiar branding, or absence of suspicious words. |
| `PHISHING_CREDENTIAL_THEFT` | The message deceptively seeks passwords, MFA/OTP codes, account recovery secrets, or equivalent authentication material. | It contains a login link, security vocabulary, or an authentication failure without evidence of deceptive collection intent. |
| `PHISHING_OTHER` | Deceptive social engineering seeks another harmful action or disclosure, but credential theft and BEC are not the best primary class. | A generic urgent or unusual request alone. |
| `BEC` | Impersonation or compromised-account behavior seeks payment, payroll/bank-detail change, gift cards, invoice diversion, or another business transaction/control change. | A payment topic without deceptive intent or a verified/request-context mismatch. |
| `SPAM_UNSOLICITED` | Unwanted bulk/promotional or abusive solicitation is supported, with no better-supported phishing/BEC intent. | A legitimate newsletter/marketing email, or the legacy dataset folder name alone. |
| `UNCERTAIN_NEEDS_REVIEW` | Evidence is insufficient, conflicting, malformed, context-dependent, or not safely attributable to one of the classes above. | A requirement to fill every row with a confident threat class. |

`PHISHING_OTHER` is included to avoid forcing non-credential phish into BEC or spam. The required core product groups may roll it up under `phishing` in display/metrics while preserving its exact label in source records.

## Overlap and ambiguity rules

1. Use one primary label for mutually exclusive top-level evaluation. Store co-occurring behaviors as secondary tags, such as `credential_request`, `brand_impersonation`, `payment_change`, `bulk_marketing`, `malformed_mime`, or `auth_result_untrusted`.
2. Choose `BEC` when the central deceptive objective is a business transaction or payment/control change, even if a credential or attachment signal is also present. Preserve the other behavior as a tag.
3. Choose `PHISHING_CREDENTIAL_THEFT` when credential or authentication-secret collection is the central objective. If the email also requests a business payment, use evidence and intended outcome to choose the dominant primary objective; otherwise mark `UNCERTAIN_NEEDS_REVIEW` and retain both tags.
4. Choose `SPAM_UNSOLICITED` only where unsolicited solicitation is supported and stronger fraud intent is not. Spam and malicious intent are separate dimensions; use `unsolicited` as a secondary tag when a phishing/BEC message is also bulk-distributed.
5. A legitimate message containing risky words, a link, or suspicious-looking authentication metadata can still be `BENIGN`; evaluate context, intent, sender relationship, and actual destination evidence safely.
6. If available evidence cannot support the distinction, label `UNCERTAIN_NEEDS_REVIEW`. Do not force a label from a model score, a single detector, a source folder, display name, keyword, or SPF/DKIM/DMARC result.

## Orthogonal quality and review fields

Parser state (`valid`, `malformed`, `partial`), authentication claims/results, MIME structure, language, and whether evidence was independently reviewed are metadata/tags, not threat labels. The existing Step 16 labels `malformed_email` and `authentication_edge_case` describe test scenarios; they must not be mapped to malicious classes. A malformed sample can have an uncertain threat label.

Use review states `UNREVIEWED`, `INDEPENDENTLY_REVIEWED`, `ADJUDICATED`, or `REVIEW_BLOCKED`. Keep `UNCERTAIN_NEEDS_REVIEW` as a message label and separate from the review-process status. For disagreement, retain each reviewer decision and record a separate adjudication with rationale and timestamp; never silently overwrite the original label.

## Evidence and source quality

- Ground labels in message context and multiple relevant indicators where available. Record concise evidence locations (header/body/MIME part) rather than copying full message content into label notes.
- Source-provided labels are `source_proxy`, not project-reviewed ground truth. In particular, legacy `ham` does not guarantee that a message is benign; `spam` does not mean phishing; and a phishing-corpus folder does not provide a BEC subtype.
- Do not label a sample malicious solely due to suspicious wording. Authentication failure, a recently registered domain, an IP location, or one threat-intelligence match is contextual evidence, not automatically conclusive.
- Evaluation must retain uncertain samples as a separately reported outcome. Excluding them from binary metrics requires an explicit policy and a count/denominator disclosure.

## Privacy, licensing, and retention

- Do not upload private mailbox content or raw corpus emails to external services. Do not visit URLs or resolve indicators during labeling.
- Keep raw public-corpus data and any real authorized email in access-controlled, Git-ignored storage. Do not commit raw messages, attachments, credentials, authentication tokens, personal addresses, or unredacted review notes.
- Record source terms per component, including derivative obligations. A public download is not an unrestricted reuse license. If the license or authorization is unknown, set `license_status: UNKNOWN` and block external/commercial use pending review.
- Sanitize a copy only; retain the raw source immutably subject to documented retention/deletion requirements. Redact secrets and direct identifiers, and preserve a transformation log and hashes.
- Set a retention period and deletion process before future authorized real-email collection. The current repository has no approved retention period for raw public email artifacts; treat retention as unresolved.

## Versioning and split requirements

This guide is `mailtrace-email-label-taxonomy` version `1.0`. Taxonomy changes require a version bump, migration note, reviewer approval, and re-adjudication plan. Split by campaign, thread, source family, and time when such metadata exists; deduplicate before splitting. Keep a frozen, reviewed test set out of training and threshold tuning. Report source/class counts and label-review status for every split.
