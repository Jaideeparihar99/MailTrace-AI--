# Blinded Phase 4 synthetic fixture review

Status: **PENDING**. This packet is prepared for independent human adjudication; it is not evidence that any review has occurred.

## Send only these items to the reviewer

- `README.md`
- `review_sheet.csv`
- the `review_emails/` directory

Do **not** share `maintainer_key.json`, the source manifest, the main repository, or `false_positive_trace.md`. The key contains the expected labels. The reviewer should be a person other than the fixture author and should classify each raw message before seeing any expected label.

Each email is synthetic and uses inert `.invalid` domains. The body and other evidence are preserved; only filenames and the synthetic Message-ID were replaced to hide the original fixture IDs. Do not visit or resolve any URL.

For every case, fill `reviewer_label` using a taxonomy label, `reviewer_severity`, confidence (`LOW`, `MEDIUM`, or `HIGH`), concrete `evidence_notes`, reviewer role/identity, `reviewer_relationship_to_author` as `INDEPENDENT`, UTC `reviewed_at_utc`, and set `review_status` to `COMPLETE`. Record your decision before seeing any maintainer label. Do not fill the adjudication fields unless a disagreement is independently resolved by a second person.

## Reconciliation

Return the completed CSV to the maintainer. The maintainer should keep the key private, then run from `backend/`:

```powershell
.\venv\Scripts\python.exe scripts\reconcile_phase4_blind_review.py
```

The script verifies every response, reviewer independence attestation, UTC timestamps, packet hashes, and all case IDs. It writes a **private** `reconciliation_report.json` beside the maintainer key and does not modify fixture labels. If a reviewed label disagrees with the current expected label, the script stops and requires a separately identified adjudicator, documented rationale, and UTC time in the adjudication columns. Review status remains pending until maintainers inspect the report and approve any manifest changes. Do not send the key or reconciliation report to the blind reviewer.

## Decision rubric (use the labels as fixture-content classifications)

Use only the labels in the Step 16 source manifest. Review the message content and available headers as untrusted evidence; do not treat message-supplied Authentication-Results or display names as independently verified facts.

- `benign_legitimate`: routine expected communication with no persuasive malicious request.
- `phishing`: impersonation or a deceptive request intended to induce an unsafe action; credential theft is not required.
- `credential_harvesting`: explicit attempt to collect passwords, one-time codes, or account authentication data.
- `bec_payment_change`: deceptive business communication seeking a payment or beneficiary change.
- `suspicious_inconclusive`: an anomaly exists but the evidence does not establish malicious intent. Use this when uncertain; do not force a malicious/benign decision.
- `malformed_email`: the fixture is deliberately malformed for parser robustness. This is a fixture/parser condition, not by itself a threat verdict.
- `authentication_edge_case`: the fixture tests how untrusted authentication claims are handled. This is a fixture/parser condition, not by itself a threat verdict; record the content assessment in `evidence_notes` and explain the edge case.

Severity is a separate assessment (`NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, or `UNKNOWN`); confidence must be `LOW`, `MEDIUM`, or `HIGH`. Quote or summarize observable evidence without following URLs. If a message cannot be classified from available evidence, choose `suspicious_inconclusive`, use low confidence as appropriate, and explain the uncertainty.

## Packet integrity and status tracking

The eight `review_case_id` values are stable non-identifying IDs; each maps to one blinded email copy whose SHA-256 is held in the private maintainer key. Before review, all reviewer and adjudication fields remain blank and `review_status=PENDING`. A completed row must record the reviewer decision, evidence, identity/role, independent relationship attestation, UTC timestamp, confidence, severity, and `COMPLETE` status. Disagreements require a different named adjudicator, rationale, and UTC timestamp. An unresolved case must remain pending; preparation or validation of this packet is not independent adjudication.
