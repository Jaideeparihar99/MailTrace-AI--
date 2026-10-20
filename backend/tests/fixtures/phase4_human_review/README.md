# Phase 4 Independent Label Review

**Status: PENDING.** No independent reviewer has adjudicated the labels yet.

## Reviewer packet

Share only the files inside `blind_packet/`: its `README.md`, `review_sheet.csv`, and `review_emails/`. Do not share this directory's `maintainer_key.json`, the source manifest, or `false_positive_trace.md` before the reviewer records their first-pass decisions.

The packet uses random case IDs and filenames, excludes expected labels, and replaces synthetic Message-ID values that reveal the source fixture numbers. The messages remain synthetic and use inert `.invalid` URLs. The preparation script verifies fixture hashes and does not change the source labels.

To regenerate a packet after the current review has been archived, run from `backend/`:

```powershell
.\venv\Scripts\python.exe scripts\prepare_phase4_blind_review.py
```

The script refuses to overwrite an existing packet or review key. Keep the key access-controlled and reconcile the blinded decisions only after a reviewer other than the fixture author submits the completed sheet with reviewer role/identity, UTC time, evidence, confidence and disagreement resolution. Do not mark manifest labels human-reviewed before that reconciliation.

After receiving the completed sheet, validate it from `backend/` with:

```powershell
.\venv\Scripts\python.exe scripts\reconcile_phase4_blind_review.py
```

This checks reviewer attestation, completeness, timestamps, packet hashes, and case IDs. It writes a private, Git-ignored reconciliation report and never modifies the source manifest. Label disagreements require separately recorded second-person adjudication. Review and approve the private report before manually updating any manifest label or review status.

The root-level `review_sheet.csv` is an older, non-blinded record and contains expected labels. Do not share it; use `blind_packet/review_sheet.csv` instead. `false_positive_trace.md` also reveals labels and model outcomes and is for maintainer investigation only.
