# Phase 3 — Step 11: Header and MIME Parsing Audit

**Status:** Step 11 implementation and focused regressions complete. Stop here for review before Step 12, as specified in the Phase 3 handoff.

## A. Existing parser flow and failure modes

### Entry points

- `POST /api/analyze-email` calls `main._analyze_email`, reads at most 25 MiB, then calls `services.email_parser.parse_email`.
- `POST /api/analyze-thread` previously parsed each EML twice: a direct `BytesParser` call and `parse_email`. It now uses the parser output for Message-ID, In-Reply-To, References, and thread fields. Each message and the combined thread are bounded to 25 MiB.
- `services.email_parser.parse_email` parses EML with Python's standard email parser. MSG is converted by `extract_msg` to an EmailMessage/MIME derivative before analysis. Original uploaded bytes remain separate from that derivative.
- `services.email_forensics.header_parser.parse_email_headers`, called by `email_forensics.orchestrator.analyze_email_forensics`, separately parses the EML or normalized MSG analysis input to collect forensic headers and body data.

### Problems confirmed before changes

- Primary `extract_headers` retained every Received header but overwrote repeated From, Sender, Reply-To, Return-Path, Message-ID, Date, and other non-Received values.
- The forensic parser returned an `all_headers` list, but the anomaly detector counted keys in a dictionary. Dictionary keys are unique, so duplicate sensitive headers were not detected.
- Body charset/transfer decoding exceptions were silently skipped by the primary parser; forensic body decoding also discarded errors. MIME defects were not surfaced in the analysis result.
- The thread endpoint read each upload without a size bound and reparsed bytes unnecessarily.

## B. Parsing policy

| Data | Policy |
|---|---|
| Original message | Do not rewrite uploaded bytes. Record SHA-256 and byte length in the parsed result. The analyze-email API registers and preserves the original upload in the access-controlled evidence custody vault after successful analysis. MSG analysis uses a separate normalized MIME derivative; custody still uses original MSG bytes. |
| Duplicate headers | Preserve all occurrences, in source order, under `header_occurrences` and `duplicate_headers`. For existing single-value consumers, use the first occurrence deterministically. Keep all Received values as the existing ordered list. Forensic identity analysis consumes the occurrence lists and flags duplicate sensitive identity headers. |
| Missing headers | Remain absent/None; no values are invented. Basic information also carries Sender, In-Reply-To, and References. |
| MIME parts | Use bounded iterative structure inspection first; then existing body/attachment extraction remains static-only. Do not execute attachments or render active HTML. Attachment analysis remains metadata/static scanning; detonation remains disabled. |
| Malformed input | Expose parser defects and decode issues as structured `parsing.status = PARTIAL`; retain safe partial fields. API analysis does not report a partial parse as LOW RISK: it returns `REVIEW REQUIRED (PARTIAL EMAIL PARSE)` with UNKNOWN confidence. Hard resource-limit violations return a bounded 413 error rather than a verdict. |
| Limits | 25 MiB per email, 1,000 MIME parts, MIME depth 20, and 1,000 total header fields. Analyze-thread also caps aggregate uploaded bytes at 25 MiB. |

## C. Focused regression matrix

| Case | Expected result | Actual |
|---|---|---|
| Valid UTF-8 single-part EML | Complete parse, fields/body available, source fingerprint matches original bytes | Pass |
| multipart/alternative plus attachment | Plain body extracted, bounded MIME tree, attachment remains non-executed | Pass |
| Duplicate From, Reply-To, Received | First-value compatibility maintained; every occurrence retained; sensitive duplicates detected | Pass |
| Missing identity headers | Missing values remain None; no fabricated identity | Pass |
| Missing multipart boundary terminator | Parser defects exposed and status is PARTIAL | Pass |
| Unknown charset | Decode issue exposed and status is PARTIAL | Pass |
| Oversized input, >1,000 headers, MIME depth >20 | Rejected by explicit parser bounds, not treated as safe | Pass |
| Existing EML / MSG parser regressions | Existing parse and MSG-adapter behaviors preserved | Pass (4 selected tests) |

Focused command:

```powershell
cd backend
$env:PYTHONDONTWRITEBYTECODE='1'
.\venv\Scripts\python.exe -m pytest -p no:cacheprovider -q tests\test_phase3_step11_header_mime_parsing.py
```

Result: **7 passed**. Existing parser regressions: **4 passed, 8 deselected**. Python compile checks passed for changed parser, forensic, and API modules. A combined run that also selected the full existing API security module stalled in its TestClient portion; that full module was not counted as passed.

## D. Changed files

- `backend/services/email_parsing.py`: shared bounded parser and structural inspection limits.
- `backend/services/email_parser.py`: deterministic duplicate-header handling, source fingerprint, parse diagnostics, and explicit body decode errors.
- `backend/services/email_forensics/header_parser.py`: shared bounded parser, all header occurrences, explicit MIME decode status, and attachment exclusion from body extraction.
- `backend/services/email_forensics/header_anomaly_detector.py`: duplicate-sensitive-header detection now uses occurrences rather than unique dict keys.
- `backend/services/email_forensics/orchestrator.py`: propagate parsing status into forensic output.
- `backend/main.py`: remove duplicate thread parsing, bound thread input, preserve controlled parser errors, propagate parse status, and require review for partial parses.
- `backend/tests/test_phase3_step11_header_mime_parsing.py`: seven focused regression cases.

## E. Limitations and follow-up

- MIME defects are those reported by Python's standard email parser; this is not a full RFC conformance validator.
- Header policy deliberately keeps the first occurrence for compatibility. Complete ordered values are retained for forensic review; detector-specific identity conflict logic may need policy review for each header.
- MSG analysis uses an extract_msg-normalized MIME representation. The original MSG bytes are preserved by the API evidence custody path, but MSG-specific container metadata is outside MIME parsing.
- Over-limit requests are rejected before investigation creation, so they do not receive the normal evidence-custody record. They are rejected rather than assigned a safe verdict.
- The full pre-existing API security test module did not finish in this environment; only the focused parser tests and selected existing parsing tests are reported as passed.

**Review gate:** No Step 12 work has started.
