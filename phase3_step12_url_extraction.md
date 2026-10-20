# Phase 3 — Step 12: Unified HTML and Plain-Text URL Extraction

**Status:** Implemented; focused URL/parser regressions pass. Stop for review before Step 13.

## A. Existing pipeline and extraction call graph

The Step 3 trace documents this original path: `parse_email` extracted plain and HTML bodies, regex-scanned both strings, then fed body URLs into URL analysis; rendered anchor comparison ran separately; IOC extraction again regex-scanned plain body text; and forensic analysis independently regex-scanned its plain body. These paths could disagree on HTML `href`-only URLs, escaped entities, and what constituted an occurrence. The Step 3 trace is [phase1_step3_pipeline_trace.md](</C:/Users/ritur/New folder/mailtrace/MailTrace-AI/phase1_step3_pipeline_trace.md:32>).

Current implementation call graph:

```text
POST /api/analyze-email
  -> backend/main.py::_analyze_email
  -> backend/services/email_parser.py::parse_email
     -> email MIME walk (decoded, non-attachment text/plain and text/html parts)
     -> services/url_extraction.py::extract_url_evidence
        -> plain text: bounded HTTP(S) candidate scan
        -> HTML: stdlib HTMLParser, <a href> attributes only
        -> validate supported URL, retain original + decoded comparison form + provenance
        -> canonical URL identity and merge occurrences
     -> url_analysis.analyze_urls(urls) [static analysis on shared list]
     -> advanced_url_intelligence.analyze_urls_deception(urls) [static analysis on shared list]
     -> link_deception_intelligence.analyze_link_deception(html) [separate anchor deception metric]
  -> main.py passes parser url_evidence to threat_intelligence.ioc_normalizer.extract_iocs
     -> IOC URL list comes from authoritative evidence (does not rescan body for URLs)
  -> email_forensics.orchestrator reuses services.url_extraction for its own output
```

Other URL-like parsing found:

- `backend/services/threat_intelligence/ioc_normalizer.py::extract_urls` remains a compatibility wrapper for callers that only provide plain text; it uses the shared extractor/normalizer. In the analysis API, `url_evidence` is authoritative, so the IOC module does not perform a second URL scan.
- `backend/services/email_forensics/url_analyzer.py::analyze_urls` now consumes a supplied canonical URL list; string callers route through the shared extractor.
- `backend/services/link_deception_intelligence.py` parses anchor `href` and visible text to compare them. Its anchor/link counts intentionally include relative or dangerous-scheme links that are not HTTP(S) URL IOC counts. It runs no browser or network activity.
- `backend/services/advanced_url_intelligence.py::analyze_urls_deception` accepts URL strings and performs static scoring; it is no longer given an independently regex-derived URL set from the primary parser.
- Generic IOC domain/IP extraction remains a separate category and can still report a host/domain contained in an email. Those are domain/IP IOC counts, not URL counts.

## B. Extraction and normalization policy

| Topic | Policy |
|---|---|
| Supported body sources | Decoded `text/plain` body parts and HTTP(S) destinations in HTML anchor `href` attributes. MIME attachments, `src` attributes, scripts, CSS, comments, and unrelated HTML text are not URL sources. `HTMLParser` is used as a static parser; no script, renderer, remote resource or browser is invoked. |
| Supported schemes | Only `http` and `https` are URL IOC candidates. `ftp`, `mailto`, `javascript`, `data`, relative hrefs and other schemes are not rewritten into web URLs. The separate link-deception analyzer may still report these as anchor behaviors. |
| HTML entities | HTML parser decodes attribute entities for URL parsing. The evidence retains the raw href spelling in `original_url` / source fragment and records decoded `comparison_url`. |
| Original and normalized values | `original_url` preserves the source spelling; `comparison_url` is the decoded candidate used by static analyzers; `normalized_url` is only a deduplication/comparison key. `original_values` and `comparison_values` retain every variant merged under a canonical key, and every occurrence remains in `source_locations`. |
| Canonicalization | Lowercase scheme and IDNA ASCII hostname; remove default HTTP/HTTPS port; add `/` for empty path. Preserve user-info, non-default port, path case, query, fragment and percent-escape spelling. Do not sort query fields or decode percent escapes. |
| Punctuation | Trim terminal sentence punctuation. Strip only unmatched `)`, `]`, or `}`; balanced brackets inside URLs remain. Exact match fragment and nearby source fragment remain in evidence. |
| Malformed / unsupported URL-like strings | Invalid authority, host, port, control/whitespace, invalid IDN, or unsupported scheme is omitted from URL IOC evidence. It is not repaired into a valid URL. No-scheme domain-like text is not upgraded into `https://`; domain IOC extraction remains independent. |
| Internationalized hosts | Validate and canonicalize using IDNA UTS #46 / STD3 rules while retaining the original Unicode spelling in evidence. |
| Provenance | Each occurrence records MIME part index, body type, character offset, source fragment; HTML adds line/column. Offsets are in decoded text, not byte positions in the original RFC 5322 file. |
| Network safety | Extraction and normalization use local parsing only. No DNS, HTTP, URL visits, redirect following, reputation requests, or execution occur. Later reputation integrations remain a separate stage. Extraction is not URL verification. |

## C. Test matrix

| Case | Expected | Actual |
|---|---|---|
| Plain text URL followed by sentence punctuation | Strip sentence punctuation, preserve URL path and evidence offset | Pass |
| Balanced parentheses in URL path | Retain balanced `(...)`; remove only unmatched sentence close | Pass |
| HTML anchor with `&amp;` / encoded colon | Decode for comparison, preserve raw source spelling and HTML fragment | Pass |
| Unicode hostname | Retain original URL; compare using IDNA hostname | Pass |
| Duplicate URL in `text/plain` and HTML `href` | One canonical URL, both source occurrences, consistent IOC count | Pass |
| Same URL with host case/default-port variants | One canonical key; retain each source URL spelling | Pass |
| HTML-only anchor href | Include it in parser and IOC URL counts | Pass |
| Invalid port / missing host | Skip as malformed; do not repair | Pass |
| `javascript:`, `ftp:`, script text URL | Exclude from HTTP(S) URL IOC evidence | Pass |
| Percent-encoded path/query and fragment | Preserve all components and escape spelling in canonical key | Pass |
| Parsed multipart EML | Preserve actual MIME part indices and decoded-text offsets | Pass |

Command run from `backend` with the project dependency path available:

```powershell
$env:PYTHONPATH=(Resolve-Path '.\venv\Lib\site-packages').Path + ';' + (Get-Location).Path
pytest tests\test_phase3_step12_url_extraction.py tests\test_domain_alignment_evidence.py -k 'not analyze_email_api_reconciles_url_and_ioc_counts'
```

Result: **18 passed, 1 deselected**. The deselected case is the pre-existing FastAPI `TestClient` endpoint test; parser/extractor tests, primary-versus-forensic count reconciliation, and the other URL/domain regressions passed. `py_compile` passed for all changed Python modules.

## D. Before / after counts on existing safe fixture

The Phase 2 Step 9 safe multipart fixture contains `https://offers.example.com/Deal` in plain text and in an HTML anchor, plus an HTML-only `https://offers.example.com/login`.

| Metric | Existing regex-based result | Unified result | Notes |
|---|---:|---:|---|
| Unique URLs | 2 | 2 | No count change on this fixture. |
| Source occurrences | 3 inferred from two string scans | 3 explicit MIME-source records | Unified result records part/type/offset/source fragment and all original variants for each occurrence. |
| IOC URL count | 2 | 2 | IOC count consumes parser evidence as the sole URL source. |
| HTML entity href fixture (`https&#58;...` / `&amp;`) | Not reliably extracted/canonicalized | 1 URL | Decoded destination is analyzed; exact source spelling stays in evidence. |

The prior safe-fixture results are documented in [phase2_step9_domain_alignment_evidence_fix.md](</C:/Users/ritur/New folder/mailtrace/MailTrace-AI/phase2_step9_domain_alignment_evidence_fix.md:69>). This before/after comparison is against that documented synthetic fixture, not a real-email corpus or live reputation lookup.

## E. Changed files

- `backend/services/url_extraction.py` — new shared local extractor, validation, IDNA canonicalization and provenance collection.
- `backend/services/email_parser.py` — walk supported MIME body parts, retain source records, and feed common URL list to URL analyzers; expose HTML body alongside plain text.
- `backend/services/threat_intelligence/ioc_normalizer.py` — share URL policy; use parser evidence as authoritative URL source; retain raw and comparison variants and source locations.
- `backend/services/email_forensics/url_analyzer.py` — remove independent regex scan; consume canonical list or call common policy for string input.
- `backend/services/email_forensics/orchestrator.py` — extract forensic URL evidence from plain text and HTML hrefs using same policy.
- `backend/tests/test_phase3_step12_url_extraction.py` — eight focused cases covering source types, duplicate variants/count agreement, entities, punctuation, IDN, malformed/unsupported URLs and percent encoding.

## F. Unresolved edge cases and handoff

- Defanged spellings such as `hxxp://`, `hxxps://`, `[.]`, or whitespace-obfuscated schemes are not decoded. No evidence-based defang decoder exists in this scope; treating them as live URLs risks inventing a destination. A future detector can label them as obfuscated URL-like text without visiting or silently rewriting them.
- HTML source offsets refer to decoded text positions; raw href value and start-tag fragment are preserved, but offsets are not byte offsets into the original message.
- `text/plain` has bounded email input size from Step 11. HTML body extraction has the existing 2 MiB aggregate / 32-part cap; beyond those parser caps, omitted parts are not analyzed.
- No reputation, DNS, redirect, content-fetch or browser verification was performed. A URL's successful extraction or parse does not mean it is reachable, safe, malicious, or verified.
- Endpoint-level TestClient verification was deselected from this focused run; no live API or browser count was claimed.

**Review gate:** Step 12 is complete. Do not start Step 13 until this handoff is reviewed.
