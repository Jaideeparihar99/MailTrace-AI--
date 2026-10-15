# Phase 2 Step 9 — Domain Alignment and Evidence Consistency

**Status:** Domain comparisons and URL/IOC accounting were updated and focused tests pass. The original promotional email is still not present in the repository, so the suspected exact real-message case remains unverified.

## A. Domain comparison policy and implementation

### Policy

`backend/services/domain_alignment.py` is the shared policy implementation. It normalizes mailbox/domain inputs to lowercase ASCII IDNA form, rejects malformed hostnames and IP literals for organizational-domain comparison, then uses the project’s existing `tldextract` Public Suffix List snapshot. The extractor is configured with `suffix_list_urls=()` and `cache_dir=None`, so comparison uses the bundled snapshot without fetching an updated list at runtime. Private suffixes are included.

`compare_domains(left, right)` reports one of:

- `EXACT_HOST`: normalized hostnames are identical.
- `ORGANIZATIONAL_ALIGNMENT`: hostnames differ, but their PSL-derived registrable domains match.
- `MISMATCH`: both registrable domains are known and different.
- `UNKNOWN`: input is malformed or the bundled PSL cannot establish a registrable domain.

`domains_differ` now returns true only for `MISMATCH`. Unknown values do not create a mismatch finding. IDNA handling uses the existing `idna` dependency with UTS #46 and STD3 processing. No last-two-label comparison is used; the old helper in email feature extraction has been replaced with the PSL result.

Organizational alignment is a domain relationship only. It does not prove the message is authentic, safe, authorized, or benign. SPF/DKIM/DMARC observations and validation remain separate fields; authentication PASS does not turn an unrelated Return-Path into an aligned domain or suppress an unrelated-domain finding.

### Traced paths

- `email_parser.extract_headers` retains From, Sender, Reply-To and Return-Path header values; `parse_email` also returns these in `basic_information` and the normalized header object. `extract_domain` now delegates to `normalized_host` for safe IDNA-aware extraction. The parser’s Reply-To and Return-Path score rules compare organizational domains. Return-Path mismatch remains visible even if reported DMARC status is PASS.
- `email_forensics.header_anomaly_detector.detect_header_anomalies` normalizes each parsed address and compares From/Reply-To, From/Return-Path and From/Sender through `compare_domains`. Findings are limited to actual organizational mismatch. Its `identity_snapshot` now includes the comparison state for those pairs.
- `email_forensics.authentication_analyzer.analyze_authentication` reports `sender_return_path_alignment` as its existing `ALIGNED`/`MISMATCH`/`UNKNOWN` contract and adds `sender_return_path_domain_comparison` to distinguish exact host match from same-organization subdomain alignment. Authentication result provenance stays separately marked; it does not establish message intent.
- `email_ai.intelligence_fusion._identity_signals` no longer creates a strong mismatch merely because complete sender and Reply-To addresses differ. It emits an identity signal only when both domains are parseable and the organizational domains differ.
- `email_ai.features` and `email_classification.rules` previously compared raw domains/hostnames in their identity paths. They now use the same PSL-aware helper, preventing host variation from becoming an ML feature or rule signal solely due to subdomain differences.

The Step 6 Myntra report says no original `.eml`/`.msg` or full saved result was found. The test fixture in `test_false_positive_scoring.py` is inline synthetic data. No real From/Return-Path pair was available to validate as the known example.

## B. URL and IOC policy

### Extraction and deduplication

`email_parser.parse_email` extracts URL occurrences from both non-attachment `text/plain` and `text/html` MIME parts. `extract_url_evidence` deduplicates by canonical URL identity while retaining the first original URL spelling and every source location as `{part, offset}`. Offsets are character offsets local to the decoded MIME part, not byte offsets into the raw RFC 5322 file.

The canonical URL identity in `ioc_normalizer.url_deduplication_key`:

- lowercases scheme and IDNA-normalized hostname;
- removes the default port for HTTP/HTTPS and uses `/` for an empty path;
- keeps non-default ports;
- preserves path, query and fragment spelling and case; and
- does not sort query parameters or otherwise collapse distinct paths/queries/fragments.

Thus host-case/default-port aliases deduplicate, HTML/plain-text copies of the same URL deduplicate, and `/Login` remains distinct from `/login`. `url_evidence` keeps the original URL and source positions for review. IOC URL records preserve these as `original_values` and `source_locations`.

The API passes parser `url_evidence` into `extract_iocs`, so HTML-only URLs are included in threat-intelligence lookup even when the plain-text body is empty. `ioc_summary.url` is the unique normalized URL count. `url_summary` reports parser `unique_count`, occurrence count, IOC URL count, and a `counts_consistent` boolean. The UI’s URL-count cards use the canonical `url_summary.unique_count`; its URL count in the IOC summary uses that same value. Total IOC count remains distinct because it includes IPs, IP:port values and domains as well as URLs.

### Lookup state and counts

The main API preserves distinct `threat_intelligence.status` values: `no_iocs`, `no_matches`, `matched`, `coverage_limited`, and `error`, with coverage provenance separately available. `matched_count` now counts IOC keys with nonempty match records, not empty result buckets. `ioc_threat_score` propagates lookup and coverage status, so score zero alone is not presented as a successful safe lookup. The UI now distinguishes no extracted indicators, no matches, coverage-limited results, and lookup unavailability; its copy explicitly avoids treating zero matches as a safe verdict.

## C. Before/after verification

### Domain regressions

Before the implementation, the newly added targeted tests produced **4 failures, 1 pass**:

- malformed mailbox text `not-an-email@@example.com` was parsed as `example.com`;
- From and Sender subdomains within `example.com` generated a spoof-style finding;
- Sender and Reply-To subdomains within the same organization generated a high-risk fusion identity signal; and
- case-insensitive whole-URL deduplication merged `/Login` and `/login`.

After the changes, exact-host match, PSL alignment (including `example.co.uk` and IDN), unrelated registrable domains and malformed input all pass their focused assertions. For a mismatched Return-Path, a reported DMARC PASS does not remove the separate mismatch finding.

### URL/IOC/report counts

Static baseline inspection showed that parser URL extraction and IOC lookup each consumed only `body.text`; the HTML body was sent to link-deception analysis but not IOC extraction. Therefore an HTML-only URL could be omitted from both counts, and the parser and UI had no shared canonical count field. The URL normalizer also lowercased the entire IOC dedup key, merging case-sensitive paths.

The post-change MIME regression contains one URL in both text and HTML and a second URL in HTML only. Runtime output from the parser and IOC normalizer was:

```text
parser_unique_urls: 2
url_occurrences_with_sources: 3
ioc_unique_urls: 2
api_counts_consistent_field: true
source_sets: [[text/html, text/plain], [text/html]]
```

This verifies parser-to-IOC extraction consistency with a synthetic MIME message. The API field wiring and UI count source were verified in code; no browser-level report run or saved real email report was available for a full before/after UI capture.

## D. Tests and commands

Regression tests were added in `backend/tests/test_domain_alignment_evidence.py` for:

- exact host, same registrable domain, unrelated domains, malformed addresses, PSL multi-label suffixes and IDN;
- From/Sender/Return-Path and fusion Reply-To subdomain alignment versus unrelated domains;
- authentication PASS remaining separate from an unrelated Return-Path mismatch;
- parser Return-Path behavior; and
- duplicate URLs across HTML/plain parts, HTML-only URLs, source locations, case-sensitive paths, and consistent URL/IOC summary counts.

The combined relevant test run from `backend` was:

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
.\venv\Scripts\python.exe -m pytest -p no:cacheprovider -q tests/test_domain_alignment_evidence.py tests/test_false_positive_scoring.py tests/test_email_processing_security.py -k 'not readiness_discloses and not webhook and not sse_stream and not stale_webhook and not webhook_ledger'
```

Result:

```text
25 passed, 5 deselected in 2.62s
```

The deselected tests are the readiness/webhook/SSE cases; this run focused on parser, authentication, URL and fusion behavior. `node --check frontend/script.js` passed. `git diff --check` reported no whitespace errors; Git printed only line-ending conversion warnings.

## E. Changed files and limitations

Step 9 changed:

- `backend/services/domain_alignment.py` — shared robust IDNA/PSL comparison and explicit comparison states.
- `backend/services/email_parser.py` — normalized domain extraction, both MIME URL sources, URL evidence/source locations and URL summary; Return-Path handling no longer disappears solely because DMARC reports PASS.
- `backend/services/email_forensics/header_anomaly_detector.py` — consistent From/Reply-To/Sender/Return-Path comparison and comparison details in the identity snapshot.
- `backend/services/email_forensics/authentication_analyzer.py` — separate alignment classification and authentication observations; preserve mismatches regardless of DMARC PASS.
- `backend/services/email_ai/intelligence_fusion.py` — organizational-domain rather than exact-address/host comparison for sender and Reply-To.
- `backend/services/email_ai/features.py` and `backend/services/email_classification/rules.py` — PSL comparison in existing identity features/rules; remove naïve root-domain splitting.
- `backend/services/threat_intelligence/ioc_normalizer.py` — URL canonicalization, safe deduplication and source-location propagation.
- `backend/main.py` — HTML URL evidence passed into IOC lookup, reconciled counts and explicit match/coverage states.
- `frontend/script.js` — consistent displayed URL count and honest no-match/unavailable/coverage messaging.
- `backend/tests/test_domain_alignment_evidence.py` — new focused regression coverage.

`backend/services/email_parser.py`, `backend/services/email_ai/intelligence_fusion.py`, and `backend/tests/test_false_positive_scoring.py` also contain the already completed Step 8 edits in this working tree; the Step 9 handoff does not replace those prior changes.

Limitations: PSL behavior follows the installed `tldextract` snapshot and will not update until the dependency data is updated. Unknown or malformed domains intentionally remain `UNKNOWN` instead of being called mismatched. URL fragments are retained as separate identities to avoid merging potentially meaningful client-side routes. Source offsets refer to decoded part text. No real Myntra email, full main API run, or browser screenshot was available, so the known message’s exact before/after verdict and actual UI report rendering are not claimed as reproduced.

## Handoff

The tested policy now avoids labeling different hostnames under the same PSL-derived organizational domain as a spoofing mismatch, while unrelated registrable domains remain distinguishable. Parser and IOC counts are consistent on the tested multipart example, and the UI reads a shared canonical URL count. Review the policy and residual limitations before moving to the next step.
