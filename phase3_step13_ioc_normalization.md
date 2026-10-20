# Phase 3 — Step 13: Normalize and Deduplicate IOCs

**Status:** Implemented; targeted IOC, URL, and parser regressions pass. Stop for review before Step 14.

## A. IOC type inventory and canonical record

### Before this step

`backend/services/threat_intelligence/ioc_normalizer.py::extract_iocs` actually emitted only `ip`, `ip:port`, `url`, and `domain`. IP regexes handled IPv4 only. The attachment parser calculated SHA-256, but those hashes were not in the IOC collection. Email addresses were not extracted into it. `email_forensics/ip_extractor.py` separately classified IPv4/IPv6 from `Received` headers, but those candidates were not unified with threat-intelligence IOCs. Do not read unrelated hash, URL, or email parsers elsewhere in the codebase as proof these types had been in the canonical collection.

### Now supported in the canonical collection

| Type (`ioc_type`) | Evidence source | Normalized key |
|---|---|---|
| `url` | Shared Step 12 URL evidence | HTTP(S) canonical URL, including path/query/fragment and non-default port |
| `domain` | Body text, email-address domains, URL hostnames | Lowercase IDNA ASCII domain |
| `ip` | Body text and URL hostnames | `ipaddress` compressed address; IPv4 and IPv6 with `ip_version` and `ip_scope` |
| `ip:port` | IPv4 `address:port` and bracketed IPv6 `[address]:port` in body text | Validated compressed IP plus validated port |
| `email` | Body text, HTML body text and identity headers | Preserve local-part case; lowercase/IDNA-normalize domain |
| `md5`, `sha1`, `sha256` | Hex digest-shaped body text and computed attachment SHA-256 | Lowercase hex; length selects digest algorithm; `indicator_type` is `hash` |

Canonical output stays in `analysis.threat_intelligence.iocs` for backward compatibility. Each record has:

```json
{
  "ioc": "canonical value",
  "value": "canonical value",
  "ioc_type": "sha256",
  "indicator_type": "hash",
  "normalized_value": "canonical value",
  "original_value": "first observed spelling",
  "original_values": ["all distinct observed spellings"],
  "source_locations": [{"source": "body.text", "offset": 12}],
  "occurrence_count": 2,
  "extraction_method": "hex_digest_pattern",
  "extraction_methods": ["hex_digest_pattern", "attachment_sha256"],
  "normalization_decision": "lowercase hexadecimal; length identifies digest algorithm"
}
```

IP records also carry `ip_version` and `ip_scope`; hashes carry `hash_algorithm`; IP:port records carry `port`. `first_seen` / `last_seen` are omitted because the parser does not provide timestamps per occurrence. Email body/header source offsets are decoded-text character offsets; attachment hashes refer to attachment MIME part and filename.

## B. Normalization and deduplication policy

| Type | Comparison rule | Evidence preserved / distinctions |
|---|---|---|
| IPv4 / IPv6 | Validate and compress with Python `ipaddress`; deduplicate within IP type by compressed value. | Original spelling and every source location retained. Scope labels distinguish `public`, `private`, `loopback`, `link_local`, `documentation`, `reserved`, `multicast`, `unspecified`, and `non_public`. |
| IP plus port | Validate IP and port 1–65535; IPv6 must be bracketed to bind its port unambiguously. | Port stays part of the IOC and is also exposed as `port`; address and address:port are separate typed indicators. |
| Domain | Validate IDNA UTS #46 / STD3, output lowercase ASCII; trailing DNS root dot is removed. | Domain IOCs are distinct from URL IOCs and email IOCs. Same normalized domain across body, email domain, and URL hostname is one domain record with distinct context/source locations. |
| URL | Reuse Step 12 canonicalizer: lowercase scheme/host, IDNA hostname, remove default port, normalize empty path to `/`. | Preserve original URL variants and source locations; do not remove path, query, fragment, user-info or non-default port; do not sort parameters or decode percent escapes. Paths, query and fragment remain case-sensitive. |
| Email | Parse one mailbox candidate; preserve local-part case and IDNA/lowercase only the domain. | `Alice@example.com` and `alice@example.com` remain distinct because local-part case can be meaningful. Domain-only variants merge as the same domain IOC with separate email context. |
| File hashes | Accept exactly 32, 40, or 64 hexadecimal characters as MD5, SHA-1, or SHA-256; compare lowercase. | Every spelling and body/attachment source is retained. UUID-like hyphenated strings do not match the hash token rule. |

Malformed IPs, invalid ports, invalid IDN/domain labels, malformed mailbox strings and non-hex hash lookalikes are skipped rather than repaired. An IP's public/private classification is local only. `ip_intelligence.analyze_ip` now also returns early for every non-global address (including shared-use `100.64.0.0/10`) before reverse DNS, geolocation or network-reputation calls; the forensic relay-IP candidate extractor also sets public only when `ipaddress.is_global` is true. A focused regression mocks all three network-facing functions and confirms they are not called for private/shared-use addresses. Cached/local TI matching remains separate from geo/reputation enrichment.

## C. API, UI and report assembly

- `backend/main.py` builds one canonical `normalized_iocs` list from body text, Step 12 URL evidence, HTML/body and identity-header text, and computed attachment SHA-256 values.
- `threat_intelligence.iocs` and `threat_intelligence.ioc_summary` are built from that same collection. URL count reconciliation still compares this canonical collection to Step 12's URL summary.
- The investigation analysis JSON is persisted and returned with `threat_intelligence.iocs`. `frontend/script.js` renders those same records and shows type, occurrence count, original spellings, source context, and IP scope; the counts now include hashes and email addresses.
- No separate CSV/PDF/IOC-export implementation was found in the repository. There is no parallel export extractor to reconcile. If a standalone export is added later, it should serialize this canonical `threat_intelligence.iocs` array and summary rather than re-extracting from message text.

## D. Collision, malformed-input and count verification

Focused cases cover domain case/IDN variants, email local-part case distinction, body/header/URL contexts, repeated URL evidence and distinct URL paths/ports/fragments, IPv4/IPv6 and bracketed IP ports, private/documentation scope, hash case variants and attachment digest source, malformed email/IP/hash/URL values, plus occurrence/source preservation.

On the existing Step 12 safe fixture (same URL in text and HTML plus one HTML-only URL), URL counts remain **2 unique URL indicators / 3 source occurrences / 2 IOC URLs**.

Additional deterministic mixed-type fixture:

```text
From User@Example.test and user@EXAMPLE.test; host Example.test and example.test;
8.8.8.8 8.8.8.8:53; 2001:4860:4860::8888;
https://example.test/Login https://example.test/login; <same SHA-256 in upper/lower case>
```

| Summary count | Before | After |
|---|---:|---:|
| Total distinct IOC records | 5 | 9 |
| IPv4 + IPv6 `ip` | 1 (IPv4 only) | 2 (1 IPv4, 1 IPv6) |
| `ip:port` | 1 | 1 |
| URL | 2 | 2 |
| Domain | 1 | 1 |
| Email | unsupported / 0 | 2 (local-part case preserved) |
| Hash | unsupported / 0 | 1 (upper/lower hex deduplicated) |

After-change occurrence checks: repeated `8.8.8.8` retains two locations; the same digest in body twice plus an attachment SHA-256 yields one SHA-256 record with three source locations; the repeated email-domain variants share one domain record but remain two email records; distinct URL paths remain two URL records. These are synthetic regression fixtures, not corpus-wide accuracy claims.

Command run from `backend`:

```powershell
$env:PYTHONPATH=(Resolve-Path '.\venv\Lib\site-packages').Path + ';' + (Get-Location).Path
pytest tests\test_phase3_step13_ioc_normalization.py tests\test_phase3_step12_url_extraction.py tests\test_domain_alignment_evidence.py -k 'not analyze_email_api_reconciles_url_and_ioc_counts'
```

Result: **24 passed, 1 deselected**. The deselected case is the pre-existing FastAPI `TestClient` API test; all selected IOC, URL, parser and evidence tests passed. `py_compile` passed for changed Python modules, and `node --check frontend/script.js` passed.

## E. Changed files

- `backend/services/threat_intelligence/ioc_normalizer.py` — typed canonical indicators, type-aware deduplication, IPv6 and IP scope, IDNA domains, email/hash extraction, provenance and summary counts.
- `backend/main.py` — include repeated identity headers, HTML text and computed attachment SHA-256 in the single IOC collection; summary includes IPv4/IPv6/email/hash.
- `backend/services/email_parser.py` — expose attachment MIME part index beside its existing computed SHA-256.
- `backend/services/ip_intelligence.py` and `backend/services/email_forensics/ip_extractor.py` — prevent non-global and shared-use addresses from being labeled public or sent to public enrichment.
- `frontend/script.js` — show hash/email counts, original values, source/occurrence details and IP scope from API canonical records.
- `frontend/style.css` — provenance detail styling.
- `backend/tests/test_phase3_step13_ioc_normalization.py` — six focused typed-indicator regressions, including provider-call guard for private IPs.
- `backend/tests/test_phase3_step12_url_extraction.py` — adjust URL assertions to select URL records now that domains are also canonical records.

## F. Limitations and handoff

- Hash-shaped body text is heuristic; a 32/40/64-character hex token can be a non-hash value. The source fragment/method makes that classification auditable. Attachment SHA-256 is computed from attachment bytes and is stronger evidence of a file digest.
- Quoted mailbox local-parts and unusual RFC email syntax are not supported by the simple mailbox extractor; they are omitted rather than guessed.
- `first_seen` / `last_seen` are not emitted because occurrence timestamps are not available. No temporal claim is inferred from email dates.
- No standalone IOC export exists yet. The report UI and stored/API analysis share the canonical IOC list; future export work must serialize that same list.
- The deselected API TestClient test means there was no endpoint-level response/persistence run in this verification batch; normalization, summary, and UI syntax were checked independently.

**Review gate:** Step 13 is complete. Do not start Step 14 until this handoff is reviewed.
