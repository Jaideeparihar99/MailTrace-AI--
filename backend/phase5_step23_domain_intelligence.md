# Phase 5 — Step 23: DNS, MX, WHOIS and Domain Age Enrichment

**Status:** DNS/MX enrichment implemented as an opt-in, bounded contextual enrichment. WHOIS/domain-age lookup is explicitly not implemented because no approved provider is configured. Step 24 has not been started.

## A. Integration inventory

| Signal | Existing status | Source / call site | Step 23 handling |
|---|---|---|---|
| SPF DNS TXT | Implemented when trusted SMTP context is provided; bounded dnspython resolver and pyspf query limits | `backend/services/email_forensics/authentication_analyzer.py::validate_email_authentication` | Existing auth validation remains separate; uploaded `Authentication-Results` stays untrusted evidence. |
| DKIM DNS TXT | Implemented for up to two signatures; bounded resolver lifetime | `backend/services/email_forensics/authentication_analyzer.py::dnsfunc` | Existing validator output semantics retained. |
| DMARC DNS TXT | Implemented; NXDOMAIN becomes `NO_POLICY`, other resolver failures become `DNS_LOOKUP_ERROR` | `backend/services/email_forensics/authentication_analyzer.py::validate_email_authentication` | Kept separate from general DNS/MX context so policy checks are not conflated with infrastructure records. |
| MX / A / AAAA / NS | Previously absent as normalized email-domain enrichment | New `backend/services/domain_intelligence.py`, called by `backend/services/email_parser.py::parse_email` | Implemented with explicit per-record status, normalized domain, source, resolver, time and cache metadata. Disabled by default; opt-in via `MAILTRACE_DOMAIN_INTELLIGENCE_ENABLED=true`. |
| WHOIS / registration date / domain age | Absent; no WHOIS library, configured service, or tested integration found | No previous call site | Explicit `domain_age.status=NOT_RUN`; age/date/provider stay null. No scraping or inferred age. |
| Reverse DNS (PTR) | Implemented for public relay IPs, not domain registration/DNS age | `backend/services/ip_intelligence_v2/providers/dns.py` and legacy IP intelligence | Treated as IP enrichment; not presented as WHOIS or MX evidence. |
| Domain normalization | Implemented for alignment and IOC extraction | `backend/services/domain_alignment.py`, `backend/services/threat_intelligence/ioc_normalizer.py` | New enrichment keeps the original domain string and a separate IDNA ASCII query form. |

### Call path

```text
parse_email(.eml/.msg)
  ├─ sender domain from From header (original text retained)
  ├─ URL evidence → original URL hostname (not visited)
  └─ analyze_domains (deduplicate IDNA form; cap at 3 domains)
       └─ lookup_domain → system-configured DNS resolver: A, AAAA, MX, NS
            └─ per-domain TTL cache → domain_intelligence result
```

The lookup does not visit extracted URLs, perform WHOIS scraping, or send domains to a separately configured commercial API. DNS enrichment is off by default because enabling it sends queried domains to the host-configured resolver.

## B. Canonical result shape

Each queried domain returns:

- `original_domain`: source spelling/case/Unicode form supplied by the email evidence.
- `query_domain`: lower-case IDNA ASCII form used for DNS and cache identity.
- `status`: `AVAILABLE`, `NO_RECORDS`, `NXDOMAIN`, `TIMEOUT`, `SERVFAIL`, `DNS_ERROR`, `INVALID_DOMAIN`, or `NOT_CONFIGURED`.
- `records`: arrays for `A`, `AAAA`, `MX` (preference and exchange), and `NS`.
- `record_statuses`: independent result for each record type, so no MX does not erase a successful A/AAAA answer.
- `resolver`, `provider`, `lookup_timestamp`, `cache_status`, `cache_ttl_seconds`, and `cache_expires_at`.
- `error`: bounded safe message or exception class only; raw resolver exception details are not returned.
- `domain_age`: explicit `NOT_RUN` with null registration date/age/provider and a reason.
- `interpretation`: contextual-only caveat.

Top-level `domain_intelligence.status` is `NOT_RUN` when disabled, `AVAILABLE` when any domain has records, `NO_DATA` when eligible domains return no records, and `UNKNOWN` when resolver/dependency failures prevent a conclusion. The result is included in the email parser API object as `domain_intelligence`.

## C. Normalization, timeout, cache and error policy

- Normalize through UTS #46 IDNA with STD3 rules. Reject IP literals, malformed labels, path/userinfo forms, single-label names, and overlong domains. Preserve `original_domain`; do not overwrite evidence with the normalized query form.
- Query only domains from the parsed sender and extracted URL hostnames, never URL paths or arbitrary body words. URLs are not fetched.
- Deduplicate case/trailing-dot/IDNA-equivalent domains within the analysis and cap work at three unique domains.
- Use dnspython with a 1 second per-query lifetime and no retry loop. Query types are A, AAAA, MX and NS. Maximum normal-path DNS wait is bounded to approximately 12 seconds per uncached email (3 domains × 4 query types × 1 second); cached domains do not issue DNS calls. System DNS resolver settings are used.
- Successful and authoritative empty/NXDOMAIN outcomes use in-process cache entries for 300/60 seconds respectively. Timeout, SERVFAIL and unexpected resolver errors are not cached. `clear_domain_cache()` invalidates local entries; process restart also clears them. No shared Redis cache is used.
- DNS `NO_RECORDS` and `NXDOMAIN` are distinct; timeout, SERVFAIL, dependency missing and malformed domain are also distinct. A missing MX does not imply maliciousness.
- WHOIS is `NOT_RUN`, not `NO_DATA`: no provider is configured or approved. Registration privacy, unsupported TLD and missing registration date cannot be distinguished without a registration data provider and therefore are not inferred.

## D. Deterministic test coverage

Added `backend/tests/test_phase5_step23_domain_intelligence.py`, using a fake resolver and no network. It covers:

- Successful A/MX results and provenance fields.
- Empty DNS answers and negative-cache metadata.
- NXDOMAIN distinct from an empty RRset.
- Timeout, SERVFAIL and unexpected resolver failure; safe errors and no transient caching.
- Invalid domain rejected before resolver calls.
- IDNA normalization while retaining original input.
- Duplicate normalization and maximum-domain cap.
- Cache hit and expiry.
- Per-record no-MX status while other DNS results succeed.
- Enrichment disabled without DNS calls.
- WHOIS/domain age explicitly `NOT_RUN`.
- Email parser includes sender and URL host domains in its domain-intelligence section.

## E. Scoring caveats and limitations

- Recent registration age is not currently retrieved and must not be guessed. If an approved registration provider is introduced later, age should remain a weak contextual feature and require corroboration before escalation.
- Missing MX, NXDOMAIN, privacy-redacted WHOIS and DNS irregularities are not standalone malicious verdicts. No changes were made to risk scoring.
- Current resolver behavior and data reflect the host-configured recursive DNS infrastructure; this is not an independent authoritative-DNS audit. Resolver caching may make provider TTLs unavailable, so MailTrace uses its documented local TTLs.
- DNS enrichment defaults off to avoid unexpected egress and analysis latency. Operators must approve resolver disclosure and enable it intentionally.
- The opt-in lookup currently caps at three domains, so additional domains are omitted from enrichment; original email/URL evidence remains available elsewhere in the analysis result.
- No commercial WHOIS/age provider, fallback resolver, or live DNS integration test was added. No legal/provider approval is implied.

## Verification

From `backend`:

```powershell
$env:PYTHONPATH = (Resolve-Path ".\venv\Lib\site-packages").Path
$python = "C:\Users\ritur\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
& $python -m py_compile services\domain_intelligence.py services\email_parser.py tests\test_phase5_step23_domain_intelligence.py
& $python -m pytest -p no:cacheprovider -q tests\test_phase5_step23_domain_intelligence.py
```

Observed: `py_compile` passed; Step 23 deterministic tests **14 passed**. An additional combined run covering the Step 23 tests, domain-alignment tests (excluding one API test blocked by the runtime mismatch below), and Phase 3 explicit-state tests reported **29 passed, 1 deselected**. A broader selected run attempted `tests/test_domain_alignment_evidence.py::test_analyze_email_api_reconciles_url_and_ioc_counts` but collection failed because the available bundled Python 3.12 cannot load the project's Python 3.11 compiled `pydantic_core` extension. No live DNS or WHOIS request was made.

**Review handoff:** DNS/MX enrichment is implemented and deterministic tests pass. WHOIS/domain age remains explicitly unimplemented pending provider approval. Review this step before starting Step 24.
