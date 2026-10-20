# Phase 5 â€” Step 22: Geolocation Provider, Fallback and Cache

**Status:** Review fixes implemented and locally regression-tested; external provider/real Redis/legal release checks remain pending. Step 23 has not been started.

## Scope and safety boundary

This step hardens the existing legacy IP enrichment path (`backend/services/ip_intelligence.py`) and the v2 provider path (`backend/services/ip_intelligence_v2/providers/geolocation.py`, consumed by `backend/services/ip_intelligence_v2/engine.py`). Both continue to use the Step 21 public-IP eligibility policy before any provider request. Non-public, special-use, documentation, malformed and otherwise ineligible addresses do not reach geolocation providers.

No live geolocation requests were made during this step. All provider behavior in new tests is mocked. This is not a claim of production accuracy, SLA, security certification, or legal approval of a third-party provider.

## A. Provider inventory and normalized interface

| Provider / source | Implemented | Default active | Step 22 treatment | Test evidence |
|---|---|---|---|---|
| `ipapi.co` | Yes; legacy and v2 | Yes, as the single default provider | Bounded JSON GET; normalized fields; explicit failure states; cache | Mocked success, no-data, malformed response, timeout and rate-limit tests |
| IPinfo (`ipinfo.io`) | Yes, v2 only | No | Not used merely because `IPINFO_TOKEN` exists. Requires explicit provider allowlist, `MAILTRACE_GEOLOCATION_IPINFO_APPROVED=true`, and token. No approval/legal status is inferred by code. | Mocked allow/deny/configuration tests; no live request |
| `ip-api.com` | Existing legacy network-intelligence call | Not a geolocation fallback | Used for proxy/hosting flags by the separate network-intelligence function; not silently added to the geolocation fallback chain | Existing tests stub provider I/O |
| Reverse DNS | Existing socket lookup | Separate enrichment | Hostname context only; not a country/city source or geolocation fallback | Existing provider-stubbing and analysis tests |

Configuration inspection for this checkout found no `IPINFO_TOKEN`, `MAILTRACE_GEOLOCATION_PROVIDERS`, or `MAILTRACE_GEOLOCATION_IPINFO_APPROVED` key in the process environment or root `.env`. Therefore IPinfo is dormant in this checkout. `ipapi.co` remains the default code path; its real-world reachability was not tested.

The v2 normalized result uses `ProviderResult` and `data` fields including `ip`, `provider`, `status`, `lookup_timestamp`, `cache_status`, `cache_ttl_seconds`, `cache_expires_at`, `precision`, and `confidence` (null when the provider supplies no confidence value). Available location/network fields are country, country code, region, city, postal code, latitude/longitude, timezone, continent, ASN, organization and hostname when actually returned. Missing values remain absent/null; no city/country is inferred.

Legacy analysis preserves its established top-level fields and adds a `geolocation` provenance object plus `geolocation_status.geolocation_state`. Provider status metadata is also surfaced by the v2 result. `AVAILABLE`, `NO_DATA`, `NOT_PUBLIC`, `TIMEOUT`, `RATE_LIMITED`, and `PROVIDER_ERROR` are distinguished in the geolocation state; the existing shared analysis status vocabulary continues to use `PASS`, `ERROR` and `NOT_APPLICABLE` for its high-level status.

## B. Timeout, retry, fallback and cache policy

- **Timeout:** 3 seconds per geolocation HTTP request. The v2 request helper caps caller-provided timeouts at 5 seconds and bounds response reads to 1 MiB. A configured two-provider chain has at most two sequential geolocation calls; normal defaults use one provider.
- **Retries:** none. GET is idempotent, but automatic retries would multiply provider latency and request volume. A later retry policy would need an explicit bounded budget and provider-specific rate-limit guidance.
- **Fallback:** default provider list is only `ipapi`. The v2 path permits at most two configured providers from the allowlist. IPinfo is skipped unless the provider list includes it, the explicit approval flag is true, and the token is present. No fallback service is activated based only on a token. The legacy analysis path stays on `ipapi`; no unapproved fallback was introduced there.
- **Cache key:** normalized eligible public IP plus provider name, so one provider's result is never mistaken for another's.
- **Cache location:** process-local in-memory cache by default, with an optional Redis-backed shared cache for multi-worker deployments. If Redis is not configured or unavailable, the provider falls back to process-local memory; confirm `cache_backend=redis` before relying on cross-worker sharing.
- **Positive TTL:** 24 hours, with provider/source, lookup timestamp, cache status and expiry retained.
- **No-location-data TTL:** 5 minutes. A response with only ASN/organization and no location fields is treated as `NO_DATA`, not a location result.
- **Transient errors:** timeout, HTTP 429/rate limit, malformed payload and provider errors are not cached. The next lookup can retry on a later analysis request. Provider exception strings and token-bearing URLs are not returned to callers.
- **Outage behavior:** geolocation failure is an enrichment error, not a clean/benign finding and not a fabricated location. The email/IP analysis continues with absent location fields and an explicit state.

## C. Mocked test coverage

New file: `backend/tests/test_phase5_step22_geolocation_reliability.py`

Covers:

1. Success and normalized provider/source/time/cache metadata.
2. Explicit `NO_DATA` and short negative-cache TTL.
3. Timeout, HTTP 429 rate limit and malformed JSON, with no transient-error caching.
4. Cache hit and expiry-triggered fresh lookup.
5. Non-public IP rejected before provider I/O.
6. IPinfo token alone does not enable fallback.
7. IPinfo requires provider allowlist, approval flag and token.
8. ASN/organization without country/region/city/coordinates is not reported as a location.
9. V2 IP analysis completes when geolocation provider fails; geolocation status remains an error and no location is fabricated.
10. Legacy IP analysis continues after a geolocation timeout and exposes the timeout state.
11. Legacy cache hit preserves provenance metadata, expiry triggers a fresh lookup, and ASN-only payloads remain `NO_DATA`.

## D. Verification evidence

Executed through the repository's local Python virtual environment, from `backend`:

```text
.\venv\Scripts\python.exe -m py_compile services\ip_intelligence.py services\ip_intelligence_v2\engine.py services\ip_intelligence_v2\providers\geolocation.py tests\test_phase5_step22_geolocation_reliability.py
.\venv\Scripts\python.exe -m pytest -p no:cacheprovider -q tests\test_phase5_step22_geolocation_reliability.py
.\venv\Scripts\python.exe -m pytest -p no:cacheprovider -ra -q
.\venv\Scripts\python.exe scripts\run_phase4_offline.py
```

Observed results after the final code changes:

- `py_compile`: exit 0.
- Step 22 geolocation reliability tests before follow-up hardening: **15 passed**; after follow-up hardening, the focused suite plus opt-in live module reports **21 passed, 1 skipped**.
- Full backend test suite after follow-up hardening: **447 passed, 1 skipped, 8 subtests passed**.
- Canonical Phase 4 offline gate: **PASS**, 66 passed + 8 subtests; baseline `mailtrace-phase4-step18-offline-v1` matched; fixture metrics TP=3, FP=0, TN=3, FN=0, with 2 inconclusive/excluded cases.
- No live external provider tests were run. These results validate mocked behavior and local regression compatibility only.

## E. Configuration, cost and privacy considerations

- Default requires no credential: `ipapi.co` is the single configured-by-code provider. Its current quotas, acceptable use, privacy terms and regional transfer implications must be checked by the operator before production use.
- To request an IPinfo fallback in the v2 path, set `MAILTRACE_GEOLOCATION_PROVIDERS=ipapi,ipinfo`, provide `IPINFO_TOKEN`, and set `MAILTRACE_GEOLOCATION_IPINFO_APPROVED=true` only after organizational/legal approval. This repository does not establish that such approval exists. Without all three, IPinfo is not queried.
- Each uncached public IP can disclose an IP address to a third-party geolocation provider. Limit lookups to eligible public IPs, review retention/contract terms, and avoid sending private message content; only the IP is sent in the geolocation request.
- Cache reduces repeated calls and provider cost. Memory entries are cleared on process restart; optional Redis entries follow their TTL and are shared across workers. Monitor provider 429/error rates, Redis fallback warnings, and lookup latency before choosing production concurrency or scaling settings.
- IP geolocation is approximate infrastructure context, not proof of a sender's identity or physical location.

## Handoff

Step 22 implementation and local automated verification are complete for review. Known limitations: shared Redis and external live provider behavior were not tested against real services; provider terms and legal approval remain an operator responsibility, and IPinfo stays opt-in until explicitly approved. **Do not start Step 23 until this report is reviewed.**




## F. Follow-up hardening implemented after review

### Shared cache option

- Added optional Redis-backed TTL caching to the v2 geolocation provider. Set `MAILTRACE_GEOLOCATION_REDIS_URL` to a protected Redis URL to enable it. Install the optional dependency from `backend/requirements-geolocation-redis.txt`; the normal backend requirements remain unchanged.
- Redis keys are namespaced by provider and normalized public IP (`mailtrace:geo:v1:<provider>:<ip>`); values contain only normalized geolocation result/provenance, not email content or provider credentials. Redis TTL uses the same policy as the in-process cache: successful lookups 24 hours; `NO_DATA` 5 minutes. Transient provider failures are not cached.
- Redis reads/writes have short connection/socket timeouts. If Redis is missing or unavailable, analysis continues with the process-local cache and emits a warning; response metadata identifies `cache_backend` as `memory` or `redis`. This is fail-soft for analysis availability, not a guarantee of shared-cache availability. Operators should alert on Redis warnings and confirm `cache_backend=redis` before relying on multi-worker cache sharing.
- `clear_geolocation_cache()` clears the in-process cache only; it does not flush shared Redis data.

Example configuration for a deployment that already has an approved, protected Redis instance (do not put credentials in source control):

```text
MAILTRACE_GEOLOCATION_REDIS_URL=redis://localhost:6379/2
```

Install the optional dependency from the backend folder with `venv\Scripts\python.exe -m pip install -r requirements-geolocation-redis.txt`. Use TLS/authenticated Redis and network restrictions for production; the localhost URL above is a local example only.

### Opt-in live provider smoke test

- Added `backend/tests/test_phase5_step22_live_geolocation.py`. It is skipped by default and makes no external request in ordinary CI. To opt in manually, set `MAILTRACE_GEOLOCATION_LIVE_TESTS=true` and `MAILTRACE_GEOLOCATION_IPAPI_APPROVED=true`; optional `MAILTRACE_GEOLOCATION_LIVE_TEST_IP` selects the public IP to test (defaults to `8.8.8.8`). This transmits that IP to ipapi.co and may consume quota. Use only an approved test IP and run only when provider terms and network egress are approved.
- The live test was **not run** during this implementation; external service availability, current provider terms, quotas, and actual live response are not certified.

### Provider approval and production release gate

Before enabling this feature in production, an accountable operator must complete and record all of the following:

- [ ] Review the selected provider's current acceptable-use terms, quotas/rate limits, pricing, privacy/retention terms, data processing terms, and international transfer implications.
- [ ] Obtain organizational/legal approval to disclose eligible public IP addresses to that provider; record approver, date, and provider. Code cannot grant legal approval.
- [ ] Keep `MAILTRACE_GEOLOCATION_PROVIDERS` allowlisted to approved providers only. IPinfo additionally requires `IPINFO_TOKEN` and `MAILTRACE_GEOLOCATION_IPINFO_APPROVED=true`; token presence alone never enables it. Do not set the approval flag until the review is complete.
- [ ] For multi-worker/multi-instance deployments, configure protected Redis, install the optional dependency, and verify response metadata shows `cache_backend=redis`; monitor fallback warnings and Redis connectivity.
- [ ] Monitor provider latency, `TIMEOUT`, `RATE_LIMITED`, `PROVIDER_ERROR`, `NO_DATA` rates and Redis fallback logs. Set thresholds based on observed traffic/provider quotas; no production SLO is claimed by this change.
- [ ] Exercise provider outage, Redis outage, timeout and 429 scenarios before release. Missing geolocation must remain unknown/unavailable evidence and must never alone turn an investigation into a benign/safe verdict.
- [ ] Run the standard offline CI suite; keep live tests in a separate explicitly approved job, never an implicit default CI step.

## G. Verification after follow-up hardening

- Python compilation: PASS.
- Focused Step 22 suite plus opt-in live-test module: **21 passed, 1 skipped**. The skip is expected because the live-test opt-in and explicit IPAPI approval flags were not enabled.
- Full backend suite: **447 passed, 1 skipped, 8 subtests passed**. The only skip is the opt-in live provider test.
- Canonical Phase 4 offline gate: **PASS**, 66 passed + 8 subtests; baseline `mailtrace-phase4-step18-offline-v1` matched; TP=3, FP=0, TN=3, FN=0, 2 inconclusive/excluded.
- `git diff --check`: PASS for the command's working tree scope. No commit was made.
- Redis behavior was validated with a fake in-memory Redis-compatible test double, not a real Redis server. A real Redis deployment and external live provider remain unverified.

Step 22 remains the current handoff. **Step 23 has not been started.**


## H. Review remediation: approval enforcement and release evidence

### IPinfo approval gate hardened

- `_query("ipinfo", ip)` now checks the explicit approval flag, provider allowlist, and token **before cache lookup or network I/O**. Therefore a direct `query_ipinfo()` call cannot bypass the same policy enforced by `get_geolocation()`, and an existing cache entry cannot be returned while the provider is disabled.
- `get_geolocation()` uses the same gate helper to keep its error behavior aligned with direct provider calls.
- Added direct-call regression tests for: approval missing (blocked with no provider I/O), provider absent from allowlist even when approval is true (blocked), missing token (blocked), and all gates satisfied (mocked provider call allowed).

### Live-provider smoke test made meaningful

- The opt-in live smoke test now passes only when the provider returns `AVAILABLE` or a legitimate `NO_DATA`. `TIMEOUT`, `RATE_LIMITED`, `PROVIDER_ERROR`, and malformed/provider failures fail the smoke test instead of being mistaken for successful live verification.
- The test remains skipped unless both `MAILTRACE_GEOLOCATION_LIVE_TESTS=true` and `MAILTRACE_GEOLOCATION_IPAPI_APPROVED=true` are set. **It was not run during this review**, because no live provider approval was provided; no external request was made.

### Verification boundaries and operator-only release gates

- Automated tests and the Phase 4 offline gate validate local behavior only. Redis was tested with a fake Redis-compatible test double; no real Redis server has been verified in this review.
- Provider acceptable-use terms, quotas, privacy/retention terms, data-processing terms, and any cross-border transfer implications remain to be reviewed by the accountable operator. Legal/organizational approval is not inferred from an environment variable and cannot be certified by this code review.
- Before production, the operator must record provider approval and date, run the live smoke test only under approved conditions, verify `cache_backend=redis` against the intended Redis deployment if multi-worker sharing is required, and monitor provider/Redis failure metrics.
- Step 23 has **not** been started. No commit was made.


### Latest review test run

- Python compilation: PASS.
- Focused Step 22 reliability + opt-in live module: **21 passed, 1 skipped**.
- Full backend suite: **447 passed, 1 skipped, 8 subtests passed**.
- Phase 4 offline gate: **PASS**, 66 passed + 8 subtests; baseline `mailtrace-phase4-step18-offline-v1` matched; TP=3, FP=0, TN=3, FN=0, 2 inconclusive/excluded.
- `git diff --check`: PASS. The live provider test remains intentionally skipped; no live provider request or real Redis server verification was performed. No commit was made, and Step 23 remains unstarted.

## I. Current-turn reliability fixes and verification (2026-10-19)

### Changes in this review

- Provider payloads now pass bounded type and coordinate-range validation. Invalid latitude/longitude values are discarded; malformed-only payloads become `PROVIDER_ERROR` and are not cached. Latitude/longitude are retained only as a valid pair.
- The v2 and legacy result paths now preserve geolocation semantics end-to-end: `AVAILABLE` → `PASS`, `NO_DATA` → `UNKNOWN`, `NOT_PUBLIC` → `NOT_APPLICABLE`, and `NOT_CONFIGURED` → `NOT_RUN`; provider outages remain `ERROR`.
- Missing IPinfo approval/allowlist/token and an empty/unsupported provider list are represented as `NOT_CONFIGURED`, rather than a provider outage. They cause no provider I/O.
- The existing explicitly configured fallback order remains in effect: it proceeds after no-data or a provider failure, and stops at the first successful location. IPinfo remains opt-in behind its approval flag, provider allowlist and token. No new provider was added.
- `.env.example` now documents provider selection, Redis cache URL, IPinfo opt-in and token fields without credentials.
- Added mocked tests for malformed provider fields/coordinates, incomplete coordinate pairs, no supported provider, fallback after `NO_DATA`, and high-level `NO_DATA`/`NOT_CONFIGURED` result states.

### Current verification

- `py_compile` using the bundled Python 3.12 runtime: PASS for changed Python modules and test file.
- Focused Step 22 reliability suite plus opt-in live module: **29 passed, 1 skipped**. The skip is the live external provider test; no live service request was made.
- Focused combined Step 21, Step 22 and Step 3 status tests: **71 passed, 1 skipped, 3 failed**. All three failures are existing Step 21 IPv4-mapped-IPv6 canonicalization expectations (`test_ipv4_mapped_ipv6_uses_embedded_ipv4_policy`, `test_public_ipv4_mapped_ipv6_is_sent_as_canonical_ipv4`, `test_ioc_normalizer_uses_shared_scope_for_mapped_ipv6_without_inner_duplicate`). They are outside Step 22 changes and indicate the current Step 21 checkout needs follow-up.
- Full backend suite could not be collected cleanly with the available runtime: the project venv's compiled `pydantic_core` extension targets Python 3.11, while the available bundled interpreter is Python 3.12 (`ModuleNotFoundError: pydantic_core._pydantic_core`). This is an environment incompatibility; the full suite result is **unverified in this run**. The repository venv's own Python executable could not be started here (`Access is denied`).
- Redis was tested only with the existing fake Redis-compatible object; no live provider, real Redis, provider-contract or legal approval check was performed.

Step 22 code changes and focused mocked acceptance tests are ready for review. The full backend regression status is not certified by this run. Step 23 has **not** been started.
