# MailTrace-AI — Step 4: Dependencies, Configuration and Tests Audit

**Audit date:** 2026-10-12  
**Repository:** D:\jaideep\practice\practice\mailtrace ai\MailTrace-AI--  
**Scope:** Read-only review of runtime declarations, dependency manifests, configuration references, startup instructions, tests and repository hygiene. No dependencies/configuration were changed. No secret values are included.

## A. Runtime and framework inventory

| Area | Verified current state |
|---|---|
| Backend language/runtime | Python. README says Python 3.11. No .python-version/runtime.txt or package metadata constrains Python. The checked backend virtualenv and system interpreter report Python 3.14.7. Documented and local configured runtime differ. |
| Backend framework/server | FastAPI and Uvicorn in backend/requirements.txt. Launcher uses Uvicorn with main:app. |
| Persistence | Python sqlite3; schema created/extended by source code. No migration framework or migration directory found. |
| Frontend | Static HTML/CSS/plain JavaScript. No Node/package.json/package manager/build step. Python http.server serves it. |
| Tests | pytest and unittest. Backend virtualenv has pytest 9.1.1; system Python does not. |
| Package manager | pip requirements files. No lockfile, pyproject.toml, setup.py/setup.cfg, Pipfile, poetry.lock or uv.lock found. |
| Optional external runtime | ClamAV daemon can be configured by socket/host; it is not bundled as a service. |

Python 3.14.7 is the actual local venv runtime. Repository documentation specifies 3.11. No CI/version matrix establishes compatibility across 3.11 and 3.14.

## B. Dependency manifests and lockfiles

| File | Contents | Version policy |
|---|---|---|
| backend/requirements.txt | Main runtime and pytest. Includes FastAPI, Uvicorn, Starlette, Pydantic, multipart, cryptography, DNS/DKIM/SPF, extract-msg, scikit-learn, joblib, NumPy/SciPy, tldextract, BeautifulSoup and supporting packages. | Mostly exact == pins; 60 lines including comments. |
| backend/requirements-email-processing.txt | Optional email processing and authentication packages: cryptography, extract-msg, dnspython, dkimpy and pyspf. | Mix of exact pins and bounded ranges; overlaps main requirements. |
| backend/requirements-soc-security.txt | Optional OIDC/security dependencies, including PyJWT with crypto extras and cryptography. | Bounded ranges; overlaps main requirements. |

No lockfile, hashes, constraints file, package build metadata, frontend package manifest or automated dependency update configuration found. Exact version pins are not hash-locked. Main requirements pin pytest, but there is no separate dev/test manifest. Standard library modules need no package declaration.

Dependency checks:

- Backend venv python -m pip check: exit 0, “No broken requirements found.”
- Vulnerability scanner: not run. pip-audit executable was unavailable; no vulnerability claims are made.
- No packages were installed, uninstalled or upgraded.
- Main requirements.txt omits PyJWT, while requirements-soc-security.txt includes it. services/access_control.py imports jwt when OIDC validation is invoked and raises a runtime error if unavailable. SOC security docs separately instruct installing the security manifest.
- Manifests overlap on cryptography, extract-msg, DNS, DKIM and SPF with different pin/range styles. pip check only verifies the current venv graph; it does not prove clean installation or compatibility on Python 3.11.

## C. Configuration variable inventory

Backend configuration is read via os.getenv/os.environ. No load_dotenv call was found; installing python-dotenv does not itself load a .env file. No root/backend .env or .env.example exists. Values are intentionally omitted. “Required” here means production-required or required when the feature is enabled.

| Variable name | Purpose | Requirement / behavior |
|---|---|---|
| MAILTRACE_ENV | Selects development/production validation and data-protection behavior. | Optional; defaults development. Set in production. |
| MAILTRACE_SINGLE_TENANT_ID | Tenant boundary for production auth/DB scope. | Required in production while stores are not fully tenant-isolated. |
| MAILTRACE_API_KEYS_JSON | Digest-based API-key identities, roles and tenant configuration. | Optional; valid JSON when API-key auth is enabled; tenant must match production boundary. |
| MAILTRACE_OIDC_ISSUER | Expected JWT issuer. | Required for production OIDC. |
| MAILTRACE_OIDC_AUDIENCE | Expected JWT audience. | Required for production OIDC. |
| MAILTRACE_OIDC_JWKS_URL | JWKS endpoint used for JWT signature validation. | Required for production OIDC. |
| MAILTRACE_OIDC_TENANT_CLAIM | Tenant claim name. | Optional; defaults tenant_id. |
| MAILTRACE_OIDC_ROLES_CLAIM | Roles claim name. | Optional; defaults roles. |
| MAILTRACE_OIDC_ROLE_MAP_JSON | Maps provider roles to app roles. | Optional JSON object. |
| MAILTRACE_OIDC_EMAIL_VERIFIED_CLAIM | Verified email claim path for employee reports. | Optional; defaults email_verified. |
| MAILTRACE_OIDC_REGION_CLAIM | Analyst region claim name. | Optional; defaults region. |
| MAILTRACE_OIDC_TEAM_CLAIM | Team claim name. | Optional; defaults team. |
| MAILTRACE_OIDC_SKILLS_CLAIM | Analyst skills claim name. | Optional; defaults skills. |
| MAILTRACE_OIDC_CLIENT_ID | Public SPA OIDC client ID. | Optional client configuration; needed for browser OIDC. |
| MAILTRACE_OIDC_AUTHORIZATION_ENDPOINT | IdP authorization URL. | Optional client configuration; needed for browser OIDC. |
| MAILTRACE_OIDC_TOKEN_ENDPOINT | IdP token endpoint. | Optional client configuration; needed for browser OIDC. |
| MAILTRACE_OIDC_REDIRECT_URI | SPA redirect URI. | Optional; needed for configured browser OIDC flow. |
| MAILTRACE_OIDC_SCOPES | Requested OIDC scopes. | Optional; defaults openid profile email. |
| MAILTRACE_WEBHOOK_SECRET | HMAC key for email intake webhook. | Optional integration; webhook disabled without it; readiness requires at least 32 characters when configured. |
| MAILTRACE_WEBHOOK_TENANT_ID | Tenant assigned to webhook deliveries. | Required for production webhook; must match single tenant. |
| MAILTRACE_GATEWAY_ACK_SECRET | HMAC key for gateway action-receipt callbacks. | Optional integration; needed for signed callbacks; readiness requires at least 32 characters. |
| MAILTRACE_ROUTING_EMAIL_HMAC_KEY | HMAC key for recipient-to-region mapping. | Optional; required for recipient-based routing; source requires >=32 characters. |
| MAILTRACE_DATA_ENCRYPTION_KEY | Legacy/single active encryption key. | Optional in development; one of this or key-ring setting required in production. |
| MAILTRACE_DATA_ENCRYPTION_KEYS_JSON | Encryption key ring. | Optional; one of this or legacy key required in production; JSON object. |
| MAILTRACE_DATA_ENCRYPTION_KEY_ID | Selects active key in key-ring mode. | Required with key ring; must name a configured key. |
| MAILTRACE_CORS_ORIGINS | Comma-separated allowed browser origins. | Optional; built-in local origins otherwise. |
| MAILTRACE_LOG_LEVEL | Application log level. | Optional; defaults INFO. |
| MAILTRACE_TI_SYNC_INTERVAL_MINUTES | Background feed sync interval; 0 disables it. | Optional; default 60; otherwise 15–1440 minutes. |
| THREATFOX_AUTH_KEY / THREATFOX_API_KEY | ThreatFox feed credentials; aliases accepted. | Optional provider config. |
| URLHAUS_AUTH_KEY / URLHAUS_API_KEY | URLhaus feed credentials; aliases accepted. | Optional provider config. |
| IPINFO_TOKEN | IPInfo geolocation token. | Optional provider config. |
| ABUSEIPDB_API_KEY | AbuseIPDB reputation token. | Optional provider config. |
| MAILTRACE_CLAMD_UNIX_SOCKET | Local ClamAV socket path. | Optional scanner; alternative to TCP host/port. |
| MAILTRACE_CLAMD_HOST | ClamAV network host. | Optional; required with port for TCP scanner. |
| MAILTRACE_CLAMD_PORT | ClamAV TCP port. | Optional; defaults 3310. |
| MAILTRACE_CLAMD_TIMEOUT_SECONDS | Scanner timeout. | Optional; defaults 2s and is capped at 5s. |
| MAILTRACE_REQUIRE_ATTACHMENT_SCAN | Require verified scan for attachment allow decision. | Optional; default true; boolean text only. |
| MAILTRACE_GATEWAY_ENFORCEMENT_MODE | monitor_only or enforce decision mode. | Optional; default monitor_only; enforce requires external gateway adapter. |
| MAILTRACE_REVIEW_THRESHOLD | Score threshold for review. | Optional; default 40; range 0–99 and below quarantine threshold. |
| MAILTRACE_QUARANTINE_THRESHOLD | Score threshold for quarantine consideration. | Optional; default 85; range 50–100 plus confidence/corroboration policy. |
| MAILTRACE_CASE_CLAIM_LEASE_MINUTES | Analyst claim lease. | Optional; default 20 minutes. |
| MAILTRACE_SLA_CRITICAL_MINUTES | Critical case SLA. | Optional; default 15 minutes. |
| MAILTRACE_SLA_HIGH_MINUTES | High case SLA. | Optional; default 60 minutes. |
| MAILTRACE_SLA_MEDIUM_MINUTES | Medium case SLA. | Optional; default 240 minutes. |
| MAILTRACE_SLA_LOW_MINUTES | Low case SLA. | Optional; default 1440 minutes. |
| MAILTRACE_RETENTION_DAYS_INTERNAL | Internal retention period. | Optional; default 365 days; range 0–3650. |
| MAILTRACE_RETENTION_DAYS_SENSITIVE | Sensitive retention period. | Optional; default 730 days; range 0–3650. |
| MAILTRACE_RETENTION_DAYS_RESTRICTED | Restricted retention period. | Optional; default 1095 days; range 0–3650. |
| MAILTRACE_PURGE_RAW_EVIDENCE | Enables raw evidence deletion after retention. | Optional; default false; only true/false accepted; deletion irreversible. |

MAILTRACE_API_BASE is a frontend JavaScript global set directly in frontend/index.html, not a backend environment variable. MAILTRACE_FORENSIC_SIGNAL_BUILD and MAILTRACE_HEADER_ENTRANCE_ANIMATION occur as frontend names; OBSERVED_INFRA_JS markers are code comments. They were excluded from runtime environment variables.

## D. Documented and executed commands

### Documented in repository, not executed as setup

README.md says to install Python 3.11, run START_MAILTRACE.ps1, or install with python -m pip install -r backend/requirements.txt and launch from backend with python -m uvicorn main:app --host 127.0.0.1 --port 8002. Launcher serves frontend on port 5503.

START_MAILTRACE.ps1 prefers the interpreter identified by backend/venv/pyvenv.cfg, otherwise python; starts Uvicorn on 127.0.0.1:8002 and Python static HTTP server on 127.0.0.1:5503. MAILTRACE_RELOAD=1 enables reload. START_MAILTRACE.bat invokes PowerShell.

README contains no test command. python -m pytest is inferred from manifest and tests, not a repository-defined script. No application startup or dependency install command was run in this audit.

### Commands actually executed

| Working directory | Command | Result |
|---|---|---|
| backend | .\venv\Scripts\python.exe --version | Python 3.14.7 |
| backend | .\venv\Scripts\python.exe -m pytest --version | pytest 9.1.1 |
| backend | $env:PYTHONDONTWRITEBYTECODE='1'; .\venv\Scripts\python.exe -m pytest -p no:cacheprovider -q tests/test_false_positive_scoring.py services/email_ai/test_intelligence_fusion.py | Exit 0; 4 passed in 2.90s. Four tests came from test_false_positive_scoring.py; test_intelligence_fusion.py has a main() demonstration, not pytest test functions. |
| backend | .\venv\Scripts\python.exe -m pip check | Exit 0; no broken requirements. |
| system | python --version | Python 3.14.7 |
| system | python -m pytest --version | Failed: No module named pytest. |

No production API, live provider, database test, model download, or launcher was invoked. The selected scoring tests import pure fusion/domain code and do not target application DB/network. The broader suite was not run: some test modules import backend.main, whose module initialization initializes the application database/runtime paths. Under this read-only audit, those side effects cannot be assumed away. Temp DB fixtures exist, but the full test group should be audited before collection/execution.

## E. Test inventory

| File(s) | Source-verified test type and area | Run status |
|---|---|---|
| backend/tests/test_false_positive_scoring.py | Four pytest tests: public-suffix domain comparison, promo-mail cap, phishing signals, corroboration. | Run; all passed. |
| backend/services/email_ai/test_intelligence_fusion.py | Demo main() function; no pytest test_* functions. | Passed as pytest argument but no tests collected from it. |
| backend/tests/test_access_control_oidc.py | pytest OIDC claims, issuer, tenant/role/config fail-closed cases. | Not run. |
| backend/tests/test_campaign_correlation.py | unittest campaign/IOC correlation cases. | Not run. |
| backend/tests/test_case_audit_chain.py | pytest audit/hash-chain behavior with tmp_path DB. | Not run. |
| backend/tests/test_churu_local_intake.py | pytest intake dry-run, bootstrap idempotence and production/tenant guards. | Not run. |
| backend/tests/test_cors_policy.py | unittest FastAPI TestClient CORS; imports main. | Not run. |
| backend/tests/test_email_alerting_policy.py | unittest alert policy, threshold, receipts and signature route. | Not run. |
| backend/tests/test_email_processing_security.py | unittest parser/auth/webhook/SSE/lease tests; imports main; temp artifacts in parts. | Not run. |
| backend/tests/test_soc_case_claims.py | pytest claims, tenant isolation, routing, rate-limit and SLA workflows; includes temp DB fixtures. | Not run. |
| backend/tests/test_soc_routing.py | Standalone pytest-style routing test using temporary SQLite and cleanup. | Not run. |
| backend/services/analysis_provenance/tests/test_soc.py | pytest ledger/provenance, deterministic hashes, persistence/reload and export. | Not run. |
| backend/services/analysis_provenance/tests/test_high_assurance.py | pytest replay/locking/journal recovery; subprocess/cross-process cases. | Not run. |
| backend/services/integrity_anchoring/tests/test_integrity_anchor_engine.py | pytest anchor persistence/idempotency/provider/local trust/RFC3161 adapter. | Not run. |
| backend/services/privacy_governance/tests/test_soc.py | Service-level privacy governance tests. | Not run. |
| backend/services/email_thread_intelligence/step2_test.py, step3_test.py, step4_test.py | Step-named test scripts; conventional discovery not established. | Not run. |
| backend/tests/attack_chain_adversarial_audit.py, mitre_attack_adversarial_audit.py | Adversarial/audit scripts, not established as pytest test files by name. | Not run. |
| backend/test_ip.py | Standalone IP test script. | Not run. |

No full-suite collection was run, so total collected test count is not asserted. No frontend unit/e2e/browser test files or JS test runner were found. Existing security coverage is mostly unit/in-process API tests; deployed-stack system testing was not established. ML training/evaluation scripts exist, but model artifact/dataset metrics were not run.

## F. Blockers and external-service reliance

- Production OIDC needs issuer/audience/JWKS configuration, claim mappings and PyJWT crypto dependency. No IdP or credentials were configured or validated.
- Email webhook and gateway action receipt need HMAC secrets; no vendor-specific adapter is supplied.
- SPF recomputation needs trusted SMTP context from signed webhook; browser uploads cannot provide it.
- DKIM/DMARC and IP/TI providers need network access; optional reputation providers need tokens. Not tested.
- ClamAV requires a reachable daemon; absent scanner is unavailable, not clean.
- Local phishing inference requires ignored joblib artifacts under backend/models/email_ai. README says trained binaries are excluded; artifact availability was not verified.
- No .env.example or centralized config schema documents every option.
- No CI workflow, Docker/Compose, deployment manifest, migration framework or Python version matrix.
- python-dotenv is declared, but no automatic dotenv loader was found; shell/service manager must supply variables.

## G. Risks and hygiene

1. **High — Runtime drift:** docs say Python 3.11, local venv is 3.14.7, no runtime pin or CI matrix.
2. **High — OIDC dependency split:** base requirements omit PyJWT; OIDC auth imports it dynamically. Optional security manifest includes it; deployment must follow that documented extra.
3. **Medium — No lock/hash strategy:** main pins mostly exact versions, optional manifests use ranges/overlap; clean-install reproduction not verified.
4. **Medium — No complete config template:** no .env.example; production settings are distributed across backend modules and feature docs.
5. **Medium — No vulnerability scan evidence:** pip-audit unavailable/not run; pip check only validates installed dependency consistency.
6. **Medium — Broader test suite side effects:** some tests import main, which initializes DB/runtime paths; no documented safe isolated suite command.
7. **Low/Medium — Test discoverability:** some test-named files are demos or step scripts, not pytest test functions.
8. **Low — Cache ignore gap:** .gitignore excludes __pycache__ but not .pytest_cache; normal pytest can create an untracked cache. This audit disabled cache writes.
9. **Low — Report ignore gap:** generated audit reports are not ignored. This is useful for requested deliverables if committed intentionally; repository policy is unstated.
10. **Low — python-dotenv appears unused:** package is pinned but no load_dotenv call exists; users may assume .env is loaded when it is not.

.gitignore excludes Python bytecode, virtual environments, .env/.env.* while allowing .env.example, common key/certificate and credential/secret filename patterns, databases, logs, .eml/.msg, local runtime/evidence/test data and joblib model binaries. This reduces accidental commits of local secrets, emails, DBs and models. No .env.example exists. The ignore rules do not establish absence of secrets in Git history; no history-wide secret scan was run.

## H. Safe reproducibility recommendations

1. Declare/test supported Python version(s), aligning README, launcher and venv.
2. Add a sanitized .env.example and central config reference with required/conditional names and safe defaults.
3. Make optional dependencies explicit in setup instructions, particularly PyJWT for OIDC; test clean installs from each supported manifest.
4. Use a lock/constraints strategy with hashes and automate dependency vulnerability reporting in CI.
5. Isolate DB/runtime paths for all tests before full-suite execution; document exact safe test commands.
6. Separate pure unit, temporary DB integration and live-provider tests; mark network/credential requirements opt-in.
7. Add frontend lint/unit/browser coverage if UI behavior is in scope.
8. Document model artifact provenance/version/evaluation and how missing artifacts are represented.

## Handoff

Runtime, manifests, environment variable names, documented versus executed commands, test result, blockers and hygiene risks are recorded. Only the isolated scoring tests were run (4 passed); no dependencies or source/configuration files changed. Stop for review.

