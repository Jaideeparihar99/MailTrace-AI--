# MailTrace AI - SOC case security configuration

## Identity and production access

Production SOC case endpoints require a signed OIDC bearer access token. The API validates its signature against the configured JWKS endpoint and validates issuer, audience, expiry, and subject. The stable analyst identity is the token `sub`; the tenant and roles are read only from configured token claims. Static API keys remain available for existing service integrations, but they are not accepted for production SOC case routes.

In production, every configured static API-key tenant must exactly match `MAILTRACE_SINGLE_TENANT_ID`; startup fails closed on mismatch. OIDC tokens are subject to the same single-tenant restriction. This is a temporary deployment boundary, not multi-tenant production support.

The investigations database accessors and `save_investigation` also enforce the configured production tenant at the storage boundary. A caller cannot use these functions to read or write a different tenant by passing an arbitrary ID; omitted read scope resolves only to the configured tenant, while production writes still require an explicit tenant ID.

Configure these deployment environment variables from the organization's identity-provider metadata:

- `MAILTRACE_ENV=production`
- `MAILTRACE_DATA_ENCRYPTION_KEY=<base64-encoded 32-byte key from the deployment secret manager>` (required for legacy v1 data; never put the value in source control or logs)
- Or `MAILTRACE_DATA_ENCRYPTION_KEYS_JSON={"key-id":"<base64-encoded 32-byte key>",...}` with `MAILTRACE_DATA_ENCRYPTION_KEY_ID=<active-key-id>` for key-ring-based encryption and rotation.
- `MAILTRACE_SINGLE_TENANT_ID=<the one tenant enabled for this deployment>` (required while global stores remain)
- `MAILTRACE_OIDC_ISSUER=https://<trusted-issuer>`
- `MAILTRACE_OIDC_AUDIENCE=<API-audience>`
- `MAILTRACE_OIDC_JWKS_URL=https://<trusted-issuer>/.well-known/jwks.json`
- `MAILTRACE_OIDC_TENANT_CLAIM=tenant_id` (or the provider's verified organization claim)
- `MAILTRACE_OIDC_ROLES_CLAIM=roles` (or a dotted claim path such as `realm_access.roles`)
- `MAILTRACE_OIDC_CLIENT_ID=<public SPA client id>`
- `MAILTRACE_OIDC_AUTHORIZATION_ENDPOINT=https://<issuer>/authorize`
- `MAILTRACE_OIDC_TOKEN_ENDPOINT=https://<issuer>/token`
- `MAILTRACE_OIDC_REDIRECT_URI=https://<frontend-origin>/index.html` (must exactly match the provider registration)
- Optional `MAILTRACE_OIDC_SCOPES=openid profile email`
- Optional `MAILTRACE_OIDC_ROLE_MAP_JSON` JSON object mapping provider roles/groups to MailTrace roles such as `analyst`, `soc_lead`, and `tenant_admin`.
- Optional `MAILTRACE_OIDC_REGION_CLAIM`, `MAILTRACE_OIDC_TEAM_CLAIM`, and `MAILTRACE_OIDC_SKILLS_CLAIM` for signed organization metadata.
- `MAILTRACE_CASE_CLAIM_LEASE_MINUTES=20` (accepted range 5 to 60 minutes).
- `MAILTRACE_WEBHOOK_TENANT_ID=<tenant>` for trusted email-webhook alert creation in production; it must equal `MAILTRACE_SINGLE_TENANT_ID`.
- `MAILTRACE_CORS_ORIGINS=https://<frontend-origin>` (comma-separated exact origins; no wildcard for production).

Install the security dependency with `python -m pip install -r backend/requirements-soc-security.txt` in the deployment environment. Never use example issuer, audience, tenant, or role values as production configuration. The OIDC provider must issue signed JWT access tokens with a stable `sub`, trusted tenant claim, and mapped roles. Register the frontend as a public client using Authorization Code + PKCE (S256), allow the exact redirect URI and browser token-endpoint CORS origin, and do not configure a client secret in the browser. The SPA keeps the access token in memory only (no local/session storage and no refresh token); a full page reload requires another sign-in redirect. Set `window.MAILTRACE_API_BASE` before `soc-auth.js` when the frontend is deployed separately from the backend. The frontend origin must also be allowed by `MAILTRACE_CORS_ORIGINS`; configure only trusted exact origins. Do not trust browser-supplied region/team values.

## Database migration behavior

`initialize_database()` adds tenant scope without dropping existing records. In development, legacy cases and investigations are assigned to `local`. In production, legacy cases are marked `__legacy_unassigned__` and investigations keep a null tenant; both remain hidden from tenant-scoped reads until an authorized migration maps each record to its verified tenant. Investigation uploads require a tenant in production, and list, detail, map, campaign, high-risk, and live-intelligence reads are tenant-filtered. Evidence and integrity lookups are authorized through their linked investigation's tenant. Even old internal calls that omit a tenant are restricted to `MAILTRACE_SINGLE_TENANT_ID` in production. Back up the database and review quarantined rows before mapping them.

Sensitive investigation fields (filename, subject, sender, recipients, SMTP envelope recipients, and the full analysis JSON) use AES-256-GCM when a data key is configured. Production initialization requires a data key and migrates legacy plaintext database fields before serving requests. Preserved raw email files in the evidence vault are encrypted with the key; legacy vault files and stored evidence filenames are migrated and verified at startup. For rotation, keep the previous singleton key in `MAILTRACE_DATA_ENCRYPTION_KEY` while configuring `MAILTRACE_DATA_ENCRYPTION_KEYS_JSON` with both old and new key IDs, and set the new ID in `MAILTRACE_DATA_ENCRYPTION_KEY_ID`. Restart so database fields, ledger filenames, and vault files are re-encrypted; verify every ciphertext key ID and evidence hash before removing the previous key from the key ring and retiring the legacy variable. Keep keys in a managed secret store with a separately protected backup; never replace a key before migration and verification finish. Development remains plaintext unless a key is explicitly configured.

The initial retention periods for new investigations are configurable with `MAILTRACE_RETENTION_DAYS_INTERNAL` (default 365), `MAILTRACE_RETENTION_DAYS_SENSITIVE` (default 730), and `MAILTRACE_RETENTION_DAYS_RESTRICTED` (default 1095); each accepts 0–3650 days. The service persists each investigation's expiry and runs an hourly, transaction-serialized cleanup. Expired records are skipped while legal/forensic holds exist, while an associated case is open, or while an analyst claim is active. The cleanup purges configured derived email content, employee notes/addresses, case notes, and linked derived evidence, while preserving a tombstone and tenant hash-chained retention event. Raw evidence is retained by default. An institution may explicitly enable irreversible raw-file expiry with `MAILTRACE_PURGE_RAW_EVIDENCE=true`; `false` is the default and only `true`/`false` are accepted. The custody ledger writes a policy-bound purge request and completion event with the original hashes before the DB retention event completes. A crash after file deletion is reconciled idempotently on the next hourly pass; custody metadata and hash commitments remain, while the original bytes are no longer available for content verification. Back up according to institutional policy and review legal, regulatory, litigation, and incident-response retention obligations before enabling this setting. `GET /api/privacy/retention/{investigation_id}` returns status and tenant-chain integrity; only a tenant administrator can update holds through `PUT /api/privacy/retention/{investigation_id}/holds`.

Claim events are append-only at the SQLite layer. Claim, renew, and release endpoints accept `Idempotency-Key` (maximum 128 characters); clients should reuse the same key when retrying the same operation. The `reason` request field is stored in the claim audit event; email content and investigation body data are not added to claim audit details.

Case creation, analyst updates, investigation attachments, notes, automated high-risk case creation, and employee-report case updates also append actor-attributed events to a tenant hash chain. `GET /api/cases/{case_id}/audit` returns that case's events and verifies the complete tenant chain; the UI reports verification state alongside claim and routing history. Audit event details retain changed-field names and status transitions, not the note body or employee-provided sensitive content. The hash chain detects edits to retained records; production-grade external anchoring and retention controls still require deployment-specific configuration.

Employee reporting endpoints require an authenticated employee identity and verify that the reported message was addressed to that employee. For OIDC employee identities, the IdP must provide a verified email claim (`email_verified=true` by default); deployments with a namespaced claim can set `MAILTRACE_OIDC_EMAIL_VERIFIED_CLAIM` to its dotted claim path. Missing or false verification fails closed. API-key employee identities use the email configured in the trusted server-side key entry. Employee submit/list/detail responses are allowlisted to the report ID, incident type, priority, coarse report status, and timestamps; they do not return case IDs, investigation IDs, SOC region/team, assigned analyst, skills, or SLA data. Investigator routing remains available only through SOC-authorized endpoints.

## Current tenant boundary limitation

The existing access-control module deliberately refuses configurations containing multiple tenants while legacy evidence and other stores remain globally keyed. Investigation metadata and analysis records now carry tenant IDs, but evidence and other persistent/file-backed stores still need tenant isolation and independently verified access controls. Multi-tenant production is **not enabled** until that work is complete. Keep the existing fail-closed tenant-count guard enabled.
