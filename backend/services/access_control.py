"""Environment-configured API key authentication for hosted deployments.

Keys are supplied as SHA-256 digests so a database/config snapshot does not
contain usable credentials. Local development remains loopback-only and does
not need a key.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from urllib.parse import urlparse
from dataclasses import dataclass


_TENANT_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{1,62}$")


@dataclass(frozen=True)
class ApiPrincipal:
    tenant_id: str
    roles: frozenset[str]
    subject_id: str | None = None
    email: str | None = None
    auth_method: str = "api_key"
    region: str | None = None
    team: str | None = None
    skills: frozenset[str] = frozenset()


def is_production() -> bool:
    return os.getenv("MAILTRACE_ENV", "development").strip().lower() in {
        "prod", "production"
    }


def configured_api_keys() -> tuple[tuple[str, ApiPrincipal], ...]:
    """Parse MAILTRACE_API_KEYS_JSON; each entry has tenant_id, token_sha256, roles."""
    raw = os.getenv("MAILTRACE_API_KEYS_JSON", "").strip()
    if not raw:
        if is_production():
            raise RuntimeError("MAILTRACE_API_KEYS_JSON is required in production.")
        return ()

    try:
        entries = json.loads(raw)
    except json.JSONDecodeError as error:
        raise RuntimeError("MAILTRACE_API_KEYS_JSON must be valid JSON.") from error
    if not isinstance(entries, list) or not entries:
        raise RuntimeError("MAILTRACE_API_KEYS_JSON must be a non-empty JSON array.")

    parsed: list[tuple[str, ApiPrincipal]] = []
    seen_digests: set[str] = set()
    tenant_ids: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise RuntimeError("Every API key entry must be a JSON object.")
        tenant_id = str(entry.get("tenant_id", ""))
        digest = str(entry.get("token_sha256", "")).lower()
        roles_value = entry.get("roles", ["read", "write"])
        if not _TENANT_ID.fullmatch(tenant_id):
            raise RuntimeError("API key tenant_id has an invalid format.")
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise RuntimeError("API key token_sha256 must be a 64-character SHA-256 digest.")
        if not isinstance(roles_value, list) or not roles_value:
            raise RuntimeError("API key roles must be a non-empty array.")
        roles = frozenset(str(role).lower() for role in roles_value)
        allowed_roles = {
            "read", "write", "admin", "employee", "analyst", "soc_lead",
            "tenant_admin", "platform_admin", "service",
        }
        if not roles <= allowed_roles:
            raise RuntimeError(
                "API key roles may contain only read, write, admin, employee, analyst, "
                "soc_lead, tenant_admin, platform_admin, and service."
            )
        if "employee" in roles and roles & {
            "admin", "analyst", "soc_lead", "tenant_admin", "platform_admin", "service"
        }:
            raise RuntimeError(
                "Employee credentials cannot be combined with SOC, admin, or service roles."
            )
        subject_id = str(entry.get("subject_id", "")).strip() or None
        employee_email = str(entry.get("email", "")).strip().lower() or None
        if "employee" in roles:
            if not {"read", "write"} <= roles:
                raise RuntimeError("Employee credentials must include both read and write roles.")
            if not subject_id or len(subject_id) > 128:
                raise RuntimeError("Employee credentials require a configured subject_id.")
            if (
                not employee_email
                or len(employee_email) > 320
                or not re.fullmatch(r"[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+", employee_email)
            ):
                raise RuntimeError("Employee credentials require a valid configured email.")
        if digest in seen_digests:
            raise RuntimeError("Duplicate API key digest configured.")
        seen_digests.add(digest)
        tenant_ids.add(tenant_id)
        parsed.append((digest, ApiPrincipal(tenant_id, roles, subject_id, employee_email)))

    # Until every persistent and file-backed store is tenant-scoped, fail closed
    # instead of presenting a multi-tenant configuration as isolated.
    if len(tenant_ids) > 1:
        raise RuntimeError(
            "Multiple tenants are not enabled yet: tenant isolation for all stores is incomplete."
        )
    if is_production():
        allowed_tenant = os.getenv("MAILTRACE_SINGLE_TENANT_ID", "").strip()
        if not allowed_tenant or tenant_ids != {allowed_tenant}:
            raise RuntimeError(
                "Production API-key tenant_id values must all match MAILTRACE_SINGLE_TENANT_ID until multi-tenant isolation is complete."
            )
    return tuple(parsed)


def authenticate_api_key(token: str, entries=None) -> ApiPrincipal | None:
    if not token or len(token) > 512:
        return None
    candidate = hashlib.sha256(token.encode("utf-8")).hexdigest()
    for digest, principal in configured_api_keys() if entries is None else entries:
        if hmac.compare_digest(candidate, digest):
            return principal
    return None


# OIDC bearer-token verification is configured only through trusted deployment
# environment variables. No issuer, tenant, role, or subject is accepted from headers.
_OIDC_JWKS_CLIENTS = {}
_OIDC_ALLOWED_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]


def _claim_value(payload: dict, dotted_path: str):
    value = payload
    for part in str(dotted_path or "").split("."):
        if not part or not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def oidc_is_configured() -> bool:
    return all(os.getenv(name, "").strip() for name in (
        "MAILTRACE_OIDC_ISSUER",
        "MAILTRACE_OIDC_AUDIENCE",
        "MAILTRACE_OIDC_JWKS_URL",
    ))


def authenticate_oidc_token(token: str) -> ApiPrincipal | None:
    """Verify a signed OIDC access token and derive identity only from its claims."""
    if not oidc_is_configured():
        raise RuntimeError(
            "OIDC is not configured; set MAILTRACE_OIDC_ISSUER, MAILTRACE_OIDC_AUDIENCE, and MAILTRACE_OIDC_JWKS_URL."
        )
    if not token or len(token) > 16384 or token.count(".") != 2:
        return None
    try:
        import jwt
        from jwt import InvalidTokenError
        from jwt import PyJWKClient
    except ImportError as error:
        raise RuntimeError("PyJWT[crypto] is required for OIDC authentication.") from error

    issuer = os.environ["MAILTRACE_OIDC_ISSUER"].strip()
    audience = os.environ["MAILTRACE_OIDC_AUDIENCE"].strip()
    jwks_url = os.environ["MAILTRACE_OIDC_JWKS_URL"].strip()
    if is_production() and (
        urlparse(issuer).scheme != "https" or urlparse(jwks_url).scheme != "https"
    ):
        raise RuntimeError("Production OIDC issuer and JWKS URLs must use HTTPS.")
    try:
        client = _OIDC_JWKS_CLIENTS.get(jwks_url)
        if client is None:
            client = PyJWKClient(jwks_url, cache_jwk_set=True, lifespan=300, timeout=5)
            _OIDC_JWKS_CLIENTS[jwks_url] = client
        signing_key = client.get_signing_key_from_jwt(token)
    except Exception as error:
        # Key-discovery failures fail closed and are distinguished from bad claims.
        raise RuntimeError("OIDC signing keys could not be retrieved.") from error

    try:
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=_OIDC_ALLOWED_ALGORITHMS,
            audience=audience,
            issuer=issuer,
            options={"require": ["exp", "sub", "iss", "aud"]},
        )
    except InvalidTokenError:
        return None

    subject = str(claims.get("sub", "")).strip()
    tenant_claim = os.getenv("MAILTRACE_OIDC_TENANT_CLAIM", "tenant_id")
    roles_claim = os.getenv("MAILTRACE_OIDC_ROLES_CLAIM", "roles")
    tenant_id = str(_claim_value(claims, tenant_claim) or "").strip()
    if is_production():
        # Legacy investigation/evidence stores are still globally keyed. Until
        # those stores are tenant-scoped, production is deliberately single-tenant.
        allowed_tenant = os.getenv("MAILTRACE_SINGLE_TENANT_ID", "").strip()
        if not allowed_tenant or not _TENANT_ID.fullmatch(allowed_tenant):
            raise RuntimeError("MAILTRACE_SINGLE_TENANT_ID must be configured until all stores support multi-tenancy.")
        if tenant_id != allowed_tenant:
            return None
    raw_roles = _claim_value(claims, roles_claim)
    if isinstance(raw_roles, str):
        raw_roles = raw_roles.split()
    if not isinstance(raw_roles, (list, tuple, set)):
        return None
    role_map_raw = os.getenv("MAILTRACE_OIDC_ROLE_MAP_JSON", "{}").strip() or "{}"
    try:
        role_map = json.loads(role_map_raw)
    except json.JSONDecodeError as error:
        raise RuntimeError("MAILTRACE_OIDC_ROLE_MAP_JSON must be valid JSON.") from error
    if not isinstance(role_map, dict):
        raise RuntimeError("MAILTRACE_OIDC_ROLE_MAP_JSON must be a JSON object.")
    roles = frozenset(str(role_map.get(str(role), role)).strip().lower() for role in raw_roles if str(role).strip())
    allowed_roles = {
        "read", "write", "admin", "employee", "analyst", "soc_lead",
        "tenant_admin", "platform_admin", "service",
    }
    if not subject or len(subject) > 128 or not _TENANT_ID.fullmatch(tenant_id) or not roles or not roles <= allowed_roles:
        return None
    if "employee" in roles and roles & {"admin", "analyst", "soc_lead", "tenant_admin", "platform_admin", "service"}:
        return None
    email = str(claims.get("email", "")).strip().lower() or None
    if "employee" in roles:
        # Employee mailbox ownership is a security boundary for reporting a
        # message. Do not trust an IdP email claim unless the IdP explicitly
        # asserts that it verified the address. This is configurable for IdPs
        # that use a namespaced/custom claim, but missing/false fails closed.
        verified_claim = os.getenv(
            "MAILTRACE_OIDC_EMAIL_VERIFIED_CLAIM", "email_verified"
        ).strip()
        email_verified = _claim_value(claims, verified_claim)
        if email_verified is not True or not email or not re.fullmatch(
            r"[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+", email
        ):
            return None
    region = str(_claim_value(claims, os.getenv("MAILTRACE_OIDC_REGION_CLAIM", "region")) or "").strip() or None
    team = str(_claim_value(claims, os.getenv("MAILTRACE_OIDC_TEAM_CLAIM", "team")) or "").strip() or None
    raw_skills = _claim_value(claims, os.getenv("MAILTRACE_OIDC_SKILLS_CLAIM", "skills"))
    if isinstance(raw_skills, str):
        raw_skills = raw_skills.split()
    skills = frozenset(str(skill).strip().lower() for skill in raw_skills) if isinstance(raw_skills, (list, tuple, set)) else frozenset()
    return ApiPrincipal(
        tenant_id=tenant_id,
        roles=roles,
        subject_id=subject,
        email=email,
        auth_method="oidc",
        region=region,
        team=team,
        skills=skills,
    )



def oidc_public_client_config() -> dict:
    """Return only public SPA OIDC settings; never expose a client secret."""
    client_id = os.getenv("MAILTRACE_OIDC_CLIENT_ID", "").strip()
    authorization_endpoint = os.getenv("MAILTRACE_OIDC_AUTHORIZATION_ENDPOINT", "").strip()
    token_endpoint = os.getenv("MAILTRACE_OIDC_TOKEN_ENDPOINT", "").strip()
    redirect_uri = os.getenv("MAILTRACE_OIDC_REDIRECT_URI", "").strip()
    public_urls_secure = all(
        urlparse(value).scheme == "https"
        for value in (authorization_endpoint, token_endpoint, redirect_uri)
        if value
    )
    enabled = bool(
        oidc_is_configured() and client_id and authorization_endpoint and token_endpoint and redirect_uri
        and (not is_production() or public_urls_secure)
    )
    return {
        "enabled": enabled,
        "issuer": os.getenv("MAILTRACE_OIDC_ISSUER", "").strip() if enabled else None,
        "client_id": client_id if enabled else None,
        "authorization_endpoint": authorization_endpoint if enabled else None,
        "token_endpoint": token_endpoint if enabled else None,
        "redirect_uri": redirect_uri if enabled else None,
        "scopes": os.getenv("MAILTRACE_OIDC_SCOPES", "openid profile email").strip() if enabled else None,
    }
