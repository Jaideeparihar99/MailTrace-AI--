from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import services.access_control as access_control


@pytest.fixture()
def oidc_key(monkeypatch):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    issuer = "https://identity.example.test"
    audience = "mailtrace-api"
    jwks_url = "https://identity.example.test/.well-known/jwks.json"
    monkeypatch.setenv("MAILTRACE_OIDC_ISSUER", issuer)
    monkeypatch.setenv("MAILTRACE_OIDC_AUDIENCE", audience)
    monkeypatch.setenv("MAILTRACE_OIDC_JWKS_URL", jwks_url)
    monkeypatch.setenv("MAILTRACE_OIDC_TENANT_CLAIM", "tenant_id")
    monkeypatch.setenv("MAILTRACE_OIDC_ROLES_CLAIM", "roles")
    access_control._OIDC_JWKS_CLIENTS.clear()

    class FakeJwksClient:
        def __init__(self, url, **kwargs):
            assert url == jwks_url
        def get_signing_key_from_jwt(self, token):
            return SimpleNamespace(key=public_key)

    monkeypatch.setattr(jwt, "PyJWKClient", FakeJwksClient)
    claims = {
        "iss": issuer,
        "aud": audience,
        "sub": "oidc-subject-analyst-42",
        "tenant_id": "tenant-a",
        "roles": ["analyst", "read", "write"],
        "region": "NORTH",
        "team": "SOC-NORTH",
        "skills": ["phishing", "bec"],
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }
    token = jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "test-key"})
    return token, claims, private_key


def test_oidc_subject_roles_tenant_and_metadata_come_from_verified_claims(oidc_key):
    token, _, _ = oidc_key
    principal = access_control.authenticate_oidc_token(token)
    assert principal is not None
    assert principal.auth_method == "oidc"
    assert principal.subject_id == "oidc-subject-analyst-42"
    assert principal.tenant_id == "tenant-a"
    assert principal.roles == frozenset({"analyst", "read", "write"})
    assert principal.region == "NORTH"
    assert principal.team == "SOC-NORTH"
    assert principal.skills == frozenset({"phishing", "bec"})


def test_oidc_rejects_wrong_issuer(oidc_key):
    _, claims, private_key = oidc_key
    claims["iss"] = "https://attacker.example.test"
    token = jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "test-key"})
    assert access_control.authenticate_oidc_token(token) is None


def test_oidc_requires_tenant_and_known_roles(oidc_key):
    _, claims, private_key = oidc_key
    claims["tenant_id"] = ""
    token = jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "test-key"})
    assert access_control.authenticate_oidc_token(token) is None
    claims["tenant_id"] = "tenant-a"
    claims["roles"] = ["superuser"]
    token = jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "test-key"})
    assert access_control.authenticate_oidc_token(token) is None


def test_oidc_fails_closed_when_provider_configuration_missing(monkeypatch):
    for name in ("MAILTRACE_OIDC_ISSUER", "MAILTRACE_OIDC_AUDIENCE", "MAILTRACE_OIDC_JWKS_URL"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(RuntimeError, match="OIDC is not configured"):
        access_control.authenticate_oidc_token("header.payload.signature")



def test_production_oidc_is_limited_to_configured_tenant(oidc_key, monkeypatch):
    _, claims, private_key = oidc_key
    monkeypatch.setenv("MAILTRACE_ENV", "production")
    monkeypatch.setenv("MAILTRACE_SINGLE_TENANT_ID", "tenant-a")
    same_tenant = jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "test-key"})
    assert access_control.authenticate_oidc_token(same_tenant).tenant_id == "tenant-a"
    claims["tenant_id"] = "tenant-b"
    other_tenant = jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "test-key"})
    assert access_control.authenticate_oidc_token(other_tenant) is None


def test_production_oidc_fails_closed_without_single_tenant_setting(oidc_key, monkeypatch):
    token, _, _ = oidc_key
    monkeypatch.setenv("MAILTRACE_ENV", "production")
    monkeypatch.delenv("MAILTRACE_SINGLE_TENANT_ID", raising=False)
    with pytest.raises(RuntimeError, match="MAILTRACE_SINGLE_TENANT_ID"):
        access_control.authenticate_oidc_token(token)



def test_public_oidc_client_config_requires_secure_production_urls(monkeypatch):
    monkeypatch.setenv("MAILTRACE_ENV", "production")
    for name, value in {
        "MAILTRACE_OIDC_ISSUER": "https://idp.example.test",
        "MAILTRACE_OIDC_AUDIENCE": "mailtrace-api",
        "MAILTRACE_OIDC_JWKS_URL": "https://idp.example.test/jwks",
        "MAILTRACE_OIDC_CLIENT_ID": "mailtrace-spa",
        "MAILTRACE_OIDC_AUTHORIZATION_ENDPOINT": "https://idp.example.test/authorize",
        "MAILTRACE_OIDC_TOKEN_ENDPOINT": "https://idp.example.test/token",
        "MAILTRACE_OIDC_REDIRECT_URI": "https://soc.example.test/index.html",
    }.items():
        monkeypatch.setenv(name, value)
    assert access_control.oidc_public_client_config()["enabled"] is True
    monkeypatch.setenv("MAILTRACE_OIDC_TOKEN_ENDPOINT", "http://idp.example.test/token")
    assert access_control.oidc_public_client_config()["enabled"] is False



def test_oidc_issuer_trailing_slash_is_compared_exactly(oidc_key, monkeypatch):
    _, claims, private_key = oidc_key
    issuer = "https://identity.example.test/"
    claims["iss"] = issuer
    monkeypatch.setenv("MAILTRACE_OIDC_ISSUER", issuer)
    token = jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "test-key"})
    principal = access_control.authenticate_oidc_token(token)
    assert principal is not None
    assert principal.subject_id == "oidc-subject-analyst-42"
