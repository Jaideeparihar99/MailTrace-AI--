"""Bounded, provenance-aware geolocation providers and in-process TTL cache.

Only explicitly configured providers run. No automatic retry is performed: both
providers use idempotent GET, but retries can double latency and provider cost.
"""
import json
import os
import time
import threading
import logging
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
import math
from typing import Any

from ..models import ProviderResult
from services.ip_address_policy import require_public_ip

DEFAULT_TIMEOUT_SECONDS = 3
SUCCESS_TTL_SECONDS = 24 * 60 * 60
NO_DATA_TTL_SECONDS = 5 * 60
_CACHE: dict[tuple[str, str], tuple[float, ProviderResult]] = {}
_CACHE_LOCK = threading.RLock()
_LOGGER = logging.getLogger(__name__)
_REDIS_CLIENT = None
_REDIS_URL = None


def _redis_client():
    """Return an optional shared Redis client; never make Redis a hard dependency."""
    global _REDIS_CLIENT, _REDIS_URL
    url = os.getenv("MAILTRACE_GEOLOCATION_REDIS_URL", "").strip()
    if not url:
        _REDIS_CLIENT = None
        _REDIS_URL = None
        return None
    if _REDIS_URL == url:
        # Avoid repeated optional-dependency setup attempts after a failed init.
        return _REDIS_CLIENT
    try:
        import redis
        _REDIS_CLIENT = redis.Redis.from_url(
            url, decode_responses=True, socket_connect_timeout=0.5,
            socket_timeout=0.5, health_check_interval=30,
        )
        _REDIS_URL = url
        return _REDIS_CLIENT
    except Exception as error:
        _LOGGER.warning("Geolocation Redis cache unavailable (%s); using local cache for this lookup", type(error).__name__)
        _REDIS_CLIENT = None
        _REDIS_URL = url
        return None


def _redis_key(provider: str, ip: str) -> str:
    # Namespace and normalize key identity; no provider token or email content is stored.
    return "mailtrace:geo:v1:" + provider + ":" + ip


def _from_payload(provider: str, payload: str) -> ProviderResult | None:
    try:
        item = json.loads(payload)
        if not isinstance(item, dict) or not isinstance(item.get("data"), dict):
            return None
        data = dict(item["data"])
        data["cache_status"] = "HIT"
        return ProviderResult(provider=provider, success=bool(item.get("success")), data=data,
                              error=item.get("error"), latency_ms=0)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _request_json(url: str, headers: dict | None = None, timeout: int = DEFAULT_TIMEOUT_SECONDS):
    request = urllib.request.Request(url, headers=headers or {"User-Agent": "MailTrace-AI/2.0"})
    with urllib.request.urlopen(request, timeout=min(max(float(timeout), 0.1), 5.0)) as response:
        raw = response.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("Provider response exceeded size limit")
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Provider response must be a JSON object")
    return data


def _status_from_error(error: Exception) -> str:
    if isinstance(error, urllib.error.HTTPError):
        if error.code == 429:
            return "RATE_LIMITED"
        return "PROVIDER_ERROR"
    if isinstance(error, (TimeoutError,)) or isinstance(error, urllib.error.URLError) and isinstance(getattr(error, "reason", None), TimeoutError):
        return "TIMEOUT"
    if isinstance(error, (json.JSONDecodeError, UnicodeDecodeError, ValueError, TypeError)):
        return "PROVIDER_ERROR"
    return "PROVIDER_ERROR"


def _normalize_provider_fields(data: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Keep only bounded, correctly typed provider values; reject malformed coordinates."""
    text_limits = {"country": 120, "country_code": 8, "region": 160, "city": 160,
                   "postal": 32, "timezone": 80, "continent": 8, "asn": 40,
                   "organization": 240, "hostname": 253}
    normalized: dict[str, Any] = {}
    malformed = False
    for key, limit in text_limits.items():
        value = data.get(key)
        if value is None or value == "":
            continue
        if not isinstance(value, str):
            malformed = True
            continue
        value = value.strip()
        if value:
            normalized[key] = value[:limit]
    for key, minimum, maximum in (("latitude", -90, 90), ("longitude", -180, 180)):
        value = data.get(key)
        if value is None or value == "":
            continue
        if isinstance(value, bool):
            malformed = True
            continue
        try:
            number = float(value)
        except (TypeError, ValueError, OverflowError):
            malformed = True
            continue
        if not math.isfinite(number) or not minimum <= number <= maximum:
            malformed = True
            continue
        normalized[key] = number
    if ("latitude" in normalized) != ("longitude" in normalized):
        normalized.pop("latitude", None)
        normalized.pop("longitude", None)
        malformed = True
    return normalized, malformed


def _cached(provider: str, ip: str) -> ProviderResult | None:
    client = _redis_client()
    if client is not None:
        try:
            payload = client.get(_redis_key(provider, ip))
            if payload:
                result = _from_payload(provider, payload)
                if result is not None:
                    result.data["cache_backend"] = "redis"
                    return result
        except Exception as error:
            _LOGGER.warning("Geolocation Redis cache read failed (%s); continuing without shared cache", type(error).__name__)
    key = (ip, provider)
    now = time.monotonic()
    with _CACHE_LOCK:
        entry = _CACHE.get(key)
        if not entry:
            return None
        expires, result = entry
        if now >= expires:
            _CACHE.pop(key, None)
            return None
        data = dict(result.data or {})
        data.update({"cache_status": "HIT", "cache_expires_at": data.get("cache_expires_at"), "cache_backend": "memory"})
        return ProviderResult(provider=provider, success=result.success, data=data, error=result.error, latency_ms=0)


def _store(provider: str, ip: str, result: ProviderResult, ttl: int) -> ProviderResult:
    data = dict(result.data or {})
    data.setdefault("ip", ip)
    data.setdefault("provider", provider)
    data.setdefault("lookup_timestamp", _now_iso())
    data["cache_status"] = "MISS"
    data["cache_ttl_seconds"] = ttl
    data["cache_expires_at"] = datetime.fromtimestamp(time.time() + ttl, timezone.utc).isoformat().replace("+00:00", "Z")
    normalized = ProviderResult(provider=provider, success=result.success, data=data, error=result.error, latency_ms=result.latency_ms)
    client = _redis_client()
    if client is not None:
        try:
            payload = json.dumps({"success": normalized.success, "data": normalized.data, "error": normalized.error}, separators=(",", ":"))
            client.setex(_redis_key(provider, ip), ttl, payload)
            normalized.data["cache_backend"] = "redis"
            return normalized
        except Exception as error:
            _LOGGER.warning("Geolocation Redis cache write failed (%s); retaining local cache", type(error).__name__)
    normalized.data["cache_backend"] = "memory"
    with _CACHE_LOCK:
        _CACHE[(ip, provider)] = (time.monotonic() + ttl, normalized)
    return normalized


def clear_geolocation_cache() -> None:
    """Clear the process-local cache (also useful for deterministic tests)."""
    with _CACHE_LOCK:
        _CACHE.clear()


def _ipinfo_gate_error() -> str | None:
    """Return why IPinfo is disabled; enforce policy for every call path."""
    if os.getenv("MAILTRACE_GEOLOCATION_IPINFO_APPROVED", "false").strip().lower() != "true":
        return "IPinfo is not explicitly approved for use."
    configured = os.getenv("MAILTRACE_GEOLOCATION_PROVIDERS", "ipapi")
    providers = {part.strip().lower() for part in configured.split(",") if part.strip()}
    if "ipinfo" not in providers:
        return "IPinfo is not enabled in MAILTRACE_GEOLOCATION_PROVIDERS."
    if not os.getenv("IPINFO_TOKEN"):
        return "IPINFO_TOKEN is not configured."
    return None


def _query(provider: str, ip: str) -> ProviderResult:
    # Enforce the IPinfo approval/allowlist/token gate before cache access or network I/O.
    # This prevents direct query_ipinfo() calls and old cache entries bypassing policy.
    if provider == "ipinfo":
        gate_error = _ipinfo_gate_error()
        if gate_error:
            return ProviderResult(
                provider="ipinfo", success=False,
                data={"status": "NOT_CONFIGURED", "ip": ip, "provider": "ipinfo",
                      "cache_status": "BYPASS", "lookup_timestamp": _now_iso()},
                error=gate_error, latency_ms=0,
            )
    cached = _cached(provider, ip)
    if cached is not None:
        return cached
    started = time.perf_counter()
    try:
        if provider == "ipapi":
            raw = _request_json(f"https://ipapi.co/{urllib.parse.quote(ip)}/json/", timeout=DEFAULT_TIMEOUT_SECONDS)
            if raw.get("error") or raw.get("reserved"):
                reason = str(raw.get("reason") or raw.get("message") or "")
                status = "RATE_LIMITED" if "rate" in reason.lower() or "limit" in reason.lower() else "PROVIDER_ERROR"
                return ProviderResult(provider=provider, success=False, data={"status": status}, error=status)
            data = {
                "country": raw.get("country_name"), "country_code": raw.get("country"),
                "region": raw.get("region"), "city": raw.get("city"), "postal": raw.get("postal"),
                "latitude": raw.get("latitude"), "longitude": raw.get("longitude"),
                "timezone": raw.get("timezone"), "continent": raw.get("continent_code"),
                "asn": raw.get("asn"), "organization": raw.get("org"),
            }
        elif provider == "ipinfo":
            token = os.getenv("IPINFO_TOKEN")
            if not token:
                return ProviderResult(provider=provider, success=False, data={"status": "NOT_CONFIGURED"}, error="Provider is selected but IPINFO_TOKEN is not configured.")
            raw = _request_json(
                f"https://ipinfo.io/{urllib.parse.quote(ip)}/json?token={urllib.parse.quote(token)}",
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
            latitude = longitude = None
            location = raw.get("loc")
            if isinstance(location, str) and "," in location:
                try:
                    latitude, longitude = (float(part.strip()) for part in location.split(",", 1))
                except (TypeError, ValueError):
                    latitude = longitude = None
            org = raw.get("org")
            data = {
                "country": raw.get("country_name"), "country_code": raw.get("country"),
                "region": raw.get("region"), "city": raw.get("city"), "postal": raw.get("postal"),
                "latitude": latitude, "longitude": longitude, "timezone": raw.get("timezone"),
                "asn": org.split(" ", 1)[0] if isinstance(org, str) and org else None,
                "organization": org, "hostname": raw.get("hostname"),
            }
        else:
            return ProviderResult(provider=provider, success=False, data={"status": "PROVIDER_ERROR"}, error="Unsupported geolocation provider.")
        data, malformed_fields = _normalize_provider_fields(data)
        has_location = any(data.get(field) is not None and data.get(field) != "" for field in ("country", "country_code", "region", "city", "latitude", "longitude"))
        if malformed_fields and not has_location:
            return ProviderResult(provider=provider, success=False,
                                  data={"status": "PROVIDER_ERROR", "ip": ip, "provider": provider,
                                        "cache_status": "BYPASS", "lookup_timestamp": _now_iso()},
                                  error="PROVIDER_ERROR", latency_ms=round((time.perf_counter() - started) * 1000, 2))
        location_fields = {"country", "country_code", "region", "city", "latitude", "longitude"}
        if not data or not any(data.get(field) is not None and data.get(field) != "" for field in location_fields):
            data.update({"status": "NO_DATA", "ip": ip})
            result = ProviderResult(provider=provider, success=False, data=data, error="NO_DATA")
            return _store(provider, ip, result, NO_DATA_TTL_SECONDS)
        data.update({"status": "AVAILABLE", "precision": "IP-derived approximate infrastructure location", "confidence": None})
        result = ProviderResult(provider=provider, success=True, data=data, latency_ms=round((time.perf_counter() - started) * 1000, 2))
        return _store(provider, ip, result, SUCCESS_TTL_SECONDS)
    except Exception as error:
        status = _status_from_error(error)
        latency = round((time.perf_counter() - started) * 1000, 2)
        # Do not cache transient errors. Never expose exception text, URLs or tokens.
        return ProviderResult(provider=provider, success=False, data={"status": status, "ip": ip, "provider": provider, "lookup_timestamp": _now_iso(), "cache_status": "BYPASS"}, error=status, latency_ms=latency)


def query_ipapi(ip: str) -> ProviderResult:
    safe_ip, policy = require_public_ip(ip)
    if safe_ip is None:
        return ProviderResult(provider="ipapi", success=False, data={"status": "NOT_PUBLIC", "classification": policy.get("classification")}, error="NOT_APPLICABLE: NOT_PUBLIC", latency_ms=0)
    return _query("ipapi", safe_ip)


def query_ipinfo(ip: str) -> ProviderResult:
    safe_ip, policy = require_public_ip(ip)
    if safe_ip is None:
        return ProviderResult(provider="ipinfo", success=False, data={"status": "NOT_PUBLIC", "classification": policy.get("classification")}, error="NOT_APPLICABLE: NOT_PUBLIC", latency_ms=0)
    return _query("ipinfo", safe_ip)


def get_geolocation(ip: str) -> list[ProviderResult]:
    safe_ip, policy = require_public_ip(ip)
    if safe_ip is None:
        return [ProviderResult(provider="geolocation", success=False, data={"status": "NOT_PUBLIC", "classification": policy.get("classification"), "ip": ip, "cache_status": "BYPASS"}, error="NOT_APPLICABLE: NOT_PUBLIC", latency_ms=0)]

    # Default is one provider. IPinfo is never activated merely because its token exists;
    # operators must explicitly opt it in via MAILTRACE_GEOLOCATION_PROVIDERS.
    configured = os.getenv("MAILTRACE_GEOLOCATION_PROVIDERS", "ipapi")
    providers = [part.strip().lower() for part in configured.split(",") if part.strip()]
    providers = [name for name in providers if name in {"ipapi", "ipinfo"}]
    if not providers:
        return [ProviderResult(provider="geolocation", success=False, data={"status": "NOT_CONFIGURED", "ip": safe_ip, "cache_status": "BYPASS", "lookup_timestamp": _now_iso()}, error="No supported geolocation provider is configured.", latency_ms=0)]
    results = []
    for name in providers[:2]:
        if name == "ipinfo":
            gate_error = _ipinfo_gate_error()
            if gate_error:
                results.append(ProviderResult(
                    provider="ipinfo", success=False,
                    data={"status": "NOT_CONFIGURED", "ip": safe_ip, "cache_status": "BYPASS", "lookup_timestamp": _now_iso()},
                    error=gate_error, latency_ms=0,
                ))
                continue
        result = query_ipapi(safe_ip) if name == "ipapi" else query_ipinfo(safe_ip)
        results.append(result)
        if result.success:
            break
    return results
