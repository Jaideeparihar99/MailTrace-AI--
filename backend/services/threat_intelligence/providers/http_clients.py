"""Small, independently testable HTTP adapters for threat-intelligence providers."""
from __future__ import annotations
import base64
import json
import logging
import os
import ipaddress
import re
import socket
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from services.ip_address_policy import require_public_ip

logger = logging.getLogger(__name__)
PROVIDERS = {
    "abuseipdb": {"key_env": "ABUSEIPDB_API_KEY", "url_env": "ABUSEIPDB_API_URL", "url": "https://api.abuseipdb.com/api/v2/check"},
    "virustotal": {"key_env": "VIRUSTOTAL_API_KEY", "url_env": "VIRUSTOTAL_API_URL", "url": "https://www.virustotal.com/api/v3"},
    "threatfox": {"key_env": "THREATFOX_API_KEY", "url_env": "THREATFOX_API_URL", "url": "https://threatfox-api.abuse.ch/api/v1/"},
    "urlhaus": {"key_env": "URLHAUS_API_KEY", "url_env": "URLHAUS_API_URL", "url": "https://urlhaus-api.abuse.ch/v1/url/"},
}
def _failure(provider, code, *, http_status=None):
    if code != "NOT_CONFIGURED":
        logger.warning("threat_intel_provider_failure provider=%s code=%s http_status=%s", provider, code, http_status)
    return {"provider": provider, "status": "unavailable", "available": False, "error_code": code, "http_status": http_status, "data": None}
def _request_json(provider, url, *, method="GET", headers=None, data=None, timeout=4.0):
    request = Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urlopen(request, timeout=timeout) as response:
            status = getattr(response, "status", 200)
            raw = response.read()
    except HTTPError as exc:
        code = "AUTH_ERROR" if exc.code in (401, 403) else "RATE_LIMITED" if exc.code == 429 else "PROVIDER_HTTP_ERROR"
        return _failure(provider, code, http_status=exc.code)
    except (socket.timeout, TimeoutError):
        return _failure(provider, "TIMEOUT")
    except (URLError, OSError):
        return _failure(provider, "NETWORK_ERROR")
    if status == 429: return _failure(provider, "RATE_LIMITED", http_status=status)
    if status in (401, 403): return _failure(provider, "AUTH_ERROR", http_status=status)
    if status >= 400: return _failure(provider, "PROVIDER_HTTP_ERROR", http_status=status)
    try: parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError): return _failure(provider, "MALFORMED_JSON", http_status=status)
    if not isinstance(parsed, dict): return _failure(provider, "MALFORMED_SCHEMA", http_status=status)
    return {"provider": provider, "status": "ok", "available": True, "error_code": None, "http_status": status, "data": parsed}
def _key(provider):
    aliases = {
        "threatfox": ("THREATFOX_AUTH_KEY", "THREATFOX_API_KEY"),
        "urlhaus": ("URLHAUS_AUTH_KEY", "URLHAUS_API_KEY"),
    }.get(provider, (PROVIDERS[provider]["key_env"],))
    for name in aliases:
        value = (os.getenv(name) or "").strip()
        if value:
            return value
    return ""
def lookup_abuseipdb(ip, *, timeout=4.0, api_key=None, url=None):
    safe_ip, policy = require_public_ip(ip)
    if safe_ip is None:
        code = "NOT_APPLICABLE_NOT_PUBLIC" if policy["valid"] else "INVALID_IP"
        return _failure("abuseipdb", code)
    ip = safe_ip
    provider = "abuseipdb"; key = api_key or _key(provider)
    if not key: return _failure(provider, "NOT_CONFIGURED")
    endpoint = url or os.getenv(PROVIDERS[provider]["url_env"]) or PROVIDERS[provider]["url"]
    result = _request_json(provider, endpoint + "?" + urlencode({"ipAddress": ip, "maxAgeInDays": "90"}), headers={"Key": key, "Accept": "application/json"}, timeout=timeout)
    if result["available"] and not isinstance(result["data"].get("data"), dict): return _failure(provider, "MALFORMED_SCHEMA", http_status=result["http_status"])
    return result
def lookup_virustotal(ioc, *, ioc_type="ip", timeout=4.0, api_key=None, base_url=None):
    if ioc_type == "ip":
        safe_ip, policy = require_public_ip(ioc)
        if safe_ip is None:
            code = "NOT_APPLICABLE_NOT_PUBLIC" if policy["valid"] else "INVALID_IP"
            return _failure("virustotal", code)
        ioc = safe_ip
    provider = "virustotal"; key = api_key or _key(provider)
    if not key: return _failure(provider, "NOT_CONFIGURED")
    base = (base_url or os.getenv(PROVIDERS[provider]["url_env"]) or PROVIDERS[provider]["url"]).rstrip("/")
    if ioc_type == "url": path = "/urls/" + base64.urlsafe_b64encode(ioc.encode("utf-8")).decode("ascii").rstrip("=")
    elif ioc_type == "domain": path = "/domains/" + ioc
    elif ioc_type in {"hash", "md5", "sha1", "sha256", "file"}: path = "/files/" + ioc
    else: path = "/ip_addresses/" + ioc
    result = _request_json(provider, base + path, headers={"x-apikey": key, "Accept": "application/json"}, timeout=timeout)
    if result["available"] and not isinstance(result["data"].get("data"), dict): return _failure(provider, "MALFORMED_SCHEMA", http_status=result["http_status"])
    return result
def lookup_threatfox(ioc, *, ioc_type=None, timeout=4.0, api_key=None, url=None):
    # The adapter is also called directly outside the orchestrator, so infer a
    # literal IP when callers omit its type and guard typed IPs unconditionally.
    candidate = str(ioc).strip()
    inferred_ip = False
    if ioc_type == "ip":
        inferred_ip = True
    elif ioc_type is None and not candidate.lower().startswith(("http://", "https://")):
        try:
            ipaddress.ip_address(candidate)
            inferred_ip = True
        except ValueError:
            # Reject malformed dotted-quad candidates instead of treating them
            # as arbitrary ThreatFox search text.
            inferred_ip = bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", candidate))
    if inferred_ip:
        safe_ip, policy = require_public_ip(candidate)
        if safe_ip is None:
            code = "NOT_APPLICABLE_NOT_PUBLIC" if policy["valid"] else "INVALID_IP"
            return _failure("threatfox", code)
        ioc = safe_ip
    provider = "threatfox"; key = api_key or _key(provider)
    if not key: return _failure(provider, "NOT_CONFIGURED")
    endpoint = url or os.getenv(PROVIDERS[provider]["url_env"]) or PROVIDERS[provider]["url"]
    payload = json.dumps({"query": "search_ioc", "search_term": ioc}).encode("utf-8")
    result = _request_json(provider, endpoint, method="POST", headers={"Auth-Key": key, "Content-Type": "application/json", "Accept": "application/json"}, data=payload, timeout=timeout)
    if result["available"] and not isinstance(result["data"].get("query_status"), str): return _failure(provider, "MALFORMED_SCHEMA", http_status=result["http_status"])
    return result
def lookup_urlhaus(url_value, *, timeout=4.0, api_key=None, url=None):
    provider = "urlhaus"; key = api_key or _key(provider)
    if not key: return _failure(provider, "NOT_CONFIGURED")
    endpoint = url or os.getenv(PROVIDERS[provider]["url_env"]) or PROVIDERS[provider]["url"]
    payload = urlencode({"url": url_value}).encode("ascii")
    result = _request_json(provider, endpoint, method="POST", headers={"Auth-Key": key, "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}, data=payload, timeout=timeout)
    if result["available"] and not isinstance(result["data"].get("query_status"), str): return _failure(provider, "MALFORMED_SCHEMA", http_status=result["http_status"])
    return result
