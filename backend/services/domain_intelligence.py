"""Bounded DNS/MX context for extracted email domains.

WHOIS/registration age is deliberately NOT_RUN until an approved provider exists.
This module never treats age or DNS absence as a standalone malicious verdict.
"""
from __future__ import annotations

import ipaddress
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any

import idna

MAX_DOMAINS_PER_EMAIL = 3
DNS_TIMEOUT_SECONDS = 1.0
DNS_LIFETIME_SECONDS = 2.0
DNS_CACHE_TTL_SECONDS = 300
DNS_NEGATIVE_TTL_SECONDS = 60
_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_LOCK = threading.RLock()
_RR_TYPES = ("A", "AAAA", "MX", "NS")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_domain(value: str) -> str | None:
    """Return an IDNA ASCII comparison domain while retaining caller input separately."""
    candidate = str(value or "").strip().rstrip(".")
    if not candidate or len(candidate) > 253 or any(ch in candidate for ch in " /:@[]\\"):
        return None
    try:
        ipaddress.ip_address(candidate)
        return None
    except ValueError:
        pass
    try:
        ascii_domain = idna.encode(candidate, uts46=True, std3_rules=True).decode("ascii").lower()
    except (idna.IDNAError, UnicodeError):
        return None
    labels = ascii_domain.split(".")
    if len(labels) < 2 or any(not label or len(label) > 63 for label in labels):
        return None
    return ascii_domain


def _base_result(original: str, query: str, status: str, *, cache_status: str,
                 records: dict[str, list[Any]] | None = None, resolver: str | None = None,
                 error: str | None = None, expires_at: str | None = None,
                 record_statuses: dict[str, str] | None = None) -> dict[str, Any]:
    return {
        "original_domain": original,
        "query_domain": query,
        "status": status,
        "resolver": resolver or "system-configured",
        "provider": "dnspython/system resolver",
        "lookup_timestamp": _now(),
        "cache_status": cache_status,
        "cache_ttl_seconds": DNS_CACHE_TTL_SECONDS if status == "AVAILABLE" else DNS_NEGATIVE_TTL_SECONDS,
        "cache_expires_at": expires_at,
        "records": records or {kind: [] for kind in _RR_TYPES},
        "record_statuses": record_statuses or {kind: "NOT_RUN" for kind in _RR_TYPES},
        "error": error,
        "domain_age": {
            "status": "NOT_RUN",
            "registration_date": None,
            "age_days": None,
            "provider": None,
            "reason": "No approved WHOIS or registration-date provider is configured.",
        },
        "interpretation": "Context only; DNS and registration age do not prove maliciousness.",
    }


def clear_domain_cache() -> None:
    with _LOCK:
        _CACHE.clear()


def lookup_domain(domain: str) -> dict[str, Any]:
    """Query A/AAAA/MX/NS using bounded system DNS; no WHOIS scraping or web fetch."""
    query = normalize_domain(domain)
    if query is None:
        return _base_result(str(domain or ""), "", "INVALID_DOMAIN", cache_status="BYPASS",
                            error="Domain format is invalid or unsupported.")
    now_mono = time.monotonic()
    with _LOCK:
        entry = _CACHE.get(query)
        if entry and now_mono < entry[0]:
            cached = dict(entry[1])
            cached["cache_status"] = "HIT"
            cached["original_domain"] = domain
            return cached
        _CACHE.pop(query, None)

    try:
        import dns.exception
        import dns.resolver
    except ImportError:
        return _base_result(domain, query, "NOT_CONFIGURED", cache_status="BYPASS",
                            error="DNS enrichment dependency is unavailable.")

    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT_SECONDS
    resolver.lifetime = DNS_LIFETIME_SECONDS
    records: dict[str, list[Any]] = {kind: [] for kind in _RR_TYPES}
    record_statuses: dict[str, str] = {}
    statuses: list[str] = []
    safe_errors: list[str] = []
    for record_type in _RR_TYPES:
        try:
            answer = resolver.resolve(query, record_type, lifetime=DNS_LIFETIME_SECONDS,
                                      search=False, raise_on_no_answer=False)
            if answer.rrset is None:
                statuses.append("NO_RECORDS")
                record_statuses[record_type] = "NO_RECORDS"
                continue
            for item in answer:
                if record_type in {"A", "AAAA"}:
                    value: Any = item.address
                elif record_type == "MX":
                    value = {"preference": int(item.preference), "exchange": str(item.exchange).rstrip(".")}
                else:
                    value = str(item.target).rstrip(".")
                if value not in records[record_type]:
                    records[record_type].append(value)
            statuses.append("AVAILABLE" if records[record_type] else "NO_RECORDS")
            record_statuses[record_type] = statuses[-1]
        except dns.resolver.NXDOMAIN:
            statuses.append("NXDOMAIN")
            record_statuses[record_type] = "NXDOMAIN"
        except dns.resolver.NoAnswer:
            statuses.append("NO_RECORDS")
            record_statuses[record_type] = "NO_RECORDS"
        except dns.resolver.LifetimeTimeout:
            statuses.append("TIMEOUT")
            record_statuses[record_type] = "TIMEOUT"
            safe_errors.append("DNS query timed out.")
        except dns.resolver.NoNameservers:
            statuses.append("SERVFAIL")
            record_statuses[record_type] = "SERVFAIL"
            safe_errors.append("Configured DNS resolver could not complete the query.")
        except Exception as exc:
            statuses.append("DNS_ERROR")
            record_statuses[record_type] = "DNS_ERROR"
            safe_errors.append(type(exc).__name__)

    if all(state == "NXDOMAIN" for state in statuses):
        status = "NXDOMAIN"
    elif all(state == "NO_RECORDS" for state in statuses):
        status = "NO_RECORDS"
    elif any(records.values()):
        status = "AVAILABLE"
    elif "TIMEOUT" in statuses:
        status = "TIMEOUT"
    elif "SERVFAIL" in statuses:
        status = "SERVFAIL"
    else:
        status = "DNS_ERROR"

    ttl = DNS_CACHE_TTL_SECONDS if status == "AVAILABLE" else DNS_NEGATIVE_TTL_SECONDS
    expires = datetime.fromtimestamp(time.time() + ttl, timezone.utc).isoformat().replace("+00:00", "Z")
    result = _base_result(domain, query, status, cache_status="MISS", records=records,
                          resolver=", ".join(str(item) for item in resolver.nameservers) or "system-configured",
                          error="; ".join(dict.fromkeys(safe_errors)) or None, expires_at=expires,
                          record_statuses=record_statuses)
    result["cache_ttl_seconds"] = ttl
    if status not in {"TIMEOUT", "SERVFAIL", "DNS_ERROR"}:
        with _LOCK:
            _CACHE[query] = (time.monotonic() + ttl, result)
    return result


def analyze_domains(domains: list[str], *, enabled: bool | None = None) -> dict[str, Any]:
    """Deduplicate IDNA-normalized domains, cap work, and make disabled state explicit."""
    if enabled is None:
        enabled = os.getenv("MAILTRACE_DOMAIN_INTELLIGENCE_ENABLED", "false").strip().lower() == "true"
    selected: list[tuple[str, str]] = []
    seen: set[str] = set()
    truncated = False
    for original in domains:
        normalized = normalize_domain(original)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        if len(selected) >= MAX_DOMAINS_PER_EMAIL:
            truncated = True
            continue
        selected.append((str(original), normalized))
    if not selected:
        return {"status": "NOT_RUN", "reason": "No valid sender or URL domains were available for enrichment.",
                "unique_domain_count": 0, "domains": [], "truncated": False}
    if not enabled:
        return {"status": "NOT_RUN", "reason": "Domain DNS enrichment is disabled by configuration.",
                "unique_domain_count": len(selected), "domains": []}
    results = [lookup_domain(original) for original, _ in selected]
    aggregate = "AVAILABLE" if any(item["status"] == "AVAILABLE" for item in results) else (
        "UNKNOWN" if any(item["status"] in {"TIMEOUT", "SERVFAIL", "DNS_ERROR", "NOT_CONFIGURED"} for item in results)
        else "NO_DATA")
    return {"status": aggregate, "unique_domain_count": len(results), "domains": results,
            "truncated": truncated}
