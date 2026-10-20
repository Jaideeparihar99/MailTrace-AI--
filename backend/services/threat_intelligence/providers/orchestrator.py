"""Fail-open live provider enrichment for normalized email IOCs.

Only provider metadata and sanitized status are logged. NOT_CONFIGURED providers are
skipped quietly; configured-provider failures are exposed in an evidence ledger.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from .http_clients import (
    lookup_abuseipdb, lookup_threatfox, lookup_urlhaus, lookup_virustotal,
)
from services.ip_address_policy import classify_ip

logger = logging.getLogger(__name__)


def _ioc_type(item: dict[str, Any]) -> str:
    raw = str(item.get("ioc_type") or item.get("indicator_type") or item.get("type") or "").lower()
    value = str(item.get("value") or item.get("ioc") or "").strip()
    if raw in {"sha256", "sha1", "md5", "hash", "file_hash", "hash_sha256", "hash_sha1", "hash_md5"}:
        return "hash"
    if re.fullmatch(r"(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})", value):
        return "hash"
    if raw in {"ip", "ipv4", "ipv6", "ip:port", "ip_address"}:
        return "ip"
    if raw in {"url", "uri", "http_url", "https_url"} or value.startswith(("http://", "https://")):
        return "url"
    if raw in {"domain", "hostname", "fqdn"}:
        return "domain"
    return "unknown"


def _value(item: dict[str, Any]) -> str:
    return str(item.get("value") or item.get("ioc") or "").strip()


def enrich_iocs_with_live_providers(iocs: list[dict[str, Any]], *, max_iocs: int = 30) -> dict[str, Any]:
    """Enrich each supported IOC independently; no provider can abort other lookups."""
    results: dict[str, list[dict[str, Any]]] = {}
    ledger: list[dict[str, Any]] = []
    skipped: dict[str, int] = {}
    non_public_ip_skips: list[dict[str, Any]] = []
    attempted = 0
    for item in iocs[:max_iocs]:
        if not isinstance(item, dict):
            continue
        value = _value(item)
        kind = _ioc_type(item)
        if not value or kind == "unknown":
            continue
        provider_value = value
        if kind == "ip":
            ip_policy = classify_ip(value)
            planned_providers = ["virustotal", "threatfox"]
            if ip_policy.get("effective_version") == 4 or (not ip_policy["valid"] and ":" not in value):
                planned_providers.insert(0, "abuseipdb")
            if not ip_policy["valid"] or ip_policy["provider_ip"] is None:
                code = "INVALID_IP" if not ip_policy["valid"] else "NOT_PUBLIC"
                key = f"{kind}:{value}"
                results.setdefault(key, [])
                for provider in planned_providers:
                    results[key].append({
                        "ioc": value, "ioc_type": kind, "provider": provider,
                        "status": "not_applicable", "error_code": code, "data": None,
                    })
                non_public_ip_skips.append({
                    "ioc": value, "ioc_type": kind,
                    "classification": ip_policy["classification"],
                    "status": "INVALID_IP" if not ip_policy["valid"] else "NOT_APPLICABLE",
                    "providers_skipped": planned_providers,
                })
                continue
            provider_value = ip_policy["provider_ip"]
        calls = []
        if kind == "ip":
            # AbuseIPDB is an IP reputation source; VT and ThreatFox support IOC search.
            if ip_policy["effective_version"] == 4:
                calls.append(("abuseipdb", lambda v=provider_value: lookup_abuseipdb(v)))
            calls.extend([
                ("virustotal", lambda v=provider_value: lookup_virustotal(v, ioc_type="ip")),
                ("threatfox", lambda v=provider_value: lookup_threatfox(v, ioc_type="ip")),
            ])
        elif kind == "url":
            calls.extend([
                ("urlhaus", lambda v=value: lookup_urlhaus(v)),
                ("virustotal", lambda v=value: lookup_virustotal(v, ioc_type="url")),
                ("threatfox", lambda v=value: lookup_threatfox(v)),
            ])
        elif kind == "domain":
            calls.extend([
                ("virustotal", lambda v=value: lookup_virustotal(v, ioc_type="domain")),
                ("threatfox", lambda v=value: lookup_threatfox(v)),
            ])
        elif kind == "hash":
            calls.extend([
                ("virustotal", lambda v=value: lookup_virustotal(v, ioc_type="hash")),
                ("threatfox", lambda v=value: lookup_threatfox(v)),
            ])
        if not calls:
            continue
        key = f"{kind}:{value}"
        results.setdefault(key, [])
        for provider, lookup in calls:
            try:
                outcome = lookup()
                if not isinstance(outcome, dict):
                    outcome = {"provider": provider, "status": "unavailable", "available": False, "error_code": "INVALID_ADAPTER_RESULT", "data": None}
            except Exception as exc:  # adapter contract: fail open, keep the rest of the evidence
                logger.warning("threat_intel_provider_failure provider=%s code=UNHANDLED_EXCEPTION exception_type=%s", provider, type(exc).__name__)
                outcome = {"provider": provider, "status": "unavailable", "available": False, "error_code": "UNHANDLED_EXCEPTION", "data": None}
            attempted += 1
            status = str(outcome.get("status") or "unavailable")
            code = str(outcome.get("error_code") or "")
            if code == "NOT_CONFIGURED" or status == "not_configured":
                skipped[provider] = skipped.get(provider, 0) + 1
                continue
            record = {
                "ioc": value, "ioc_type": kind, "provider_ip": provider_value if kind == "ip" else None,
                "provider": provider,
                "status": "available" if outcome.get("available") else "unavailable",
                "error_code": code or None,
                "http_status": outcome.get("http_status"),
                "data": outcome.get("data") if outcome.get("available") else None,
            }
            results[key].append(record)
            if not outcome.get("available"):
                ledger.append({
                    "ioc": value, "ioc_type": kind, "provider_ip": provider_value if kind == "ip" else None,
                    "provider": provider,
                    "evidence_type": "provider_unavailable",
                    "status": "provider unavailable",
                    "error_code": code or "PROVIDER_UNAVAILABLE",
                    "http_status": outcome.get("http_status"),
                })
            else:
                ledger.append({
                    "ioc": value, "ioc_type": kind, "provider_ip": provider_value if kind == "ip" else None,
                    "provider": provider,
                    "evidence_type": "provider_result", "status": "available",
                    "error_code": None, "http_status": outcome.get("http_status"),
                })
    available = sum(1 for records in results.values() for record in records if record["status"] == "available")
    unavailable = sum(1 for record in ledger if record["evidence_type"] == "provider_unavailable")
    return {
        "mode": "live_provider_enrichment",
        "status": ("available" if available else "unavailable" if unavailable else
                   "not_applicable" if attempted == 0 and non_public_ip_skips else "not_configured"),
        "iocs_considered": min(len(iocs), max_iocs),
        "provider_calls_attempted": attempted,
        "provider_results": results,
        "evidence_ledger": ledger,
        "not_configured_skips": skipped,
        "non_public_ip_skips": non_public_ip_skips,
        "not_applicable_result_count": sum(
            len(item["providers_skipped"]) for item in non_public_ip_skips
        ),
        "available_result_count": available,
        "unavailable_result_count": unavailable,
        "truncated": len(iocs) > max_iocs,
    }
