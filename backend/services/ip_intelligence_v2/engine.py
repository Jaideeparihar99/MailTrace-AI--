from typing import Any

from .models import IPProfile
from .validators import (
    validate_ip,
    classify_address,
)
from .providers.dns import reverse_dns
from .providers.geolocation import get_geolocation
from .providers.network import (
    query_ipapi_network,
    classify_network,
)
from .providers.reputation import get_reputation
from .intelligence.evidence import build_evidence
from .intelligence.confidence import calculate_confidence
from .intelligence.scoring import calculate_risk


def _first_value(provider_results, field: str):
    for result in provider_results:
        if not result.success:
            continue

        value = (result.data or {}).get(field)

        if value is not None and value != "":
            return value

    return None


def _merge_geolocation(results) -> dict[str, Any]:

    fields = (
        "country",
        "country_code",
        "region",
        "city",
        "postal",
        "latitude",
        "longitude",
        "timezone",
        "continent",
        "asn",
        "organization",
        "hostname",
    )

    merged = {}

    for field in fields:

        value = _first_value(
            results,
            field
        )

        if value is not None:
            merged[field] = value

    return merged


def _address_type(
    classification: dict,
) -> str:

    version = classification["version"]
    suffix = f"IPv{version}"

    if classification["is_private"]:
        return f"PRIVATE {suffix}"

    if classification["is_loopback"]:
        return f"LOOPBACK {suffix}"

    if classification["is_documentation"]:
        return f"DOCUMENTATION {suffix}"

    if classification["is_reserved"]:
        return f"RESERVED {suffix}"

    return f"PUBLIC {suffix}"


def _local_result(
    address,
    classification: dict,
) -> dict:

    is_unspecified = classification["classification"] == "UNSPECIFIED"

    if is_unspecified:
        local_type, local_risk = "UNSPECIFIED", "SPECIAL"
    elif classification["classification"] == "LOOPBACK":
        local_type, local_risk = "LOOPBACK", "LOCAL"
    elif classification["classification"] == "PRIVATE":
        local_type, local_risk = "PRIVATE", "PRIVATE"
    elif classification["classification"] == "DOCUMENTATION":
        local_type, local_risk = "DOCUMENTATION", "TEST"
    elif classification["classification"] == "LINK_LOCAL":
        local_type, local_risk = "LINK_LOCAL", "SPECIAL"
    elif classification["classification"] == "MULTICAST":
        local_type, local_risk = "MULTICAST", "SPECIAL"
    elif classification["classification"] == "RESERVED":
        local_type, local_risk = "RESERVED", "RESERVED"
    else:
        local_type, local_risk = classification["classification"], "SPECIAL"

    profile = IPProfile(
        ip=str(address),
        valid=True,
        version=classification["version"],
        type=local_type,

        is_private=classification["is_private"],
        is_loopback=classification["is_loopback"],
        is_reserved=classification["is_reserved"],
        is_documentation=classification["is_documentation"],

        risk=local_risk,

        risk_score=0,
        confidence=1.0,

        signal_breakdown={
            "reputation": 0.0,
            "anonymity": 0.0,
            "infrastructure": 0.0,
            "correlation_bonus": 0.0,
            "evidence_quality_bonus": 0.0
        },

        risk_engine="v5",

        notes=[],
        evidence=[],
        provider_status=[],
    )

    if is_unspecified:

        profile.notes.append(
            "Unspecified/special-use IP address; "
            "not evidence of a real sender."
        )

        profile.evidence.append({
            "source": "local_validation",
            "category": "network",
            "field": "address_classification",
            "value": "unspecified",
            "confidence": 1.0,
            "description":
                "Unspecified special-use address."
        })

    elif profile.is_private:

        profile.notes.append(
            "Private/non-routable IP address."
        )

        profile.evidence.append({
            "source": "local_validation",
            "category": "network",
            "field": "is_private",
            "value": True,
            "confidence": 1.0,
            "description":
                "Private/non-routable address."
        })

    elif profile.is_loopback:

        profile.notes.append(
            "Loopback address."
        )

        profile.evidence.append({
            "source": "local_validation",
            "category": "network",
            "field": "is_loopback",
            "value": True,
            "confidence": 1.0,
            "description":
                "Loopback address."
        })

    elif profile.is_documentation:

        profile.notes.append(
            "Documentation/test IP address; "
            "not evidence of a real sender."
        )

        profile.evidence.append({
            "source": "local_validation",
            "category": "network",
            "field": "is_documentation",
            "value": True,
            "confidence": 1.0,
            "description":
                "Documentation/test address."
        })

    elif profile.is_reserved:

        profile.notes.append(
            "Reserved IP address."
        )

        profile.evidence.append({
            "source": "local_validation",
            "category": "network",
            "field": "is_reserved",
            "value": True,
            "confidence": 1.0,
            "description":
                "Reserved address space."
        })

    else:

        profile.notes.append(
            f"{classification['classification'].replace('_', ' ').title()} address; "
            "public enrichment was skipped."
        )

    result = profile.to_dict()
    result.update({
        "raw_input": str(address),
        "normalized_ip": str(address),
        "provider_ip": None,
        "classification": classification["classification"],
        "is_global": False,
        "status": "NOT_APPLICABLE",
        "enrichment_status": "NOT_PUBLIC",
        "is_ipv4_mapped": classification.get("is_ipv4_mapped", False),
        "provider_status": [
            {"provider": name, "success": False, "status": "NOT_APPLICABLE",
             "reason": "NOT_PUBLIC: external enrichment skipped by IP policy."}
            for name in ("reverse_dns", "geolocation", "network_intelligence", "reputation")
        ],
    })
    return result


def analyze_ip_v2(ip: str) -> dict:

    # ======================================
    # VALIDATION
    # ======================================

    address, error = validate_ip(ip)

    if error:

        return {
            "ip": ip,
            "raw_input": ip,
            "normalized_ip": None,
            "provider_ip": None,
            "classification": "INVALID",
            "is_global": False,
            "status": "ERROR",
            "enrichment_status": "INVALID_IP",
            "valid": False,
            "version": None,
            "type": "INVALID",
            "risk": "INVALID",
            "risk_score": 0,
            "confidence": 0.0,
            "signal_breakdown": {},
            "risk_engine": "v5",
            "notes": [error],
            "evidence": [],
            "provider_status": [
                {"provider": name, "success": False, "status": "NOT_APPLICABLE",
                 "reason": "INVALID_IP: no lookup attempted."}
                for name in ("reverse_dns", "geolocation", "network_intelligence", "reputation")
            ],
        }

    classification = classify_address(
        address
    )

    # ======================================
    # SPECIAL ADDRESS FAST PATH
    # ======================================

    if classification["enrichment_status"] != "ELIGIBLE":
        local_result = _local_result(address, classification)
        local_result.update({
            "raw_input": ip,
            "normalized_ip": classification["normalized_ip"],
            "provider_ip": None,
            "is_ipv4_mapped": classification.get("is_ipv4_mapped", False),
        })
        return local_result

    # ======================================
    # PUBLIC IP PROFILE
    # ======================================

    provider_ip = classification["provider_ip"]
    profile = IPProfile(
        ip=str(address),
        valid=True,
        version=classification["version"],
        type=_address_type(classification),

        is_private=False,
        is_loopback=False,
        is_reserved=False,
        is_documentation=False,
    )

    # ======================================
    # PROVIDER PIPELINE
    # ======================================

    provider_results = []

    # DNS
    dns_result = reverse_dns(provider_ip)

    provider_results.append(
        dns_result
    )

    # GEOLOCATION
    geo_results = get_geolocation(provider_ip)

    provider_results.extend(
        geo_results
    )

    # NETWORK
    network_result = query_ipapi_network(provider_ip)

    provider_results.append(
        network_result
    )

    # REPUTATION
    reputation_results = get_reputation(provider_ip)

    provider_results.extend(
        reputation_results
    )

    # ======================================
    # GEOLOCATION MERGE
    # ======================================

    geo = _merge_geolocation(
        geo_results
    )

    profile.hostname = (
        _first_value(
            [dns_result] + geo_results,
            "hostname"
        )
    )

    profile.country = geo.get(
        "country"
    )

    profile.country_code = geo.get(
        "country_code"
    )

    profile.region = geo.get(
        "region"
    )

    profile.city = geo.get(
        "city"
    )

    profile.postal = geo.get(
        "postal"
    )

    profile.latitude = geo.get(
        "latitude"
    )

    profile.longitude = geo.get(
        "longitude"
    )

    profile.timezone = geo.get(
        "timezone"
    )

    profile.continent = geo.get(
        "continent"
    )

    profile.asn = (
        geo.get("asn")
        or _first_value(
            [network_result],
            "asn"
        )
    )

    profile.organization = (
        geo.get("organization")
        or _first_value(
            [network_result],
            "organization"
        )
    )

    # ======================================
    # NETWORK CLASSIFICATION
    # ======================================

    network_info = classify_network(
        profile.organization,
        profile.hostname,
        profile.asn
    )

    network_result.data.update(
        network_info
    )

    # ASN/organization/hostname text is not enough to classify hosting,
    # VPN, proxy or Tor. Keep these flags UNKNOWN until a provider explicitly
    # supports and reports that classification.

    # ======================================
    # REPUTATION
    # ======================================

    for result in reputation_results:

        if not result.success:
            continue

        value = result.data.get(
            "abuse_confidence_score"
        )

        if value is None:
            continue

        try:

            profile.reputation_score = float(
                value
            )

            break

        except (
            TypeError,
            ValueError
        ):

            pass

    # ======================================
    # PROFILE FOR INTELLIGENCE ENGINE
    # ======================================

    profile_dict = {
        "is_private": profile.is_private,
        "is_loopback": profile.is_loopback,
        "is_reserved": profile.is_reserved,
        "is_documentation":
            profile.is_documentation,

        "is_proxy": profile.is_proxy,
        "is_vpn": profile.is_vpn,
        "is_tor": profile.is_tor,
        "is_hosting": profile.is_hosting,
    }

    # ======================================
    # EVIDENCE
    # ======================================

    evidence = build_evidence(
        str(address),
        provider_results,
        profile_dict
    )

    profile.evidence = evidence

    # ======================================
    # CONFIDENCE
    # ======================================

    profile.confidence = calculate_confidence(
        provider_results,
        evidence
    )

    # ======================================
    # RISK
    # ======================================

    risk = calculate_risk(
        profile_dict,
        provider_results,
        evidence
    )

    profile.risk = risk["risk"]

    profile.risk_score = risk[
        "risk_score"
    ]

    # ======================================
    # ADVANCED RISK ENGINE V4
    # Preserve explainable scoring metadata.
    # ======================================

    profile.signal_breakdown = risk.get(
        "signal_breakdown",
        {}
    )

    profile.risk_engine = risk.get(
        "risk_engine",
        "v4"
    )

    # ======================================
    # NOTES
    # ======================================

    for reason in risk.get(
        "reasons",
        []
    ):

        if reason not in profile.notes:

            profile.notes.append(
                reason
            )

    # ======================================
    # PROVIDER STATUS
    # ======================================

    for result in provider_results:

        provider_data = result.data if isinstance(result.data, dict) else {}
        profile.provider_status.append({
            "provider": result.provider,
            "source": provider_data.get("source"),
            "success": result.success,
            "status": provider_data.get("status") or ("AVAILABLE" if result.success else "PROVIDER_ERROR"),
            "latency_ms": result.latency_ms,
            "error": result.error,
            "ip": provider_data.get("ip"),
            "lookup_timestamp": provider_data.get("lookup_timestamp"),
            "cache_status": provider_data.get("cache_status"),
            "cache_ttl_seconds": provider_data.get("cache_ttl_seconds"),
            "cache_expires_at": provider_data.get("cache_expires_at"),
            "precision": provider_data.get("precision"),
            "confidence": provider_data.get("confidence"),
        })

    result = profile.to_dict()
    result.update({
        "raw_input": ip,
        "normalized_ip": classification["normalized_ip"],
        "provider_ip": provider_ip,
        "classification": classification["classification"],
        "type": ("PUBLIC IPv4-MAPPED IPv6" if classification.get("is_ipv4_mapped") else result.get("type")),
        "is_global": True,
        "status": "PASS",
        "enrichment_status": "ELIGIBLE",
        "is_ipv4_mapped": classification.get("is_ipv4_mapped", False),
    })
    geo_results_for_status = [item for item in geo_results if item.provider in {"ipapi", "ipinfo", "geolocation"}]
    geo_winner = next((item for item in geo_results_for_status if item.success), geo_results_for_status[-1] if geo_results_for_status else None)
    geo_data = (geo_winner.data or {}) if geo_winner else {}
    geo_state = geo_data.get("status") or ("AVAILABLE" if geo_winner and geo_winner.success else "PROVIDER_ERROR")
    geo_result_status = {
        "AVAILABLE": "PASS", "NO_DATA": "UNKNOWN", "NOT_PUBLIC": "NOT_APPLICABLE",
        "NOT_CONFIGURED": "NOT_RUN",
    }.get(str(geo_state).upper(), "ERROR")
    result["geolocation_status"] = {
        "status": geo_result_status,
        "state": geo_state,
        "provider": geo_winner.provider if geo_winner else None,
        "message": {
            "NO_DATA": "Provider completed the lookup but returned no location data.",
            "NOT_CONFIGURED": "No approved geolocation provider is configured.",
            "NOT_PUBLIC": "Public geolocation does not apply to this address.",
        }.get(str(geo_state).upper()),
    }
    result["geolocation"] = {
        key: geo_data.get(key) for key in (
            "ip", "provider", "lookup_timestamp", "cache_status", "cache_ttl_seconds",
            "cache_expires_at", "precision", "confidence"
        ) if geo_data.get(key) is not None
    }
    return result





