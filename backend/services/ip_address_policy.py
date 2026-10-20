"""Library-backed IP parsing and conservative public-enrichment policy.

Only addresses classified PUBLIC may be sent to public intelligence providers.
The policy intentionally blocks special-use ranges even if a Python release's
``is_global`` flag treats an individual anycast/special address as global.
"""
from __future__ import annotations

import ipaddress
from typing import Any


_SPECIAL_V4 = tuple(ipaddress.ip_network(item) for item in (
    "0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24",
    "192.88.99.0/24", "198.18.0.0/15", "240.0.0.0/4",
    "255.255.255.255/32",
))
_SPECIAL_V6 = tuple(ipaddress.ip_network(item) for item in (
    "64:ff9b:1::/48", "100::/64", "2001::/23",
    "2002::/16", "3fff::/20",
))
_DOCUMENTATION = tuple(ipaddress.ip_network(item) for item in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
    "2001:db8::/32",
))


def classify_ip(raw_input: Any) -> dict[str, Any]:
    """Return raw, canonical and provider-safe forms with an explicit state."""
    raw = raw_input if isinstance(raw_input, str) else str(raw_input or "")
    candidate = raw.strip()
    base = {
        "raw_input": raw,
        "normalized_ip": None,
        "provider_ip": None,
        "valid": False,
        "version": None,
        "effective_version": None,
        "classification": "INVALID",
        "is_global": False,
        "is_private": False,
        "is_loopback": False,
        "is_link_local": False,
        "is_multicast": False,
        "is_unspecified": False,
        "is_reserved": False,
        "is_documentation": False,
        "status": "ERROR",
        "enrichment_status": "INVALID_IP",
    }
    if not candidate:
        base["reason"] = "IP address is empty."
        return base
    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError:
        base["reason"] = "Invalid IP address."
        return base

    # IPv4-mapped IPv6 is classified using the embedded IPv4 address; providers
    # receive the canonical IPv4 form only when that embedded address is public.
    mapped = parsed.ipv4_mapped if isinstance(parsed, ipaddress.IPv6Address) else None
    effective = mapped or parsed
    v = effective.version
    documentation = any(effective in net for net in _DOCUMENTATION)
    explicit_special = any(effective in net for net in (_SPECIAL_V4 if v == 4 else _SPECIAL_V6))

    if effective.is_unspecified:
        kind = "UNSPECIFIED"
    elif effective.is_loopback:
        kind = "LOOPBACK"
    elif effective.is_link_local:
        kind = "LINK_LOCAL"
    elif effective.is_multicast:
        kind = "MULTICAST"
    elif documentation:
        kind = "DOCUMENTATION"
    elif effective.is_reserved:
        kind = "RESERVED"
    elif explicit_special:
        kind = "SPECIAL_USE"
    elif effective.is_private:
        kind = "PRIVATE"
    elif not effective.is_global:
        kind = "NON_GLOBAL"
    else:
        kind = "PUBLIC"

    public = kind == "PUBLIC" and effective.is_global
    if mapped is not None:
        # Python 3.12+ may stringify IPv4-mapped IPv6 with a dotted IPv4 tail,
        # while earlier runtimes used hexadecimal groups. Pin one stable form
        # so IOC identity and deduplication do not vary by runtime version.
        mapped_value = int(mapped)
        normalized_value = f"::ffff:{mapped_value >> 16:x}:{mapped_value & 0xffff:x}"
    else:
        normalized_value = str(parsed)
    base.update({
        "normalized_ip": normalized_value,
        "provider_ip": str(effective) if public else None,
        "valid": True,
        "version": parsed.version,
        "effective_version": v,
        "classification": kind,
        "is_global": bool(public),
        "is_private": bool(effective.is_private),
        "is_loopback": bool(effective.is_loopback),
        "is_link_local": bool(effective.is_link_local),
        "is_multicast": bool(effective.is_multicast),
        "is_unspecified": bool(effective.is_unspecified),
        "is_reserved": bool(effective.is_reserved),
        "is_documentation": bool(documentation),
        "status": "PASS" if public else "NOT_APPLICABLE",
        "enrichment_status": "ELIGIBLE" if public else "NOT_PUBLIC",
        "reason": None if public else f"{kind} address; public intelligence enrichment is not applicable.",
        "is_ipv4_mapped": mapped is not None,
    })
    return base


def require_public_ip(value: Any) -> tuple[str | None, dict[str, Any]]:
    """Shared provider guard. Return safe canonical provider IP or None."""
    result = classify_ip(value)
    return (result["provider_ip"] if result["enrichment_status"] == "ELIGIBLE" else None), result
