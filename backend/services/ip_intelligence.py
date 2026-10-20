import ipaddress
import socket
import urllib.request
import json
import time
import threading
import urllib.error
from datetime import datetime, timezone
from services.result_states import check_result
from services.ip_address_policy import classify_ip, require_public_ip
from services.ip_intelligence_v2.providers.geolocation import _normalize_provider_fields


# ==========================================
# IP GEOLOCATION API
# ==========================================

_GEO_CACHE = {}
_GEO_CACHE_LOCK = threading.RLock()
_GEO_SUCCESS_TTL = 24 * 60 * 60
_GEO_NO_DATA_TTL = 5 * 60


def _geo_timestamp():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def clear_geolocation_cache():
    """Clear process-local geolocation cache; exposed for deterministic tests."""
    with _GEO_CACHE_LOCK:
        _GEO_CACHE.clear()


def get_ip_geolocation(ip: str):
    safe_ip, policy = require_public_ip(ip)
    if safe_ip is None:
        return {"success": False, "status": "NOT_APPLICABLE", "state": "NOT_PUBLIC",
                "geolocation_state": "NOT_PUBLIC", "provider": "ipapi", "ip": ip,
                "cache_status": "BYPASS", "error": "Public geolocation skipped for non-public address."}
    ip = safe_ip
    now = time.monotonic()
    with _GEO_CACHE_LOCK:
        entry = _GEO_CACHE.get(ip)
        if entry:
            expires, cached = entry
            if now < expires:
                hit = dict(cached)
                hit["cache_status"] = "HIT"
                return hit
            _GEO_CACHE.pop(ip, None)

    url = f"https://ipapi.co/{ip}/json/"
    started = time.perf_counter()
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "MailTrace-AI/1.0"})
        with urllib.request.urlopen(request, timeout=3) as response:
            raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("Provider response exceeded size limit")
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict) or data.get("error") or data.get("reserved"):
            reason = str((data.get("reason") or data.get("message") or "") if isinstance(data, dict) else "")
            state = "RATE_LIMITED" if "rate" in reason.lower() or "limit" in reason.lower() else "PROVIDER_ERROR"
            return {"success": False, "status": "ERROR", "state": state, "geolocation_state": state,
                    "provider": "ipapi", "ip": ip, "lookup_timestamp": _geo_timestamp(),
                    "cache_status": "BYPASS", "error": "Geolocation provider could not complete the lookup."}

        fields = {
            "country": data.get("country_name"), "country_code": data.get("country"),
            "region": data.get("region"), "city": data.get("city"), "postal": data.get("postal"),
            "latitude": data.get("latitude"), "longitude": data.get("longitude"),
            "timezone": data.get("timezone"), "asn": data.get("asn"),
            "organization": data.get("org"), "continent": data.get("continent_code"),
        }
        fields, malformed_fields = _normalize_provider_fields(fields)
        has_location = any(fields.get(key) is not None for key in ("country", "country_code", "region", "city", "latitude", "longitude"))
        if malformed_fields and not has_location:
            return {"success": False, "status": "ERROR", "state": "PROVIDER_ERROR", "geolocation_state": "PROVIDER_ERROR",
                    "provider": "ipapi", "ip": ip, "lookup_timestamp": _geo_timestamp(), "cache_status": "BYPASS",
                    "error": "Geolocation provider returned malformed location data."}
        location_fields = {"country", "country_code", "region", "city", "latitude", "longitude"}
        if not fields or not any(fields.get(key) is not None and fields.get(key) != "" for key in location_fields):
            result = {"success": False, "status": "UNKNOWN", "state": "NO_DATA", "geolocation_state": "NO_DATA",
                      "provider": "ipapi", "ip": ip, "lookup_timestamp": _geo_timestamp(),
                      "cache_status": "MISS", "error": "Provider returned no location data."}
            with _GEO_CACHE_LOCK:
                _GEO_CACHE[ip] = (time.monotonic() + _GEO_NO_DATA_TTL, dict(result))
            return result

        result = {"success": True, "status": "PASS", "state": "AVAILABLE", "geolocation_state": "AVAILABLE",
                  **fields, "provider": "ipapi", "source": "ipapi.co", "ip": ip,
                  "lookup_timestamp": _geo_timestamp(), "cache_status": "MISS",
                  "cache_ttl_seconds": _GEO_SUCCESS_TTL,
                  "cache_expires_at": datetime.fromtimestamp(time.time() + _GEO_SUCCESS_TTL, timezone.utc).isoformat().replace("+00:00", "Z"),
                  "precision": "IP-derived approximate infrastructure location", "confidence": None,
                  "latency_ms": round((time.perf_counter() - started) * 1000, 2)}
        with _GEO_CACHE_LOCK:
            _GEO_CACHE[ip] = (time.monotonic() + _GEO_SUCCESS_TTL, dict(result))
        return result
    except Exception as error:
        if isinstance(error, urllib.error.HTTPError) and error.code == 429:
            state = "RATE_LIMITED"
        elif isinstance(error, TimeoutError) or (isinstance(error, urllib.error.URLError) and isinstance(getattr(error, "reason", None), TimeoutError)):
            state = "TIMEOUT"
        else:
            state = "PROVIDER_ERROR"
        # Transient failures are intentionally not cached and exception text is not exposed.
        return {"success": False, "status": "ERROR", "state": state, "geolocation_state": state,
                "provider": "ipapi", "ip": ip, "lookup_timestamp": _geo_timestamp(),
                "cache_status": "BYPASS", "latency_ms": round((time.perf_counter() - started) * 1000, 2),
                "error_type": type(error).__name__, "error": "Geolocation provider could not complete the lookup."}

# ==========================================
# REAL-TIME PROXY / HOSTING INTELLIGENCE
# ==========================================

def get_network_intelligence(ip: str):

    safe_ip, policy = require_public_ip(ip)
    if safe_ip is None:
        return {"success": False, "status": "NOT_APPLICABLE", "state": "NOT_PUBLIC",
                "is_proxy": None, "is_hosting": None,
                "is_vpn": None, "is_tor": None,
                "provider": "ip-api.com", "source": "ip-api.com/json",
                "lookup_timestamp": _geo_timestamp(),
                "error": f"Public network/reputation lookup skipped for {policy['classification']} address."}
    return {
        "success": False,
        "status": "ERROR",
        "state": "NOT_CONFIGURED",
        "is_proxy": None,
        "is_hosting": None,
        "is_vpn": None,
        "is_tor": None,
        "provider": None,
        "source": None,
        "lookup_timestamp": None,
        "ip": safe_ip,
        "error": "No approved secure network-classification provider is configured; proxy, VPN, Tor, and hosting status remain unknown.",
    }


# ==========================================
# DOCUMENTATION / TEST IP DETECTION
# ==========================================

def is_documentation_ip(address):

    documentation_networks = [

        ipaddress.ip_network(
            "192.0.2.0/24"
        ),

        ipaddress.ip_network(
            "198.51.100.0/24"
        ),

        ipaddress.ip_network(
            "203.0.113.0/24"
        ),

        ipaddress.ip_network(
            "2001:db8::/32"
        )

    ]

    return any(
        address in network
        for network in documentation_networks
    )


# ==========================================
# SINGLE IP ANALYSIS
# ==========================================

def analyze_ip(ip: str):

    raw_input = ip if isinstance(ip, str) else str(ip or "")
    ip = raw_input.strip()
    policy = classify_ip(raw_input)

    result = {

        "ip": ip,
        "raw_input": raw_input,
        "normalized_ip": None,
        "provider_ip": None,
        "classification": "INVALID",
        "is_global": False,
        "enrichment_status": "INVALID_IP",

        "valid": False,

        "type": "unknown",

        "hostname": None,

        "country": None,

        "country_code": None,

        "region": None,

        "city": None,

        "postal": None,

        "latitude": None,

        "longitude": None,

        "timezone": None,

        "continent": None,

        "asn": None,

        "isp": None,

        "organization": None,

        "is_private": False,

        "is_loopback": False,

        "is_reserved": False,

        "is_documentation": False,

        "is_proxy": None,

        "is_hosting": None,

        "risk": "UNKNOWN",

        "risk_score": 0,

        "notes": []

    }


    # ======================================
    # VALIDATE IP
    # ======================================

    try:

        address = ipaddress.ip_address(ip)

        result["valid"] = True
        result["normalized_ip"] = str(address)
        result["effective_version"] = policy["effective_version"]
        result["provider_ip"] = policy["provider_ip"]
        result["classification"] = policy["classification"]
        result["is_global"] = policy["is_global"]
        result["enrichment_status"] = policy["enrichment_status"]
        result["is_ipv4_mapped"] = policy.get("is_ipv4_mapped", False)

    except ValueError:

        result["notes"].append(
            "Invalid IP address."
        )
        result["status"] = "ERROR"
        result["enrichment_status"] = "INVALID_IP"
        result["geolocation_status"] = check_result("NOT_APPLICABLE", message="Invalid IP; no enrichment attempted.")
        result["network_intelligence_status"] = check_result("NOT_APPLICABLE")

        return result


    # ======================================
    # IP VERSION
    # ======================================

    if address.version == 4:

        result["type"] = "IPv4"

    else:

        result["type"] = "IPv6"


    # ======================================
    # ADDRESS FLAGS
    # ======================================

    result["is_private"] = policy["is_private"]

    result["is_loopback"] = policy["is_loopback"]

    result["is_reserved"] = policy["is_reserved"]

    result["is_documentation"] = policy["is_documentation"]

    # Enrichment eligibility is a single library-backed policy decision. This
    # branch also covers multicast, link-local, shared, special-use and mapped
    # IPv4 addresses before reverse DNS or any public provider can be called.
    if policy["enrichment_status"] != "ELIGIBLE":
        kind = policy["classification"]
        result["type"] = kind
        result["risk"] = "INTERNAL" if kind == "PRIVATE" else "UNKNOWN"
        result["risk_score"] = 0
        result["status"] = "NOT_APPLICABLE"
        result["enrichment_status"] = "NOT_PUBLIC"
        result["notes"].append(policy.get("reason") or "Public enrichment is not applicable.")
        result["geolocation_status"] = check_result("NOT_APPLICABLE", message="NOT_PUBLIC: no provider call made.")
        result["network_intelligence_status"] = check_result("NOT_APPLICABLE", message="NOT_PUBLIC: no provider call made.")
        return result


    # ======================================
    # DOCUMENTATION / TEST ADDRESS
    # ======================================

    if result["is_documentation"]:

        result["type"] = "DOCUMENTATION"

        result["risk"] = "LOW"

        result["risk_score"] = 0

        result["notes"].append(
            "Documentation/test IP address."
        )

        result["notes"].append(
            "This address is not attributable "
            "to a real Internet host."
        )
        result["status"] = "NOT_APPLICABLE"
        result["geolocation_status"] = check_result("NOT_APPLICABLE", message="Documentation address; public enrichment skipped.")
        result["network_intelligence_status"] = check_result("NOT_APPLICABLE")

        return result


    # ======================================
    # LOOPBACK
    # ======================================

    if address.is_loopback:

        result["type"] = "LOOPBACK"

        result["risk"] = "LOW"

        result["risk_score"] = 0

        result["notes"].append(
            "Loopback IP address."
        )
        result["status"] = "NOT_APPLICABLE"
        result["geolocation_status"] = check_result("NOT_APPLICABLE")
        result["network_intelligence_status"] = check_result("NOT_APPLICABLE")

        return result


    # ======================================
    # PRIVATE ADDRESS
    # ======================================

    if address.is_private:

        result["type"] = "PRIVATE"

        result["risk"] = "INTERNAL"

        result["risk_score"] = 0

        result["notes"].append(
            "Private/internal IP address."
        )

        result["notes"].append(
            "This address is not publicly routable."
        )
        result["status"] = "NOT_APPLICABLE"
        result["geolocation_status"] = check_result("NOT_APPLICABLE", message="Private address; public enrichment skipped.")
        result["network_intelligence_status"] = check_result("NOT_APPLICABLE")

        return result


    # ======================================
    # RESERVED ADDRESS
    # ======================================

    if address.is_reserved:

        result["type"] = "RESERVED"

        result["risk"] = "UNKNOWN"

        result["risk_score"] = 0

        result["notes"].append(
            "Reserved IP address."
        )

        result["notes"].append(
            "The address should not be treated "
            "as a normal public endpoint."
        )

        return result


    # Shared/special-use networks can be neither `is_private` nor `is_reserved`
    # in Python's ipaddress table. Only globally routable addresses may reach
    # reverse DNS, geolocation, or network-reputation providers.
    if not address.is_global:
        result["type"] = "NON_GLOBAL"
        result["risk"] = "UNKNOWN"
        result["risk_score"] = 0
        result["notes"].append(
            "Special-use or non-global IP address; public intelligence lookups were skipped."
        )
        return result


    # ======================================
    # REVERSE DNS
    # ======================================

    try:

        hostname = socket.gethostbyaddr(
            policy["provider_ip"]
        )[0]

        result["hostname"] = hostname

    except (
        socket.herror,
        socket.gaierror,
        OSError
    ):

        result["notes"].append(
            "No reverse DNS hostname found."
        )


    # ======================================
    # GEOLOCATION
    # ======================================

    geo = get_ip_geolocation(policy["provider_ip"])
    geo_state = str(geo.get("geolocation_state") or "UNKNOWN").upper()
    geo_status = {"AVAILABLE": "PASS", "NO_DATA": "UNKNOWN", "NOT_PUBLIC": "NOT_APPLICABLE", "NOT_CONFIGURED": "NOT_RUN"}.get(geo_state, "ERROR")
    result["geolocation_status"] = check_result(geo_status, provider_status=geo.get("status"))
    if geo.get("geolocation_state"):
        result["geolocation_status"]["geolocation_state"] = geo.get("geolocation_state")
    result["geolocation"] = {key: geo.get(key) for key in ("provider", "source", "ip", "lookup_timestamp", "cache_status", "cache_ttl_seconds", "cache_expires_at", "precision", "confidence", "geolocation_state") if geo.get(key) is not None}


    if geo.get("success"):

        result["country"] = geo.get(
            "country"
        )

        result["country_code"] = geo.get(
            "country_code"
        )

        result["region"] = geo.get(
            "region"
        )

        result["city"] = geo.get(
            "city"
        )

        result["postal"] = geo.get(
            "postal"
        )

        result["latitude"] = geo.get(
            "latitude"
        )

        result["longitude"] = geo.get(
            "longitude"
        )

        result["timezone"] = geo.get(
            "timezone"
        )

        result["continent"] = geo.get(
            "continent"
        )

        result["asn"] = geo.get(
            "asn"
        )

        result["organization"] = geo.get(
            "organization"
        )

        result["isp"] = geo.get(
            "organization"
        )

    else:

        result["notes"].append(
            "Geolocation lookup failed: "
            + "provider unavailable; location is unknown."
        )


    # ======================================
    # REAL-TIME NETWORK INTELLIGENCE
    # ======================================

    network = get_network_intelligence(policy["provider_ip"])
    result["network_intelligence_status"] = check_result("PASS" if network.get("success") else "ERROR", provider_status=network.get("status"))
    result["network_intelligence"] = network


    if network.get("success"):

        result["is_proxy"] = (
            network.get("is_proxy")
        )

        result["is_hosting"] = (
            network.get("is_hosting")
        )

    else:

        result["notes"].append(
            "No approved secure network-classification provider is configured; proxy, VPN, Tor, and hosting status remain unknown."
            if network.get("state") == "NOT_CONFIGURED"
            else "Network intelligence lookup failed; proxy, VPN, Tor, and hosting status remain unknown."
        )


    # ======================================
    # PUBLIC IP
    # ======================================

    result["type"] = (
        "PUBLIC IPv4-MAPPED IPv6"
        if policy.get("is_ipv4_mapped")
        else ("PUBLIC IPv4" if policy["effective_version"] == 4 else "PUBLIC IPv6")
    )

    result["risk"] = "PUBLIC"

    result["risk_score"] = 0
    result["status"] = "PASS" if geo.get("success") or network.get("success") else "ERROR"
    result["enrichment_status"] = "ELIGIBLE"

    result["notes"].append(
        "Publicly routable IP address."
    )


    # ======================================
    # NETWORK INTELLIGENCE NOTES
    # ======================================

    if result["is_proxy"] is True:

        result["notes"].append(
            "The configured provider reported a proxy/anonymization indicator; this does not distinguish VPN or Tor, identify the user, or prove intent."
        )


    if result["is_hosting"] is True:

        result["notes"].append(
            "IP is associated with hosting "
            "or data-center infrastructure."
        )


    return result


# ==========================================
# MULTIPLE IP ANALYSIS
# ==========================================

def analyze_ips(ip_addresses: list):

    results = []

    seen = set()

    for ip in ip_addresses:

        if not ip:
            continue

        ip = ip.strip()

        if not ip:
            continue

        if ip in seen:
            continue

        seen.add(ip)

        results.append(
            analyze_ip(ip)
        )

    return results


# ==========================================
# EXTRACT IPS FROM RELAY CHAIN
# ==========================================

def extract_ips_from_chain(
    received_chain: list
):

    ips = []

    for hop in received_chain:

        hop_ips = hop.get(
            "ip_addresses",
            []
        )

        for ip in hop_ips:

            if ip not in ips:

                ips.append(ip)

    return ips
