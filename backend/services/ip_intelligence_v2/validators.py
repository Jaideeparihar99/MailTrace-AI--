import ipaddress

from services.ip_address_policy import classify_ip


DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)


def validate_ip(value: str):
    value = (value or "").strip()

    if not value:
        return None, "IP address is empty."

    try:
        return ipaddress.ip_address(value), None
    except ValueError:
        return None, "Invalid IP address."


def is_documentation_ip(address) -> bool:
    return any(
        address in network
        for network in DOCUMENTATION_NETWORKS
    )


def classify_address(address) -> dict:
    policy = classify_ip(str(address))
    return {
        "version": address.version,
        "normalized_ip": policy["normalized_ip"],
        "effective_version": policy["effective_version"],
        "is_private": policy["is_private"],
        "is_loopback": policy["is_loopback"],
        "is_link_local": policy["is_link_local"],
        "is_multicast": policy["is_multicast"],
        "is_unspecified": policy["is_unspecified"],
        "is_reserved": policy["is_reserved"],
        "is_documentation": policy["is_documentation"],
        "is_global": policy["is_global"],
        "classification": policy["classification"],
        "provider_ip": policy["provider_ip"],
        "enrichment_status": policy["enrichment_status"],
        "is_ipv4_mapped": policy.get("is_ipv4_mapped", False),
    }
