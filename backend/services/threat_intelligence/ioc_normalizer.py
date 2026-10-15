from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit
import idna


# =========================================================
# IOC NORMALIZER
# =========================================================

IP_PORT_PATTERN = re.compile(
    r"(?<![\w.])"
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
    r":(?P<port>\d{1,5})"
    r"(?!\w)"
)

IP_PATTERN = re.compile(
    r"(?<![\w.])"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"(?![\w.])"
)

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"']+",
    re.IGNORECASE
)

DOMAIN_PATTERN = re.compile(
    r"(?<![@\w.-])"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}"
    r"(?![\w.-])"
)


def _clean(value: str) -> str:
    return str(value).strip().rstrip(
        ".,;:!?)]}>\"'"
    )


def normalize_ip(value: str) -> str | None:
    value = _clean(value)

    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        return None


def normalize_url(value: str) -> str | None:
    value = _clean(value)
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if scheme not in {"http", "https"} or not hostname:
        return None
    try:
        try:
            host = str(ipaddress.ip_address(hostname))
            if ":" in host:
                host = f"[{host}]"
        except ValueError:
            host = idna.encode(hostname, uts46=True, std3_rules=True).decode("ascii").lower().rstrip(".")
            if not normalize_domain(host):
                return None
    except (UnicodeError, ValueError):
        return None
    userinfo = parsed.netloc.rsplit("@", 1)[0] + "@" if "@" in parsed.netloc else ""
    if port is not None and not (scheme == "http" and port == 80 or scheme == "https" and port == 443):
        host = f"{host}:{port}"
    path = parsed.path or "/"
    return urlunsplit((scheme, userinfo + host, path, parsed.query, parsed.fragment))


def url_deduplication_key(value: str) -> str | None:
    """Canonical identity: lowercase scheme/host, default ports removed;
    path, query and fragment remain case-sensitive and otherwise unchanged.
    """
    return normalize_url(value)


def normalize_domain(value: str) -> str | None:
    value = _clean(value).lower().rstrip(".")

    if not value:
        return None

    if "@" in value:
        return None

    if "/" in value:
        return None

    if ":" in value:
        return None

    if not DOMAIN_PATTERN.fullmatch(value):
        return None

    return value


def extract_ip_ports(text: str) -> list[dict]:
    if not text:
        return []

    results = []
    seen = set()

    for match in IP_PORT_PATTERN.finditer(text):
        ip = normalize_ip(match.group("ip"))

        if not ip:
            continue

        port = int(match.group("port"))

        if port < 1 or port > 65535:
            continue

        ioc = f"{ip}:{port}"

        if ioc.lower() in seen:
            continue

        seen.add(ioc.lower())

        results.append({
            "ioc": ioc,
            "ioc_type": "ip:port",
            "value": ip,
            "port": port,
        })

    return results


def extract_ips(text: str) -> list[dict]:
    if not text:
        return []

    results = []
    seen = set()

    for match in IP_PATTERN.finditer(text):
        ip = normalize_ip(match.group(0))

        if not ip:
            continue

        key = ip.lower()

        if key in seen:
            continue

        seen.add(key)

        results.append({
            "ioc": ip,
            "ioc_type": "ip",
            "value": ip,
        })

    return results


def extract_urls(text: str) -> list[dict]:
    if not text:
        return []

    results = []
    seen = set()

    for match in URL_PATTERN.finditer(text):
        url = normalize_url(match.group(0))

        if not url:
            continue

        key = url_deduplication_key(url)
        if not key:
            continue

        if key in seen:
            continue

        seen.add(key)

        parsed = urlsplit(key)

        results.append({
            "ioc": key,
            "ioc_type": "url",
            "value": key,
            "domain": parsed.hostname.lower()
            if parsed.hostname
            else None,
        })

    return results


def extract_domains(text: str) -> list[dict]:
    if not text:
        return []

    results = []
    seen = set()

    for match in DOMAIN_PATTERN.finditer(text):
        domain = normalize_domain(match.group(0))

        if not domain:
            continue

        key = domain.lower()

        if key in seen:
            continue

        seen.add(key)

        results.append({
            "ioc": domain,
            "ioc_type": "domain",
            "value": domain,
        })

    return results


def extract_iocs(text: str, url_evidence: list[dict] | None = None) -> list[dict]:
    """
    Extract and normalize IP, IP:port, URL and domain IOCs.

    Values are deduplicated while preserving discovery order.
    """

    if not text and not url_evidence:
        return []

    results = []
    seen = set()

    groups = [
        extract_ip_ports(text),
        extract_ips(text),
        extract_urls(text),
        extract_domains(text),
    ]

    url_sources: dict[str, dict[str, list]] = {}
    for evidence in url_evidence or []:
        if not isinstance(evidence, dict):
            continue
        value = evidence.get("normalized_url") or evidence.get("original_url")
        key = url_deduplication_key(str(value or ""))
        if not key:
            continue
        current = url_sources.setdefault(key, {"original_values": [], "source_locations": []})
        original = evidence.get("original_url")
        if original and original not in current["original_values"]:
            current["original_values"].append(original)
        for location in evidence.get("source_locations", []):
            if location not in current["source_locations"]:
                current["source_locations"].append(location)
        groups[2].append({"ioc": key, "ioc_type": "url", "value": key})

    for group in groups:
        for item in group:
            ioc = item.get("ioc")

            if not ioc:
                continue

            key = (
                url_deduplication_key(ioc)
                if item.get("ioc_type") == "url"
                else ioc.strip().lower()
            )
            if not key:
                continue

            if key in seen:
                continue

            seen.add(key)
            if item.get("ioc_type") == "url":
                item.update(url_sources.get(key, {}))
            results.append(item)

    return results


def summarize_iocs(iocs: list[dict]) -> dict:
    summary = {
        "total": 0,
        "ip": 0,
        "ip:port": 0,
        "url": 0,
        "domain": 0,
    }

    for item in iocs or []:
        ioc_type = item.get("ioc_type")

        summary["total"] += 1

        if ioc_type in summary:
            summary[ioc_type] += 1

    return summary
