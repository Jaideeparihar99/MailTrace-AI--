"""Public-suffix-aware organizational domain comparison."""

from functools import lru_cache
import ipaddress
import re
from email.utils import parseaddr

import idna
import tldextract


_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)


def normalized_host(value: str | None) -> str | None:
    """Normalize a hostname or mailbox to ASCII IDNA form; reject malformed input."""
    raw = str(value or "").strip()
    if not raw:
        return None
    if "@" in raw:
        _, address = parseaddr(raw)
        if address.count("@") != 1:
            return None
        local, raw = address.rsplit("@", 1)
        if not local:
            return None
    raw = raw.strip().strip("<>").rstrip(".").lower()
    if not raw or any(ch in raw for ch in "/:@[]\\"):
        return None
    try:
        ipaddress.ip_address(raw)
        return None
    except ValueError:
        pass
    try:
        raw = idna.encode(raw, uts46=True, std3_rules=True).decode("ascii").lower()
    except (UnicodeError, idna.IDNAError):
        return None
    if len(raw) > 253 or any(not _DOMAIN_LABEL.fullmatch(label) for label in raw.split(".")):
        return None
    return raw


@lru_cache(maxsize=2048)
def organizational_domain(value: str) -> str | None:
    """Return the registrable domain, or None when it cannot be determined.

    Parsing uses tldextract's packaged PSL snapshot and never performs a lookup.
    """
    raw = normalized_host(value)
    if not raw:
        return None
    result = _extractor()(raw)
    return result.top_domain_under_public_suffix or None


@lru_cache(maxsize=1)
def _extractor():
    return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)


def domains_differ(left: str, right: str) -> bool:
    return compare_domains(left, right) == "MISMATCH"


def compare_domains(left: str, right: str) -> str:
    """Classify exact host equality, PSL organizational alignment, or mismatch."""
    left_host, right_host = normalized_host(left), normalized_host(right)
    if not left_host or not right_host:
        return "UNKNOWN"
    if left_host == right_host:
        return "EXACT_HOST"
    left_org, right_org = organizational_domain(left_host), organizational_domain(right_host)
    if not left_org or not right_org:
        return "UNKNOWN"
    return "ORGANIZATIONAL_ALIGNMENT" if left_org == right_org else "MISMATCH"
