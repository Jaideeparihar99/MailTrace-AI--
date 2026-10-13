"""Public-suffix-aware organizational domain comparison."""

from functools import lru_cache

import tldextract


@lru_cache(maxsize=2048)
def organizational_domain(value: str) -> str | None:
    """Return the registrable domain, or None when it cannot be determined.

    Parsing uses tldextract's packaged PSL snapshot and never performs a lookup.
    """
    raw = str(value or "").strip().rstrip(".").lower()
    if "@" in raw:
        raw = raw.rsplit("@", 1)[1].strip().strip("<>")
    try:
        raw = raw.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not raw or any(ch in raw for ch in "/:@[]"):
        return None
    result = _extractor()(raw)
    return result.top_domain_under_public_suffix or None


@lru_cache(maxsize=1)
def _extractor():
    return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)


def domains_differ(left: str, right: str) -> bool:
    left_org, right_org = organizational_domain(left), organizational_domain(right)
    return bool(left_org and right_org and left_org != right_org)
