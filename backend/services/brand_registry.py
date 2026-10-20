"""Versioned, provenance-bearing brand-domain candidate registry."""
from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path

_DEFAULT_PATH = Path(__file__).resolve().parents[1] / "config" / "brand_domains.json"


@lru_cache(maxsize=8)
def _load(path: str, modified_ns: int) -> tuple[dict[str, set[str]], dict[str, str]]:
    del modified_ns
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        brands = raw.get("brands")
        if not isinstance(brands, dict) or not brands:
            raise ValueError("Brand registry has no brands object")
        parsed: dict[str, set[str]] = {}
        for name, values in brands.items():
            if not isinstance(name, str) or not isinstance(values, list):
                continue
            domains = {str(value).strip().lower().rstrip(".") for value in values
                       if isinstance(value, str) and "." in value and len(value) <= 253}
            if domains:
                parsed[name.casefold()] = domains
        if not parsed:
            raise ValueError("Brand registry contained no usable domain candidates")
        metadata = {key: str(raw.get(key, ""))[:500]
                    for key in ("version", "provenance", "last_reviewed", "maintenance_policy")}
        metadata["source"] = Path(path).name
        return parsed, metadata
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        if Path(path) != _DEFAULT_PATH:
            return get_brand_registry(str(_DEFAULT_PATH))
        return {}, {"source": "unavailable", "provenance": "Brand registry could not be loaded."}


def get_brand_registry(path: str | None = None) -> tuple[dict[str, set[str]], dict[str, str]]:
    selected = Path(path or os.getenv("MAILTRACE_BRAND_DOMAIN_LIST", "").strip() or _DEFAULT_PATH).expanduser().resolve()
    try:
        modified = selected.stat().st_mtime_ns
    except OSError:
        modified = 0
    brands, metadata = _load(str(selected), modified)
    return {name: set(domains) for name, domains in brands.items()}, dict(metadata)
