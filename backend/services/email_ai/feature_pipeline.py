"""Deterministic, bounded feature extraction and grouped splitting for MailTrace-AI."""
from __future__ import annotations
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
import hashlib, json, re, unicodedata, platform
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

PIPELINE_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0.0"
DEFAULT_MAX_TEXT_CHARS = 200_000
DEFAULT_MAX_URLS = 500
DEFAULT_SEED = 2701
FORBIDDEN_FEATURE_NAMES = frozenset({"label", "target", "expected_label", "analyst_verdict", "verdict", "threat_score", "risk_score", "final_risk_score", "report", "report_summary", "investigation_summary", "post_investigation", "review_outcome", "ground_truth", "prediction", "model_output"})
FEATURE_ALLOWLIST = frozenset({"subject_char_count", "body_char_count", "body_word_count", "url_count", "url_host_count", "url_invalid_host_count", "url_query_count", "url_at_symbol_count", "url_punycode_host_count", "header_count", "received_hop_count", "attachment_count", "subject_available", "body_available", "body_source", "header_block_available", "from_header_present", "reply_to_header_present", "return_path_header_present", "received_chain_available", "message_date_trustworthy_format", "spf_status", "spf_status_available", "dkim_status", "dkim_status_available", "dmarc_status", "dmarc_status_available", "authentication_results_trusted", "parse_status", "exclamation_count", "question_count", "uppercase_ratio", "has_urgent_language", "has_credential_language", "has_financial_language", "has_ip_literal_url", "contains_non_ascii", "contains_bidi_or_invisible_controls"})
ALLOWED_PARSE_STATUSES = frozenset({"COMPLETE", "PARTIAL", "FAILED", "ERROR", "MISSING", "OTHER"})

class _VisibleText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True); self.parts = []; self.hidden = 0
    def handle_starttag(self, tag, attrs):
        if tag.lower() in {"script", "style", "head", "title", "noscript"}: self.hidden += 1
        elif tag.lower() in {"br", "p", "div", "li", "tr"}: self.parts.append(" ")
    def handle_endtag(self, tag):
        if tag.lower() in {"script", "style", "head", "title", "noscript"} and self.hidden: self.hidden -= 1
        elif tag.lower() in {"br", "p", "div", "li", "tr"}: self.parts.append(" ")
    def handle_data(self, data):
        if not self.hidden: self.parts.append(data)

def _map(value):
    return value if isinstance(value, Mapping) else {}

def _bounded(value, limit):
    if not isinstance(value, str): return "", value is None, False
    return value[:limit], False, len(value) > limit

def normalize_text(value, *, max_chars=DEFAULT_MAX_TEXT_CHARS):
    raw, missing, truncated = _bounded(value, max_chars)
    if missing: return {"text": "", "available": False, "missing_reason": "MISSING", "truncated": False}
    normalized = unicodedata.normalize("NFKC", raw)
    normalized = "".join(ch for ch in normalized if unicodedata.category(ch) != "Cf")
    normalized = re.sub(r"\s+", " ", normalized).strip().casefold()
    return {"text": normalized, "available": bool(normalized), "missing_reason": None if normalized else "EMPTY", "truncated": truncated}

def _html_to_text(value):
    parser = _VisibleText()
    try:
        parser.feed(value); parser.close()
        return " ".join(parser.parts)
    except Exception:
        return re.sub(r"<[^>]{0,1000}>", " ", value)

def _host(value):
    if not isinstance(value, str) or len(value) > 8192: return None
    try:
        host = urlsplit(value.strip()).hostname
        return host.rstrip(".").encode("idna").decode("ascii").lower() if host else None
    except (ValueError, UnicodeError):
        return None

def _auth_status(auth, key):
    value = auth.get(key)
    if not isinstance(value, str) or not value.strip(): return "MISSING", False
    status = value.strip().upper()
    allowed = {"PASS", "FAIL", "SOFTFAIL", "NEUTRAL", "NONE", "TEMPERROR", "PERMERROR", "NOT_FOUND"}
    return (status if status in allowed else "OTHER"), True

def extract_features(parsed_email, *, max_text_chars=DEFAULT_MAX_TEXT_CHARS, max_urls=DEFAULT_MAX_URLS):
    """Consume existing parse_email() output only. Never fetch URLs or mutate evidence."""
    if max_text_chars < 1 or max_urls < 0: raise ValueError("Invalid preprocessing limits.")
    parsed = _map(parsed_email); basic = _map(parsed.get("basic_information"))
    body = _map(parsed.get("body")); headers = _map(parsed.get("headers")); auth = _map(parsed.get("authentication"))
    subject = normalize_text(basic.get("subject"), max_chars=min(max_text_chars, 20_000))
    plain_raw, _, body_truncated = _bounded(body.get("text"), max_text_chars)
    html_raw, _, html_truncated = _bounded(body.get("html"), max_text_chars)
    plain = normalize_text(plain_raw, max_chars=max_text_chars) if body.get("text") is not None else normalize_text(None)
    html_visible = normalize_text(_html_to_text(html_raw), max_chars=max_text_chars) if html_raw else normalize_text(None)
    selected = plain if plain["available"] else html_visible
    text_for_model = " ".join(part for part in (subject["text"], selected["text"]) if part).strip()
    urls_value = parsed.get("urls"); urls_present = isinstance(urls_value, list)
    urls = [url for url in (urls_value or []) if isinstance(url, str)][:max_urls] if urls_present else []
    hosts = [_host(url) for url in urls]; valid_hosts = [host for host in hosts if host]
    text = selected["text"]
    auth_values = {key: _auth_status(auth, key) for key in ("spf", "dkim", "dmarc")}
    received = parsed.get("received_chain")
    date_value = basic.get("date"); date_trustworthy = False
    if isinstance(date_value, str) and date_value.strip():
        try:
            dt = parsedate_to_datetime(date_value)
            date_trustworthy = bool(dt and dt.tzinfo)
        except (TypeError, ValueError, OverflowError): pass
    sample_text = (plain_raw + " " + html_raw)[:max_text_chars]
    raw_unicode_text = str(basic.get("subject") or "")[:20000] + " " + sample_text
    letters = sum(ch.isalpha() for ch in sample_text)
    lexical = {
        "exclamation_count": min(text.count("!"), 10000), "question_count": min(text.count("?"), 10000),
        "uppercase_ratio": round(sum(ch.isupper() for ch in sample_text) / max(1, letters), 6),
        "has_urgent_language": bool(re.search(r"\b(urgent|immediately|action required|verify your account|suspended|payment overdue)\b", text)),
        "has_credential_language": bool(re.search(r"\b(password|login|sign in|credentials|one.time.code|verification code)\b", text)),
        "has_financial_language": bool(re.search(r"\b(invoice|wire transfer|bank account|payment|payroll|gift card)\b", text)),
        "has_ip_literal_url": any(host and re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host) for host in valid_hosts),
        "contains_non_ascii": any(ord(ch) > 127 for ch in raw_unicode_text),
        "contains_bidi_or_invisible_controls": any(unicodedata.category(ch) in {"Cf", "Cc"} and ch not in "\n\r\t" for ch in raw_unicode_text),
    }
    numeric = {
        "subject_char_count": len(subject["text"]), "body_char_count": len(text), "body_word_count": len(text.split()),
        "url_count": len(urls), "url_host_count": len(set(valid_hosts)), "url_invalid_host_count": sum(host is None for host in hosts),
        "url_query_count": sum("?" in url for url in urls), "url_at_symbol_count": sum("@" in url for url in urls),
        "url_punycode_host_count": sum(bool(host and "xn--" in host) for host in valid_hosts),
        "header_count": len(headers) if isinstance(headers, Mapping) else 0,
        "received_hop_count": len(received) if isinstance(received, list) else 0,
        "attachment_count": len(parsed.get("attachments")) if isinstance(parsed.get("attachments"), list) else 0,
    }
    categorical = {
        "subject_available": subject["available"], "body_available": selected["available"],
        "body_source": "plain" if plain["available"] else ("html" if html_visible["available"] else "missing"),
        "header_block_available": isinstance(parsed.get("headers"), Mapping),
        "from_header_present": bool(isinstance(basic.get("from"), str) and basic["from"].strip()),
        "reply_to_header_present": bool(isinstance(basic.get("reply_to"), str) and basic["reply_to"].strip()),
        "return_path_header_present": bool(isinstance(basic.get("return_path"), str) and basic["return_path"].strip()),
        "received_chain_available": isinstance(received, list), "message_date_trustworthy_format": date_trustworthy,
        "spf_status": auth_values["spf"][0], "spf_status_available": auth_values["spf"][1],
        "dkim_status": auth_values["dkim"][0], "dkim_status_available": auth_values["dkim"][1],
        "dmarc_status": auth_values["dmarc"][0], "dmarc_status_available": auth_values["dmarc"][1],
        # Only an explicit parser boolean can mark this field trusted; strings like "false" fail closed.
        "authentication_results_trusted": auth.get("authentication_results_trusted") is True,
        "parse_status": (lambda status: status if status in ALLOWED_PARSE_STATUSES else "OTHER")(
            str(_map(parsed.get("parsing")).get("status") or "MISSING").upper()[:32]),
    }
    available = {"subject": basic.get("subject"), "body_text": body.get("text"), "body_html": body.get("html"),
                 "headers": parsed.get("headers"), "urls": parsed.get("urls"), "authentication": parsed.get("authentication"),
                 "received_chain": parsed.get("received_chain"), "attachments": parsed.get("attachments")}
    return {
        "schema_version": SCHEMA_VERSION, "pipeline_version": PIPELINE_VERSION,
        "raw_evidence": {"available_fields": sorted(k for k, v in available.items() if v is not None),
                         "source_paths": {"subject": "basic_information.subject", "body_text": "body.text", "body_html": "body.html",
                                          "headers": "headers", "urls": "urls", "authentication": "authentication",
                                          "received_chain": "received_chain", "attachments": "attachments"},
                         "original_evidence_mutated": False},
        "normalized_features": {
            "subject_text": subject["text"], "body_text": selected["text"], "text_for_model": text_for_model,
            "numeric": numeric, "categorical": categorical, "lexical": lexical,
            "missingness": {"subject": subject["missing_reason"], "body": selected["missing_reason"],
                            "headers": None if isinstance(parsed.get("headers"), Mapping) else "MISSING",
                            "urls": None if urls_present else "MISSING",
                            "authentication": None if isinstance(parsed.get("authentication"), Mapping) else "MISSING"},
            "truncation": {"subject": subject["truncated"], "body": body_truncated or plain["truncated"],
                           "html": html_truncated, "url_list": urls_present and len(parsed["urls"]) > max_urls}},
        "model_output": None, "final_risk_score": None,
        "provenance": {"numeric": {k: "deterministic parser-field transformation" for k in numeric},
                       "categorical": {k: "deterministic parser-field transformation" for k in categorical},
                       "lexical": {k: "bounded deterministic text/URL lexical indicator; not a verdict" for k in lexical}},
    }

def feature_vector(record):
    """Allow-list only model-input sections; reject verdict/label leakage."""
    normalized = _map(_map(record).get("normalized_features")); result = {}
    for section in ("numeric", "categorical", "lexical"):
        for name, value in _map(normalized.get(section)).items():
            lower = name.casefold()
            if lower in FORBIDDEN_FEATURE_NAMES or any(token in lower for token in ("verdict", "risk_score", "analyst", "report_summary", "label")):
                raise ValueError(f"Forbidden/leaking feature name: {name}")
            if name not in FEATURE_ALLOWLIST:
                raise ValueError(f"Unknown feature is not in the v{SCHEMA_VERSION} allow-list: {name}")
            result[name] = value
    result["text_for_model"] = normalized.get("text_for_model", "")
    return result

def _canonical_text(row):
    raw = row.get("text", row.get("body_text", ""))
    raw = unicodedata.normalize("NFKC", str(raw or ""))
    raw = "".join(ch for ch in raw if unicodedata.category(ch) != "Cf")
    return re.sub(r"\s+", " ", raw).strip().casefold()


def _tokens_for_similarity(row):
    text = _canonical_text(row)
    return set(re.findall(r"[a-z0-9]+", text))

def _simhash(tokens):
    if len(tokens) < 4: return None
    weights = [0] * 64
    for token in sorted(tokens):
        value = int.from_bytes(hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest(), "big")
        for bit in range(64): weights[bit] += 1 if (value >> bit) & 1 else -1
    return sum((1 << bit) for bit, weight in enumerate(weights) if weight >= 0)

def _near_duplicate_pairs(items):
    # Collapse exact canonical duplicates before candidate generation. Exact rows are already
    # unioned by grouped_split, so this avoids quadratic buckets of repeated copies.
    representatives = {}
    for index, row in enumerate(items):
        canonical = _canonical_text(row)
        key = hashlib.sha256(canonical.encode("utf-8")).hexdigest() if canonical else f"empty:{index}"
        representatives.setdefault(key, index)
    representative_indices = list(representatives.values())
    token_sets = [_tokens_for_similarity(items[index]) for index in representative_indices]
    signatures = [_simhash(tokens) for tokens in token_sets]
    buckets = {}
    for local_index, signature in enumerate(signatures):
        if signature is None: continue
        for band in range(8):
            key = (band, (signature >> (band * 8)) & 0xFF)
            buckets.setdefault(key, []).append(local_index)
    candidates = set()
    def add_pairs(members):
        if len(members) > 250:
            raise ValueError(
                f"Near-duplicate candidate generation incomplete: refined SimHash bucket has "
                f"{len(members)} members (maximum 250); refusing to silently skip candidates."
            )
        for position, left in enumerate(members):
            for right in members[position + 1:]:
                if left != right: candidates.add((min(left, right), max(left, right)))
    for (band, _value), members in buckets.items():
        if len(members) <= 250:
            add_pairs(members)
            continue
        # Oversized 8-bit buckets are refined with a second independent SimHash band;
        # do not silently discard the entire candidate bucket at the first threshold.
        refined = {}
        second_band = (band + 4) % 8
        for member in members:
            signature = signatures[member]
            second_value = (signature >> (second_band * 8)) & 0xFF
            refined.setdefault(second_value, []).append(member)
        for sub_members in refined.values(): add_pairs(sub_members)
    for left, right in sorted(candidates):
        a, b = token_sets[left], token_sets[right]
        if not a or not b: continue
        similarity = len(a & b) / len(a | b)
        if similarity >= 0.80:
            yield representative_indices[left], representative_indices[right]

def _parse_timestamp(value):
    if not isinstance(value, str) or not value.strip(): return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc) if dt.tzinfo else None
    except (ValueError, OverflowError):
        try:
            dt = parsedate_to_datetime(value)
            return dt.astimezone(timezone.utc) if dt and dt.tzinfo else None
        except (TypeError, ValueError, OverflowError): return None

def grouped_split(rows: Iterable[Mapping[str, Any]], *, seed=DEFAULT_SEED, train_ratio=0.70, dev_ratio=0.15, test_ratio=0.15, group_by_source=True, time_aware=True):
    """Split campaign/thread/duplicate groups together; chronology only with trustworthy timestamps."""
    items = [dict(row) for row in rows]
    if not items: raise ValueError("Cannot split an empty dataset.")
    ratios = (train_ratio, dev_ratio, test_ratio)
    if any(r < 0 for r in ratios) or abs(sum(ratios)-1.0) > 1e-8 or train_ratio <= 0 or test_ratio <= 0:
        raise ValueError("Split ratios must sum to 1; train/test must be positive.")
    sources = {str(row.get("source_group") or row.get("source")).strip().casefold()
               for row in items if row.get("source_group") or row.get("source")}
    use_source = group_by_source and len(sources) >= 3
    parent = list(range(len(items)))
    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]; i = parent[i]
        return i
    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb: parent[max(ra, rb)] = min(ra, rb)
    owner = {}; fingerprints = []; timestamps = []
    for i, row in enumerate(items):
        canonical = _canonical_text(row)
        fingerprint = hashlib.sha256(canonical.encode("utf-8")).hexdigest() if canonical else f"empty-row:{i}"
        fingerprints.append(fingerprint)
        keys = [f"duplicate:{fingerprint}"]
        for field in ("campaign_id", "campaign", "thread_id", "conversation_id", "duplicate_group_id", "near_duplicate_group_id"):
            value = row.get(field)
            if value is not None and str(value).strip(): keys.append(f"{field}:{str(value).strip().casefold()}")
        source = row.get("source_group") or row.get("source")
        if use_source and source is not None and str(source).strip(): keys.append(f"source:{str(source).strip().casefold()}")
        for key in keys:
            if key in owner: union(i, owner[key])
            else: owner[key] = i
        dt = None
        for field in ("timestamp", "sent_at", "date", "email_date"):
            dt = _parse_timestamp(row.get(field))
            if dt is not None: break
        timestamps.append(dt)
    # Similarity candidates are local-only; no text is written to the split manifest.
    for left, right in _near_duplicate_pairs(items):
        union(left, right)
    groups = {}
    for i in range(len(items)): groups.setdefault(find(i), []).append(i)
    group_items = list(groups.values())
    if len(group_items) < 3: raise ValueError("At least 3 independent groups are required for train/dev/test; relax source grouping only with documented justification.")
    temporal = time_aware and all(dt is not None for dt in timestamps)
    if temporal: group_items.sort(key=lambda members: (max(timestamps[i] for i in members), min(fingerprints[i] for i in members)))
    else: group_items.sort(key=lambda members: hashlib.sha256((str(seed)+":"+"|".join(sorted(fingerprints[i] for i in members))).encode("utf-8")).hexdigest())
    total = len(items); train_target = max(1, round(total*train_ratio)); dev_target = max(1, round(total*dev_ratio)) if dev_ratio else 0
    assignment = {}; counts = {"train": 0, "dev": 0, "test": 0}
    assignment = {}; counts = {"train": 0, "dev": 0, "test": 0}
    group_total = len(group_items)
    train_group_boundary = max(1, min(group_total - 2, round(group_total * train_ratio)))
    dev_group_boundary = max(train_group_boundary + 1, min(group_total - 1, round(group_total * (train_ratio + dev_ratio))))
    for group_index, members in enumerate(group_items):
        if temporal:
            split = "train" if group_index < train_group_boundary else ("dev" if group_index < dev_group_boundary else "test")
        elif group_index < 3:
            split = ("train", "dev", "test")[group_index]
        else:
            deficits = {"train": train_ratio*total-counts["train"], "dev": dev_ratio*total-counts["dev"], "test": test_ratio*total-counts["test"]}
            split = max(("train", "dev", "test"), key=lambda name: (deficits[name], -("train", "dev", "test").index(name)))
        for i in members: assignment[i] = split; counts[split] += 1
    if any(len({assignment[i] for i in members}) != 1 for members in group_items): raise AssertionError("Group leakage detected.")
    output = {name: [items[i] for i in range(len(items)) if assignment[i] == name] for name in ("train", "dev", "test")}
    if not output["train"] or not output["test"]: raise ValueError("Split produced an empty train/test partition; provide more independent groups.")
    if temporal:
        time_by_split = {name: [timestamps[i] for i in range(len(items)) if assignment[i] == name] for name in ("train", "dev", "test")}
        for earlier, later in (("train", "dev"), ("dev", "test")):
            if time_by_split[earlier] and time_by_split[later] and max(time_by_split[earlier]) >= min(time_by_split[later]):
                raise ValueError("Grouped timestamps overlap across temporal partitions; cannot guarantee a strict chronological holdout. Use a reviewed split policy or non-temporal grouped split.")
    payload = {"schema_version": SCHEMA_VERSION, "pipeline_version": PIPELINE_VERSION, "seed": seed,
               "strategy": "chronological_grouped" if temporal else "stable_hash_grouped",
                "configuration": {"train_ratio": train_ratio, "dev_ratio": dev_ratio, "test_ratio": test_ratio,
                                   "group_by_source_requested": group_by_source, "time_aware_requested": time_aware,
                                   "near_duplicate_similarity_threshold": 0.80, "near_duplicate_bucket_limit": 250,
                                   "text_canonicalization": "NFKC; remove Cf; collapse whitespace; casefold"},
                "runtime": {"python_version": platform.python_version()},
               "group_by_source": use_source, "source_group_count": len(sources), "group_count": len(group_items),
               "input_rows": len(items), "split_counts": {k: len(v) for k,v in output.items()},
               "dataset_sha256": hashlib.sha256(json.dumps(items, sort_keys=True, ensure_ascii=False, default=str, separators=(",", ":")).encode("utf-8")).hexdigest(),
               "time_aware_used": temporal, "timestamp_rule": "All rows require timezone-aware timestamps; missing/naive timestamps disable temporal split.",
               "leakage_policy": ["campaign_id", "campaign", "thread_id", "conversation_id", "duplicate_group_id", "near_duplicate_group_id", "normalized_exact_text_fingerprint"] + (["source/source_group"] if use_source else []),
               "limitations": ["Near-duplicate detection is approximate SimHash-band candidate generation plus token-set Jaccard >= 0.80; oversized SimHash buckets are refined with a second band and sub-buckets above 250 records are skipped.", "Source-level grouping requires at least three distinct source values and may make strict chronological partitioning infeasible.", "Temporal splits fail closed when grouped timestamp ranges overlap; this split does not adjudicate labels or licensing."]}
    payload["split_sha256"] = {name: hashlib.sha256(json.dumps(values, sort_keys=True, ensure_ascii=False, default=str, separators=(",", ":")).encode("utf-8")).hexdigest() for name, values in output.items()}
    return {"splits": output, "manifest": payload}

def write_split_manifest(result, path):
    """Write only aggregate split metadata; no message text or per-message IDs."""
    from pathlib import Path
    manifest = dict(_map(result.get("manifest"))); destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(manifest, indent=2, sort_keys=True)+"\n", encoding="utf-8")

def build_text_classifier(seed=DEFAULT_SEED):
    """The TF-IDF vocabulary is learned inside fit(), never during preprocessing."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    return Pipeline([("tfidf", TfidfVectorizer(lowercase=False, strip_accents=None, ngram_range=(1,2), min_df=1, max_df=1.0, sublinear_tf=True, max_features=60000, token_pattern=r"(?u)\b\w+\b")),
                     ("classifier", LogisticRegression(max_iter=2000, class_weight="balanced", random_state=seed, solver="liblinear"))])

def fit_text_classifier(train_records, labels, *, seed=DEFAULT_SEED):
    """Fit only records explicitly supplied by the caller (must be training split)."""
    records = list(train_records); targets = [str(label) for label in labels]
    if len(records) != len(targets) or not records: raise ValueError("Training records and labels must be non-empty and equal length.")
    texts = [str(_map(_map(_map(record).get("features", record)).get("normalized_features")).get("text_for_model") or "") for record in records]
    if any(not text.strip() for text in texts): raise ValueError("Training rows contain empty text; handle missing text before fitting.")
    if len(set(targets)) < 2: raise ValueError("At least two target classes are required.")
    model = build_text_classifier(seed); model.fit(texts, targets); return model
