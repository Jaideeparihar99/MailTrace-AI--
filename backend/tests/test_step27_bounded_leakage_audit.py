import json
from pathlib import Path
import pytest
from scripts import audit_meajor_leakage_bounded as audit

def _dataset(path, rows):
    path.write_text("\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n", encoding="utf-8")
    return path

def _rows():
    return [
        {"text":"alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu", "label":"LEGITIMATE", "source":"trec5"},
        {"text":"malware red alert payload seven eight nine ten", "label":"PHISHING", "source":"trec5"},
        {"text":"alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu", "label":"PHISHING", "source":"trec6"},
        {"text":"alpha beta gamma delta epsilon zeta eta theta iota kappa lambda nu", "label":"LEGITIMATE", "source":"trec6"},
        {"text":"travel calendar meeting lunch tomorrow morning afternoon", "label":"LEGITIMATE", "source":"trec7"},
        {"text":"credential steal login password malicious redirect account", "label":"PHISHING", "source":"trec7"},
    ]

def _run(tmp_path, dataset, **kwargs):
    return audit.run(dataset, tmp_path/"audit.json", tmp_path/"audit.md", kwargs.get("pair_cap",10000), kwargs.get("max_seconds",30), kwargs.get("max_db_bytes",100_000_000), kwargs.get("cache_kib",1024))

def test_audit_is_repeatable_and_detects_cross_source_exact_and_near_duplicates(tmp_path):
    data=_dataset(tmp_path/"dataset.jsonl",_rows())
    first=_run(tmp_path,data); second=_run(tmp_path,data)
    assert first["status"] == second["status"] == "COMPLETE"
    assert first["dataset"]["sha256_before"] == second["dataset"]["sha256_before"]
    for key in ("source_family_class_counts","exact_duplicate_audit","near_duplicate_audit","source_grouped_partitions"):
        assert first[key] == second[key]
    assert first["exact_duplicate_audit"]["cross_source_duplicate_groups"] == 1
    assert first["exact_duplicate_audit"]["conflicting_label_groups"] == 1
    assert first["near_duplicate_audit"]["confirmed_pairs_jaccard_gte_threshold"] >= 1
    assert first["near_duplicate_audit"]["confirmed_cross_source_pairs"] >= 1
    assert first["source_grouped_partitions"]["all_partitions_valid"] is True
    evidence=json.loads((tmp_path/"audit.json").read_text(encoding="utf-8"))
    assert evidence["status"] == "COMPLETE"

def test_oversized_buckets_are_quantified_and_never_complete(tmp_path, monkeypatch):
    rows=[]
    for i in range(251):
        rows.append({"text":f"unique synthetic email token alpha beta gamma {i}","label":"LEGITIMATE" if i%2 else "PHISHING","source":"trec5" if i%4<2 else "trec6"})
    data=_dataset(tmp_path/"largebucket.jsonl",rows)
    monkeypatch.setattr(audit,"simhash",lambda tokens:0x1234567890ABCDEF)
    result=_run(tmp_path,data)
    assert result["status"] == "INCOMPLETE"
    assert result["near_duplicate_audit"]["oversized_bucket_count"] > 0
    assert result["near_duplicate_audit"]["potential_pairs_excluded_due_to_oversized_buckets"] > 0
    assert json.loads((tmp_path/"audit.json").read_text())["status"] != "COMPLETE"

def test_malformed_jsonl_fails_and_records_unprocessed_count(tmp_path):
    data=tmp_path/"bad.jsonl"; data.write_text(json.dumps(_rows()[0])+"\nnot-json\n",encoding="utf-8")
    result=_run(tmp_path,data)
    assert result["status"] == "FAILED"
    assert result["dataset"]["malformed_records"] == 1
    assert result["dataset"]["unprocessed_records"] == 1

def test_runtime_and_disk_limits_fail_closed(tmp_path):
    data=_dataset(tmp_path/"data.jsonl",_rows())
    runtime=_run(tmp_path,data,max_seconds=0)
    assert runtime["status"] == "INCOMPLETE"
    assert runtime["resource_limits"]["runtime_limit_reached"] is True
    disk=_run(tmp_path,data,max_db_bytes=1)
    assert disk["status"] == "INCOMPLETE"
    assert disk["resource_limits"]["disk_limit_reached"] is True

def test_candidate_pair_cap_is_never_exceeded(tmp_path):
    data=_dataset(tmp_path/"data.jsonl",_rows())
    result=_run(tmp_path,data,pair_cap=0)
    assert result["status"] == "INCOMPLETE"
    assert result["resource_limits"]["candidate_pair_limit_reached"] is True
    assert result["near_duplicate_audit"]["candidate_pairs"] <= 1
    assert json.loads((tmp_path/"audit.json").read_text())["status"] == "INCOMPLETE"

def test_dataset_mutation_is_failed_and_cannot_be_marked_complete(tmp_path,monkeypatch):
    data=_dataset(tmp_path/"data.jsonl",_rows()); original=audit.sha; calls={"n":0}
    def changing_hash(path):
        calls["n"]+=1; value=original(path)
        return value if calls["n"]==1 else "0"*64
    monkeypatch.setattr(audit,"sha",changing_hash)
    result=_run(tmp_path,data)
    assert result["status"] == "FAILED"
    assert result["dataset"]["hash_stable"] is False

def test_sqlite_error_writes_failed_evidence(tmp_path,monkeypatch):
    data=_dataset(tmp_path/"data.jsonl",_rows())
    monkeypatch.setattr(audit.sqlite3,"connect",lambda *a,**k: (_ for _ in ()).throw(sqlite3.OperationalError("synthetic database failure")))
    import sqlite3
    result=_run(tmp_path,data)
    assert result["status"] == "FAILED"
    saved=json.loads((tmp_path/"audit.json").read_text())
    assert saved["status"] == "FAILED"
    assert saved["coverage"]["error_type"] == "OperationalError"
