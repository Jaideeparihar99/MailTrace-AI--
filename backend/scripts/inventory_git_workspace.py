"""Classify the complete Git porcelain inventory without changing the index."""
from __future__ import annotations
import csv, json, subprocess
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "backend" / "reports" / "phase4_git_inventory"
def classify(path):
    p = path.lower().replace("\\", "/")
    if "phase5" in p or "/phase5_" in p: return "Phase 5 - do not mix into Phase 4"
    if "ip_intelligence" in p or "geolocation" in p or "/ip/" in p: return "IP/geolocation"
    if any(x in p for x in ["backup", ".bak", ".before-", ".pre-", ".zip", "shot-home.png", "pytest-tmp", "__pycache__", ".pyc"]): return "generated/junk/recovery"
    if "/tests/" in p or p.startswith("backend/tests/") or p.startswith("backend/test_") or p.startswith("test_"): return "tests/fixtures"
    if p.endswith((".md", ".txt", ".rst")) or "audit" in p or "step" in p: return "docs/audits"
    if p.endswith((".yml", ".yaml", ".ini", ".toml", ".gitignore")) or p.endswith(".example"): return "config/CI"
    if p.startswith("frontend/") or p in {"index.html"} or p.endswith((".py", ".js", ".css", ".html")): return "application/source"
    if p.startswith("bridge/"): return "bridge tooling - review"
    return "unrelated/needs owner review"
def main():
    raw = subprocess.check_output(["git", "status", "--porcelain=v1", "-z"], cwd=ROOT)
    parts = raw.decode("utf-8", "replace").split("\0")
    rows = []
    i = 0
    while i < len(parts):
        item = parts[i]; i += 1
        if not item: continue
        status, path = item[:2], item[3:]
        if status[0] in "RC" or status[1] in "RC":
            if i < len(parts): i += 1
        rows.append({"status_code": status, "staged": status[0] not in " ?", "unstaged": status[1] not in " ?", "untracked": status == "??", "path": path, "classification": classify(path)})
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.with_suffix(".json").write_text(json.dumps({"root": str(ROOT), "counts": {"total": len(rows), "staged": sum(r["staged"] for r in rows), "unstaged": sum(r["unstaged"] for r in rows), "untracked": sum(r["untracked"] for r in rows)}, "rows": rows}, indent=2), encoding="utf-8")
    fields = ["status_code", "staged", "unstaged", "untracked", "classification", "path"]
    with OUT.with_suffix(".csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(rows)
    counts = {}
    for row in rows: counts[row["classification"]] = counts.get(row["classification"], 0) + 1
    report = ["# Git workspace inventory", "", "Generated from git status --porcelain=v1 -z. No files were staged, reset, deleted, committed, or pushed.", "",
      f"- Total changed paths: {len(rows)}",
      f"- Staged/working-index paths: {sum(r['staged'] for r in rows)}",
      f"- Unstaged paths: {sum(r['unstaged'] for r in rows)}",
      f"- Untracked paths: {sum(r['untracked'] for r in rows)}", "", "## Classification counts", ""]
    report += [f"- {k}: {v}" for k, v in sorted(counts.items())]
    report += ["", "## Full path inventory", "", "| Status | Class | Path |", "|---|---|---|"]
    report += [f"| {r['status_code']} | {r['classification']} | {r['path']} |" for r in rows]
    OUT.with_suffix(".md").write_text("\n".join(report) + "\n", encoding="utf-8")
    print(json.dumps({"inventory_json": str(OUT.with_suffix(".json")), "inventory_csv": str(OUT.with_suffix(".csv")), "inventory_md": str(OUT.with_suffix(".md")), "counts": counts, "status_counts": {"total": len(rows), "staged": sum(r["staged"] for r in rows), "unstaged": sum(r["unstaged"] for r in rows), "untracked": sum(r["untracked"] for r in rows)}}, indent=2))
if __name__ == "__main__": main()
