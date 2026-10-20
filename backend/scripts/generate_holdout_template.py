"""Generate EMPTY holdout annotation slots; this script does not synthesize emails or labels."""
from __future__ import annotations
import argparse, json
from pathlib import Path
def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--count", type=int, default=200)
    p.add_argument("--output", type=Path, default=Path("tests/fixtures/phase4_holdout/holdout.jsonl"))
    args = p.parse_args()
    if args.count < 1 or args.count > 10000: p.error("--count must be between 1 and 10000")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as handle:
        for n in range(1, args.count + 1):
            row = {"fixture_id": f"MT-HOLDOUT-{n:04d}", "split": "holdout", "email_path": None,
                "sha256": None, "provenance": None, "expected_label": None, "predicted_label": None,
                "independent_review_status": "pending", "reviewer_id": None, "reviewed_at_utc": None,
                "review_notes": None, "model_version": None, "policy_version": None}
            handle.write(json.dumps(row, ensure_ascii=True) + "\n")
    print(json.dumps({"output": str(args.output), "template_slots_written": args.count,
        "actual_email_samples": 0, "labelled_samples": 0, "status": "TEMPLATE_ONLY_NOT_A_HOLDOUT_DATASET"}, indent=2))
if __name__ == "__main__": main()
