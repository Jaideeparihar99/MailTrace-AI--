from __future__ import annotations

import argparse
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXCLUDED_DIRS = {".git", "venv", ".venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "node_modules", "backups", "runtime_data", "runtime_test_artifacts", ".pytest-tmp"}
TEXT_SUFFIXES = {".py", ".js", ".ts", ".tsx", ".jsx", ".html", ".css", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".md", ".txt", ".ps1", ".bat", ".sh", ".env", ".example", ".conf", ".properties"}
PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    "credential_assignment": re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|client[_-]?secret|password|passwd)\s*[:=]\s*['\"](?!test[-_ ]|example|dummy|changeme|your[_ -])[A-Za-z0-9_./+=-]{16,}['\"]"),
    "url_embedded_credential": re.compile(r"https?://[^/\s:@]+:[^/\s@]{8,}@", re.I),
}
SENSITIVE_LOG = re.compile(r"(?i)(?:logger|logging|print)\.(?:debug|info|warning|error|exception)\s*\([^\n]*(?:authorization|bearer|password|passwd|secret|token|email_body|raw_email|message\.as_string)\s*[,)=]")

def should_skip(path: Path) -> bool:
    try:
        rel = path.relative_to(ROOT)
    except ValueError:
        return True
    return any(part in EXCLUDED_DIRS or part.startswith(".pytest-tmp") for part in rel.parts)

def candidate_files():
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS and not d.startswith(".pytest-tmp")]
        for name in files:
            path = Path(base) / name
            if should_skip(path) or (path.suffix.lower() not in TEXT_SUFFIXES and not path.name.lower().startswith(".env")):
                continue
            try:
                if path.stat().st_size > 5 * 1024 * 1024:
                    continue
                yield path
            except OSError:
                continue

def main() -> int:
    parser = argparse.ArgumentParser(description="Scan repository text files for likely secrets and sensitive logging without printing matched values.")
    parser.add_argument("--strict", action="store_true", help="return exit 1 when any candidate finding exists")
    args = parser.parse_args()
    scanned = 0
    findings = []
    for path in candidate_files():
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        scanned += 1
        for number, line in enumerate(lines, 1):
            for category, pattern in PATTERNS.items():
                if pattern.search(line):
                    findings.append((path.relative_to(ROOT).as_posix(), number, category))
            if SENSITIVE_LOG.search(line):
                findings.append((path.relative_to(ROOT).as_posix(), number, "sensitive_logging_review"))
    print(f"Scanned {scanned} repository text files; matched values are never printed.")
    if not findings:
        print("No candidate secret/sensitive-log patterns found.")
        return 0
    for file_name, line_number, category in findings:
        print(f"REVIEW {category}: {file_name}:{line_number}")
    print(f"Candidate findings: {len(findings)}. These are heuristic candidates, not confirmed secrets; review each privately.")
    return 1 if args.strict else 0

if __name__ == "__main__":
    raise SystemExit(main())
