"""
static_prompt_scan.py
Stage 1 — Scans all prompt template files for security anti-patterns.
Fails the pipeline (exit code 1) if critical issues are found.
"""

import os
import re
import sys
import json
from pathlib import Path

# ── Patterns that are always critical (pipeline FAIL) ─────────────────────
CRITICAL_PATTERNS = [
    (r"ignore (all )?previous instructions", "Instruction override pattern"),
    (r"you are now (a |an )?(?!helpful)", "Role hijack pattern"),
    (r"(sk-|Bearer |api_key\s*=\s*)[a-zA-Z0-9]{20,}", "Hardcoded API key or token"),
    (r"<\|system\|>|<\|im_start\|>|<\|im_end\|>", "Special token injection"),
    (r"disregard (your|all) (previous |prior )?(instructions|training)", "Training override attempt"),
    (r"\[\[INJECT\]\]|\{\{INJECT\}\}", "Explicit injection marker in template"),
]

# ── Patterns that are warnings (logged, non-blocking) ─────────────────────
WARNING_PATTERNS = [
    (r"\{\{user_input\}\}(?!.*sanitize)", "Unsanitized user_input slot — confirm input validation upstream"),
    (r"system\s*:", "Literal 'system:' in template — verify this is intentional"),
    (r"assistant\s*:", "Literal 'assistant:' in template — verify this is intentional"),
    (r"jailbreak|dan mode|developer mode", "Jailbreak keyword in template"),
    (r"(password|secret|token)\s*[:=]", "Sensitive keyword in prompt template"),
]

PROMPT_EXTENSIONS = {".txt", ".yaml", ".yml", ".json", ".md", ".prompt"}
EXCLUDE_DIRS = {".git", "node_modules", "__pycache__", "reports", ".github"}

def scan_file(filepath: Path) -> dict:
    results = {"path": str(filepath), "critical": [], "warnings": []}
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore").lower()
    except Exception as e:
        results["warnings"].append(f"Could not read file: {e}")
        return results

    for pattern, description in CRITICAL_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            results["critical"].append({"pattern": pattern, "description": description})

    for pattern, description in WARNING_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            results["warnings"].append({"pattern": pattern, "description": description})

    return results

def main():
    root = Path(".")
    findings = []
    critical_count = 0
    warning_count = 0

    prompt_files = [
        f for f in root.rglob("*")
        if f.suffix in PROMPT_EXTENSIONS
        and not any(ex in f.parts for ex in EXCLUDE_DIRS)
        and f.is_file()
    ]

    print(f"[*] Scanning {len(prompt_files)} prompt template files...\n")

    for f in prompt_files:
        result = scan_file(f)
        if result["critical"] or result["warnings"]:
            findings.append(result)
            critical_count += len(result["critical"])
            warning_count += len(result["warnings"])

            if result["critical"]:
                print(f"[CRITICAL] {result['path']}")
                for c in result["critical"]:
                    print(f"  ✗ {c['description']}")
            if result["warnings"]:
                print(f"[WARNING]  {result['path']}")
                for w in result["warnings"]:
                    desc = w if isinstance(w, str) else w.get("description", w)
                    print(f"  ⚠ {desc}")

    # Save report
    os.makedirs("reports", exist_ok=True)
    report = {
        "stage": "static-prompt-analysis",
        "files_scanned": len(prompt_files),
        "critical_findings": critical_count,
        "warning_findings": warning_count,
        "details": findings,
    }
    with open("reports/static-scan-results.json", "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[SUMMARY] {len(prompt_files)} files scanned | {critical_count} critical | {warning_count} warnings")

    if critical_count > 0:
        print("\n[FAIL] Critical prompt security issues found. Blocking pipeline.")
        sys.exit(1)
    else:
        print("\n[PASS] No critical prompt security issues found.")
        sys.exit(0)

if __name__ == "__main__":
    main()
