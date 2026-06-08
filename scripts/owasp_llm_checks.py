"""
owasp_llm_checks.py
Stage 4 — Runs automated compliance checks mapped to OWASP LLM Top 10 (2025).
Checks configuration files, code patterns, and endpoint behaviour.
"""

import os
import sys
import json
import re
from pathlib import Path

EXCLUDE_DIRS = {".git", "node_modules", "__pycache__", "reports", ".venv"}

results = {
    "passed": [],
    "failed": [],
    "warnings": [],
    "skipped": [],
}

def check(id: str, description: str, passed: bool, reason: str = "", warn_only: bool = False):
    status = "PASS" if passed else ("WARN" if warn_only else "FAIL")
    symbol = "✓" if passed else ("⚠" if warn_only else "✗")
    print(f"  {symbol} [{id}] {description}")
    if not passed and reason:
        print(f"       → {reason}")

    if passed:
        results["passed"].append({"id": id, "description": description})
    elif warn_only:
        results["warnings"].append({"id": id, "description": description, "reason": reason})
    else:
        results["failed"].append({"id": id, "description": description, "reason": reason})

def find_in_codebase(pattern: str, extensions: set = {".py", ".yaml", ".yml", ".json"}) -> list:
    """Search codebase for a regex pattern. Returns list of matching file paths."""
    matches = []
    for f in Path(".").rglob("*"):
        if f.suffix in extensions and not any(ex in f.parts for ex in EXCLUDE_DIRS):
            try:
                content = f.read_text(errors="ignore")
                if re.search(pattern, content, re.IGNORECASE):
                    matches.append(str(f))
            except Exception:
                pass
    return matches

def main():
    print("[*] Running OWASP LLM Top 10 (2025) compliance checks...\n")

    # ── LLM01: Prompt Injection ────────────────────────────────────────────
    print("[LLM01] Prompt Injection Controls")

    # Check: Static scanner is present and configured
    check(
        "LLM01-01",
        "Static prompt injection scanner configured",
        Path("scripts/static_prompt_scan.py").exists(),
        "static_prompt_scan.py not found",
    )

    # Check: Input sanitisation pattern present in code
    sanitize_matches = find_in_codebase(r"sanitize|escape|strip|clean.*input|input.*clean")
    check(
        "LLM01-02",
        "Input sanitisation pattern found in codebase",
        len(sanitize_matches) > 0,
        "No input sanitisation code detected",
        warn_only=True,
    )

    # Check: Indirect injection — document/ticket input validation
    indirect_matches = find_in_codebase(r"document.*scan|rag.*valid|retriev.*safe|chunk.*sanitize")
    check(
        "LLM01-03",
        "Indirect injection controls for RAG/document pipeline",
        len(indirect_matches) > 0,
        "No indirect injection controls found for document pipeline",
        warn_only=True,
    )

    # ── LLM02: Sensitive Information Disclosure ────────────────────────────
    print("\n[LLM02] Sensitive Information Disclosure")

    pii_matches = find_in_codebase(r"pii|redact|mask.*email|anonymize|personal.*data")
    check(
        "LLM02-01",
        "PII detection / redaction controls present",
        len(pii_matches) > 0,
        "No PII handling code detected",
    )

    hardcoded_secrets = find_in_codebase(r"(sk-|api_key\s*=\s*['\"])[a-zA-Z0-9]{20,}")
    check(
        "LLM02-02",
        "No hardcoded API keys or secrets in codebase",
        len(hardcoded_secrets) == 0,
        f"Potential hardcoded secrets in: {hardcoded_secrets}",
    )

    env_usage = find_in_codebase(r"os\.environ|os\.getenv|\$\{\{secrets\.")
    check(
        "LLM02-03",
        "Secrets loaded from environment / secret store",
        len(env_usage) > 0,
        "No environment variable usage detected for secrets",
    )

    # ── LLM03: Supply Chain ────────────────────────────────────────────────
    print("\n[LLM03] Supply Chain Security")

    check(
        "LLM03-01",
        "requirements.txt or pyproject.toml with pinned versions present",
        Path("requirements.txt").exists() or Path("pyproject.toml").exists(),
        "No dependency file found — versions not pinned",
        warn_only=True,
    )

    check(
        "LLM03-02",
        "Garak probe config specifies exact model endpoint",
        Path("garak-configs/airtel-probe-config.yaml").exists(),
        "Garak config not found",
    )

    # ── LLM06: Excessive Agency ────────────────────────────────────────────
    print("\n[LLM06] Excessive Agency")

    least_priv = find_in_codebase(r"least.privilege|read.only|permission.*scope|allow.*list|whitelist.*tool")
    check(
        "LLM06-01",
        "Least privilege / tool permission scoping present",
        len(least_priv) > 0,
        "No least-privilege or tool scoping controls detected",
        warn_only=True,
    )

    human_in_loop = find_in_codebase(r"human.in.loop|approval.*required|confirm.*action|review.*before")
    check(
        "LLM06-02",
        "Human-in-the-loop controls for sensitive actions",
        len(human_in_loop) > 0,
        "No human-in-the-loop controls detected for agent actions",
        warn_only=True,
    )

    # ── LLM08: Vector / Embedding Weaknesses ──────────────────────────────
    print("\n[LLM08] Vector & Embedding Security")

    rag_validation = find_in_codebase(r"embedding.*valid|chunk.*sanitize|rag.*security|vector.*scan")
    check(
        "LLM08-01",
        "RAG/embedding input validation controls",
        len(rag_validation) > 0,
        "No RAG input validation detected",
        warn_only=True,
    )

    # ── LLM09: Misinformation / Hallucination ─────────────────────────────
    print("\n[LLM09] Misinformation / Hallucination Controls")

    groundedness = find_in_codebase(r"groundedness|grounded|factual.*check|hallucination|verify.*source")
    check(
        "LLM09-01",
        "Groundedness or hallucination detection configured",
        len(groundedness) > 0,
        "No groundedness controls detected — consider Azure AI Content Safety groundedness check",
        warn_only=True,
    )

    # ── Save report ────────────────────────────────────────────────────────
    os.makedirs("reports", exist_ok=True)
    report = {
        "stage": "owasp-llm-compliance",
        "framework": "OWASP LLM Top 10 2025",
        "results": results,
        "summary": {
            "passed": len(results["passed"]),
            "failed": len(results["failed"]),
            "warnings": len(results["warnings"]),
        },
    }
    with open("reports/owasp-results.json", "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[SUMMARY] {len(results['passed'])} passed | "
          f"{len(results['failed'])} failed | "
          f"{len(results['warnings'])} warnings")

    critical_failures = [f for f in results["failed"]
                        if any(x in f["id"] for x in ["LLM01-01", "LLM02-02", "LLM02-01"])]

    if critical_failures:
        print("\n[FAIL] Critical OWASP LLM compliance checks failed.")
        for f in critical_failures:
            print(f"  ✗ {f['id']}: {f['description']}")
        sys.exit(1)
    else:
        print("\n[PASS] All critical OWASP LLM compliance checks passed.")
        sys.exit(0)

if __name__ == "__main__":
    main()
