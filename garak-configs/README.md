# AI Security Pipeline — ZTM Secure Workforce
### Airtel Internal LLM Security CI/CD Framework

A production-grade GitHub Actions pipeline that enforces AI security gates before any LLM-powered internal tool ships to employees.

---

## Pipeline Architecture

```
Developer Push / PR
        │
        ▼
┌─────────────────────────────┐
│  Stage 1: Static Analysis   │  Scans prompt templates for injection
│  static_prompt_scan.py      │  patterns, hardcoded secrets, role hijacks
└────────────┬────────────────┘
             │ PASS
             ▼
┌─────────────────────────────┐
│  Stage 2: Adversarial Test  │  Garak fires 15+ probe categories:
│  Garak + evaluate_results   │  injection, jailbreak, exfiltration,
└────────────┬────────────────┘  encoding attacks, persona hijack
             │ PASS
             ▼
┌─────────────────────────────┐
│  Stage 3: Guardrails Check  │  Azure AI Content Safety validation:
│  guardrails_validation.py   │  block mode active, thresholds correct,
└────────────┬────────────────┘  must-block + must-allow test suite
             │ PASS
             ▼
┌─────────────────────────────┐
│  Stage 4: OWASP Compliance  │  Automated checks against OWASP LLM
│  owasp_llm_checks.py        │  Top 10 (2025): LLM01/02/03/06/08/09
└────────────┬────────────────┘
             │ ALL PASS
             ▼
┌─────────────────────────────┐
│  Stage 5: Deployment Gate   │  Aggregates all reports, posts PR
│  deployment_gate.py         │  comment, blocks or approves deploy
└────────────┬────────────────┘
             │ APPROVED
             ▼
┌─────────────────────────────┐
│  Stage 6: Post-Deploy       │  Fires 10 known-bad prompts against
│  production_smoke_test.py   │  live endpoint to confirm guardrails
└─────────────────────────────┘  active in production
```

---

## What Gets Blocked

| Threat | Stage | How |
|--------|-------|-----|
| Prompt injection in code | Stage 1 | Regex pattern scan on template files |
| Hardcoded API keys | Stage 1 | Secret pattern detection |
| Jailbreak attempts (DAN, DevMode) | Stage 2 | Garak `dan.*` probes |
| Direct prompt injection | Stage 2 | Garak `promptinject.*` probes |
| Encoding attacks (base64, hex) | Stage 2 | Garak `encoding.*` probes |
| Training data extraction | Stage 2 | Garak `leakreplay.*` probes |
| Hate/violence/self-harm content | Stage 3 | Azure AI Content Safety block mode |
| PII exposure | Stage 3 | Content Safety + custom tests |
| Missing least-privilege controls | Stage 4 | OWASP LLM06 check |
| Groundedness not configured | Stage 4 | OWASP LLM09 check |
| Production guardrail misconfiguration | Stage 6 | Live smoke test |

---

## Configuration

### Required Secrets (GitHub → Settings → Secrets)

```
AZURE_CONTENT_SAFETY_ENDPOINT   Azure AI Content Safety resource endpoint
AZURE_CONTENT_SAFETY_KEY        Azure AI Content Safety API key
LLM_ENDPOINT                    Internal LLM API endpoint URL
LLM_API_KEY                     Internal LLM API key
```

### Guardrails Configuration

Edit `scripts/guardrails_validation.py` → `EXPECTED_CONFIG`:

```python
EXPECTED_CONFIG = {
    "hate":      {"block_threshold": 2, "mode": "block"},
    "violence":  {"block_threshold": 2, "mode": "block"},
    "sexual":    {"block_threshold": 0, "mode": "block"},   # zero tolerance
    "self_harm": {"block_threshold": 0, "mode": "block"},   # zero tolerance
}
```

Severity scale: 0 (safe) → 7 (severe). `block_threshold: 2` means severity 2+ is blocked.

### Garak Probe Configuration

Edit `garak-configs/airtel-probe-config.yaml` to add/remove probe categories.
Current fail threshold: `eval_threshold: 0.5` (50% success rate triggers failure).

---

## OWASP LLM Top 10 Coverage

| ID | Risk | Coverage |
|----|------|----------|
| LLM01 | Prompt Injection | Stage 1 (static) + Stage 2 (dynamic) |
| LLM02 | Sensitive Data Exposure | Stage 3 (guardrails) + Stage 4 (code check) |
| LLM03 | Supply Chain | Stage 4 (dependency check) |
| LLM06 | Excessive Agency | Stage 4 (permission scoping check) |
| LLM08 | Vector/Embedding Weaknesses | Stage 4 (RAG validation check) |
| LLM09 | Misinformation | Stage 4 (groundedness check) |

---

## Local Testing

```bash
# Run all scripts locally (mock mode — no live credentials needed)
python scripts/static_prompt_scan.py
python scripts/evaluate_garak_results.py
python scripts/guardrails_validation.py
python scripts/owasp_llm_checks.py
python scripts/deployment_gate.py
python scripts/production_smoke_test.py
```
