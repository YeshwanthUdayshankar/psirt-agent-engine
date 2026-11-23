# Agentic PSIRT & Vulnerability Response Engine (`psirt-agent-engine`)

An open-source, multi-agent Product Security Incident Response (PSIRT) & Vulnerability Response Engine built with **Zero-Trust Separation of Duties**, **Read-Only Tree-sitter AST MCP Tools**, **Deterministic Guardrails**, and **Mandatory Human-in-the-Loop (HITL) Approval Gates**.

## Why This Exists

- **High Noise-to-Signal Ratio:** Dependency scanners flag every transitive CVE regardless of reachability. `psirt-agent-engine` uses Tree-sitter AST call-graph analysis to separate reachable (`affected`) from unreachable (`not_affected`) CVEs with verifiable code citations and standardized OpenVEX justifications.
- **Manual PSIRT Overhead:** Automatically drafts root-cause MITRE CWE mappings, environmental **CVSS v4.0** assessments, **MITRE ATT&CK** mappings, tiered remediations (**Track A** patch/upgrade + **Track B** compensating controls + `pytest` reproducer), and standards-compliant **OpenVEX v0.2.0**, **OASIS CSAF 2.0** (`csaf_vex` & `csaf_security_advisory`), **CVE JSON 5.1**, and Markdown security advisories.
- **Trust & Hallucination Risk:** No LLM output reaches human reviewers—let alone external publication—without passing deterministic JSON Schema validation, SBOM version/PURL cross-checks, CVSS v4.0 math recalculation, zero-leakage secret scanning, and explicit signed human sign-off.

---

## Architecture & Trust Boundaries

```text
[Target Git Repo]
       │
       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ LAYER 1: DETERMINISTIC INTAKE & SANITIZATION (Zero LLM Involvement)     │
│  • Syft (SBOM) + Grype/OSV-Scanner (CVEs) + Semgrep (SAST) + Gitleaks   │
│    (plus built-in deterministic fallbacks & scanner JSON import)        │
│  • Secret/PII Redactor (strips credentials before any LLM sees context) │
│  • Canonical Normalizer & Deduplicator -> Consolidated TriageCase[]     │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   │ (Untrusted code wrapped in XML fences)
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ LAYER 2: AGENTIC ANALYSIS GRAPH (Read-Only MCP Tool Access)             │
│  • Triage & Scoring Agent (CWE + Environmental CVSS v4.0 + ATT&CK)      │
│  • VEX Reachability Agent (Tree-sitter AST MCP -> affected/not_affected)│
│  • Remediation Agent (Track A patch/bump + Track B controls + pytest)   │
│  • Advisory Drafting Agent (OpenVEX, CSAF 2.0, CVE JSON 5.1, Markdown)  │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ LAYER 3: DETERMINISTIC GUARDRAILS & VALIDATION GATE                     │
│  • JSON Schema Check (OpenVEX v0.2.0, OASIS CSAF 2.0, CVE JSON 5.1)     │
│  • Cross-Artifact Consistency (Versions/PURL/CVE/CWE match SBOM)        │
│  • Deterministic CVSS v4.0 Math Recalculation & Secret Leak Scan        │
│  • [FAIL] -> Retry loop (max 2 retries) or flag NEEDS_MANUAL_TRIAGE     │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ LAYER 4: HUMAN-IN-THE-LOOP (HITL) APPROVAL GATE                         │
│  • LangGraph HALTS via interrupt_before=["human_review"] (SQLite state) │
│  • Interactive Rich TUI review or GitHub Actions Environment Gate       │
│  • Human overrides re-trigger Layer 3 guardrails automatically          │
│  • Signed approval writes hash-chained decision_audit.yaml & unlocks    │
│    deterministic export (.vex.json, .csaf.json, .cve5.json, ADVISORY.md)│
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Quickstart

### 1. Install

```bash
cd /data/projects/psirt-agent-engine
uv venv --python 3.12
source .venv/bin/activate
uv pip install -e ".[dev]"
```

Optional: install external deterministic scanners (`syft`, `grype`, `osv-scanner`, `semgrep`, `gitleaks`, `vexctl`):

```bash
bash scripts/install-tools.sh
```

> The engine works out-of-the-box even without external binaries installed by falling back to built-in CycloneDX SBOM, CVE, SAST, and secret scanners, or by ingesting pre-generated scanner JSON reports via `--scanner-report`.

### 2. Run Locally (Interactive CLI + HITL Gate)

```bash
# Step 1: Scan & triage target repo — halts automatically at 6_AWAITING_HUMAN_REVIEW
psirt-engine scan tests/fixtures/sample_python_app --profile ollama_local

# Step 2: Check status & metrics (Noise Reduction Rate, Schema Pass Rate, Redactions)
psirt-engine status

# Step 3: Interactive Rich TUI review (inspect citations/diffs, override VEX, approve)
psirt-engine review --reviewer psirt-engineer

# Or approve non-interactively and export the validated disclosure bundle:
psirt-engine approve --reviewer psirt-engineer --export
```

### 3. Model-Agnostic / Privacy Configuration (`config/models.yaml`)

- **`ollama_local` (default):** Connects to local Ollama (`http://127.0.0.1:11434`) with automatic fallback to deterministic offline heuristics if Ollama is unreachable.
- **`vllm_local`:** Connects to a self-hosted vLLM OpenAI-compatible endpoint.
- **`anthropic_zdr` / `openai_zdr`:** Enterprise Zero-Data-Retention API endpoints.
- **`offline_heuristic`:** 100% offline deterministic execution for air-gapped environments and CI tests.

### 4. Read-Only MCP Servers

Both MCP servers expose strictly read-only tools (zero file write, shell execution, or outbound mutation capabilities):

```bash
# Repository Tree-sitter AST & sanitized file reader MCP server
PSIRT_TARGET_REPO=./tests/fixtures/sample_python_app psirt-mcp-repo-ast

# Vulnerability Intelligence (CWE / MITRE ATT&CK / VEX / OSV) MCP server
psirt-mcp-vuln-intel
```

### 5. Run Tests

```bash
pytest -v
```

---

## Governance & Evaluation Metrics

Every run computes and records the PRD evaluation metrics in the immutable, SHA-256 hash-chained `decision_audit.yaml`:

| Metric | Guarantee / Measurement |
|---|---|
| **Noise Reduction Rate** | % of third-party dependency CVEs deterministically triaged as `not_affected` with Tree-sitter AST code citations |
| **Schema Pass Rate** | 100% deterministic JSON Schema validation pass rate across OpenVEX v0.2.0, OASIS CSAF 2.0, and CVE JSON 5.1 prior to human review |
| **Zero-Leakage Guarantee** | 100% deterministic redaction of secrets/PII before LLM invocation AND verified again in Layer 3 Guardrails & Layer 4 Publisher |
| **Immutable Audit Trail** | Tamper-evident SHA-256 hash-chained event log recording scanner inputs, agent traces, human overrides, artifact hashes, and reviewer sign-offs |
