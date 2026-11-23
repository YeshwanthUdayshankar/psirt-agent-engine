# Agentic PSIRT & Vulnerability Response Engine (`psirt-agent-engine`)

[![CI](https://github.com/YeshwanthUdayshankar/psirt-agent-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/YeshwanthUdayshankar/psirt-agent-engine/actions/workflows/ci.yml)

An open-source, multi-agent Product Security Incident Response (PSIRT) & Vulnerability Response Engine built with **Zero-Trust Separation of Duties**, **Read-Only Tree-sitter AST MCP Tools**, **CVE Program CNA Counting Rules**, **CISA KEV/EPSS Threat Intel**, **Jira Schema-Drift & `CODEOWNERS` Routing**, **Deterministic Guardrails**, and **Mandatory Human-in-the-Loop (HITL) Approval Gates**.

> **Looking for the full deep-dive?** See the **[Detailed Features, Architecture & Setup Guide](docs/DETAILED_GUIDE.md)** for complete CLI references, LLM/Ollama/vLLM/ZDR configuration, MCP server integration, Jira mapping, CNA policy rules, and GitHub Actions HITL setup.

---

## Why This Exists

- **High Noise-to-Signal Ratio:** Dependency scanners flag every transitive CVE regardless of reachability. `psirt-agent-engine` uses Tree-sitter AST call-graph analysis (with monorepo sub-service scoping) to separate reachable (`affected`) from unreachable (`not_affected`) CVEs with verifiable code citations and standardized OpenVEX justifications.
- **Manual PSIRT & CNA Overhead:** Automatically enforces CVE Program CNA rules (`on_prem` vs. `hybrid` vs. `saas`), maps root-cause MITRE CWEs, calculates environmental **CVSS v4.0** scores, enriches with **CISA KEV / FIRST EPSS** and **MITRE ATT&CK**, drafts tiered remediations (**Track A** patch/upgrade + **Track B** compensating controls + runnable `pytest` reproducer), routes tickets via `CODEOWNERS` into division-specific Jira schemas, and exports **OpenVEX v0.2.0**, **OASIS CSAF 2.0** (`csaf_vex` & `csaf_security_advisory`), **CVE JSON 5.1**, and Markdown bulletins.
- **Trust & Hallucination Risk:** No LLM output reaches human reviewers—let alone external publication—without passing 8 deterministic guardrail gates (JSON Schema, CSAF profile integrity, SBOM version/PURL cross-checks, CVSS v4.0 math recalculation, logical version ordering, CNA policy, public prose hygiene, and zero-leakage secret scanning) plus explicit signed human sign-off.

---

## Architecture & Trust Boundaries

```text
[Target Git Repo]
       │
       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ LAYER 1: DETERMINISTIC INTAKE & SANITIZATION (Zero LLM Involvement)     │
│  • Syft (SBOM) + Grype/OSV-Scanner (CVEs) + Semgrep (SAST) + Gitleaks   │
│    (plus built-in deterministic fallbacks & --scanner-report JSON)      │
│  • Secret/PII Redactor + Repo-Wide Prompt Injection Scanner             │
│  • Canonical Normalizer & Deduplicator -> Consolidated TriageCase[]     │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   │ (Untrusted code wrapped in XML fences)
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ LAYER 2: AGENTIC ANALYSIS GRAPH (Read-Only MCP Tool Access)             │
│  • CODEOWNERS Router + Triage Agent (CWE + CVSS v4.0 + KEV/EPSS + ATT&CK)│
│  • VEX Reachability Agent (Tree-sitter AST MCP -> affected/not_affected)│
│  • CNA Rules Engine (on_prem / hybrid / saas -> CVE assignment policy)  │
│  • Remediation Agent (Track A patch/bump + Track B controls + pytest)   │
│  • Advisory Drafting Agent (OpenVEX, CSAF 2.0, CVE JSON 5.1, Markdown)  │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ LAYER 3: DETERMINISTIC GUARDRAILS & VALIDATION GATE (8 Gates)           │
│  • JSON Schema + OASIS CSAF Profile Rules (OpenVEX, CSAF 2.0, CVE 5.1)  │
│  • SBOM Version/PURL Alignment, Logical Version Order (fixed > affected)│
│  • CVSS v4.0 Math Recalculation, CNA Policy, Prose Hygiene & Leak Scan  │
│  • [FAIL] -> Retry loop (max 2 retries) or flag NEEDS_MANUAL_TRIAGE     │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ LAYER 4: HUMAN-IN-THE-LOOP (HITL) APPROVAL GATE                         │
│  • LangGraph HALTS via interrupt_before=["human_review"] (SQLite state) │
│  • Interactive Rich TUI review or GitHub Actions Environment Gate       │
│  • Human overrides re-trigger Layer 3 guardrails automatically          │
│  • Signed approval writes hash-chained decision_audit.yaml & unlocks    │
│    export (.vex.json, .csaf.json, .cve5.json, ADVISORY.md, jira_tickets)│
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Quickstart

### 1. Install

```bash
git clone https://github.com/YeshwanthUdayshankar/psirt-agent-engine.git
cd psirt-agent-engine
uv venv --python 3.12
source .venv/bin/activate
uv pip install -e ".[dev]"
```

Optional: install external deterministic scanners (`syft`, `grype`, `osv-scanner`, `semgrep`, `gitleaks`, `vexctl`):

```bash
bash scripts/install-tools.sh
```

> Works out-of-the-box offline with built-in CycloneDX SBOM, CVE, SAST, and secret scanners, or by importing pre-generated scanner JSON reports (`--scanner-report`).

### 2. Run Locally (Interactive CLI + HITL Gate)

```bash
# Step 1: Scan & triage target repo — halts automatically at 6_AWAITING_HUMAN_REVIEW
# Supports --deployment-mode on_prem | hybrid | saas (enforces CVE Program CNA rules)
psirt-engine scan tests/fixtures/sample_python_app \
  --profile ollama_local \
  --deployment-mode on_prem

# Step 2: Inspect checkpointed status & metrics
psirt-engine status

# Step 3: Interactive Rich TUI review (inspect citations/diffs, override VEX, approve)
psirt-engine review --reviewer psirt-engineer

# Or approve non-interactively and export the validated disclosure bundle + Jira payloads:
psirt-engine approve --reviewer psirt-engineer --export
```

### 3. Run Tests, Lint & Golden-Dataset Benchmark

```bash
ruff check src tests scripts
pytest -v
python scripts/run_eval.py
```

---

## Core Enterprise PSIRT Features

| Capability | Implementation |
|---|---|
| **CNA Assignment Rules** | [cna_rules.py](src/psirt_engine/agents/cna_rules.py) — Enforces CVE Program Section 7 rules across `--deployment-mode on_prem\|hybrid\|saas` (`assign_new_cve`, `reference_upstream_cve`, `no_cve_saas_excluded`, `no_cve_not_affected`, `no_cve_secret_hygiene`) |
| **CISA KEV & FIRST EPSS** | [vuln_intel_server.py](src/psirt_engine/mcp_servers/vuln_intel_server.py) — Read-only `lookup_kev_epss` MCP tool assigning `emergency_kev`, `elevated_epss`, or `standard` priority tiers alongside CVSS v4.0 |
| **Jira Schema-Drift & `CODEOWNERS`** | [jira_adapter.py](src/psirt_engine/hitl/jira_adapter.py) + [config/jira_mapping.yaml](config/jira_mapping.yaml) — Routes via `CODEOWNERS`, maps division-specific Jira custom field IDs, generates deterministic SHA-256 idempotency keys, exports `jira_tickets.json`, and handles HTTP `429` exponential backoff |
| **Read-Only AST & Intel MCP Servers** | `psirt-mcp-repo-ast` (Tree-sitter Python/Go call graphs, path jail, redacted reads) & `psirt-mcp-vuln-intel` (CWE, ATT&CK, KEV/EPSS, VEX, OSV) — zero write/shell/mutation tools |
| **`Advisory-Ready` Guardrails (8 Gates)** | [consistency.py](src/psirt_engine/guardrails/consistency.py) — Schema validation, CSAF profile rules, SBOM version/PURL check, CVSS v4.0 math, `fixed_version > affected_version`, CNA policy enforcement, internal URL/path hygiene check, and secret leak blocking |
| **Model-Agnostic / ZDR Privacy** | [config/models.yaml](config/models.yaml) — Local `ollama_local` (default), `vllm_local`, `anthropic_zdr`, `openai_zdr`, and air-gapped `offline_heuristic` |

See **[docs/DETAILED_GUIDE.md](docs/DETAILED_GUIDE.md)** for full architecture walkthroughs, MCP client config, and CI/CD setup.

---

## Golden-Dataset Evaluation Metrics (`python scripts/run_eval.py`)

Verified in CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) against [eval/golden_dataset.yaml](eval/golden_dataset.yaml) across Python (`on_prem` & `saas`) and Go fixtures:

| Metric | Result | Target / Gate |
|---|---|---|
| **VEX Reachability Precision / Recall / F1** | **100.0% / 100.0% / 100.0%** (`tp=7, fp=0, fn=0, tn=4`) | `100.0%` |
| **CWE Root-Cause Accuracy** | **100.0%** | `100.0%` |
| **CNA Rule Accuracy (`on_prem` vs. `saas` vs. 3rd-party)** | **100.0%** | `100.0%` |
| **CISA KEV Detection Accuracy** | **100.0%** | `100.0%` |
| **Avg Dependency Noise Reduction Rate** | **66.7%** | Maximize |
| **Deterministic Schema Pass Rate** | **100.0%** (OpenVEX, CSAF 2.0, CVE JSON 5.1) | `100.0%` |
| **Zero-Leakage Secret Leaks** | **0** | `0` |
| **Avg Human Edit Distance** | **0.0018** | Minimize |

---

## Sample Outputs (Verified on [OWASP PyGoat](https://github.com/adeyosemanputra/pygoat))

Actual outputs captured from running `psirt-agent-engine` against OWASP PyGoat (commit `2aa4cc14f251`):

- **39 raw findings → 36 consolidated cases** (`28` hardcoded secrets redacted, **0 secret leaks** in exported bundle)
- **50.0% dependency Noise Reduction Rate** (`4/8` third-party CVEs triaged `not_affected` via Tree-sitter AST monorepo scoping)
- **100.0% JSON Schema Pass Rate** across `108` published JSON artifacts (`37` OpenVEX, `36` CSAF 2.0 VEX, `32` CSAF 2.0 Advisory, `3` CVE JSON 5.1)
- **179 hash-chained audit events** verified intact in `decision_audit.yaml`

### 1. CLI Triage & HITL Checkpoint Output

```text
╭───────────────────── PSIRT Triage Pipeline Checkpointed ─────────────────────╮
│ Run ID: pygoat-eval-2                                                        │
│ Repository: /tmp/psirt-eval/pygoat (commit `2aa4cc14f251`)                   │
│ Scanners: builtin-sbom, builtin-osv-matcher, builtin-sast,                   │
│ builtin-secret-scanner                                                       │
│ Redactions (NFR-2): 28 | Prompt Injection Warnings (NFR-1): 0                │
│ Noise Reduction Rate: 50.0% | Schema Pass Rate: 100.0%                       │
│ Graph Status: HALTED at HITL Gate (human_review)                             │
╰──────────────────────────────────────────────────────────────────────────────╯
```

| Case ID | CVE / Finding | Package | CVSS v4.0 | VEX Status | Traced AST Call Path |
|---|---|---|---|---|---|
| `PSIRT-002-12E838` | `CVE-2020-14343` (`CWE-502`) | `pyyaml@5.1` | `9.3` (CRITICAL) | `affected` | `dockerized_labs/a9_uckv_lab/app.py:62:upload_yaml` → `yaml.load` |
| `PSIRT-003-8ACA4E` | `CVE-2023-50447` (`CWE-94`) | `pillow@8.0.0` | `9.2` (CRITICAL) | `affected` | `dockerized_labs/a9_uckv_lab/app.py:94:process_image` → `ImageMath.eval` |
| `PSIRT-006-593F63` | `CVE-2023-32681` (`CWE-200`) | `requests@2.26.0` | `6.0` (MEDIUM) | `affected` | `dockerized_labs/ssrf_lab/app.py:37:lab2` → `requests.get` |
| `PSIRT-007-23A633` | `CVE-2023-32681` (`CWE-200`) | `requests@2.28.2` | `6.0` (MEDIUM) | `affected` | `challenge/views.py:353:start_lab` → `check_traefik_reachable` → `requests.get` |
| `PSIRT-005-285557` | `CVE-2023-32681` (`CWE-200`) | `requests@2.28.1` | `6.0` (MEDIUM) | `not_affected` | `[]` (`sensitive_data_exposure` never invokes `requests`) |
| `PSIRT-001-F5E44F` | `CVE-2024-34064` (`CWE-79`) | `jinja2@3.1.2` | `5.3` (MEDIUM) | `not_affected` | `[]` (`xmlattr`/`do_xmlattr` not in execute path) |
| `PSIRT-008-E2D2B4` | `CVE-2023-45803` (`CWE-200`) | `urllib3@1.26.9` | `2.3` (LOW) | `not_affected` | `[]` (never imported directly) |
| `PSIRT-009-10706F` | Unsafe `yaml.load` (`CWE-502`) | first-party | `9.3` (CRITICAL) | `affected` | `dockerized_labs/a9_uckv_lab/app.py:62:yaml.load` |

### 2. Post-Approval Exported Bundle

Running `psirt-engine export` prior to approval is blocked by FR-5.1 (`exit 2`). After `psirt-engine approve --reviewer psirt-lead --export`, the engine publishes the validated disclosure bundle:

```text
output/
├── sbom.cdx.json                     # CycloneDX 1.5 SBOM
├── bundle.vex.json                   # Merged OpenVEX v0.2.0 statements
├── jira_tickets.json                 # Team-mapped Jira payloads with idempotency keys
├── decision_audit.yaml               # SHA-256 hash-chained immutable audit trail
├── decision_audit.json
└── psirt-003-8aca4e/
    ├── ADVISORY.md                   # Customer-facing security bulletin
    ├── psirt-003-8aca4e.vex.json     # OpenVEX v0.2.0
    ├── psirt-003-8aca4e.csaf-vex.json# OASIS CSAF 2.0 VEX (status: final)
    ├── psirt-003-8aca4e.csaf.json    # OASIS CSAF 2.0 Security Advisory (status: final)
    ├── remediation_track_a.diff      # Minimal upgrade / patch diff
    └── test_repro_pillow.py          # Verification harness
```

<details>
<summary><strong>Sample OpenVEX v0.2.0 (<code>not_affected</code> with AST Justification)</strong></summary>

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://security.example.com/advisories/vex/psirt-005-285557",
  "author": "Example Product Security Incident Response Team (PSIRT)",
  "role": "Product Security Incident Response Team (PSIRT)",
  "timestamp": "2026-11-23T01:36:27Z",
  "version": 1,
  "tooling": "psirt-agent-engine/0.1.0",
  "statements": [
    {
      "vulnerability": {
        "name": "CVE-2023-32681",
        "description": "Requests Proxy-Authorization header leaked to destination servers on redirect",
        "@id": "https://nvd.nist.gov/vuln/detail/CVE-2023-32681"
      },
      "timestamp": "2026-11-23T01:36:27Z",
      "products": [
        {
          "@id": "pkg:pypi/requests@2.28.1",
          "identifiers": { "purl": "pkg:pypi/requests@2.28.1" }
        }
      ],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "impact_statement": "Transitive/unused dependency requests@2.28.1 is present in dockerized_labs/sensitive_data_exposure/requirements.txt but is never imported or called in any first-party execution path."
    }
  ]
}
```

</details>

<details>
<summary><strong>Sample Customer-Facing Security Advisory (<code>ADVISORY.md</code> — Track A + Track B + KEV/EPSS + ATT&amp;CK)</strong></summary>

````markdown
# Security Advisory: EXSA-PSIRT-003-8ACA4E — Pillow ImageMath.eval arbitrary code execution

- **Publisher:** Example Product Security Incident Response Team (PSIRT)
- **Case ID:** `PSIRT-003-8ACA4E` | **CVE ID:** `CVE-2023-50447`
- **CNA Decision:** `reference_upstream_cve` (`on_prem`)
- **Owning Team (CODEOWNERS):** `@appsec-backend`
- **Root-Cause CWE:** `CWE-94` — Improper Control of Generation of Code ('Code Injection')
- **VEX Status:** `affected` | **Confidence Score:** 0.88
- **Threat Intel (KEV / EPSS):** CISA KEV: **NO** | EPSS: `0.412 (p92)` | Tier: `standard`

## 1. Executive Summary
Confirmed reachable: package pillow@8.0.0 is imported and vulnerable symbol(s) ['ImageMath.eval']
are invoked at dockerized_labs/a9_uckv_lab/app.py:94.

## 2. Technical Description & Severity (CVSS v4.0)
- **CVSS v4.0 Score:** `9.2` (**CRITICAL**)
- **CVSS v4.0 Vector:** `CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`
- **Base Reference Score:** `8.1` (Environmental Delta: `+1.1`)
- **Environmental Rationale:** Code path is directly exposed on an HTTP/network handler without inline auth guards (AV:N/PR:N).

## 3. Affected & Fixed Versions
- **Affected Package:** `pillow@8.0.0` (`pkg:pypi/pillow@8.0.0`)
- **Fixed Version:** `10.3.0`

## 4. Remediation & Workarounds
### Track A — Primary Fix
Upgrade pillow from 8.0.0 to 10.3.0 in dockerized_labs/a9_uckv_lab/requirements.txt.
- **Breaking-Change Risk:** `high` — MAJOR version upgrade (8.0.0 -> 10.3.0): review breaking API changes before merging.

```diff
--- a/dockerized_labs/a9_uckv_lab/requirements.txt
+++ b/dockerized_labs/a9_uckv_lab/requirements.txt
@@ -1 +1 @@
-pillow==8.0.0
+pillow==10.3.0
```

### Track B — Compensating Controls & Workarounds
- Block untrusted payloads targeting vulnerable symbols (`ImageMath.eval`, `ImageMath`) at the API gateway/WAF.
- Restrict endpoint access via mTLS / RBAC / network segmentation ACLs.
- Add runtime input validation rejecting unexpected tags, oversized frames, or malformed headers.

## 5. Detection & Indicator of Compromise (IoC) Guidance (MITRE ATT&CK)
- **T1190 (Exploit Public-Facing Application — Initial Access)**
- **T1059 (Command and Scripting Interpreter — Execution)**

## 6. Verifiable Evidence Citations
- `dockerized_labs/a9_uckv_lab/app.py:94-94` (symbol=`ImageMath.eval`, commit=`2aa4cc14f251...`): Vulnerable symbol 'ImageMath.eval' invoked in `process_image`
````

</details>

<details>
<summary><strong>Sample CVE JSON 5.1 CNA Record (with Native <code>cvssV4_0</code> Metrics)</strong></summary>

```json
{
  "dataType": "CVE_RECORD",
  "dataVersion": "5.1",
  "cveMetadata": {
    "cveId": "CVE-2026-15931",
    "assignerOrgId": "550e8400-e29b-41d4-a716-446655440000",
    "assignerShortName": "example-psirt",
    "state": "PUBLISHED",
    "dateReserved": "2026-11-23T01:36:27Z",
    "datePublished": "2026-11-23T01:36:27Z",
    "dateUpdated": "2026-11-23T01:36:27Z"
  },
  "containers": {
    "cna": {
      "providerMetadata": {
        "orgId": "550e8400-e29b-41d4-a716-446655440000",
        "shortName": "example-psirt",
        "dateUpdated": "2026-11-23T01:36:27Z"
      },
      "title": "Unsafe YAML deserialization using yaml.load",
      "descriptions": [
        {
          "lang": "en",
          "value": "Unsafe YAML deserialization using yaml.load. Root cause maps to CWE-502 (Deserialization of Untrusted Data) based on builtin-sast evidence in dockerized_labs/a9_uckv_lab/app.py. Affected component: pygoat."
        }
      ],
      "problemTypes": [
        {
          "descriptions": [
            {
              "type": "CWE",
              "cweId": "CWE-502",
              "lang": "en",
              "description": "CWE-502: Deserialization of Untrusted Data"
            }
          ]
        }
      ],
      "metrics": [
        {
          "format": "CVSS",
          "scenarios": [{ "lang": "en", "value": "GENERAL" }],
          "cvssV4_0": {
            "version": "4.0",
            "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "baseScore": 9.3,
            "baseSeverity": "CRITICAL",
            "attackVector": "NETWORK",
            "attackComplexity": "LOW",
            "privilegesRequired": "NONE",
            "userInteraction": "NONE"
          }
        }
      ]
    }
  }
}
```

</details>

<details>
<summary><strong>Sample Schema-Drift-Mapped Jira Payload (<code>jira_tickets.json</code>)</strong></summary>

```json
{
  "idempotency_key": "psirt-idem-8f3c1e74c2a1b49d0e52f1a8",
  "case_id": "PSIRT-006-D604C5",
  "owning_team": "@appsec-backend",
  "project_key": "APPAPI",
  "fields": {
    "project": { "key": "APPAPI" },
    "issuetype": { "name": "Bug" },
    "summary": "[PSIRT-006-D604C5] CWE-89: SQL Injection via unsanitized string interpolation in SQL query",
    "priority": { "name": "High" },
    "labels": ["psirt-automated", "vex-affected", "cna-assign_new_cve"],
    "customfield_10202": "CWE-89",
    "customfield_20101": 8.8,
    "customfield_20102": "affected",
    "customfield_20199": "psirt-idem-8f3c1e74c2a1b49d0e52f1a8"
  }
}
```

</details>

<details>
<summary><strong>Sample Immutable Hash-Chained Audit Log (<code>decision_audit.yaml</code>)</strong></summary>

```yaml
run_id: pygoat-eval-2
repo_path: /tmp/psirt-eval/pygoat
commit_sha: 2aa4cc14f251e4a780e94e200aed6b36a5b15c21
model_profile: offline_heuristic
sbom_sha256: a14e602264fecc3eaf841d74530ca0c24c78a9b8b9fc0ff17a4a7b9f3364c241
redactions_performed: 28
prompt_injection_warnings: []
events:
- event_id: 1
  actor: system:layer1_intake
  action: scan_and_sanitize
  summary: 'Scanned pygoat (2aa4cc14f251): 39 raw findings -> 36 consolidated cases; 28 secrets/PII redacted.'
  prev_hash: GENESIS
  entry_hash: 72ddc5df489c8732862ab5337bc27e9e9195136ce34dcb2d64abecaac0c39a78
- event_id: 2
  actor: agent:triage_and_vex
  action: case_triaged
  case_id: PSIRT-001-F5E44F
  summary: 'PSIRT-001-F5E44F: CWE-79, CVSS v4.0 5.3, VEX=not_affected (conf=0.88)'
  prev_hash: 72ddc5df489c8732862ab5337bc27e9e9195136ce34dcb2d64abecaac0c39a78
  entry_hash: 47d9c267d4b06790c8873fcf201bef5788cdd52f51e3ee5062145465ffafec04
```

</details>

---

## Documentation

- **[Detailed Features, Architecture & Setup Guide](docs/DETAILED_GUIDE.md)** — In-depth technical documentation covering every layer, CNA rules, MCP servers, Jira integration, guardrails, LLM profiles, CLI flags, CI/CD setup, and evaluation benchmarks.
