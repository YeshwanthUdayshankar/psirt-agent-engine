# Detailed Technical Guide: Features, Architecture & Setup

This guide is the complete reference for **`psirt-agent-engine`** — covering every feature, architectural trust boundary, configuration file, CLI option, MCP tool, guardrail gate, and CI/CD deployment flow.

---

## Table of Contents

1. [Repository Layout](#1-repository-layout)
2. [Four-Layer Zero-Trust Architecture & State Machine](#2-four-layer-zero-trust-architecture--state-machine)
3. [Feature Deep-Dives](#3-feature-deep-dives)
   - [3.1 Multi-Modal Intake, SBOM & Deduplication (Layer 1)](#31-multi-modal-intake-sbom--deduplication-layer-1)
   - [3.2 Secret/PII Redaction & Prompt-Injection Isolation (NFR-1 / NFR-2)](#32-secretpii-redaction--prompt-injection-isolation-nfr-1--nfr-2)
   - [3.3 Read-Only MCP Servers (Tree-sitter AST & Threat Intel)](#33-read-only-mcp-servers-tree-sitter-ast--threat-intel)
   - [3.4 CVE Program CNA Assignment Rules Engine](#34-cve-program-cna-assignment-rules-engine)
   - [3.5 CISA KEV, FIRST EPSS & Environmental CVSS v4.0](#35-cisa-kev-first-epss--environmental-cvss-v40)
   - [3.6 Tiered Remediation (Track A, Track B & Verification Harnesses)](#36-tiered-remediation-track-a-track-b--verification-harnesses)
   - [3.7 Standards-Compliant PSIRT Disclosure Artifacts](#37-standards-compliant-psirt-disclosure-artifacts)
   - [3.8 Deterministic Guardrails (8 Validation Gates)](#38-deterministic-guardrails-8-validation-gates)
   - [3.9 Jira Schema-Drift Adapter & CODEOWNERS Auto-Routing](#39-jira-schema-drift-adapter--codeowners-auto-routing)
   - [3.10 Immutable Hash-Chained Audit Log & HITL Gate](#310-immutable-hash-chained-audit-log--hitl-gate)
4. [Complete Setup & Configuration Guide](#4-complete-setup--configuration-guide)
   - [4.1 Prerequisites & Installation](#41-prerequisites--installation)
   - [4.2 Installing Optional External Scanners](#42-installing-optional-external-scanners)
   - [4.3 Configuring LLM Providers (Ollama, vLLM, Anthropic/OpenAI ZDR, Offline)](#43-configuring-llm-providers-ollama-vllm-anthropicopenai-zdr-offline)
   - [4.4 Configuring Your Organization CNA Profile](#44-configuring-your-organization-cna-profile)
   - [4.5 Configuring Jira Schema-Drift Mappings & CODEOWNERS](#45-configuring-jira-schema-drift-mappings--codeowners)
5. [CLI Reference & Workflows](#5-cli-reference--workflows)
6. [GitHub Actions CI/CD & HITL Environment Setup](#6-github-actions-cicd--hitl-environment-setup)
7. [Testing & Golden-Dataset Evaluation Benchmark](#7-testing--golden-dataset-evaluation-benchmark)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. Repository Layout

```text
psirt-agent-engine/
├── pyproject.toml                          # Package metadata, dependencies, CLI & MCP entrypoints
├── README.md                               # Quickstart, architecture overview & PyGoat sample outputs
├── docs/
│   └── DETAILED_GUIDE.md                   # This document
├── .github/workflows/
│   ├── ci.yml                              # Push/PR CI: ruff lint, pytest, golden-dataset eval
│   └── psirt-triage.yml                    # HITL CI/CD workflow with GitHub Environment Protection
├── config/
│   ├── models.yaml                         # LLM profiles (ollama_local, vllm_local, ZDR, offline)
│   ├── cna_profile.yaml                    # CNA orgId UUID, namespace, advisory prefix, SLAs
│   └── jira_mapping.yaml                   # Per-team Jira project & custom-field drift mappings
├── schemas/
│   ├── openvex.json                        # OpenVEX v0.2.0 strict JSON Schema
│   ├── csaf_2.0.json                       # OASIS CSAF 2.0 JSON Schema (VEX & Advisory profiles)
│   └── cve_5.1.json                        # CVE JSON 5.1 CNA Schema (with native cvssV4_0)
├── scripts/
│   ├── install-tools.sh                    # Installs syft, grype, osv-scanner, semgrep, gitleaks, vexctl
│   └── run_eval.py                         # Golden-dataset benchmark runner (Precision/Recall/F1/EditDist)
├── eval/
│   └── golden_dataset.yaml                 # Labeled ground-truth dataset for evaluation
├── src/psirt_engine/
│   ├── cli.py                              # Typer CLI (scan, triage, status, review, approve, export)
│   ├── config.py                           # YAML/env config loaders
│   ├── llm.py                              # Model-agnostic zero-leakage LLM client
│   ├── state.py                            # LangGraph TypedDict state & SqliteSaver helper
│   ├── graph.py                            # 7-state LangGraph HITL state machine
│   ├── models/
│   │   ├── canonical.py                    # CanonicalFinding, TriageCase, VEX, CNA, ThreatIntel, etc.
│   │   └── audit.py                        # SHA-256 hash-chained DecisionAuditLog & overrides
│   ├── intake/
│   │   ├── scanners.py                     # Syft/Grype/OSV/Semgrep/Gitleaks adapters + built-ins
│   │   ├── sanitizer.py                    # Secret/PII redaction, XML fences, prompt-injection scan
│   │   └── deduplicator.py                 # Structural + semantic deduplication
│   ├── mcp_servers/
│   │   ├── repo_ast_server.py              # Read-only Tree-sitter AST MCP server
│   │   └── vuln_intel_server.py            # Read-only CWE/ATT&CK/KEV/EPSS/VEX/OSV MCP server
│   ├── agents/
│   │   ├── prompts.py                      # Hardened anti-injection system prompts
│   │   ├── triage_agent.py                 # CWE, environmental CVSS v4.0, KEV/EPSS, ATT&CK
│   │   ├── vex_agent.py                    # Tree-sitter AST reachability -> OpenVEX
│   │   ├── cna_rules.py                    # CVE Program Section 7 CNA decision engine
│   │   ├── remediation_agent.py            # Track A + Track B + pytest verification harness
│   │   └── advisory_agent.py               # OpenVEX, CSAF 2.0, CVE JSON 5.1, ADVISORY.md
│   ├── guardrails/
│   │   ├── schema_validator.py             # Draft 2020-12 JSON Schema & CSAF profile checks
│   │   ├── cvss_math.py                    # Deterministic CVSS v4.0 calculator & verifier
│   │   └── consistency.py                  # Cross-artifact, SBOM, version, CNA & prose hygiene gates
│   └── hitl/
│       ├── reviewer.py                     # Rich TUI reviewer, PR comment builder, override recorder
│       ├── jira_adapter.py                 # CODEOWNERS router, Jira field mapper & 429 retry sync
│       └── publishers.py                   # FR-5.1 gated exporter (VEX, CSAF, CVE, Jira, Audit)
└── tests/
    ├── fixtures/                           # Vulnerable Python & Go sample apps + CODEOWNERS + secrets
    ├── test_intake_and_sanitizer.py
    ├── test_mcp_servers.py
    ├── test_scanners_and_mcp_protocol.py
    ├── test_adversarial_and_llm.py
    ├── test_guardrails.py
    ├── test_cli_and_audit.py
    ├── test_graph_hitl_e2e.py
    ├── test_go_e2e_and_harnesses.py
    └── test_psirt_enterprise_features.py
```

---

## 2. Four-Layer Zero-Trust Architecture & State Machine

`psirt-agent-engine` enforces strict **Zero-Trust Separation of Duties** via a persistent LangGraph state machine (`src/psirt_engine/graph.py`) backed by SQLite (`langgraph-checkpoint-sqlite`):

| State | Execution Mode | Responsibility | Exit / Transition Rule |
|---|---|---|---|
| `1_SCAN_AND_SANITIZE` | Deterministic (Zero LLM) | Runs SBOM, CVE, SAST, and secret scanners; redacts secrets/PII; scans repo for prompt injections; deduplicates into `TriageCase[]`. | `cases > 0` → `2_AGENT_TRIAGE`; else `END`. |
| `2_AGENT_TRIAGE` | Autonomous (Read-Only MCP) | Resolves `CODEOWNERS`; maps CWE, CVSS v4.0, KEV/EPSS, ATT&CK; runs Tree-sitter AST VEX reachability; evaluates CNA assignment rules. | Any `affected` case → `3_REMEDIATE`; all `not_affected` → `4_DRAFT_ARTIFACTS`. |
| `3_REMEDIATE` | Autonomous (Read-Only MCP) | Drafts Track A (patch diff / version bump w/ breaking-change risk), Track B (WAF/config/ACL workarounds), and `pytest` reproducer for `affected` cases. | Transitions to `4_DRAFT_ARTIFACTS`. |
| `4_DRAFT_ARTIFACTS` | Structured Synthesis | Re-evaluates CNA rules (post-override safe) and drafts OpenVEX v0.2.0, CSAF 2.0 (`csaf_vex` & `csaf_security_advisory`), CVE JSON 5.1 (only when CNA-approved), and `ADVISORY.md`. | Transitions to `5_GUARDRAIL_CHECK`. |
| `5_GUARDRAIL_CHECK` | Deterministic (8 Gates) | Validates schemas, CSAF profile rules, SBOM alignment, CVSS v4.0 math, `fixed > affected`, CNA policy, public prose hygiene, and secret leaks. | **Pass** → `human_review` (**HALTS**). **Fail** → loops back to `4_DRAFT_ARTIFACTS` (max `2` retries), then flags `needs_manual_triage = True` and halts at `human_review`. |
| `6_AWAITING_HUMAN_REVIEW` | **HALTED (HITL Interrupt)** | Graph compiles with `interrupt_before=["human_review"]`. Execution halts completely until a human reviews via `review` TUI or `approve`. | **Override** (`recheck_requested=True`) → re-runs `4_DRAFT_ARTIFACTS` → `5_GUARDRAIL_CHECK`. **Approve** → `7_PUBLISHED`. **Reject** → `END` (no export). |
| `7_PUBLISHED` | Deterministic Exporter | Verifies signed approval (FR-5.1), guardrail pass (FR-5.3), audit hash-chain integrity (FR-5.4), and zero leaks (NFR-2); writes final artifacts (`status: final`), `jira_tickets.json`, and `decision_audit.yaml`. | Terminal (`END`). |

---

## 3. Feature Deep-Dives

### 3.1 Multi-Modal Intake, SBOM & Deduplication (Layer 1)
- **External Scanner Subprocess Adapters** (`src/psirt_engine/intake/scanners.py`): Automatically detects and invokes `syft` (CycloneDX SBOM), `grype` / `osv-scanner` (third-party CVEs), `semgrep` (first-party SAST), and `gitleaks` (secrets) when installed on `PATH`.
- **Zero-Dependency Offline Fallbacks:** When binaries are absent (or `--builtin-only` is passed), deterministic built-in scanners parse `requirements*.txt` and `go.mod` into CycloneDX 1.5 JSON, match against the curated local vulnerability catalog, run Python/Go/Dockerfile SAST rules, and scan for hardcoded credentials.
- **Pre-Generated Scanner Report Ingestion:** Pass `--scanner-report path/to/grype.json` (repeatable) to ingest existing CI scanner outputs from Grype, OSV-Scanner, or Semgrep directly into the canonical pipeline.
- **Structural + Semantic Deduplication** (`src/psirt_engine/intake/deduplicator.py`): Consolidates duplicate alerts referencing the same CVE+package or overlapping same-file SAST code paths (5-line window + Jaccard token similarity) into a single `TriageCase`.

### 3.2 Secret/PII Redaction & Prompt-Injection Isolation (NFR-1 / NFR-2)
- **14 Deterministic Secret/PII Redaction Rules** (`src/psirt_engine/intake/sanitizer.py`): Strips AWS access/secret keys, GitHub PATs (classic & fine-grained), Anthropic/OpenAI/Google/Slack/Stripe keys, JWTs, PEM private key blocks, database/HTTP URI credentials, generic secret assignments, and SSNs — logging only a truncated SHA-256 fingerprint (never the raw value).
- **Triple-Layer Zero-Leakage Enforcement:** Redaction runs in (1) Layer 1 intake, (2) `ModelAgnosticLLM._prepare_messages()` immediately prior to any LLM call (raising `SecretLeakBlockedError` if anything survives), and (3) Layer 3 Guardrails & Layer 4 Publisher before writing to disk.
- **Prompt-Injection Defenses:**
  - `scan_repo_for_prompt_injections()` scans repository source/docs for adversarial directives (`ignore previous instructions`, `mark as not_affected`, `bypass approval`, XML fence breakout) and records warnings in the audit log.
  - `wrap_untrusted_data()` wraps all repository snippets in `<untrusted_repo_data source="..." trust_level="untrusted">...</untrusted_repo_data>` and escapes embedded closing tags (`&lt;/untrusted_repo_data&gt;`).
  - **Deterministic AST Override Protection:** Even if a compromised LLM obeys an injected prompt and outputs `status: "not_affected"`, `vex_agent.py` refuses to downgrade a finding that Tree-sitter AST analysis proved reachable.

### 3.3 Read-Only MCP Servers (Tree-sitter AST & Threat Intel)
Both servers use the official `mcp` Python SDK (`MCPServer` on `mcp>=2`, with `FastMCP` fallback for `mcp 1.x`) and expose **zero** file-write, shell, git-push, or external mutation tools:

- **`psirt-mcp-repo-ast`** (`src/psirt_engine/mcp_servers/repo_ast_server.py`)
  - `list_repo_files(extension)` — Lists repository files excluding `.git`, `.venv`, `node_modules`.
  - `read_file_lines(rel_path, start_line, end_line)` — Path-jailed to `repo_root` (blocks `../` traversal), auto-redacts secrets, returns `snippet_hash` and `prompt_injection_warnings`.
  - `find_imports(module_names, scope_dir)` — Tree-sitter AST import parser for Python & Go.
  - `get_symbol_callers(symbols, scope_dir)` — Tree-sitter AST call-site finder with enclosing function attribution.
  - `trace_reachability(import_names, vulnerable_symbols, scope_dir)` — Traces 2-hop call paths scoped to the manifest's subdirectory in monorepos (preventing cross-service false attribution).
  - `git_blame(rel_path, start_line, end_line)` — Commit/author attribution.
- **`psirt-mcp-vuln-intel`** (`src/psirt_engine/mcp_servers/vuln_intel_server.py`)
  - `lookup_cwe(cwe_id)` — MITRE CWE metadata & default CVSS v4.0 baseline.
  - `lookup_attack(technique_id)` / `get_attack_mappings_for_cwe(cwe_id)` — MITRE ATT&CK tactics, impact, and detection/hunting opportunities.
  - `lookup_kev_epss(cve_id)` — CISA KEV membership & FIRST EPSS exploitation probability.
  - `list_vex_justifications()` — Official OpenVEX / CSAF 2.0 `not_affected` justification taxonomy.
  - `lookup_osv_advisory(vuln_id)` — Offline-safe OSV lookup (enables live HTTPS queries only when `PSIRT_ALLOW_ONLINE_INTEL=1`).

### 3.4 CVE Program CNA Assignment Rules Engine
Implemented in `src/psirt_engine/agents/cna_rules.py` per CVE Program CNA Rules Section 7:

| Condition | Deployment Mode | `CNADecision` | Outputs Generated |
|---|---|---|---|
| `vex.status == not_affected` | Any | `no_cve_not_affected` | OpenVEX + CSAF VEX (`not_affected`) |
| Third-party dependency CVE | Any | `reference_upstream_cve` | OpenVEX + CSAF VEX + CSAF Advisory + `ADVISORY.md` (no duplicate CVE 5.1) |
| Hardcoded repo secret | Any | `no_cve_secret_hygiene` | Rotation remediation + OpenVEX/CSAF (no CVE unless universal backdoor) |
| First-party `affected` SAST/IaC | `saas` | `no_cve_saas_excluded` | Remediation + CSAF/VEX + `ADVISORY.md` (excluded from CVE issuance per CNA SaaS rule) |
| First-party `affected` SAST/IaC | `on_prem` or `hybrid` | `assign_new_cve` | Full bundle **including schema-valid CVE JSON 5.1 CNA record** (split by independent root cause) |

### 3.5 CISA KEV, FIRST EPSS & Environmental CVSS v4.0
- **Environmental CVSS v4.0** (`src/psirt_engine/guardrails/cvss_math.py`, `triage_agent.py`): Inspects surrounding route/auth decorators (e.g., `@login_required`, `@require_auth`, `verify_jwt`) to adjust environmental metrics (such as `MPR:L`), recomputes the exact numeric score deterministically via the `cvss` library (`CVSS4`), and reports the delta from the NVD base score.
- **KEV & EPSS Priority Tiers:** Flags actively exploited vulnerabilities (`CVE-2023-44487`, etc.) as `emergency_kev`, high-probability CVEs (`EPSS >= 0.50`) as `elevated_epss`, and others as `standard`.

### 3.6 Tiered Remediation (Track A, Track B & Verification Harnesses)
For every confirmed `affected` case, `remediation_agent.py` generates:
- **Track A (Primary Fix):** Targeted dependency version bump (explicitly flagging `high` breaking-change risk on major version jumps) or minimal unified code patch diff (`remediation_track_a.diff`).
- **Track B (Compensating Controls):** Immediate WAF/ModSecurity rules, Kubernetes `securityContext` hardening, input validation allowlists, or credential revocation commands for deployments waiting on maintenance windows.
- **Verification Harness:** Runnable self-contained `pytest` script (`test_repro_*.py`) demonstrating vulnerable vs. remediated behavior.

### 3.7 Standards-Compliant PSIRT Disclosure Artifacts
All JSON artifacts are validated against vendored Draft 2020-12 JSON Schemas in `schemas/`:
- **OpenVEX v0.2.0** (`*.vex.json` + merged `bundle.vex.json`)
- **OASIS CSAF 2.0 `csaf_vex` & `csaf_security_advisory`** (`*.csaf-vex.json`, `*.csaf.json` — automatically transitioned from `tracking.status: "draft"` to `"final"` upon signed human approval)
- **CVE JSON 5.1 CNA Container** (`*.cve5.json` — includes native `cvssV4_0` metric breakdown, `problemTypes` CWE, `solutions`, `workarounds`, and `references`)
- **Customer-Facing Markdown Security Bulletin** (`ADVISORY.md`)

### 3.8 Deterministic Guardrails (8 Validation Gates)
Before any case reaches `6_AWAITING_HUMAN_REVIEW`, `src/psirt_engine/guardrails/consistency.py` enforces:
1. **Official JSON Schema Compliance** (`jsonschema` Draft 2020-12 + `FormatChecker`)
2. **OASIS CSAF 2.0 Profile Rules** (referential integrity of all `product_id`s against `product_tree`; mandatory `flags`/`threats` on `known_not_affected`; mandatory `remediations` on `known_affected`)
3. **CVSS v4.0 Math Verification** (rejects LLM-hallucinated scores or mismatched qualitative severities)
4. **SBOM Version & PURL Consistency** (blocks hallucinated package versions not present in the repository SBOM)
5. **Cross-Artifact Consistency** (verifies CVE ID, CWE ID, VEX status, and CVSS vector match identically across canonical state, OpenVEX, CSAF 2.0, and CVE JSON 5.1)
6. **Logical Version Ordering** (verifies `fixed_version > package_version` on affected dependency upgrades)
7. **CNA Policy Compliance** (ensures CVE JSON 5.1 is never emitted when `cna.decision != assign_new_cve`)
8. **Public Prose Hygiene & Zero-Leakage Secret Scan** (blocks internal Jira URLs, `.corp`/`.internal` hostnames, `localhost`, `/tmp/`/`/home/` paths, and any unredacted credentials)

### 3.9 Jira Schema-Drift Adapter & CODEOWNERS Auto-Routing
- `resolve_codeowner()` parses `.github/CODEOWNERS` or `CODEOWNERS` using GitHub's last-match-wins semantics.
- `config/jira_mapping.yaml` isolates per-division Jira `project_key`, `issue_type`, and custom-field IDs (`customfield_*`) from canonical business logic.
- `build_jira_ticket_payload()` attaches a deterministic **idempotency key** (`psirt-idem-<sha256>`) so retries never create duplicate Jira tickets.
- Approved bundles include `jira_tickets.json` (dry-run ready). Set `JIRA_BASE_URL` and `JIRA_API_TOKEN` and call `sync_jira_ticket(..., dry_run=False)` for live Jira REST API v3 sync with exponential backoff + jitter on HTTP `429`/`5xx`.

### 3.10 Immutable Hash-Chained Audit Log & HITL Gate
- Every event (Layer 1 scan, agent traces, guardrail checks, human overrides, reviewer sign-offs with SHA-256 artifact hashes, and publication) is chained via `entry_hash = SHA256(prev_hash + canonical_payload)` in `decision_audit.yaml` and `decision_audit.json`.
- `publish_approved_bundle()` raises `ApprovalGateViolationError` if:
  - Any case lacks explicit human sign-off (**FR-5.1**),
  - Any case failed deterministic guardrails (**FR-5.3**),
  - The audit log hash chain was tampered with (**FR-5.4**), or
  - Any secret is detected in the output (**NFR-2**).

---

## 4. Complete Setup & Configuration Guide

### 4.1 Prerequisites & Installation
- **Python 3.11+** (tested on Python 3.12)
- **`uv`** (recommended) or `pip`
- **Git** (optional for non-git folders, used for commit SHA & `git blame`)

```bash
git clone https://github.com/YeshwanthUdayshankar/psirt-agent-engine.git
cd psirt-agent-engine
uv venv --python 3.12
source .venv/bin/activate
uv pip install -e ".[dev]"
```

Verify installation:

```bash
psirt-engine --help
pytest -v
```

### 4.2 Installing Optional External Scanners
To run live Anchore Syft, Grype, Google OSV-Scanner, Semgrep Community Edition, Gitleaks, and OpenVEX `vexctl`:

```bash
bash scripts/install-tools.sh
export PATH="$HOME/.local/bin:$PATH"
```

Verify available scanners:

```bash
for b in syft grype osv-scanner semgrep gitleaks vexctl; do
  printf "%-15s %s\n" "$b" "$(command -v "$b" || echo 'fallback-builtin')"
done
```

### 4.3 Configuring LLM Providers (Ollama, vLLM, Anthropic/OpenAI ZDR, Offline)
Edit [`config/models.yaml`](../config/models.yaml) or set `PSIRT_LLM_PROFILE`:

| Profile | Provider | Privacy / ZDR | Notes |
|---|---|---|---|
| `ollama_local` *(default)* | Local Ollama (`http://127.0.0.1:11434`) | 100% Local | Auto-falls back to deterministic heuristic if Ollama isn't running |
| `vllm_local` | Self-hosted vLLM (`http://127.0.0.1:8000/v1`) | 100% Local | Optional `VLLM_API_KEY` env var |
| `anthropic_zdr` | Anthropic Messages API | Enterprise ZDR | Requires `ANTHROPIC_API_KEY`; `fallback_to_heuristic: false` |
| `openai_zdr` | OpenAI-compatible API | Enterprise ZDR | Requires `OPENAI_API_KEY`; `fallback_to_heuristic: false` |
| `offline_heuristic` | Deterministic offline engine | Air-gapped | Zero network calls; ideal for CI & unit tests |

**Running with local Ollama:**

```bash
ollama serve
ollama pull qwen2.5-coder:14b
psirt-engine scan /path/to/repo --profile ollama_local
```

**Running with Anthropic ZDR API:**

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
psirt-engine scan /path/to/repo --profile anthropic_zdr
```

### 4.4 Configuring Your Organization CNA Profile
Edit [`config/cna_profile.yaml`](../config/cna_profile.yaml) before generating production advisories:
- `organization.name` & `organization.short_name`: Your PSIRT/CNA identity.
- `organization.cna_org_id`: Your assigned RFC 4122 MITRE CNA UUID.
- `organization.namespace` & `advisory_base_url`: Official HTTPS advisory origin.
- `advisory_id_prefix`: Bulletin identifier prefix (e.g., `HPSB`, `EXSA`).
- `governance.max_guardrail_retries`: Default `2` before flagging `needs_manual_triage`.

### 4.5 Configuring Jira Schema-Drift Mappings & CODEOWNERS
Edit [`config/jira_mapping.yaml`](../config/jira_mapping.yaml):
- Set `default_project` for unmapped repositories.
- Add entries under `team_overrides` keyed by `@team-handle` from each repo's `.github/CODEOWNERS` to map division-specific `project_key`, `issue_type`, and `customfield_*` IDs without changing any Python code.

---

## 5. CLI Reference & Workflows

| Command | Description |
|---|---|
| `psirt-engine scan <repo>` | Runs Layers 1–3, checkpoints state in SQLite, and **halts** at `human_review`. |
| `psirt-engine triage <repo>` | Alias for `scan` focused on local interactive triage. |
| `psirt-engine status` | Displays checkpointed run stage, HITL gate status, and case summary (`--json` for CI). |
| `psirt-engine review --reviewer <id>` | Launches interactive Rich TUI: inspect citations/diffs, `approve`, `override` VEX (auto-retriggers guardrails), or `reject`. |
| `psirt-engine approve --reviewer <id>` | Non-interactive signed human approval (use `--export` to immediately publish). |
| `psirt-engine export` | Resumes an approved checkpoint to write the final bundle (exits `2` if unapproved). |

**Common Flags on `scan`:**
- `--profile, -p`: LLM profile from `config/models.yaml` (default `ollama_local`)
- `--deployment-mode, -d`: `on_prem` | `hybrid` | `saas` (default `on_prem`)
- `--state-dir`: Directory for SQLite checkpoint DB (default `.psirt-state`)
- `--output-dir, -o`: Directory for published disclosure bundle (default `./psirt-output`)
- `--run-id`: Explicit checkpoint thread ID (defaults to random `run-<hex>`)
- `--scanner-report`: Path to pre-generated Grype / OSV-Scanner / Semgrep JSON (repeatable)
- `--pr-comment-out`: Write Markdown HITL review summary for GitHub PRs
- `--builtin-only`: Skip external scanner binaries and run built-in deterministic scanners

**Environment Variables:**
- `PSIRT_LLM_PROFILE` — Overrides `default_profile` in `config/models.yaml`
- `PSIRT_ENGINE_HOME` — Overrides location of `config/` and `schemas/`
- `PSIRT_TARGET_REPO` — Target repository path for `psirt-mcp-repo-ast`
- `PSIRT_ALLOW_ONLINE_INTEL=1` — Enables optional read-only live OSV / FIRST EPSS API lookups
- `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `VLLM_API_KEY` — Provider tokens
- `JIRA_BASE_URL`, `JIRA_API_TOKEN` — Optional live Jira REST API v3 sync

---

## 6. GitHub Actions CI/CD & HITL Environment Setup

Two workflows ship in `.github/workflows/`:

1. **[`ci.yml`](../.github/workflows/ci.yml):** Runs on every push/PR to `main` — executes `ruff check src tests scripts`, `pytest -v`, and `python scripts/run_eval.py`.
2. **[`psirt-triage.yml`](../.github/workflows/psirt-triage.yml):** Two-job HITL disclosure pipeline:
   - **Job 1 (`psirt-triage-and-guardrails`):** Scans the repo, runs Layers 1–3, halts at `6_AWAITING_HUMAN_REVIEW`, uploads `.psirt-state/` as an artifact, and posts the HITL summary table to the PR.
   - **Job 2 (`psirt-hitl-approve-and-publish`):** Bound to GitHub Environment `psirt-disclosure-approval`. Execution pauses until a required PSIRT reviewer approves in GitHub UI, then downloads the checkpoint, records the reviewer's `github.actor` sign-off, and uploads the validated `psirt-output/` disclosure bundle.

**Enabling the HITL gate in your GitHub repo:**
1. Go to **Settings → Environments → New environment**.
2. Name it `psirt-disclosure-approval`.
3. Enable **Required reviewers** and add your PSIRT leads.
4. Save protection rules.

---

## 7. Testing & Golden-Dataset Evaluation Benchmark

```bash
# Lint across source, tests, and scripts
ruff check src tests scripts

# Full unit + integration + MCP protocol + CLI + E2E test suite (35 tests)
pytest -v

# Golden-dataset accuracy & guardrail benchmark
python scripts/run_eval.py
```

To add new benchmark cases, edit [`eval/golden_dataset.yaml`](../eval/golden_dataset.yaml) with expected `expected_cwe`, `expected_vex_status`, `expected_cna_decision`, and `expected_kev` labels. `scripts/run_eval.py` exits non-zero in CI if schema pass rate drops below `100%`, any secret leaks, or VEX/CWE/CNA accuracy regresses.

---

## 8. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `psirt-engine export` exits with code `2` (`FR-5.1`) | Checkpoint has not been signed off by a human reviewer | Run `psirt-engine review --reviewer <handle>` or `psirt-engine approve --reviewer <handle> --export` |
| `ollama_local` falls back to heuristic | Local Ollama daemon is not running or model not pulled | Run `ollama serve` and `ollama pull qwen2.5-coder:14b`, or pass `--profile offline_heuristic` |
| Guardrail fails with `public_prose_hygiene` | Internal URL (`jira.internal`, `localhost`) or `/tmp/` path appeared in advisory prose | Remove internal URL/path from overridden notes or `cna_profile.yaml` and re-run guardrails |
| Guardrail fails with `cna_policy` | `cve_json_5_1` attached to a `saas` or third-party case | Let `node_draft_artifacts` re-evaluate CNA rules or verify `--deployment-mode` |
| `CODEOWNERS` routes to wrong team | GitHub `CODEOWNERS` uses **last-match-wins** ordering | Place catch-all `* @default-team` at the top of `CODEOWNERS` and specific paths below it |
