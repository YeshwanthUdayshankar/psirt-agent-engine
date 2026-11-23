"""Triage & Scoring Agent: CWE root-cause mapping, environmental CVSS v4.0 scoring, and ATT&CK mapping."""

from __future__ import annotations

import re

from psirt_engine.agents.prompts import TRIAGE_SYSTEM_PROMPT
from psirt_engine.guardrails.cvss_math import calculate_cvss4
from psirt_engine.intake.sanitizer import wrap_untrusted_data
from psirt_engine.llm import ModelAgnosticLLM
from psirt_engine.mcp_servers.repo_ast_server import RepoASTService
from psirt_engine.mcp_servers.vuln_intel_server import VulnIntelService
from psirt_engine.models.canonical import (
    AttackMapping,
    CVSSv4Assessment,
    EvidenceCitation,
    FindingCategory,
    TriageCase,
)


def _infer_cwe_from_case(case: TriageCase) -> str:
    if case.cwe_id and re.match(r"^CWE-\d+$", case.cwe_id):
        return case.cwe_id
    for f in case.findings:
        if f.cwe_ids:
            return f.cwe_ids[0]
    text = f"{case.title} {' '.join(f.description for f in case.findings)}".lower()
    if "sql" in text:
        return "CWE-89"
    if "command" in text or "shell=true" in text or "exec.command" in text:
        return "CWE-78"
    if "yaml" in text or "pickle" in text or "deserializ" in text:
        return "CWE-502"
    if "xss" in text or "xmlattr" in text or "script" in text:
        return "CWE-79"
    if "secret" in text or "credential" in text or "token" in text or "api_key" in text:
        return "CWE-798"
    if "root" in text and "container" in text:
        return "CWE-250"
    if "redirect" in text or "header" in text:
        return "CWE-200"
    return "CWE-200"


def _inspect_environmental_context(
    case: TriageCase, ast_service: RepoASTService
) -> tuple[str, bool, bool]:
    """Read-only inspection of auth guards and network exposure around the finding."""
    primary = case.findings[0] if case.findings else None
    snippet = primary.code_snippet or ""
    if primary and primary.file_path:
        try:
            read = ast_service.read_file_lines(
                primary.file_path,
                start_line=max(1, (primary.line_start or 1) - 15),
                end_line=(primary.line_end or 1) + 15,
            )
            snippet = read["content"]
        except OSError:
            snippet = primary.code_snippet or ""

    lower = snippet.lower()
    has_auth_guard = any(
        tok in lower
        for tok in ("@login_required", "@require_auth", "verify_jwt", "authenticate(", "requireadmin")
    )
    is_network_exposed = any(
        tok in lower
        for tok in ("@app.route", "@router.", "http.handlefunc", "flask", "fastapi", "request.args", "r.url.query")
    )
    return snippet, has_auth_guard, is_network_exposed


def _adjust_environmental_cvss4(
    base_vector: str, has_auth_guard: bool, is_network_exposed: bool, category: FindingCategory
) -> tuple[str, str]:
    """Propose an environmental CVSS v4.0 vector reflecting repository auth/exposure context."""
    vec = base_vector
    reasons: list[str] = []
    if has_auth_guard and "/PR:N/" in vec:
        # In CVSS v4.0 environmental metrics, MPR:L reflects required low-privilege authentication.
        vec = f"{vec}/MPR:L"
        reasons.append("Route/handler enforces authentication middleware (MPR:L), reducing unauthenticated exposure.")
    elif is_network_exposed:
        reasons.append("Code path is directly exposed on an HTTP/network handler without inline auth guards (AV:N/PR:N).")
    elif category == FindingCategory.SECRET:
        reasons.append("Hardcoded credential in repository source grants direct unauthorized access if repo is exposed.")
    elif category == FindingCategory.IAC:
        reasons.append("Container privilege configuration applies locally upon workload compromise (AV:L).")
    else:
        reasons.append("Evaluated using repository runtime exposure and privilege boundary context.")
    return vec, " ".join(reasons)


def run_triage_agent(
    case: TriageCase,
    ast_service: RepoASTService,
    intel_service: VulnIntelService,
    llm: ModelAgnosticLLM,
) -> TriageCase:
    """Populate CWE root cause, environmental CVSS v4.0 assessment, and ATT&CK mappings."""
    primary = case.findings[0]
    inferred_cwe = _infer_cwe_from_case(case)
    cwe_info = intel_service.lookup_cwe(inferred_cwe)

    code_ctx, has_auth, is_exposed = _inspect_environmental_context(case, ast_service)
    raw_base_vec = (
        primary.raw_cvss_vector
        if primary.raw_cvss_vector and primary.raw_cvss_vector.startswith("CVSS:4.0/")
        else cwe_info["default_cvss4_vector"]
    )
    proposed_vec, env_rationale = _adjust_environmental_cvss4(
        raw_base_vec, has_auth, is_exposed, case.category
    )

    fallback = {
        "cwe_id": cwe_info["id"],
        "cwe_rationale": (
            f"Root cause maps to {cwe_info['id']} ({cwe_info['name']}) based on "
            f"{primary.scanner_source} evidence in {primary.file_path or case.package_name}."
        ),
        "cvss_v4_vector": proposed_vec,
        "environmental_rationale": env_rationale,
        "confidence": 0.88 if primary.cwe_ids else 0.78,
    }

    user_prompt = (
        f"Case ID: {case.case_id}\n"
        f"Category: {case.category.value}\n"
        f"Package: {case.package_name or 'first-party'}@{case.package_version or 'HEAD'}\n"
        f"CVE: {case.primary_cve_id or 'N/A'}\n"
        f"Candidate CWE: {cwe_info['id']} ({cwe_info['name']})\n"
        f"Baseline CVSS v4.0: {proposed_vec}\n"
        f"Finding Summary:\n"
        + wrap_untrusted_data(f"{case.title}\n{primary.description}", "scanner_finding")
        + "\nCode Context:\n"
        + wrap_untrusted_data(code_ctx or "(no code snippet)", primary.file_path or "repo")
    )

    result = llm.complete_json(TRIAGE_SYSTEM_PROMPT, user_prompt, fallback_data=fallback)
    data = result.parsed_json or fallback

    # Validate CWE format deterministically
    cwe_id = str(data.get("cwe_id") or inferred_cwe).upper().strip()
    if not re.match(r"^CWE-[1-9]\d{0,5}$", cwe_id):
        cwe_id = inferred_cwe
    cwe_meta = intel_service.lookup_cwe(cwe_id)

    # Validate CVSS v4.0 vector deterministically via cvss library (never trust LLM math!)
    candidate_vec = str(data.get("cvss_v4_vector") or proposed_vec).strip()
    try:
        calc = calculate_cvss4(candidate_vec)
    except ValueError:
        calc = calculate_cvss4(proposed_vec)

    base_score_ref = primary.raw_cvss_score
    if base_score_ref is None:
        base_score_ref = calculate_cvss4(raw_base_vec).score
    delta = round(calc.score - float(base_score_ref), 1)

    case.cwe_id = cwe_meta["id"]
    case.cwe_name = cwe_meta["name"]
    case.cwe_rationale = str(data.get("cwe_rationale") or fallback["cwe_rationale"])
    case.cvss_v4 = CVSSv4Assessment(
        vector_string=calc.vector_string,
        score=calc.score,
        severity=calc.severity,
        base_score_from_nvd=round(float(base_score_ref), 1),
        delta_from_base=delta,
        environmental_rationale=str(
            data.get("environmental_rationale") or fallback["environmental_rationale"]
        ),
    )

    # Attach ATT&CK mappings from read-only vulnerability intel
    raw_attacks = intel_service.get_attack_mappings_for_cwe(cwe_meta["id"])
    case.attack_mappings = [AttackMapping.model_validate(a) for a in raw_attacks]

    # Attach verifiable citation
    if primary.file_path:
        case.citations.append(
            EvidenceCitation(
                file_path=primary.file_path,
                line_start=primary.line_start or 1,
                line_end=primary.line_end or primary.line_start or 1,
                symbol=primary.symbol,
                commit_sha=primary.commit_sha,
                note=f"Primary {primary.scanner_source} finding location",
            )
        )

    conf = float(data.get("confidence", fallback["confidence"]))
    case.confidence = max(0.0, min(1.0, conf))
    case.agent_traces.append(
        {
            "agent": "triage_agent",
            "provider": result.provider,
            "model": result.model,
            "used_heuristic_fallback": result.used_heuristic_fallback,
            "cwe_id": case.cwe_id,
            "cvss_v4_score": case.cvss_v4.score,
            "cvss_delta": delta,
        }
    )
    return case
