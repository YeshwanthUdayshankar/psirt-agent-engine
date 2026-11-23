"""VEX Reachability Agent: Tree-sitter AST call-graph reachability -> OpenVEX status & justification."""

from __future__ import annotations

from pathlib import Path

from psirt_engine.agents.prompts import VEX_SYSTEM_PROMPT
from psirt_engine.intake.sanitizer import wrap_untrusted_data
from psirt_engine.llm import ModelAgnosticLLM
from psirt_engine.mcp_servers.repo_ast_server import RepoASTService
from psirt_engine.models.canonical import (
    EvidenceCitation,
    FindingCategory,
    TriageCase,
    VEXDetermination,
    VEXJustification,
    VEXStatus,
)


def run_vex_agent(
    case: TriageCase,
    ast_service: RepoASTService,
    llm: ModelAgnosticLLM,
) -> TriageCase:
    """Determine VEX reachability using strictly read-only Tree-sitter AST analysis."""
    primary = case.findings[0]

    # First-party SAST, Secrets, and IaC findings exist directly in repository source/config.
    if case.category != FindingCategory.THIRD_PARTY_CVE:
        citations: list[EvidenceCitation] = []
        if primary.file_path:
            snippet_hash = None
            try:
                read = ast_service.read_file_lines(
                    primary.file_path,
                    start_line=max(1, (primary.line_start or 1) - 1),
                    end_line=(primary.line_end or 1) + 1,
                )
                snippet_hash = read["snippet_hash"]
            except OSError:
                snippet_hash = None
            citations.append(
                EvidenceCitation(
                    file_path=primary.file_path,
                    line_start=primary.line_start or 1,
                    line_end=primary.line_end or primary.line_start or 1,
                    symbol=primary.symbol,
                    commit_sha=primary.commit_sha,
                    snippet_hash=snippet_hash,
                    note=f"Confirmed in first-party file via {primary.scanner_source}",
                )
            )
        case.vex = VEXDetermination(
            status=VEXStatus.AFFECTED,
            justification=None,
            impact_statement=(
                f"First-party {case.cwe_id or 'vulnerability'} directly present in "
                f"{primary.file_path or 'repository'} (line {primary.line_start or 1})."
            ),
            action_statement=(
                f"Apply Track A patch in {primary.file_path or 'affected source file'} "
                f"and deploy Track B compensating controls immediately."
            ),
            reachable=True,
            call_path=[f"{primary.file_path}:{primary.line_start or 1}:{primary.symbol or 'vuln'}"],
            confidence=0.92,
            citations=citations,
        )
        case.agent_traces.append(
            {
                "agent": "vex_agent",
                "mode": "first_party_direct",
                "status": "affected",
                "reachable": True,
            }
        )
        return case

    # Third-party CVE: run deterministic Tree-sitter AST import & call-graph analysis!
    import_names = list(primary.metadata.get("import_names") or [])
    if case.package_name and case.package_name not in import_names:
        import_names.append(case.package_name)
    vuln_symbols = list(primary.vulnerable_symbols or [])

    # Scope reachability to the sub-service directory when manifest lives in a monorepo subdir
    scope_dir: str | None = None
    if primary.file_path:
        parent = str(Path(primary.file_path).parent)
        if parent and parent != ".":
            scope_dir = parent

    trace = ast_service.trace_reachability(import_names, vuln_symbols, scope_dir=scope_dir)
    citations = []

    if trace["reachable"]:
        status = VEXStatus.AFFECTED
        justification = None
        for caller in trace["callers"][:5]:
            citations.append(
                EvidenceCitation(
                    file_path=caller["file_path"],
                    line_start=caller["line_start"],
                    line_end=caller["line_end"],
                    symbol=caller["symbol"],
                    commit_sha=primary.commit_sha,
                    snippet_hash=caller["snippet_hash"],
                    note=f"Vulnerable symbol '{caller['symbol']}' invoked in {caller.get('enclosing_function') or '<module>'}",
                )
            )
        impact = (
            f"Confirmed reachable: package {case.package_name}@{case.package_version} is imported "
            f"and vulnerable symbol(s) {[c['symbol'] for c in trace['callers'][:3]]} are invoked "
            f"at {citations[0].file_path}:{citations[0].line_start}."
        )
        upgrade_target = case.fixed_version or "latest patched release"
        action = (
            f"Upgrade {case.package_name} from {case.package_version} to >= {upgrade_target} "
            f"or apply Track B compensating controls."
        )
        conf = 0.94
    elif trace["imported"] and not trace["symbol_invoked"] and vuln_symbols:
        status = VEXStatus.NOT_AFFECTED
        justification = VEXJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH
        for imp in trace["imports"][:3]:
            citations.append(
                EvidenceCitation(
                    file_path=imp["file_path"],
                    line_start=imp["line_start"],
                    line_end=imp["line_end"],
                    symbol=imp["import_text"],
                    commit_sha=primary.commit_sha,
                    note=(
                        f"Module imported, but Tree-sitter AST scan found 0 invocations of "
                        f"vulnerable symbols {vuln_symbols}."
                    ),
                )
            )
        impact = (
            f"Package {case.package_name}@{case.package_version} is imported in "
            f"{citations[0].file_path}:{citations[0].line_start}, but none of the vulnerable "
            f"functions ({', '.join(vuln_symbols)}) are invoked anywhere in the repository AST."
        )
        action = ""
        conf = 0.89
    elif not trace["imported"]:
        status = VEXStatus.NOT_AFFECTED
        justification = VEXJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH
        manifest = primary.file_path or "SBOM"
        citations.append(
            EvidenceCitation(
                file_path=manifest,
                line_start=1,
                line_end=1,
                symbol=f"{case.package_name}=={case.package_version}",
                commit_sha=primary.commit_sha,
                note=(
                    f"Declared in {manifest}, but Tree-sitter AST scan across "
                    f"{len(ast_service.list_repo_files())} repository files found 0 imports "
                    f"of {import_names} and 0 calls to {vuln_symbols or ['<any>']}."
                ),
            )
        )
        impact = (
            f"Transitive/unused dependency {case.package_name}@{case.package_version} is present "
            f"in {manifest} but is never imported or called in any first-party execution path."
        )
        action = ""
        conf = 0.93
    else:
        # Imported, and no specific vulnerable symbol list was provided by scanner -> conservative affected/investigate
        status = VEXStatus.UNDER_INVESTIGATION
        justification = None
        for imp in trace["imports"][:3]:
            citations.append(
                EvidenceCitation(
                    file_path=imp["file_path"],
                    line_start=imp["line_start"],
                    line_end=imp["line_end"],
                    symbol=imp["import_text"],
                    commit_sha=primary.commit_sha,
                    note="Package imported; symbol-level call graph requires PSIRT review.",
                )
            )
        impact = (
            f"Package {case.package_name}@{case.package_version} is imported, and no narrow "
            f"vulnerable symbol signature was available for automated exclusion."
        )
        action = f"Review usage of {case.package_name} or upgrade to >= {case.fixed_version or 'patched version'}."
        conf = 0.65

    fallback = {
        "status": status.value,
        "justification": justification.value if justification else None,
        "impact_statement": impact,
        "action_statement": action,
        "confidence": conf,
    }

    # Optional LLM narrative refinement — deterministic AST status cannot be downgraded by untrusted comments!
    user_prompt = (
        f"CVE: {case.primary_cve_id}\n"
        f"Package: {case.package_name}@{case.package_version}\n"
        f"Deterministic Tree-sitter AST Facts:\n"
        f"  imported={trace['imported']}, symbol_invoked={trace['symbol_invoked']}, "
        f"reachable={trace['reachable']}, call_path={trace['call_path']}\n"
        f"Untrusted finding context:\n"
        + wrap_untrusted_data(primary.description, primary.file_path or "scanner")
    )
    res = llm.complete_json(VEX_SYSTEM_PROMPT, user_prompt, fallback_data=fallback)
    parsed = res.parsed_json or fallback

    # Hard anti-injection guardrail: if deterministic AST proved reachability, NEVER allow LLM to mark not_affected!
    final_status = status
    final_justification = justification
    if not trace["reachable"] and parsed.get("status") in {s.value for s in VEXStatus}:
        # Only allow LLM to escalate to under_investigation/affected, never falsely clear a reachable path
        candidate_status = VEXStatus(parsed["status"])
        if candidate_status in (VEXStatus.AFFECTED, VEXStatus.UNDER_INVESTIGATION):
            final_status = candidate_status
            final_justification = None

    case.vex = VEXDetermination(
        status=final_status,
        justification=final_justification,
        impact_statement=str(parsed.get("impact_statement") or impact),
        action_statement=(
            str(parsed.get("action_statement") or action)
            if final_status == VEXStatus.AFFECTED
            else ""
        ),
        reachable=bool(trace["reachable"]),
        call_path=list(trace["call_path"]),
        confidence=max(0.0, min(1.0, float(parsed.get("confidence", conf)))),
        citations=citations,
    )
    case.citations.extend(citations)

    # Clear ATT&CK mappings if confirmed not_affected (FR-2.4 applies to confirmed affected findings)
    if final_status == VEXStatus.NOT_AFFECTED:
        case.attack_mappings = []

    case.agent_traces.append(
        {
            "agent": "vex_agent",
            "provider": res.provider,
            "model": res.model,
            "used_heuristic_fallback": res.used_heuristic_fallback,
            "ast_imported": trace["imported"],
            "ast_symbol_invoked": trace["symbol_invoked"],
            "vex_status": final_status.value,
            "vex_justification": final_justification.value if final_justification else None,
        }
    )
    return case
