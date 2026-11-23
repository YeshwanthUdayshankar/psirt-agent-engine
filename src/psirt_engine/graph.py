"""Main LangGraph HITL State Machine for the Agentic PSIRT & Vulnerability Response Engine.

State lifecycle:
  1_SCAN_AND_SANITIZE -> 2_AGENT_TRIAGE -> [affected -> 3_REMEDIATE | not_affected -> 4_DRAFT_ARTIFACTS]
  -> 5_GUARDRAIL_CHECK [fail & retries < 2 -> 4_DRAFT_ARTIFACTS]
  -> (HALT: interrupt_before=["human_review"]) -> 6_AWAITING_HUMAN_REVIEW
  -> [recheck_requested -> 4_DRAFT_ARTIFACTS | approved -> 7_PUBLISHED -> END]
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph

from psirt_engine.agents.advisory_agent import run_advisory_agent
from psirt_engine.agents.cna_rules import evaluate_cna_assignment
from psirt_engine.agents.remediation_agent import run_remediation_agent
from psirt_engine.agents.triage_agent import run_triage_agent
from psirt_engine.agents.vex_agent import run_vex_agent
from psirt_engine.config import load_cna_profile
from psirt_engine.guardrails.consistency import run_guardrails_for_case
from psirt_engine.hitl.jira_adapter import resolve_codeowner
from psirt_engine.hitl.publishers import publish_approved_bundle
from psirt_engine.intake.deduplicator import deduplicate_findings
from psirt_engine.intake.sanitizer import sanitize_findings, scan_repo_for_prompt_injections
from psirt_engine.intake.scanners import run_all_scanners
from psirt_engine.llm import ModelAgnosticLLM
from psirt_engine.mcp_servers.repo_ast_server import RepoASTService
from psirt_engine.mcp_servers.vuln_intel_server import VulnIntelService
from psirt_engine.models.audit import DecisionAuditLog
from psirt_engine.models.canonical import (
    DeploymentMode,
    FindingCategory,
    SBOMComponent,
    TriageCase,
    VEXStatus,
)
from psirt_engine.state import PSIRTGraphState


def _load_cases(state: PSIRTGraphState) -> list[TriageCase]:
    return [TriageCase.model_validate(c) for c in state.get("cases", [])]


def _dump_cases(cases: list[TriageCase]) -> list[dict[str, Any]]:
    return [c.model_dump(mode="json") for c in cases]


def _load_audit(state: PSIRTGraphState) -> DecisionAuditLog:
    if state.get("audit_log"):
        return DecisionAuditLog.model_validate(state["audit_log"])
    return DecisionAuditLog(
        run_id=state.get("run_id", "run-default"),
        repo_path=state.get("repo_path", "."),
        commit_sha=state.get("commit_sha", "HEAD"),
        model_profile=state.get("model_profile", "ollama_local"),
    )


def _compute_metrics(cases: list[TriageCase], raw_findings: int, redactions: int) -> dict[str, Any]:
    dep_cases = [c for c in cases if c.category == FindingCategory.THIRD_PARTY_CVE]
    dep_not_affected = [
        c for c in dep_cases if c.vex and c.vex.status == VEXStatus.NOT_AFFECTED
    ]
    noise_reduction = (
        (len(dep_not_affected) / len(dep_cases) * 100.0) if dep_cases else 0.0
    )
    checked = [c for c in cases if c.guardrail_report is not None]
    passed = [c for c in checked if c.guardrail_report and c.guardrail_report.passed]
    schema_pass_rate = (len(passed) / len(checked) * 100.0) if checked else 0.0
    return {
        "raw_findings_count": raw_findings,
        "consolidated_cases_count": len(cases),
        "dependency_cases_count": len(dep_cases),
        "dependency_not_affected_count": len(dep_not_affected),
        "noise_reduction_rate_pct": round(noise_reduction, 1),
        "schema_pass_rate_pct": round(schema_pass_rate, 1),
        "redactions_performed": redactions,
    }


def node_scan_and_sanitize(state: PSIRTGraphState) -> PSIRTGraphState:
    """State 1_SCAN_AND_SANITIZE (Deterministic, Zero LLM)."""
    repo_path = Path(state["repo_path"]).resolve()
    extra_reports = [Path(p) for p in state.get("extra_scanner_reports", [])]
    scan = run_all_scanners(
        repo_path,
        extra_scanner_reports=extra_reports,
        prefer_builtin=bool(state.get("prefer_builtin_scanners", False)),
    )
    sanitized_findings, redactions, finding_inj_warnings = sanitize_findings(scan.findings)
    repo_inj_warnings = scan_repo_for_prompt_injections(repo_path)
    inj_warnings = list(dict.fromkeys([*repo_inj_warnings, *finding_inj_warnings]))
    cases = deduplicate_findings(sanitized_findings)

    audit = DecisionAuditLog(
        run_id=state["run_id"],
        repo_path=str(repo_path),
        commit_sha=scan.commit_sha,
        model_profile=state.get("model_profile", "ollama_local"),
        sbom_sha256=scan.sbom_sha256,
        redactions_performed=redactions,
        prompt_injection_warnings=inj_warnings,
    )
    audit.append_event(
        actor="system:layer1_intake",
        action="scan_and_sanitize",
        summary=(
            f"Scanned {repo_path.name} ({scan.commit_sha[:12]}): {len(scan.findings)} raw findings "
            f"-> {len(cases)} consolidated cases; {redactions} secrets/PII redacted."
        ),
        details={
            "scanners_used": scan.scanners_used,
            "sbom_components": len(scan.components),
            "prompt_injection_warnings": len(inj_warnings),
        },
    )

    return {
        "current_stage": "1_SCAN_AND_SANITIZE",
        "commit_sha": scan.commit_sha,
        "sbom": scan.sbom,
        "sbom_sha256": scan.sbom_sha256,
        "sbom_components": [c.model_dump(mode="json") for c in scan.components],
        "raw_findings_count": len(scan.findings),
        "scanners_used": scan.scanners_used,
        "scanner_warnings": scan.scanner_warnings,
        "redactions_performed": redactions,
        "prompt_injection_warnings": inj_warnings,
        "cases": _dump_cases(cases),
        "guardrail_retry_count": 0,
        "guardrails_passed": False,
        "human_review_completed": False,
        "human_decision": "pending",
        "recheck_requested": False,
        "audit_log": audit.model_dump(mode="json"),
        "metrics": _compute_metrics(cases, len(scan.findings), redactions),
    }


def node_agent_triage(state: PSIRTGraphState) -> PSIRTGraphState:
    """State 2_AGENT_TRIAGE (Read-Only MCP AST + Vuln Intel)."""
    repo_path = Path(state["repo_path"]).resolve()
    ast_service = RepoASTService(repo_path)
    intel_service = VulnIntelService()
    llm = ModelAgnosticLLM(profile_name=state.get("model_profile"))
    dep_mode = DeploymentMode(state.get("deployment_mode") or "on_prem")

    cases = _load_cases(state)
    audit = _load_audit(state)
    updated: list[TriageCase] = []

    for case in cases:
        primary_file = case.findings[0].file_path if case.findings else None
        case.owning_team = resolve_codeowner(repo_path, primary_file)
        case = run_triage_agent(case, ast_service, intel_service, llm)
        case = run_vex_agent(case, ast_service, llm)
        case.cna = evaluate_cna_assignment(case, deployment_mode=dep_mode)
        updated.append(case)
        audit.append_event(
            actor="agent:triage_and_vex",
            action="case_triaged",
            case_id=case.case_id,
            summary=(
                f"{case.case_id}: {case.cwe_id}, CVSS v4.0 {case.cvss_v4.score if case.cvss_v4 else 'n/a'}, "
                f"VEX={case.vex.status.value if case.vex else 'unknown'}, "
                f"CNA={case.cna.decision.value}, owner={case.owning_team or 'unassigned'} (conf={case.confidence:.2f})"
            ),
            details={
                "cwe_id": case.cwe_id,
                "vex_status": case.vex.status.value if case.vex else None,
                "vex_justification": (
                    case.vex.justification.value if (case.vex and case.vex.justification) else None
                ),
                "reachable": case.vex.reachable if case.vex else False,
                "cna_decision": case.cna.decision.value,
                "owning_team": case.owning_team,
                "in_cisa_kev": case.threat_intel.in_cisa_kev if case.threat_intel else False,
            },
        )

    return {
        "current_stage": "2_AGENT_TRIAGE",
        "cases": _dump_cases(updated),
        "audit_log": audit.model_dump(mode="json"),
        "metrics": _compute_metrics(
            updated,
            state.get("raw_findings_count", 0),
            state.get("redactions_performed", 0),
        ),
    }


def node_remediate(state: PSIRTGraphState) -> PSIRTGraphState:
    """State 3_REMEDIATE (Track A fix + Track B compensating controls + pytest harness for affected cases)."""
    repo_path = Path(state["repo_path"]).resolve()
    ast_service = RepoASTService(repo_path)
    llm = ModelAgnosticLLM(profile_name=state.get("model_profile"))

    cases = _load_cases(state)
    audit = _load_audit(state)
    updated: list[TriageCase] = []

    for case in cases:
        if case.vex and case.vex.status == VEXStatus.AFFECTED:
            case = run_remediation_agent(case, ast_service, llm)
            audit.append_event(
                actor="agent:remediation",
                action="remediation_drafted",
                case_id=case.case_id,
                summary=(
                    f"{case.case_id}: Track A ({case.remediation.track_a.kind}, "
                    f"breaking_risk={case.remediation.track_a.breaking_change_risk}) + Track B + harness"
                ),
            )
        updated.append(case)

    return {
        "current_stage": "3_REMEDIATE",
        "cases": _dump_cases(updated),
        "audit_log": audit.model_dump(mode="json"),
    }


def node_draft_artifacts(state: PSIRTGraphState) -> PSIRTGraphState:
    """State 4_DRAFT_ARTIFACTS (OpenVEX, CSAF 2.0, CVE JSON 5.1, Markdown Advisory)."""
    repo_name = Path(state["repo_path"]).resolve().name
    dep_mode = DeploymentMode(state.get("deployment_mode") or "on_prem")
    cna = load_cna_profile()
    cases = _load_cases(state)
    audit = _load_audit(state)
    updated: list[TriageCase] = []

    for case in cases:
        # Re-evaluate CNA assignment rule cleanly (handles post-override VEX status transitions)
        case.cna = evaluate_cna_assignment(case, deployment_mode=dep_mode)
        feedback = (
            case.guardrail_report.issues
            if (case.guardrail_report and not case.guardrail_report.passed)
            else None
        )
        case = run_advisory_agent(case, cna, repo_name, guardrail_feedback=feedback)
        updated.append(case)
        audit.append_event(
            actor="agent:advisory",
            action="artifacts_drafted",
            case_id=case.case_id,
            summary=f"{case.case_id}: Drafted OpenVEX, CSAF 2.0, and advisory artifacts.",
        )

    return {
        "current_stage": "4_DRAFT_ARTIFACTS",
        "cases": _dump_cases(updated),
        "recheck_requested": False,
        "audit_log": audit.model_dump(mode="json"),
    }


def node_guardrail_check(state: PSIRTGraphState) -> PSIRTGraphState:
    """State 5_GUARDRAIL_CHECK (Deterministic Schema + SBOM + CVSS Math + Leak Gate)."""
    cna = load_cna_profile()
    max_retries = cna.governance.max_guardrail_retries
    retry_count = int(state.get("guardrail_retry_count", 0))
    sbom_components = [
        SBOMComponent.model_validate(c) for c in state.get("sbom_components", [])
    ]
    cases = _load_cases(state)
    audit = _load_audit(state)

    all_passed = True
    updated: list[TriageCase] = []
    for case in cases:
        report = run_guardrails_for_case(case, sbom_components, retry_count=retry_count)
        case.guardrail_report = report
        if not report.passed:
            all_passed = False
            if retry_count >= max_retries:
                case.needs_manual_triage = True
        else:
            case.needs_manual_triage = False
        updated.append(case)
        audit.append_event(
            actor="guardrail:deterministic",
            action="guardrail_check",
            case_id=case.case_id,
            summary=(
                f"{case.case_id}: {'PASS' if report.passed else 'FAIL'} "
                f"({len(report.issues)} issues, retry={retry_count})"
            ),
            details={"issues": [i.model_dump() for i in report.issues]},
        )

    next_retry = retry_count if all_passed else retry_count + 1
    metrics = _compute_metrics(
        updated,
        state.get("raw_findings_count", 0),
        state.get("redactions_performed", 0),
    )
    audit.metrics = metrics

    return {
        "current_stage": "5_GUARDRAIL_CHECK",
        "cases": _dump_cases(updated),
        "guardrail_retry_count": next_retry,
        "guardrails_passed": all_passed,
        "audit_log": audit.model_dump(mode="json"),
        "metrics": metrics,
    }


def node_human_review(state: PSIRTGraphState) -> PSIRTGraphState:
    """State 6_AWAITING_HUMAN_REVIEW (Executed ONLY after interrupt_before resume)."""
    cases = _load_cases(state)
    audit = _load_audit(state)
    all_approved = bool(cases) and all(c.human_approved for c in cases)
    recheck = bool(state.get("recheck_requested", False))

    decision = "overridden" if recheck else ("approved" if all_approved else "rejected")
    audit.append_event(
        actor=f"human:{state.get('human_reviewer') or 'psirt'}",
        action="hitl_gate_resumed",
        summary=f"HITL gate resumed with decision='{decision}' (all_approved={all_approved}).",
    )
    return {
        "current_stage": "6_AWAITING_HUMAN_REVIEW",
        "human_review_completed": all_approved and not recheck,
        "human_decision": decision,
        "audit_log": audit.model_dump(mode="json"),
    }


def node_publish(state: PSIRTGraphState) -> PSIRTGraphState:
    """State 7_PUBLISHED (Deterministic post-approval export)."""
    cases = _load_cases(state)
    audit = _load_audit(state)
    out_dir = Path(state.get("output_dir") or "./psirt-output").resolve()
    published_files = publish_approved_bundle(
        cases=cases,
        audit_log=audit,
        output_dir=out_dir,
        sbom=state.get("sbom"),
        run_id=state.get("run_id", "run-default"),
    )
    return {
        "current_stage": "7_PUBLISHED",
        "published_files": published_files,
        "audit_log": audit.model_dump(mode="json"),
    }


def route_after_scan(state: PSIRTGraphState) -> Literal["agent_triage", "__end__"]:
    return "agent_triage" if state.get("cases") else "__end__"


def route_after_triage(state: PSIRTGraphState) -> Literal["remediate", "draft_artifacts"]:
    cases = _load_cases(state)
    if any(c.vex and c.vex.status == VEXStatus.AFFECTED for c in cases):
        return "remediate"
    return "draft_artifacts"


def route_after_guardrails(
    state: PSIRTGraphState,
) -> Literal["draft_artifacts", "human_review"]:
    cna = load_cna_profile()
    max_retries = cna.governance.max_guardrail_retries
    if state.get("guardrails_passed", False):
        return "human_review"
    if int(state.get("guardrail_retry_count", 0)) <= max_retries:
        return "draft_artifacts"
    return "human_review"


def route_after_human_review(
    state: PSIRTGraphState,
) -> Literal["draft_artifacts", "publish", "__end__"]:
    if state.get("recheck_requested", False):
        return "draft_artifacts"
    if state.get("human_review_completed", False):
        return "publish"
    return "__end__"


def build_psirt_graph(checkpointer: BaseCheckpointSaver | None = None):
    """Compile the LangGraph PSIRT state machine with mandatory HITL interrupt before human_review."""
    builder = StateGraph(PSIRTGraphState)

    builder.add_node("scan_and_sanitize", node_scan_and_sanitize)
    builder.add_node("agent_triage", node_agent_triage)
    builder.add_node("remediate", node_remediate)
    builder.add_node("draft_artifacts", node_draft_artifacts)
    builder.add_node("guardrail_check", node_guardrail_check)
    builder.add_node("human_review", node_human_review)
    builder.add_node("publish", node_publish)

    builder.add_edge(START, "scan_and_sanitize")
    builder.add_conditional_edges(
        "scan_and_sanitize",
        route_after_scan,
        {"agent_triage": "agent_triage", "__end__": END},
    )
    builder.add_conditional_edges(
        "agent_triage",
        route_after_triage,
        {"remediate": "remediate", "draft_artifacts": "draft_artifacts"},
    )
    builder.add_edge("remediate", "draft_artifacts")
    builder.add_edge("draft_artifacts", "guardrail_check")
    builder.add_conditional_edges(
        "guardrail_check",
        route_after_guardrails,
        {"draft_artifacts": "draft_artifacts", "human_review": "human_review"},
    )
    builder.add_conditional_edges(
        "human_review",
        route_after_human_review,
        {"draft_artifacts": "draft_artifacts", "publish": "publish", "__end__": END},
    )
    builder.add_edge("publish", END)

    return builder.compile(
        checkpointer=checkpointer,
        interrupt_before=["human_review"],
    )
