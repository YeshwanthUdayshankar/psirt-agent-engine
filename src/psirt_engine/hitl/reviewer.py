"""HITL Reviewer: Rich terminal review UI, PR comment Markdown generator, and override recorder."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.syntax import Syntax
from rich.table import Table

from psirt_engine.models.audit import DecisionAuditLog, HumanApproval, HumanOverride
from psirt_engine.models.canonical import TriageCase, VEXJustification, VEXStatus


def compute_artifact_hashes(case: TriageCase) -> dict[str, str]:
    hashes: dict[str, str] = {}
    if not case.artifacts:
        return hashes
    for field_name in ("openvex", "csaf_vex", "csaf_advisory", "cve_json_5_1"):
        val = getattr(case.artifacts, field_name, None)
        if val is not None:
            raw = json.dumps(val, sort_keys=True, separators=(",", ":")).encode("utf-8")
            hashes[field_name] = hashlib.sha256(raw).hexdigest()
    if case.artifacts.advisory_markdown:
        hashes["advisory_markdown"] = hashlib.sha256(
            case.artifacts.advisory_markdown.encode("utf-8")
        ).hexdigest()
    return hashes


def render_cases_summary_table(cases: list[TriageCase], console: Console | None = None) -> None:
    con = console or Console()
    table = Table(title="PSIRT Triage Cases — Awaiting Human Review (HITL Gate)")
    table.add_column("Case ID", style="cyan", no_wrap=True)
    table.add_column("CVE / Category", style="magenta")
    table.add_column("CWE", style="yellow")
    table.add_column("CVSS v4.0", justify="right")
    table.add_column("VEX Status", style="bold")
    table.add_column("Conf", justify="right")
    table.add_column("Guardrails")
    table.add_column("Approved")

    for c in cases:
        vex_status = c.vex.status.value if c.vex else "pending"
        vex_style = "red" if vex_status == "affected" else "green"
        cvss_str = f"{c.cvss_v4.score:.1f} ({c.cvss_v4.severity})" if c.cvss_v4 else "N/A"
        gr_str = (
            "[green]PASS[/green]"
            if (c.guardrail_report and c.guardrail_report.passed)
            else "[red]MANUAL[/red]"
        )
        appr = f"[green]YES ({c.human_reviewer})[/green]" if c.human_approved else "[yellow]PENDING[/yellow]"
        table.add_row(
            c.case_id,
            c.primary_cve_id or c.category.value,
            c.cwe_id or "-",
            cvss_str,
            f"[{vex_style}]{vex_status}[/{vex_style}]",
            f"{c.confidence:.2f}",
            gr_str,
            appr,
        )
    con.print(table)


def interactive_tui_review(
    cases: list[TriageCase],
    audit_log: DecisionAuditLog,
    reviewer: str,
    console: Console | None = None,
) -> tuple[list[TriageCase], DecisionAuditLog, bool, bool]:
    """Interactive terminal review: inspect evidence/diffs, override fields, and sign off.

    Returns (updated_cases, updated_audit_log, any_override_needs_recheck, all_approved).
    """
    con = console or Console()
    render_cases_summary_table(cases, con)
    recheck_needed = False

    for case in cases:
        vex_status = case.vex.status.value if case.vex else "under_investigation"
        vex_just = (
            case.vex.justification.value if (case.vex and case.vex.justification) else "none"
        )
        cvss_line = (
            f"{case.cvss_v4.score} ({case.cvss_v4.severity}) — {case.cvss_v4.vector_string} "
            f"[delta {case.cvss_v4.delta_from_base:+.1f}]"
            if case.cvss_v4
            else "N/A"
        )
        citations_text = "\n".join(
            f"  • {cit.file_path}:{cit.line_start}-{cit.line_end} ({cit.symbol or 'n/a'}): {cit.note}"
            for cit in case.citations[:4]
        ) or "  • (no citations)"

        con.print(
            Panel(
                f"[bold]{case.title}[/bold]\n"
                f"CVE: {case.primary_cve_id or 'First-Party Draft'} | CWE: {case.cwe_id} ({case.cwe_name})\n"
                f"CVSS v4.0: {cvss_line}\n"
                f"VEX: {vex_status} (justification: {vex_just}) | Confidence: {case.confidence:.2f}\n"
                f"Evidence Citations:\n{citations_text}",
                title=f"Case {case.case_id}",
                border_style="red" if vex_status == "affected" else "green",
            )
        )

        if case.remediation and case.remediation.track_a.patch_diff:
            con.print(
                Syntax(
                    case.remediation.track_a.patch_diff,
                    "diff",
                    theme="monokai",
                    line_numbers=False,
                )
            )

        action = Prompt.ask(
            f"Action for {case.case_id}",
            choices=["approve", "override", "reject", "skip"],
            default="approve",
        )
        if action == "override":
            new_status_str = Prompt.ask(
                "New VEX status",
                choices=[s.value for s in VEXStatus],
                default=vex_status,
            )
            reason = Prompt.ask("Override justification / audit note", default="PSIRT engineer override")
            old_status = case.vex.status.value if case.vex else None
            if case.vex is not None:
                case.vex.status = VEXStatus(new_status_str)
                if case.vex.status == VEXStatus.NOT_AFFECTED:
                    just_str = Prompt.ask(
                        "VEX justification code",
                        choices=[j.value for j in VEXJustification],
                        default=VEXJustification.INLINE_MITIGATIONS_ALREADY_EXIST.value,
                    )
                    case.vex.justification = VEXJustification(just_str)
                    case.vex.action_statement = ""
                else:
                    case.vex.justification = None
                    if not case.vex.action_statement:
                        case.vex.action_statement = "Remediate per PSIRT engineer override."
            audit_log.record_override(
                HumanOverride(
                    case_id=case.case_id,
                    field_path="vex.status",
                    old_value=old_status,
                    new_value=new_status_str,
                    reason=reason,
                    reviewer=reviewer,
                )
            )
            case.human_approved = False
            recheck_needed = True
        elif action == "approve":
            note = Prompt.ask("Approval note (optional)", default="Reviewed and verified evidence.")
            _mark_case_approved(case, audit_log, reviewer=reviewer, notes=note)
        elif action == "reject":
            note = Prompt.ask("Rejection reason", default="Requires deeper manual investigation.")
            case.human_approved = False
            case.needs_manual_triage = True
            case.human_notes = note
            audit_log.record_approval(
                HumanApproval(
                    case_id=case.case_id,
                    reviewer=reviewer,
                    decision="rejected",
                    notes=note,
                    artifact_hashes=compute_artifact_hashes(case),
                )
            )

    all_approved = all(c.human_approved for c in cases) and not recheck_needed
    if not recheck_needed and all_approved and not Confirm.ask(
        "All cases approved. Unlock deterministic artifact export?", default=True
    ):
        all_approved = False
    return cases, audit_log, recheck_needed, all_approved


def approve_cases_programmatically(
    cases: list[TriageCase],
    audit_log: DecisionAuditLog,
    reviewer: str,
    case_ids: list[str] | None = None,
    notes: str = "Approved via PSIRT HITL gate.",
    overrides: dict[str, dict[str, Any]] | None = None,
) -> tuple[list[TriageCase], DecisionAuditLog, bool]:
    """Approve specified (or all) cases and optionally apply audited overrides.

    Returns (updated_cases, updated_audit_log, recheck_needed).
    """
    target_set = set(case_ids) if case_ids else {c.case_id for c in cases}
    recheck_needed = False

    for case in cases:
        if case.case_id not in target_set:
            continue
        if overrides and case.case_id in overrides:
            ov = overrides[case.case_id]
            if "vex_status" in ov and case.vex is not None:
                old = case.vex.status.value
                new_status = VEXStatus(ov["vex_status"])
                case.vex.status = new_status
                if new_status == VEXStatus.NOT_AFFECTED:
                    just = ov.get("vex_justification") or VEXJustification.INLINE_MITIGATIONS_ALREADY_EXIST.value
                    case.vex.justification = VEXJustification(just)
                    case.vex.action_statement = ""
                else:
                    case.vex.justification = None
                    if not case.vex.action_statement:
                        case.vex.action_statement = "Remediate per PSIRT engineer override."
                audit_log.record_override(
                    HumanOverride(
                        case_id=case.case_id,
                        field_path="vex.status",
                        old_value=old,
                        new_value=new_status.value,
                        reason=str(ov.get("reason") or "PSIRT override"),
                        reviewer=reviewer,
                    )
                )
                recheck_needed = True
                continue
        _mark_case_approved(case, audit_log, reviewer=reviewer, notes=notes)

    return cases, audit_log, recheck_needed


def _mark_case_approved(
    case: TriageCase, audit_log: DecisionAuditLog, reviewer: str, notes: str
) -> None:
    now = datetime.now(UTC).isoformat()
    case.human_approved = True
    case.human_reviewer = reviewer
    case.human_approved_at = now
    case.human_notes = notes
    audit_log.record_approval(
        HumanApproval(
            case_id=case.case_id,
            reviewer=reviewer,
            decision="approved",
            notes=notes,
            timestamp=now,
            artifact_hashes=compute_artifact_hashes(case),
        )
    )


def generate_pr_review_comment(
    run_id: str,
    commit_sha: str,
    cases: list[TriageCase],
    metrics: dict[str, Any],
) -> str:
    """Render a concise GitHub PR comment summarizing HITL review items, confidence, and citations."""
    lines = [
        "## PSIRT Agentic Triage — Human-in-the-Loop (HITL) Review Required",
        "",
        f"- **Run ID:** `{run_id}` | **Commit:** `{commit_sha[:12]}`",
        f"- **Cases:** `{len(cases)}` | **Noise Reduction Rate:** `{metrics.get('noise_reduction_rate_pct', 0):.1f}%` | **Schema Pass Rate:** `{metrics.get('schema_pass_rate_pct', 0):.1f}%`",
        "",
        "| Case ID | CVE / Category | CWE | CVSS v4.0 | VEX Status | Confidence | Guardrails | Primary Citation |",
        "|---|---|---|---|---|---:|---|---|",
    ]
    for c in cases:
        vex_status = c.vex.status.value if c.vex else "pending"
        just = f" (`{c.vex.justification.value}`)" if (c.vex and c.vex.justification) else ""
        cvss = f"`{c.cvss_v4.score}` ({c.cvss_v4.severity})" if c.cvss_v4 else "N/A"
        gr = "PASS" if (c.guardrail_report and c.guardrail_report.passed) else "NEEDS_MANUAL_TRIAGE"
        cit = (
            f"`{c.citations[0].file_path}:{c.citations[0].line_start}`"
            if c.citations
            else "-"
        )
        lines.append(
            f"| `{c.case_id}` | `{c.primary_cve_id or c.category.value}` | `{c.cwe_id or '-'}` "
            f"| {cvss} | `{vex_status}`{just} | {c.confidence:.2f} | {gr} | {cit} |"
        )

    lines.extend(
        [
            "",
            (
                "> **Governance Gate (FR-5.1):** Publication of OpenVEX, CSAF 2.0, CVE JSON 5.1, "
                "and remediation PRs is **blocked** until a PSIRT engineer approves this checkpoint "
                "via GitHub Environment Protection Rules or `psirt-engine approve`."
            ),
        ]
    )
    return "\n".join(lines)
