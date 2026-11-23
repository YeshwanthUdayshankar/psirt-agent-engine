"""Typer CLI for the Agentic PSIRT & Vulnerability Response Engine.

Commands:
  psirt-engine scan    <repo>   Run Layer 1 -> 3 and halt at HITL gate (6_AWAITING_HUMAN_REVIEW)
  psirt-engine triage  <repo>   Alias for scan with explicit profile / report flags
  psirt-engine status           Inspect checkpointed run state & evaluation metrics
  psirt-engine review           Interactive Rich TUI review for HITL approval/override
  psirt-engine approve          Non-interactive HITL sign-off (e.g. CI/CD Environment Gate)
  psirt-engine export           Resume checkpoint after approval to publish validated bundle
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

from psirt_engine.graph import build_psirt_graph
from psirt_engine.hitl.reviewer import (
    approve_cases_programmatically,
    generate_pr_review_comment,
    interactive_tui_review,
    render_cases_summary_table,
)
from psirt_engine.models.audit import DecisionAuditLog
from psirt_engine.models.canonical import TriageCase
from psirt_engine.state import open_sqlite_checkpointer

app = typer.Typer(
    name="psirt-engine",
    help="Agentic PSIRT & Vulnerability Response Engine with Deterministic Guardrails & HITL.",
    no_args_is_help=True,
)
console = Console()


def _default_state_dir(state_dir: Path | None) -> Path:
    return (state_dir or Path(".psirt-state")).resolve()


def _save_latest_run_id(state_dir: Path, run_id: str) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "latest_run_id").write_text(run_id, encoding="utf-8")


def _resolve_run_id(state_dir: Path, run_id: str | None) -> str:
    if run_id:
        return run_id
    marker = state_dir / "latest_run_id"
    if marker.exists():
        return marker.read_text(encoding="utf-8").strip()
    raise typer.BadParameter("No --run-id provided and no previous run found in state dir.")


def _run_scan_pipeline(
    repo: Path,
    profile: str,
    deployment_mode: str,
    state_dir: Path,
    output_dir: Path,
    run_id: str | None,
    scanner_reports: list[Path],
    pr_comment_out: Path | None,
    prefer_builtin: bool,
) -> None:
    rid = run_id or f"run-{uuid.uuid4().hex[:8]}"
    sdir = _default_state_dir(state_dir)
    saver, conn = open_sqlite_checkpointer(sdir)
    try:
        graph = build_psirt_graph(checkpointer=saver)
        config = {"configurable": {"thread_id": rid}}
        initial_state = {
            "run_id": rid,
            "repo_path": str(repo.resolve()),
            "model_profile": profile,
            "deployment_mode": deployment_mode,
            "output_dir": str(output_dir.resolve()),
            "extra_scanner_reports": [str(p.resolve()) for p in scanner_reports],
            "prefer_builtin_scanners": prefer_builtin,
        }
        graph.invoke(initial_state, config=config)
        snap = graph.get_state(config)
        values = snap.values
        _save_latest_run_id(sdir, rid)

        cases = [TriageCase.model_validate(c) for c in values.get("cases", [])]
        metrics = values.get("metrics", {})
        next_nodes = list(snap.next)

        console.print(
            Panel(
                f"Run ID: [bold cyan]{rid}[/bold cyan]\n"
                f"Repository: {values.get('repo_path')} (commit `{values.get('commit_sha', 'HEAD')[:12]}`)\n"
                f"Scanners: {', '.join(values.get('scanners_used', []))}\n"
                f"Redactions (NFR-2): {values.get('redactions_performed', 0)} | "
                f"Prompt Injection Warnings (NFR-1): {len(values.get('prompt_injection_warnings', []))}\n"
                f"Noise Reduction Rate: [bold green]{metrics.get('noise_reduction_rate_pct', 0):.1f}%[/bold green] | "
                f"Schema Pass Rate: [bold green]{metrics.get('schema_pass_rate_pct', 0):.1f}%[/bold green]\n"
                f"Graph Status: {'HALTED at HITL Gate (' + ', '.join(next_nodes) + ')' if next_nodes else 'COMPLETED'}",
                title="PSIRT Triage Pipeline Checkpointed",
                border_style="cyan",
            )
        )
        if cases:
            render_cases_summary_table(cases, console)
        else:
            console.print("[green]No vulnerabilities detected.[/green]")

        if pr_comment_out is not None and cases:
            md = generate_pr_review_comment(
                rid, values.get("commit_sha", "HEAD"), cases, metrics
            )
            pr_comment_out.parent.mkdir(parents=True, exist_ok=True)
            pr_comment_out.write_text(md, encoding="utf-8")
            console.print(f"[dim]Wrote PR review summary to {pr_comment_out}[/dim]")
    finally:
        conn.close()


@app.command()
def scan(
    repo: Path = typer.Argument(..., exists=True, file_okay=False, help="Target Git repository path"),
    profile: str = typer.Option("ollama_local", "--profile", "-p", help="LLM profile from config/models.yaml"),
    deployment_mode: str = typer.Option(
        "on_prem",
        "--deployment-mode",
        "-d",
        help="Target deployment model for CNA rules: on_prem | hybrid | saas",
    ),
    state_dir: Path = typer.Option(Path(".psirt-state"), "--state-dir", help="Checkpoint SQLite directory"),
    output_dir: Path = typer.Option(Path("./psirt-output"), "--output-dir", "-o", help="Export bundle directory"),
    run_id: str | None = typer.Option(None, "--run-id", help="Optional deterministic run/thread ID"),
    scanner_report: list[Path] = typer.Option(
        [], "--scanner-report", help="Optional pre-generated Grype/OSV/Semgrep JSON report(s)"
    ),
    pr_comment_out: Path | None = typer.Option(
        None, "--pr-comment-out", help="Write GitHub PR HITL summary Markdown to file"
    ),
    prefer_builtin: bool = typer.Option(
        False, "--builtin-only", help="Skip external scanner binaries and use built-in deterministic scanners"
    ),
) -> None:
    """Scan a repository, run triage/VEX/remediation/advisory agents + guardrails, and HALT at HITL gate."""
    _run_scan_pipeline(
        repo=repo,
        profile=profile,
        deployment_mode=deployment_mode,
        state_dir=state_dir,
        output_dir=output_dir,
        run_id=run_id,
        scanner_reports=scanner_report,
        pr_comment_out=pr_comment_out,
        prefer_builtin=prefer_builtin,
    )


@app.command()
def triage(
    repo: Path = typer.Argument(..., exists=True, file_okay=False, help="Target Git repository path"),
    profile: str = typer.Option("ollama_local", "--profile", "-p", help="LLM profile"),
    deployment_mode: str = typer.Option(
        "on_prem", "--deployment-mode", "-d", help="CNA deployment mode: on_prem | hybrid | saas"
    ),
    state_dir: Path = typer.Option(Path(".psirt-state"), "--state-dir", help="Checkpoint directory"),
    output_dir: Path = typer.Option(Path("./psirt-output"), "--output-dir", "-o", help="Export directory"),
    run_id: str | None = typer.Option(None, "--run-id", help="Optional run ID"),
    prefer_builtin: bool = typer.Option(False, "--builtin-only"),
) -> None:
    """Run full scan + agentic triage up to the mandatory HITL approval checkpoint."""
    _run_scan_pipeline(
        repo=repo,
        profile=profile,
        deployment_mode=deployment_mode,
        state_dir=state_dir,
        output_dir=output_dir,
        run_id=run_id,
        scanner_reports=[],
        pr_comment_out=None,
        prefer_builtin=prefer_builtin,
    )


@app.command()
def status(
    run_id: str | None = typer.Option(None, "--run-id", help="Run/thread ID (defaults to latest)"),
    state_dir: Path = typer.Option(Path(".psirt-state"), "--state-dir", help="Checkpoint directory"),
    json_out: bool = typer.Option(False, "--json", help="Emit machine-readable status JSON"),
) -> None:
    """Display status, metrics, and HITL gate state for a checkpointed run."""
    sdir = _default_state_dir(state_dir)
    rid = _resolve_run_id(sdir, run_id)
    saver, conn = open_sqlite_checkpointer(sdir)
    try:
        graph = build_psirt_graph(checkpointer=saver)
        snap = graph.get_state({"configurable": {"thread_id": rid}})
        values = snap.values
        if not values:
            raise typer.Exit(code=1)
        if json_out:
            console.print_json(
                json.dumps(
                    {
                        "run_id": rid,
                        "current_stage": values.get("current_stage"),
                        "next_nodes": list(snap.next),
                        "metrics": values.get("metrics", {}),
                        "published_files": values.get("published_files", []),
                    }
                )
            )
            return
        cases = [TriageCase.model_validate(c) for c in values.get("cases", [])]
        console.print(
            f"[bold]Run:[/bold] {rid} | [bold]Stage:[/bold] {values.get('current_stage')} | "
            f"[bold]Next:[/bold] {list(snap.next)}"
        )
        render_cases_summary_table(cases, console)
    finally:
        conn.close()


@app.command()
def review(
    reviewer: str = typer.Option(..., "--reviewer", "-r", help="Human PSIRT engineer identity/handle"),
    run_id: str | None = typer.Option(None, "--run-id", help="Run ID (defaults to latest)"),
    state_dir: Path = typer.Option(Path(".psirt-state"), "--state-dir", help="Checkpoint directory"),
) -> None:
    """Interactive terminal UI to inspect evidence/diffs, override VEX/fields, and approve publication."""
    sdir = _default_state_dir(state_dir)
    rid = _resolve_run_id(sdir, run_id)
    saver, conn = open_sqlite_checkpointer(sdir)
    try:
        graph = build_psirt_graph(checkpointer=saver)
        config = {"configurable": {"thread_id": rid}}
        snap = graph.get_state(config)
        values = snap.values
        cases = [TriageCase.model_validate(c) for c in values.get("cases", [])]
        audit = DecisionAuditLog.model_validate(values["audit_log"])

        cases, audit, recheck_needed, all_approved = interactive_tui_review(
            cases, audit, reviewer=reviewer, console=console
        )
        graph.update_state(
            config,
            {
                "cases": [c.model_dump(mode="json") for c in cases],
                "audit_log": audit.model_dump(mode="json"),
                "human_reviewer": reviewer,
                "recheck_requested": recheck_needed,
            },
        )
        if recheck_needed:
            console.print("[yellow]Overrides recorded; re-running artifact drafting & Layer 3 guardrails...[/yellow]")
            graph.invoke(None, config=config)
            console.print("[cyan]Re-check complete. Run `psirt-engine review` again to approve updated artifacts.[/cyan]")
        elif all_approved:
            graph.invoke(None, config=config)
            final = graph.get_state(config).values
            console.print(
                f"[bold green]Published {len(final.get('published_files', []))} validated files "
                f"to {final.get('output_dir')}[/bold green]"
            )
        else:
            console.print("[yellow]HITL approval incomplete; execution remains halted before publication.[/yellow]")
    finally:
        conn.close()


@app.command()
def approve(
    reviewer: str = typer.Option(..., "--reviewer", "-r", help="Approving PSIRT engineer identity"),
    run_id: str | None = typer.Option(None, "--run-id", help="Run ID (defaults to latest)"),
    state_dir: Path = typer.Option(Path(".psirt-state"), "--state-dir", help="Checkpoint directory"),
    notes: str = typer.Option("Approved via PSIRT HITL checkpoint.", "--notes", help="Approval audit note"),
    export_now: bool = typer.Option(False, "--export", help="Immediately resume graph to 7_PUBLISHED"),
) -> None:
    """Record explicit human approval for a checkpointed run (used in CLI or CI/CD approval jobs)."""
    sdir = _default_state_dir(state_dir)
    rid = _resolve_run_id(sdir, run_id)
    saver, conn = open_sqlite_checkpointer(sdir)
    try:
        graph = build_psirt_graph(checkpointer=saver)
        config = {"configurable": {"thread_id": rid}}
        values = graph.get_state(config).values
        cases = [TriageCase.model_validate(c) for c in values.get("cases", [])]
        audit = DecisionAuditLog.model_validate(values["audit_log"])

        cases, audit, _ = approve_cases_programmatically(
            cases, audit, reviewer=reviewer, notes=notes
        )
        graph.update_state(
            config,
            {
                "cases": [c.model_dump(mode="json") for c in cases],
                "audit_log": audit.model_dump(mode="json"),
                "human_reviewer": reviewer,
                "human_notes": notes,
                "recheck_requested": False,
            },
        )
        console.print(f"[green]Recorded signed HITL approval by '{reviewer}' for {len(cases)} case(s).[/green]")
        if export_now:
            graph.invoke(None, config=config)
            final = graph.get_state(config).values
            console.print(
                f"[bold green]Published {len(final.get('published_files', []))} files to {final.get('output_dir')}[/bold green]"
            )
    finally:
        conn.close()


@app.command()
def export(
    run_id: str | None = typer.Option(None, "--run-id", help="Run ID (defaults to latest)"),
    state_dir: Path = typer.Option(Path(".psirt-state"), "--state-dir", help="Checkpoint directory"),
    output_dir: Path | None = typer.Option(None, "--output-dir", "-o", help="Override export directory"),
) -> None:
    """Resume an approved checkpoint to export validated OpenVEX, CSAF 2.0, CVE 5.1, Advisory & Audit Log."""
    sdir = _default_state_dir(state_dir)
    rid = _resolve_run_id(sdir, run_id)
    saver, conn = open_sqlite_checkpointer(sdir)
    try:
        graph = build_psirt_graph(checkpointer=saver)
        config = {"configurable": {"thread_id": rid}}
        values = graph.get_state(config).values
        cases = [TriageCase.model_validate(c) for c in values.get("cases", [])]
        if not cases or not all(c.human_approved for c in cases):
            console.print(
                "[bold red]Blocked (FR-5.1):[/bold red] Cannot export until all cases have signed human approval. "
                "Run `psirt-engine review` or `psirt-engine approve` first."
            )
            raise typer.Exit(code=2)
        if output_dir is not None:
            graph.update_state(config, {"output_dir": str(output_dir.resolve())})
        graph.invoke(None, config=config)
        final = graph.get_state(config).values
        files = final.get("published_files", [])
        console.print(f"[bold green]Exported {len(files)} validated artifacts:[/bold green]")
        for f in files:
            console.print(f"  • {f}")
    finally:
        conn.close()


if __name__ == "__main__":
    app()
