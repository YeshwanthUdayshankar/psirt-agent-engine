"""Tests for Typer CLI commands, interactive TUI review, guardrail retry loop, and audit log tamper detection."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from psirt_engine.cli import app
from psirt_engine.graph import build_psirt_graph
from psirt_engine.hitl.publishers import ApprovalGateViolationError, publish_approved_bundle
from psirt_engine.models.audit import DecisionAuditLog
from psirt_engine.models.canonical import GuardrailIssue, GuardrailReport, TriageCase
from psirt_engine.state import open_sqlite_checkpointer

PY_APP = Path(__file__).parent / "fixtures" / "sample_python_app"
GO_APP = Path(__file__).parent / "fixtures" / "sample_go_app"
runner = CliRunner()


def test_cli_scan_status_blocked_export_approve_and_export(tmp_path: Path):
    state_dir = tmp_path / "state"
    out_dir = tmp_path / "out"
    pr_md = tmp_path / "pr_comment.md"

    # 1. scan halts at HITL gate and writes PR review comment
    res_scan = runner.invoke(
        app,
        [
            "scan",
            str(PY_APP),
            "--profile",
            "offline_heuristic",
            "--builtin-only",
            "--run-id",
            "cli-test-1",
            "--state-dir",
            str(state_dir),
            "--output-dir",
            str(out_dir),
            "--pr-comment-out",
            str(pr_md),
        ],
    )
    assert res_scan.exit_code == 0, res_scan.output
    assert "HALTED at HITL Gate" in res_scan.output
    assert "Prompt Injection Warnings (NFR-1): 1" in res_scan.output
    assert pr_md.exists()
    assert not out_dir.exists()

    # 2. status --json reports halted state and metrics
    res_status = runner.invoke(
        app, ["status", "--state-dir", str(state_dir), "--json"]
    )
    assert res_status.exit_code == 0, res_status.output
    payload = json.loads(res_status.output)
    assert payload["run_id"] == "cli-test-1"
    assert payload["next_nodes"] == ["human_review"]
    assert payload["metrics"]["schema_pass_rate_pct"] == 100.0

    # 3. export before approval MUST fail with exit code 2 (FR-5.1)
    res_blocked = runner.invoke(app, ["export", "--state-dir", str(state_dir)])
    assert res_blocked.exit_code == 2
    assert "FR-5.1" in res_blocked.output
    assert not out_dir.exists()

    # 4. approve (without --export) then separate export command
    res_appr = runner.invoke(
        app,
        [
            "approve",
            "--state-dir",
            str(state_dir),
            "--reviewer",
            "psirt-bob",
            "--notes",
            "Verified via CLI",
        ],
    )
    assert res_appr.exit_code == 0, res_appr.output

    res_exp = runner.invoke(app, ["export", "--state-dir", str(state_dir)])
    assert res_exp.exit_code == 0, res_exp.output
    assert (out_dir / "bundle.vex.json").exists()
    assert (out_dir / "decision_audit.yaml").exists()


def test_cli_interactive_review_tui_approve_flow(tmp_path: Path):
    state_dir = tmp_path / "state"
    out_dir = tmp_path / "out"

    # Use Go fixture (only 3 cases -> fast deterministic stdin script)
    res_triage = runner.invoke(
        app,
        [
            "triage",
            str(GO_APP),
            "--profile",
            "offline_heuristic",
            "--builtin-only",
            "--run-id",
            "tui-go-1",
            "--state-dir",
            str(state_dir),
            "--output-dir",
            str(out_dir),
        ],
    )
    assert res_triage.exit_code == 0, res_triage.output

    # For each of 3 cases: approve + default note, then final Confirm 'y'
    stdin_answers = "approve\nLGTM\n" * 3 + "y\n"
    res_review = runner.invoke(
        app,
        ["review", "--state-dir", str(state_dir), "--reviewer", "psirt-carol"],
        input=stdin_answers,
    )
    assert res_review.exit_code == 0, res_review.output
    assert "Published" in res_review.output
    assert (out_dir / "decision_audit.yaml").exists()


def test_guardrail_retry_loop_caps_at_max_retries_and_blocks_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Force persistent guardrail failure -> verify max 2 retries -> NEEDS_MANUAL_TRIAGE -> publish blocked."""
    import psirt_engine.graph as graph_mod

    call_counter = {"count": 0}

    def _always_fail_guardrail(case, sbom_components, retry_count=0, schemas_dir=None):
        call_counter["count"] += 1
        return GuardrailReport(
            passed=False,
            issues=[
                GuardrailIssue(
                    gate="forced_failure",
                    severity="error",
                    artifact="openvex",
                    message="Simulated persistent schema failure",
                )
            ],
            retry_count=retry_count,
        )

    monkeypatch.setattr(graph_mod, "run_guardrails_for_case", _always_fail_guardrail)

    state_dir = tmp_path / "state"
    out_dir = tmp_path / "out"
    saver, conn = open_sqlite_checkpointer(state_dir)
    try:
        graph = build_psirt_graph(checkpointer=saver)
        config = {"configurable": {"thread_id": "retry-test"}}
        graph.invoke(
            {
                "run_id": "retry-test",
                "repo_path": str(GO_APP),
                "model_profile": "offline_heuristic",
                "output_dir": str(out_dir),
                "prefer_builtin_scanners": True,
            },
            config=config,
        )
        snap = graph.get_state(config)
        # Halts at human_review after initial check + 2 retries (3 rounds total)
        assert snap.next == ("human_review",)
        assert snap.values["guardrails_passed"] is False
        assert snap.values["guardrail_retry_count"] == 3  # 0 -> 1 -> 2 -> 3 (> max_retries=2)
        cases = [TriageCase.model_validate(c) for c in snap.values["cases"]]
        assert all(c.needs_manual_triage for c in cases)
        assert call_counter["count"] == len(cases) * 3

        # Even if someone forces human_approved=True, publisher MUST reject failed guardrails (FR-5.3)!
        for c in cases:
            c.human_approved = True
            c.human_reviewer = "psirt-override"
        audit = DecisionAuditLog.model_validate(snap.values["audit_log"])
        with pytest.raises(ApprovalGateViolationError, match="FR-5.3"):
            publish_approved_bundle(cases, audit, out_dir)
    finally:
        conn.close()


def test_audit_log_hash_chain_detects_tampering_and_blocks_publish(tmp_path: Path):
    audit = DecisionAuditLog(run_id="tamper-1", repo_path="/tmp/repo", commit_sha="abc123")
    audit.append_event("system", "scan", "Initial scan")
    audit.append_event("agent:triage", "triage", "Triaged case")
    audit.append_event("human:alice", "approve", "Approved case")

    ok, errs = audit.verify_integrity()
    assert ok is True
    assert errs == []

    # Tamper with middle event summary -> integrity check MUST fail!
    audit.events[1].summary = "TAMPERED SUMMARY"
    ok2, errs2 = audit.verify_integrity()
    assert ok2 is False
    assert any("Event 2" in e for e in errs2)

    # Publisher MUST refuse to export with a tampered audit log (FR-5.4)
    with pytest.raises(ApprovalGateViolationError, match="FR-5.4"):
        publish_approved_bundle([], audit, tmp_path / "out")
