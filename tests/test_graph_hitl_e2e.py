"""End-to-end tests for LangGraph HITL state machine, SQLite checkpointing, override re-checks, and publication gate."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from psirt_engine.graph import build_psirt_graph
from psirt_engine.hitl.publishers import ApprovalGateViolationError, publish_approved_bundle
from psirt_engine.hitl.reviewer import approve_cases_programmatically, generate_pr_review_comment
from psirt_engine.models.audit import DecisionAuditLog
from psirt_engine.models.canonical import TriageCase
from psirt_engine.state import open_sqlite_checkpointer

PY_APP = Path(__file__).parent / "fixtures" / "sample_python_app"


def test_langgraph_halts_at_hitl_gate_and_publishes_only_after_approval(tmp_path: Path):
    state_dir = tmp_path / "state"
    out_dir = tmp_path / "published"
    saver, conn = open_sqlite_checkpointer(state_dir)
    try:
        graph = build_psirt_graph(checkpointer=saver)
        config = {"configurable": {"thread_id": "e2e-run-001"}}

        # Phase 1: Run Layers 1 -> 3; MUST halt before human_review!
        graph.invoke(
            {
                "run_id": "e2e-run-001",
                "repo_path": str(PY_APP),
                "model_profile": "offline_heuristic",
                "output_dir": str(out_dir),
                "prefer_builtin_scanners": True,
            },
            config=config,
        )
        snap = graph.get_state(config)
        assert snap.next == ("human_review",)
        assert snap.values["current_stage"] == "5_GUARDRAIL_CHECK"
        assert snap.values["guardrails_passed"] is True
        assert not out_dir.exists()  # Zero external artifacts published prior to HITL approval!

        metrics = snap.values["metrics"]
        assert metrics["schema_pass_rate_pct"] == 100.0
        assert metrics["noise_reduction_rate_pct"] >= 50.0  # Pillow + urllib3 triaged not_affected
        assert metrics["redactions_performed"] >= 4

        cases = [TriageCase.model_validate(c) for c in snap.values["cases"]]
        audit = DecisionAuditLog.model_validate(snap.values["audit_log"])

        # Attempting direct publish before human approval MUST raise ApprovalGateViolationError (FR-5.1)
        with pytest.raises(ApprovalGateViolationError):
            publish_approved_bundle(cases, audit, out_dir)

        # Verify PR review comment generation works cleanly
        pr_md = generate_pr_review_comment("e2e-run-001", snap.values["commit_sha"], cases, metrics)
        assert "Human-in-the-Loop (HITL) Review Required" in pr_md
        assert "not_affected" in pr_md

        # Phase 2: Test human override loop (override -> re-run draft_artifacts -> guardrail_check -> halt again)
        target_case = next(c for c in cases if c.package_name == "urllib3")
        cases, audit, recheck = approve_cases_programmatically(
            cases,
            audit,
            reviewer="psirt-alice",
            case_ids=[target_case.case_id],
            overrides={
                target_case.case_id: {
                    "vex_status": "not_affected",
                    "vex_justification": "component_not_present",
                    "reason": "Confirmed stripped from production wheel build.",
                }
            },
        )
        assert recheck is True
        graph.update_state(
            config,
            {
                "cases": [c.model_dump(mode="json") for c in cases],
                "audit_log": audit.model_dump(mode="json"),
                "human_reviewer": "psirt-alice",
                "recheck_requested": True,
            },
        )
        graph.invoke(None, config=config)
        snap_after_override = graph.get_state(config)
        assert snap_after_override.next == ("human_review",)
        assert snap_after_override.values["guardrails_passed"] is True

        # Phase 3: Sign off on all cases -> resume -> transitions to 7_PUBLISHED!
        cases2 = [TriageCase.model_validate(c) for c in snap_after_override.values["cases"]]
        audit2 = DecisionAuditLog.model_validate(snap_after_override.values["audit_log"])
        cases2, audit2, recheck2 = approve_cases_programmatically(
            cases2,
            audit2,
            reviewer="psirt-alice",
            notes="Verified AST citations and CVSS v4.0 vectors.",
        )
        assert recheck2 is False
        graph.update_state(
            config,
            {
                "cases": [c.model_dump(mode="json") for c in cases2],
                "audit_log": audit2.model_dump(mode="json"),
                "human_reviewer": "psirt-alice",
                "recheck_requested": False,
            },
        )
        graph.invoke(None, config=config)

        final = graph.get_state(config)
        assert final.next == ()
        assert final.values["current_stage"] == "7_PUBLISHED"
        assert (out_dir / "bundle.vex.json").exists()
        assert (out_dir / "sbom.cdx.json").exists()
        assert (out_dir / "decision_audit.yaml").exists()
        assert (out_dir / "decision_audit.json").exists()

        # Verify immutable audit log hash chain integrity
        final_audit = DecisionAuditLog.model_validate(
            json.loads((out_dir / "decision_audit.json").read_text(encoding="utf-8"))
        )
        ok_chain, errs = final_audit.verify_integrity()
        assert ok_chain, f"Audit hash chain failed: {errs}"
        assert len(final_audit.overrides) == 1
        assert len(final_audit.approvals) == len(cases2)

        # Verify zero leaked secrets anywhere in exported bundle
        for path in out_dir.rglob("*"):
            if path.is_file():
                text = path.read_text(encoding="utf-8")
                assert "AKIAIOSFODNN7EXAMPLE" not in text
                assert "ghp_1234567890" not in text
                assert "Sup3rS3cretTestPass!" not in text
    finally:
        conn.close()
