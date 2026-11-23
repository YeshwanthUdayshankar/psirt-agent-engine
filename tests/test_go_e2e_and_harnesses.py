"""End-to-end Go repo pipeline, zero-findings edge case, published artifact schema checks, and generated harness execution."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from psirt_engine.graph import build_psirt_graph
from psirt_engine.guardrails.schema_validator import validate_artifact_schema
from psirt_engine.hitl.reviewer import approve_cases_programmatically
from psirt_engine.models.audit import DecisionAuditLog
from psirt_engine.models.canonical import TriageCase, VEXStatus
from psirt_engine.state import open_sqlite_checkpointer

PY_APP = Path(__file__).parent / "fixtures" / "sample_python_app"
GO_APP = Path(__file__).parent / "fixtures" / "sample_go_app"


def test_go_repository_full_e2e_and_published_artifact_schema_validation(tmp_path: Path):
    state_dir = tmp_path / "go_state"
    out_dir = tmp_path / "go_published"
    saver, conn = open_sqlite_checkpointer(state_dir)
    try:
        graph = build_psirt_graph(checkpointer=saver)
        config = {"configurable": {"thread_id": "go-e2e"}}
        graph.invoke(
            {
                "run_id": "go-e2e",
                "repo_path": str(GO_APP),
                "model_profile": "offline_heuristic",
                "output_dir": str(out_dir),
                "prefer_builtin_scanners": True,
            },
            config=config,
        )
        snap = graph.get_state(config)
        assert snap.next == ("human_review",)
        cases = [TriageCase.model_validate(c) for c in snap.values["cases"]]
        audit = DecisionAuditLog.model_validate(snap.values["audit_log"])

        by_pkg = {c.package_name: c for c in cases if c.package_name}
        assert by_pkg["golang.org/x/net"].vex.status == VEXStatus.AFFECTED
        assert by_pkg["golang.org/x/crypto"].vex.status == VEXStatus.NOT_AFFECTED
        assert (
            by_pkg["golang.org/x/crypto"].vex.justification.value
            == "vulnerable_code_not_in_execute_path"
        )
        assert snap.values["metrics"]["noise_reduction_rate_pct"] == 50.0
        assert snap.values["metrics"]["schema_pass_rate_pct"] == 100.0

        # Approve and publish
        cases, audit, _ = approve_cases_programmatically(cases, audit, reviewer="psirt-go")
        graph.update_state(
            config,
            {
                "cases": [c.model_dump(mode="json") for c in cases],
                "audit_log": audit.model_dump(mode="json"),
                "human_reviewer": "psirt-go",
                "recheck_requested": False,
            },
        )
        graph.invoke(None, config=config)

        # Re-validate EVERY SINGLE published JSON file on disk against official vendored schemas!
        validated_count = 0
        for p in sorted(out_dir.rglob("*.json")):
            if p.name in ("sbom.cdx.json", "decision_audit.json"):
                continue
            doc = json.loads(p.read_text(encoding="utf-8"))
            if p.name.endswith(".vex.json"):
                assert validate_artifact_schema("openvex", doc) == [], f"Invalid OpenVEX: {p}"
                validated_count += 1
            elif p.name.endswith(".csaf-vex.json"):
                assert doc["document"]["tracking"]["status"] == "final"
                assert validate_artifact_schema("csaf_vex", doc) == [], f"Invalid CSAF VEX: {p}"
                validated_count += 1
            elif p.name.endswith(".csaf.json"):
                assert doc["document"]["tracking"]["status"] == "final"
                assert validate_artifact_schema("csaf_advisory", doc) == [], f"Invalid CSAF Adv: {p}"
                validated_count += 1
            elif p.name.endswith(".cve5.json"):
                assert validate_artifact_schema("cve_json_5_1", doc) == [], f"Invalid CVE 5.1: {p}"
                validated_count += 1
        assert validated_count >= 9
    finally:
        conn.close()


def test_clean_zero_findings_repo_completes_gracefully(tmp_path: Path):
    clean_repo = tmp_path / "clean_repo"
    clean_repo.mkdir()
    (clean_repo / "hello.py").write_text("def greet(name: str) -> str:\n    return f'hi {name}'\n", encoding="utf-8")

    state_dir = tmp_path / "state"
    saver, conn = open_sqlite_checkpointer(state_dir)
    try:
        graph = build_psirt_graph(checkpointer=saver)
        config = {"configurable": {"thread_id": "clean-repo"}}
        graph.invoke(
            {
                "run_id": "clean-repo",
                "repo_path": str(clean_repo),
                "model_profile": "offline_heuristic",
                "output_dir": str(tmp_path / "out"),
                "prefer_builtin_scanners": True,
            },
            config=config,
        )
        snap = graph.get_state(config)
        assert snap.next == ()
        assert snap.values["cases"] == []
        assert snap.values["raw_findings_count"] == 0
    finally:
        conn.close()


def test_generated_remediation_harnesses_execute_cleanly_under_pytest(tmp_path: Path):
    """Export Python fixture bundle and execute self-contained generated pytest reproducers."""
    state_dir = tmp_path / "state"
    out_dir = tmp_path / "out"
    saver, conn = open_sqlite_checkpointer(state_dir)
    try:
        graph = build_psirt_graph(checkpointer=saver)
        config = {"configurable": {"thread_id": "harness-check"}}
        graph.invoke(
            {
                "run_id": "harness-check",
                "repo_path": str(PY_APP),
                "model_profile": "offline_heuristic",
                "output_dir": str(out_dir),
                "prefer_builtin_scanners": True,
            },
            config=config,
        )
        snap = graph.get_state(config)
        cases = [TriageCase.model_validate(c) for c in snap.values["cases"]]
        audit = DecisionAuditLog.model_validate(snap.values["audit_log"])
        cases, audit, _ = approve_cases_programmatically(cases, audit, reviewer="psirt-qa")
        graph.update_state(
            config,
            {
                "cases": [c.model_dump(mode="json") for c in cases],
                "audit_log": audit.model_dump(mode="json"),
                "human_reviewer": "psirt-qa",
                "recheck_requested": False,
            },
        )
        graph.invoke(None, config=config)

        # Self-contained unit test harnesses for CWE-89, CWE-78, CWE-502 should compile & pass directly
        self_contained = [
            p
            for p in out_dir.rglob("test_repro_cwe*.py")
            if any(k in p.name for k in ("cwe89", "cwe78", "cwe502"))
        ]
        assert len(self_contained) == 3

        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-v", *[str(p) for p in self_contained]],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, f"Generated harnesses failed:\n{proc.stdout}\n{proc.stderr}"
    finally:
        conn.close()
