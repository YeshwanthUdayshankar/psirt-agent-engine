"""Tests for CNA assignment policy (SaaS vs On-Prem), CISA KEV/EPSS, Jira schema-drift adapter, CODEOWNERS routing, Advisory-Ready guardrails, and golden benchmark."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import pytest

from psirt_engine.agents.advisory_agent import run_advisory_agent
from psirt_engine.agents.cna_rules import evaluate_cna_assignment
from psirt_engine.config import load_cna_profile
from psirt_engine.graph import build_psirt_graph
from psirt_engine.guardrails.consistency import run_guardrails_for_case, scan_public_prose_hygiene
from psirt_engine.hitl.jira_adapter import (
    build_jira_ticket_payload,
    compute_idempotency_key,
    resolve_codeowner,
    sync_jira_ticket,
)
from psirt_engine.hitl.reviewer import approve_cases_programmatically
from psirt_engine.mcp_servers.vuln_intel_server import VulnIntelService
from psirt_engine.models.audit import DecisionAuditLog
from psirt_engine.models.canonical import (
    CNADecision,
    DeploymentMode,
    FindingCategory,
    TriageCase,
)
from psirt_engine.state import open_sqlite_checkpointer

PY_APP = Path(__file__).parent / "fixtures" / "sample_python_app"
GO_APP = Path(__file__).parent / "fixtures" / "sample_go_app"


def test_cna_rules_differentiate_saas_vs_on_prem_and_block_cve5_on_saas(tmp_path: Path):
    saver, conn = open_sqlite_checkpointer(tmp_path / "saas_state")
    try:
        graph = build_psirt_graph(checkpointer=saver)
        config = {"configurable": {"thread_id": "saas-run"}}
        graph.invoke(
            {
                "run_id": "saas-run",
                "repo_path": str(PY_APP),
                "model_profile": "offline_heuristic",
                "deployment_mode": "saas",
                "output_dir": str(tmp_path / "out"),
                "prefer_builtin_scanners": True,
            },
            config=config,
        )
        vals = graph.get_state(config).values
        assert vals["guardrails_passed"] is True
        cases = [TriageCase.model_validate(c) for c in vals["cases"]]

        first_party = [
            c for c in cases if c.category in (FindingCategory.FIRST_PARTY_SAST, FindingCategory.IAC)
        ]
        assert len(first_party) >= 3
        for c in first_party:
            assert c.cna is not None
            assert c.cna.decision == CNADecision.NO_CVE_SAAS_EXCLUDED
            # Under CNA SaaS rules, zero CVE JSON 5.1 drafts should be emitted!
            assert c.artifacts is not None
            assert c.artifacts.cve_json_5_1 is None
    finally:
        conn.close()


def test_kev_epss_enrichment_flags_active_exploitation():
    intel = VulnIntelService()
    kev = intel.lookup_kev_epss("CVE-2023-44487")
    assert kev["in_cisa_kev"] is True
    assert kev["priority_tier"] == "emergency_kev"
    assert kev["epss_score"] >= 0.9

    elevated = intel.lookup_kev_epss("CVE-2020-14343")
    assert elevated["in_cisa_kev"] is False
    assert elevated["priority_tier"] == "elevated_epss"


def test_codeowners_routing_and_jira_schema_drift_adapter_with_backoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    assert resolve_codeowner(PY_APP, "app.py") == "@appsec-backend"
    assert resolve_codeowner(PY_APP, "Dockerfile") == "@platform-infra"

    saver, conn = open_sqlite_checkpointer(tmp_path / "state")
    out_dir = tmp_path / "out"
    try:
        graph = build_psirt_graph(checkpointer=saver)
        config = {"configurable": {"thread_id": "jira-test"}}
        graph.invoke(
            {
                "run_id": "jira-test",
                "repo_path": str(PY_APP),
                "model_profile": "offline_heuristic",
                "deployment_mode": "on_prem",
                "output_dir": str(out_dir),
                "prefer_builtin_scanners": True,
            },
            config=config,
        )
        vals = graph.get_state(config).values
        cases = [TriageCase.model_validate(c) for c in vals["cases"]]
        audit = DecisionAuditLog.model_validate(vals["audit_log"])

        app_case = next(c for c in cases if "SQL Injection" in c.title)
        infra_case = next(c for c in cases if c.category == FindingCategory.IAC)
        assert app_case.owning_team == "@appsec-backend"
        assert infra_case.owning_team == "@platform-infra"

        # Verify schema-drift isolation: different teams get different project_key & customfield IDs!
        p_app = build_jira_ticket_payload(app_case, run_id="jira-test")
        p_infra = build_jira_ticket_payload(infra_case, run_id="jira-test")
        assert p_app["project_key"] == "APPAPI"
        assert "customfield_20101" in p_app["fields"]
        assert p_infra["project_key"] == "INFRA"
        assert "customfield_30501" in p_infra["fields"]
        assert p_app["idempotency_key"] == compute_idempotency_key("jira-test", app_case.case_id)

        # Verify dry-run export in published bundle
        cases, audit, _ = approve_cases_programmatically(cases, audit, reviewer="psirt-jira")
        graph.update_state(
            config,
            {
                "cases": [c.model_dump(mode="json") for c in cases],
                "audit_log": audit.model_dump(mode="json"),
                "human_reviewer": "psirt-jira",
                "recheck_requested": False,
            },
        )
        graph.invoke(None, config=config)
        jira_export = json.loads((out_dir / "jira_tickets.json").read_text(encoding="utf-8"))
        assert len(jira_export) == len(cases)

        # Verify exponential backoff on HTTP 429 during live sync
        attempts = {"n": 0}

        class _FakeResp:
            def __init__(self, code: int, body: dict):
                self.status_code = code
                self._body = body
                self.headers: dict[str, str] = {}

            def json(self):
                return self._body

            def raise_for_status(self):
                if self.status_code >= 400:
                    raise RuntimeError(f"HTTP {self.status_code}")

        class _FakeClient:
            def __init__(self, timeout: int = 30):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def post(self, url: str, headers: dict, json: dict):
                attempts["n"] += 1
                if attempts["n"] == 1:
                    return _FakeResp(429, {})
                return _FakeResp(201, {"key": "APPAPI-42"})

        monkeypatch.setattr(httpx, "Client", _FakeClient)
        monkeypatch.setenv("JIRA_BASE_URL", "https://jira.example.com")
        monkeypatch.setenv("JIRA_API_TOKEN", "dummy-token")
        synced = sync_jira_ticket(p_app, dry_run=False, base_backoff_seconds=0.01)
        assert attempts["n"] == 2
        assert synced["status"] == "created"
        assert synced["issue_key"] == "APPAPI-42"
    finally:
        conn.close()


def test_advisory_ready_guardrails_catch_version_downgrade_and_internal_url_leak(tmp_path: Path):
    saver, conn = open_sqlite_checkpointer(tmp_path / "state")
    try:
        graph = build_psirt_graph(checkpointer=saver)
        config = {"configurable": {"thread_id": "hygiene-test"}}
        graph.invoke(
            {
                "run_id": "hygiene-test",
                "repo_path": str(PY_APP),
                "model_profile": "offline_heuristic",
                "output_dir": str(tmp_path / "out"),
                "prefer_builtin_scanners": True,
            },
            config=config,
        )
        vals = graph.get_state(config).values
        from psirt_engine.models.canonical import SBOMComponent

        sbom_comps = [SBOMComponent.model_validate(c) for c in vals["sbom_components"]]
        cases = [TriageCase.model_validate(c) for c in vals["cases"]]
        pyyaml_case = next(c for c in cases if c.package_name == "pyyaml")

        # 1. Logical version ordering failure: fixed_version <= package_version
        pyyaml_case.fixed_version = "5.3.0"
        rep1 = run_guardrails_for_case(pyyaml_case, sbom_comps)
        assert rep1.passed is False
        assert any(i.gate == "version_ordering" for i in rep1.issues)

        # 2. Public prose hygiene failure: internal Jira URL / local path leak
        pyyaml_case.fixed_version = "6.0.1"
        pyyaml_case.artifacts.advisory_markdown += "\nSee internal ticket https://jira.internal/browse/SEC-99\n"
        rep2 = run_guardrails_for_case(pyyaml_case, sbom_comps)
        assert rep2.passed is False
        assert any(i.gate == "public_prose_hygiene" for i in rep2.issues)
        assert len(scan_public_prose_hygiene("Check /tmp/secret-staging/file.txt")) == 1

        # 3. CNA policy violation: forcing CVE 5.1 onto a third-party reference_upstream_cve case
        pyyaml_case.artifacts = run_advisory_agent(pyyaml_case, load_cna_profile(), "sample_python_app").artifacts
        pyyaml_case.cna = evaluate_cna_assignment(pyyaml_case, DeploymentMode.ON_PREM)
        pyyaml_case.artifacts.cve_json_5_1 = {"dummy": True}
        rep3 = run_guardrails_for_case(pyyaml_case, sbom_comps)
        assert rep3.passed is False
        assert any(i.gate == "cna_policy" for i in rep3.issues)
    finally:
        conn.close()


def test_golden_dataset_evaluation_benchmark_passes_all_gates():
    scripts_dir = str(Path(__file__).resolve().parents[1] / "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    from run_eval import run_benchmark

    report = run_benchmark()
    assert report["vex_reachability_precision_pct"] == 100.0
    assert report["vex_reachability_recall_pct"] == 100.0
    assert report["vex_reachability_f1_pct"] == 100.0
    assert report["cwe_accuracy_pct"] == 100.0
    assert report["cna_rule_accuracy_pct"] == 100.0
    assert report["kev_accuracy_pct"] == 100.0
    assert report["schema_pass_rate_pct"] == 100.0
    assert report["zero_leakage_secret_leaks"] == 0
    assert report["avg_human_edit_distance"] < 0.05
