"""Tests for Layer 3 deterministic guardrails: JSON schemas, CVSS v4.0 math, SBOM consistency, leak blocking, and VEX accuracy."""

from __future__ import annotations

from pathlib import Path

from psirt_engine.agents.advisory_agent import run_advisory_agent
from psirt_engine.agents.remediation_agent import run_remediation_agent
from psirt_engine.agents.triage_agent import run_triage_agent
from psirt_engine.agents.vex_agent import run_vex_agent
from psirt_engine.config import load_cna_profile
from psirt_engine.guardrails.consistency import run_guardrails_for_case
from psirt_engine.guardrails.cvss_math import calculate_cvss4, verify_cvss4_score
from psirt_engine.guardrails.schema_validator import validate_artifact_schema
from psirt_engine.intake.deduplicator import deduplicate_findings
from psirt_engine.intake.sanitizer import sanitize_findings
from psirt_engine.intake.scanners import run_all_scanners
from psirt_engine.llm import ModelAgnosticLLM
from psirt_engine.mcp_servers.repo_ast_server import RepoASTService
from psirt_engine.mcp_servers.vuln_intel_server import VulnIntelService
from psirt_engine.models.canonical import VEXStatus

PY_APP = Path(__file__).parent / "fixtures" / "sample_python_app"


def _build_triaged_cases():
    scan = run_all_scanners(PY_APP, prefer_builtin=True)
    clean, _, _ = sanitize_findings(scan.findings)
    cases = deduplicate_findings(clean)
    ast_svc = RepoASTService(PY_APP)
    intel = VulnIntelService()
    llm = ModelAgnosticLLM(profile_name="offline_heuristic")
    cna = load_cna_profile()

    out = []
    for c in cases:
        c = run_triage_agent(c, ast_svc, intel, llm)
        c = run_vex_agent(c, ast_svc, llm)
        if c.vex and c.vex.status == VEXStatus.AFFECTED:
            c = run_remediation_agent(c, ast_svc, llm)
        c = run_advisory_agent(c, cna, PY_APP.name)
        out.append(c)
    return out, scan.components


def test_cvss4_deterministic_math_catches_hallucinated_score():
    vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    calc = calculate_cvss4(vec)
    assert calc.score == 9.3
    assert calc.severity == "CRITICAL"

    ok, _, _ = verify_cvss4_score(vec, 9.3, "CRITICAL")
    assert ok is True

    ok_bad, msg, _ = verify_cvss4_score(vec, 3.1, "LOW")
    assert ok_bad is False
    assert "mismatch" in msg.lower()


def test_all_generated_artifacts_achieve_100_pct_schema_and_guardrail_pass():
    cases, components = _build_triaged_cases()
    assert len(cases) >= 5

    vex_by_pkg = {c.package_name: c.vex for c in cases if c.package_name}
    assert vex_by_pkg["pyyaml"].status == VEXStatus.AFFECTED
    assert vex_by_pkg["pillow"].status == VEXStatus.NOT_AFFECTED
    assert vex_by_pkg["pillow"].justification.value == "vulnerable_code_not_in_execute_path"
    assert vex_by_pkg["urllib3"].status == VEXStatus.NOT_AFFECTED

    for case in cases:
        report = run_guardrails_for_case(case, components)
        assert report.passed, f"{case.case_id} failed guardrails: {report.issues}"


def test_guardrails_reject_sbom_version_hallucination_and_secret_leak():
    cases, components = _build_triaged_cases()
    pyyaml_case = next(c for c in cases if c.package_name == "pyyaml")

    # Tamper with package version so it no longer matches repository SBOM
    pyyaml_case.package_version = "9.9.9-hallucinated"
    report = run_guardrails_for_case(pyyaml_case, components)
    assert report.passed is False
    assert any(i.gate == "sbom_consistency" for i in report.issues)

    # Restore version, inject a raw secret into advisory markdown -> leak gate must catch it
    pyyaml_case.package_version = "5.3.1"
    pyyaml_case.artifacts.advisory_markdown += "\nLeaked token: AKIAIOSFODNN7EXAMPLE\n"
    report_leak = run_guardrails_for_case(pyyaml_case, components)
    assert report_leak.passed is False
    assert any(i.gate == "secret_leak_scan" for i in report_leak.issues)


def test_schema_validator_rejects_invalid_openvex_and_csaf():
    # OpenVEX not_affected missing justification & impact_statement
    bad_openvex = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://example.com/vex/1",
        "author": "Test",
        "timestamp": "2026-11-22T00:00:00Z",
        "version": 1,
        "statements": [
            {
                "vulnerability": {"name": "CVE-2023-50447"},
                "products": [{"@id": "pkg:pypi/pillow@10.1.0"}],
                "status": "not_affected",
            }
        ],
    }
    issues = validate_artifact_schema("openvex", bad_openvex)
    assert len(issues) > 0

    # CSAF 2.0 VEX referencing an undeclared product_id
    bad_csaf = {
        "document": {
            "category": "csaf_vex",
            "csaf_version": "2.0",
            "title": "Test",
            "publisher": {"category": "vendor", "name": "Test", "namespace": "https://example.com"},
            "tracking": {
                "id": "T-1",
                "status": "draft",
                "version": "1.0.0",
                "initial_release_date": "2026-11-22T00:00:00Z",
                "current_release_date": "2026-11-22T00:00:00Z",
                "revision_history": [
                    {"date": "2026-11-22T00:00:00Z", "number": "1.0.0", "summary": "init"}
                ],
            },
        },
        "product_tree": {"full_product_names": [{"name": "A", "product_id": "PID-A"}]},
        "vulnerabilities": [
            {
                "cve": "CVE-2023-50447",
                "product_status": {"known_not_affected": ["PID-UNDECLARED"]},
            }
        ],
    }
    csaf_issues = validate_artifact_schema("csaf_vex", bad_csaf)
    assert any(i.gate == "csaf_profile" for i in csaf_issues)
