"""Tests for external scanner JSON parsers, git blame, and live async MCP protocol tool invocation."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from psirt_engine.intake.scanners import (
    get_git_commit_sha,
    parse_grype_json,
    parse_osv_json,
    parse_semgrep_json,
    run_all_scanners,
)
from psirt_engine.mcp_servers.repo_ast_server import RepoASTService, create_repo_ast_mcp_server
from psirt_engine.mcp_servers.vuln_intel_server import create_vuln_intel_mcp_server

PY_APP = Path(__file__).parent / "fixtures" / "sample_python_app"


def test_parse_and_import_grype_osv_and_semgrep_reports(tmp_path: Path):
    grype_payload = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2024-99999",
                    "severity": "High",
                    "description": "Grype test CVE",
                    "fix": {"versions": ["2.5.0"]},
                    "cvss": [{"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "metrics": {"baseScore": 7.5}}],
                },
                "artifact": {
                    "name": "httpx",
                    "version": "2.4.0",
                    "purl": "pkg:pypi/httpx@2.4.0",
                },
            }
        ]
    }
    osv_payload = {
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [
                    {
                        "package": {"name": "jinja2", "version": "3.1.2", "ecosystem": "PyPI"},
                        "vulnerabilities": [
                            {
                                "id": "GHSA-h75v-3vvj-5mfj",
                                "aliases": ["CVE-2024-34064"],
                                "summary": "Jinja2 xmlattr XSS",
                                "details": "XSS via xmlattr filter",
                            }
                        ],
                    }
                ],
            }
        ]
    }
    semgrep_payload = {
        "results": [
            {
                "check_id": "python.lang.security.audit.eval-detected",
                "path": str(PY_APP / "app.py"),
                "start": {"line": 12},
                "end": {"line": 12},
                "extra": {
                    "message": "Avoid eval() on untrusted input",
                    "severity": "ERROR",
                    "lines": "eval(user_input)",
                    "metadata": {"cwe": ["CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code"]},
                },
            }
        ]
    }

    assert parse_grype_json(grype_payload)[0].cve_id == "CVE-2024-99999"
    assert parse_osv_json(osv_payload)[0].cve_id == "CVE-2024-34064"
    sem_f = parse_semgrep_json(semgrep_payload, PY_APP)[0]
    assert sem_f.file_path == "app.py"
    assert sem_f.cwe_ids == ["CWE-95"]

    g_path = tmp_path / "grype.json"
    o_path = tmp_path / "osv.json"
    s_path = tmp_path / "semgrep.json"
    g_path.write_text(json.dumps(grype_payload), encoding="utf-8")
    o_path.write_text(json.dumps(osv_payload), encoding="utf-8")
    s_path.write_text(json.dumps(semgrep_payload), encoding="utf-8")

    scan = run_all_scanners(
        PY_APP,
        extra_scanner_reports=[g_path, o_path, s_path],
        prefer_builtin=True,
    )
    ids = {f.cve_id for f in scan.findings if f.cve_id}
    assert {"CVE-2024-99999", "CVE-2024-34064"} <= ids
    assert any("import:grype:grype.json" == s for s in scan.scanners_used)
    assert any("import:osv:osv.json" == s for s in scan.scanners_used)
    assert any("import:semgrep:semgrep.json" == s for s in scan.scanners_used)


def test_git_commit_sha_and_git_blame_in_real_git_repo(tmp_path: Path):
    repo = tmp_path / "git_sample"
    repo.mkdir()
    sample = repo / "main.py"
    sample.write_text("import yaml\ndef load(x):\n    return yaml.load(x)\n", encoding="utf-8")

    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "psirt@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "PSIRT Bot"], cwd=repo, check=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)

    sha = get_git_commit_sha(repo)
    assert len(sha) == 40

    ast_svc = RepoASTService(repo)
    blame = ast_svc.git_blame("main.py", 1, 3)
    assert blame["available"] is True
    assert blame["commit_sha"] == sha
    assert blame["author"] == "PSIRT Bot"


@pytest.mark.asyncio
async def test_mcp_protocol_list_and_call_tools_end_to_end():
    ast_mcp = create_repo_ast_mcp_server(PY_APP)
    intel_mcp = create_vuln_intel_mcp_server()

    ast_tools = await ast_mcp.list_tools()
    ast_tool_names = {t.name for t in ast_tools}
    assert {
        "list_repo_files",
        "read_file_lines",
        "find_imports",
        "get_symbol_callers",
        "trace_reachability",
        "git_blame",
    } == ast_tool_names

    # Invoke read_file_lines through MCP protocol on secrets_fixture.py -> must redact!
    read_res = await ast_mcp.call_tool(
        "read_file_lines",
        {"rel_path": "secrets_fixture.py", "start_line": 1, "end_line": 10},
    )
    res_text = str(read_res)
    assert "AKIAIOSFODNN7EXAMPLE" not in res_text
    assert "REDACTED:AWS_ACCESS_KEY_ID" in res_text

    # Invoke read_file_lines on app.py lines 1-7 -> must flag prompt injection warnings!
    inj_res = await ast_mcp.call_tool(
        "read_file_lines",
        {"rel_path": "app.py", "start_line": 1, "end_line": 7},
    )
    assert "ignore_previous_instructions" in str(inj_res)

    # Invoke trace_reachability through MCP protocol
    trace_res = await ast_mcp.call_tool(
        "trace_reachability",
        {"import_names": ["yaml"], "vulnerable_symbols": ["yaml.load"]},
    )
    assert "load_user_profile" in str(trace_res)

    # Invoke vuln_intel MCP tools through protocol
    intel_tools = await intel_mcp.list_tools()
    assert {"lookup_cwe", "lookup_attack", "get_attack_mappings_for_cwe", "list_vex_justifications", "lookup_osv_advisory"} == {
        t.name for t in intel_tools
    }
    cwe_res = await intel_mcp.call_tool("lookup_cwe", {"cwe_id": "CWE-502"})
    assert "Deserialization" in str(cwe_res)
    just_res = await intel_mcp.call_tool("list_vex_justifications", {})
    assert "vulnerable_code_not_in_execute_path" in str(just_res)
