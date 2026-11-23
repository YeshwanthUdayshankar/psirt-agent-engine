"""Tests for read-only MCP servers: Tree-sitter AST call graphs, path containment, and vuln intel."""

from __future__ import annotations

from pathlib import Path

import pytest

from psirt_engine.mcp_servers.repo_ast_server import RepoASTService, create_repo_ast_mcp_server
from psirt_engine.mcp_servers.vuln_intel_server import (
    VulnIntelService,
    create_vuln_intel_mcp_server,
)

FIXTURES = Path(__file__).parent / "fixtures"
PY_APP = FIXTURES / "sample_python_app"
GO_APP = FIXTURES / "sample_go_app"


def test_python_ast_reachability_distinguishes_reachable_vs_unreachable():
    svc = RepoASTService(PY_APP)

    # PyYAML yaml.load IS imported and called inside load_user_profile -> handle_profile_upload
    pyyaml_trace = svc.trace_reachability(["yaml"], ["yaml.load", "FullLoader"])
    assert pyyaml_trace["imported"] is True
    assert pyyaml_trace["symbol_invoked"] is True
    assert pyyaml_trace["reachable"] is True
    assert any("load_user_profile" in hop for hop in pyyaml_trace["call_path"])

    # Pillow ImageMath.eval is declared in requirements.txt but NEVER imported or called
    pillow_trace = svc.trace_reachability(["PIL", "ImageMath"], ["ImageMath.eval", "ImageMath"])
    assert pillow_trace["imported"] is False
    assert pillow_trace["reachable"] is False


def test_go_ast_reachability_distinguishes_reachable_vs_unreachable():
    svc = RepoASTService(GO_APP)

    # golang.org/x/net/http2 IS imported and http2.ConfigureServer IS invoked in main.go
    http2_trace = svc.trace_reachability(
        ["golang.org/x/net/http2"], ["http2.ConfigureServer", "http2.Server"]
    )
    assert http2_trace["imported"] is True
    assert http2_trace["symbol_invoked"] is True
    assert http2_trace["reachable"] is True

    # golang.org/x/crypto/ssh is indirect in go.mod and NOT imported in main.go
    ssh_trace = svc.trace_reachability(
        ["golang.org/x/crypto/ssh"], ["ssh.ServerConfig", "PublicKeyCallback"]
    )
    assert ssh_trace["imported"] is False
    assert ssh_trace["reachable"] is False


def test_repo_ast_service_enforces_path_jail_and_redacts_reads():
    svc = RepoASTService(PY_APP)

    with pytest.raises(PermissionError):
        svc.read_file_lines("../../../../etc/passwd", 1, 5)

    read = svc.read_file_lines("secrets_fixture.py", 1, 20)
    assert read["redactions"] >= 4
    assert "AKIAIOSFODNN7EXAMPLE" not in read["content"]
    assert "[REDACTED:AWS_ACCESS_KEY_ID]" in read["content"]


def test_mcp_servers_expose_strictly_read_only_tools():
    ast_mcp = create_repo_ast_mcp_server(PY_APP)
    intel_mcp = create_vuln_intel_mcp_server()

    ast_tools = set(ast_mcp._tool_manager._tools.keys())
    intel_tools = set(intel_mcp._tool_manager._tools.keys())

    # Verify zero write/exec/commit tools exist on MCP servers
    forbidden_verbs = ("write", "edit", "delete", "exec", "shell", "commit", "push", "publish")
    for tool_name in ast_tools | intel_tools:
        assert not any(v in tool_name.lower() for v in forbidden_verbs)

    assert {"read_file_lines", "find_imports", "get_symbol_callers", "trace_reachability"} <= ast_tools
    assert {"lookup_cwe", "lookup_attack", "list_vex_justifications"} <= intel_tools

    intel = VulnIntelService()
    cwe = intel.lookup_cwe("CWE-89")
    assert cwe["id"] == "CWE-89"
    assert len(intel.get_attack_mappings_for_cwe("CWE-89")) >= 1
