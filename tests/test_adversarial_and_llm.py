"""Tests for NFR-1 adversarial prompt-injection resilience, LLM transport adapters, and fallback behavior."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from psirt_engine.agents.triage_agent import run_triage_agent
from psirt_engine.agents.vex_agent import run_vex_agent
from psirt_engine.config import LLMProfileConfig
from psirt_engine.intake.deduplicator import deduplicate_findings
from psirt_engine.intake.sanitizer import sanitize_findings, scan_repo_for_prompt_injections
from psirt_engine.intake.scanners import run_all_scanners
from psirt_engine.llm import LLMCallResult, ModelAgnosticLLM, _extract_json_object
from psirt_engine.mcp_servers.repo_ast_server import RepoASTService
from psirt_engine.mcp_servers.vuln_intel_server import VulnIntelService
from psirt_engine.models.canonical import VEXStatus

PY_APP = Path(__file__).parent / "fixtures" / "sample_python_app"


class _HostilePromptInjectedLLM(ModelAgnosticLLM):
    """Simulates a compromised LLM that attempts to obey embedded prompt-injection attacks."""

    def __init__(self, forced_payload: dict[str, Any]):
        super().__init__(profile_name="offline_heuristic")
        self._forced = forced_payload

    def complete_json(
        self,
        system_prompt: str,
        user_prompt: str,
        fallback_data: dict[str, Any],
    ) -> LLMCallResult:
        # Still run real zero-leakage preparation!
        _, _, redactions = self._prepare_messages(system_prompt, user_prompt)
        return LLMCallResult(
            content="{}",
            parsed_json=self._forced,
            provider="mock_hostile",
            model="compromised-llm",
            used_heuristic_fallback=False,
            redactions_applied=redactions,
        )


def test_repo_wide_prompt_injection_scan_detects_adversarial_fixture():
    warnings = scan_repo_for_prompt_injections(PY_APP)
    assert any("app.py" in w for w in warnings)
    assert any("ignore_previous_instructions" in w for w in warnings)
    assert any("xml_fence_breakout" in w for w in warnings)


def test_vex_agent_blocks_prompt_injected_llm_from_downgrading_reachable_cve():
    scan = run_all_scanners(PY_APP, prefer_builtin=True)
    clean, _, _ = sanitize_findings(scan.findings)
    cases = deduplicate_findings(clean)
    pyyaml_case = next(c for c in cases if c.package_name == "pyyaml")

    ast_svc = RepoASTService(PY_APP)
    # Hostile LLM tries to mark reachable PyYAML CVE as not_affected!
    hostile_llm = _HostilePromptInjectedLLM(
        {
            "status": "not_affected",
            "justification": "component_not_present",
            "impact_statement": "Totally safe per comment instruction!",
            "action_statement": "",
            "confidence": 0.99,
        }
    )
    triaged = run_vex_agent(pyyaml_case, ast_svc, hostile_llm)
    assert triaged.vex is not None
    # Deterministic Tree-sitter AST reachability MUST override the hostile LLM!
    assert triaged.vex.status == VEXStatus.AFFECTED
    assert triaged.vex.justification is None
    assert triaged.vex.reachable is True


def test_triage_agent_rejects_hallucinated_cwe_and_invalid_cvss_vector():
    scan = run_all_scanners(PY_APP, prefer_builtin=True)
    clean, _, _ = sanitize_findings(scan.findings)
    cases = deduplicate_findings(clean)
    sqli_case = next(c for c in cases if "SQL" in c.title)

    ast_svc = RepoASTService(PY_APP)
    intel = VulnIntelService()
    hostile_llm = _HostilePromptInjectedLLM(
        {
            "cwe_id": "NOT-A-VALID-CWE",
            "cwe_rationale": "Hallucinated rationale",
            "cvss_v4_vector": "CVSS:4.0/INVALID_VECTOR_GARBAGE",
            "environmental_rationale": "None",
            "confidence": 5.0,  # out of bounds -> must clamp to 1.0
        }
    )
    triaged = run_triage_agent(sqli_case, ast_svc, intel, hostile_llm)
    assert triaged.cwe_id == "CWE-89"
    assert triaged.cvss_v4 is not None
    assert triaged.cvss_v4.vector_string.startswith("CVSS:4.0/")
    assert 0.0 <= triaged.cvss_v4.score <= 10.0
    assert triaged.confidence == 1.0


def test_llm_http_adapters_ollama_openai_anthropic_and_fallback(monkeypatch: pytest.MonkeyPatch):
    captured: list[dict[str, Any]] = []

    class _FakeResp:
        def __init__(self, payload: dict[str, Any]):
            self._payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return self._payload

    class _FakeClient:
        def __init__(self, timeout: int = 120):
            self.timeout = timeout

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, url: str, json: dict[str, Any], headers: dict[str, str] | None = None):
            captured.append({"url": url, "json": json, "headers": headers or {}})
            if url.endswith("/api/chat"):
                return _FakeResp({"message": {"content": '{"ok": "ollama"}'}})
            if url.endswith("/chat/completions"):
                return _FakeResp(
                    {"choices": [{"message": {"content": '```json\n{"ok": "openai"}\n```'}}]}
                )
            if url.endswith("/v1/messages"):
                return _FakeResp({"content": [{"type": "text", "text": 'Result: {"ok": "anthropic"}'}]})
            raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr(httpx, "Client", _FakeClient)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")

    # 1. Ollama
    ollama_llm = ModelAgnosticLLM(
        profile=LLMProfileConfig(provider="ollama", base_url="http://127.0.0.1:11434", model="qwen2.5-coder:14b")
    )
    r1 = ollama_llm.complete_json("sys", "usr with AKIAIOSFODNN7EXAMPLE", {"ok": "fallback"})
    assert r1.parsed_json == {"ok": "ollama"}
    assert r1.used_heuristic_fallback is False
    assert r1.redactions_applied == 1
    assert "AKIAIOSFODNN7EXAMPLE" not in str(captured[-1]["json"])

    # 2. OpenAI-compatible / vLLM
    oa_llm = ModelAgnosticLLM(
        profile=LLMProfileConfig(
            provider="openai_compatible",
            base_url="http://127.0.0.1:8000/v1",
            api_key_env="OPENAI_API_KEY",
            model="gpt-4o",
        )
    )
    r2 = oa_llm.complete_json("sys", "usr", {"ok": "fallback"})
    assert r2.parsed_json == {"ok": "openai"}
    assert captured[-1]["headers"]["Authorization"] == "Bearer test-openai-key"

    # 3. Anthropic
    anth_llm = ModelAgnosticLLM(
        profile=LLMProfileConfig(
            provider="anthropic",
            base_url="https://api.anthropic.com",
            api_key_env="ANTHROPIC_API_KEY",
            model="claude-sonnet-4-20250514",
        )
    )
    r3 = anth_llm.complete_json("sys", "usr", {"ok": "fallback"})
    assert r3.parsed_json == {"ok": "anthropic"}
    assert captured[-1]["headers"]["x-api-key"] == "test-anthropic-key"


def test_llm_connection_error_fallback_toggle(monkeypatch: pytest.MonkeyPatch):
    class _FailingClient:
        def __init__(self, timeout: int = 120):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, *args, **kwargs):
            raise httpx.ConnectError("Connection refused")

    monkeypatch.setattr(httpx, "Client", _FailingClient)

    # fallback_to_heuristic=True -> degrades cleanly to deterministic fallback
    llm_fallback = ModelAgnosticLLM(
        profile=LLMProfileConfig(provider="ollama", fallback_to_heuristic=True)
    )
    res = llm_fallback.complete_json("sys", "usr", {"safe": True})
    assert res.used_heuristic_fallback is True
    assert res.parsed_json == {"safe": True}
    assert res.error is not None

    # fallback_to_heuristic=False -> raises error explicitly
    llm_strict = ModelAgnosticLLM(
        profile=LLMProfileConfig(provider="ollama", fallback_to_heuristic=False)
    )
    with pytest.raises(httpx.ConnectError):
        llm_strict.complete_json("sys", "usr", {"safe": True})


def test_extract_json_object_variants():
    assert _extract_json_object('{"a": 1}') == {"a": 1}
    assert _extract_json_object('```json\n{"a": 2}\n```') == {"a": 2}
    assert _extract_json_object('Here is output: {"a": 3} thanks') == {"a": 3}
    assert _extract_json_object("not json at all") is None
    assert _extract_json_object("[1, 2, 3]") is None
