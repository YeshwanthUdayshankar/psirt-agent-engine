"""Model-agnostic LLM client supporting Ollama, vLLM/OpenAI-compatible, Anthropic, and offline heuristic mode.

Enforces NFR-2 (100% deterministic secret redaction before any prompt leaves the process)
and NFR-3 (local/ZDR model agnosticism).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any

import httpx

from psirt_engine.config import LLMProfileConfig, load_models_config
from psirt_engine.intake.sanitizer import redact_secrets_and_pii, scan_for_secret_leaks


class SecretLeakBlockedError(RuntimeError):
    """Raised if unredacted secret material is detected immediately prior to LLM invocation."""


@dataclass
class LLMCallResult:
    content: str
    parsed_json: dict[str, Any] | None
    provider: str
    model: str
    used_heuristic_fallback: bool = False
    redactions_applied: int = 0
    error: str | None = None


class ModelAgnosticLLM:
    """Unified, zero-leakage LLM client with deterministic heuristic fallback."""

    def __init__(self, profile_name: str | None = None, profile: LLMProfileConfig | None = None):
        if profile is not None:
            self.profile_name = profile_name or "custom"
            self.profile = profile
        else:
            cfg = load_models_config()
            self.profile_name, self.profile = cfg.resolve_profile(profile_name)

    def _prepare_messages(
        self, system_prompt: str, user_prompt: str
    ) -> tuple[str, str, int]:
        sanitized_sys, sys_hits = redact_secrets_and_pii(system_prompt)
        sanitized_usr, usr_hits = redact_secrets_and_pii(user_prompt)

        # Defense-in-depth double check: guarantee zero secret leakage before network/model call.
        leaks = scan_for_secret_leaks({"system": sanitized_sys, "user": sanitized_usr})
        if leaks:
            raise SecretLeakBlockedError(
                f"Blocked LLM invocation due to residual secrets: {leaks}"
            )
        return sanitized_sys, sanitized_usr, len(sys_hits) + len(usr_hits)

    def complete_json(
        self,
        system_prompt: str,
        user_prompt: str,
        fallback_data: dict[str, Any],
    ) -> LLMCallResult:
        """Invoke configured LLM expecting JSON; fall back cleanly when offline or configured."""
        safe_sys, safe_usr, redactions = self._prepare_messages(system_prompt, user_prompt)

        if self.profile.provider == "heuristic":
            return LLMCallResult(
                content=json.dumps(fallback_data),
                parsed_json=fallback_data,
                provider="heuristic",
                model=self.profile.model,
                used_heuristic_fallback=True,
                redactions_applied=redactions,
            )

        try:
            raw = self._dispatch(safe_sys, safe_usr)
            parsed = _extract_json_object(raw)
            if parsed is None:
                raise ValueError("LLM response did not contain a valid JSON object")
            return LLMCallResult(
                content=raw,
                parsed_json=parsed,
                provider=self.profile.provider,
                model=self.profile.model,
                used_heuristic_fallback=False,
                redactions_applied=redactions,
            )
        except Exception as exc:
            if self.profile.fallback_to_heuristic:
                return LLMCallResult(
                    content=json.dumps(fallback_data),
                    parsed_json=fallback_data,
                    provider=self.profile.provider,
                    model=self.profile.model,
                    used_heuristic_fallback=True,
                    redactions_applied=redactions,
                    error=str(exc),
                )
            raise

    def _dispatch(self, system_prompt: str, user_prompt: str) -> str:
        provider = self.profile.provider
        if provider == "ollama":
            return self._call_ollama(system_prompt, user_prompt)
        if provider == "openai_compatible":
            return self._call_openai_compatible(system_prompt, user_prompt)
        if provider == "anthropic":
            return self._call_anthropic(system_prompt, user_prompt)
        raise ValueError(f"Unsupported LLM provider: {provider}")

    def _call_ollama(self, system_prompt: str, user_prompt: str) -> str:
        url = f"{self.profile.base_url.rstrip('/')}/api/chat"
        payload = {
            "model": self.profile.model,
            "stream": False,
            "format": "json",
            "options": {"temperature": self.profile.temperature},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        with httpx.Client(timeout=self.profile.timeout_seconds) as client:
            resp = client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data.get("message", {}).get("content", "")

    def _call_openai_compatible(self, system_prompt: str, user_prompt: str) -> str:
        url = f"{self.profile.base_url.rstrip('/')}/chat/completions"
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.profile.api_key_env:
            token = os.environ.get(self.profile.api_key_env, "")
            if token:
                headers["Authorization"] = f"Bearer {token}"
        payload = {
            "model": self.profile.model,
            "temperature": self.profile.temperature,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        with httpx.Client(timeout=self.profile.timeout_seconds) as client:
            resp = client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]

    def _call_anthropic(self, system_prompt: str, user_prompt: str) -> str:
        url = f"{self.profile.base_url.rstrip('/')}/v1/messages"
        api_key = os.environ.get(self.profile.api_key_env or "ANTHROPIC_API_KEY", "")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set")
        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        }
        payload = {
            "model": self.profile.model,
            "max_tokens": 2048,
            "temperature": self.profile.temperature,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        with httpx.Client(timeout=self.profile.timeout_seconds) as client:
            resp = client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            blocks = data.get("content", [])
            return "".join(b.get("text", "") for b in blocks if b.get("type") == "text")


def _extract_json_object(text: str) -> dict[str, Any] | None:
    text = text.strip()
    if not text:
        return None
    try:
        loaded = json.loads(text)
        return loaded if isinstance(loaded, dict) else None
    except json.JSONDecodeError:
        pass
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        try:
            loaded = json.loads(fenced.group(1))
            return loaded if isinstance(loaded, dict) else None
        except json.JSONDecodeError:
            pass
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            loaded = json.loads(text[start : end + 1])
            return loaded if isinstance(loaded, dict) else None
        except json.JSONDecodeError:
            return None
    return None
