"""Configuration loaders for LLM model profiles and CNA/PSIRT governance profiles."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


def get_project_root() -> Path:
    """Locate the repository root containing config/ and schemas/."""
    env_root = os.environ.get("PSIRT_ENGINE_HOME")
    if env_root:
        return Path(env_root).resolve()
    # src/psirt_engine/config.py -> repo root is 2 parents up from src/
    candidate = Path(__file__).resolve().parents[2]
    if (candidate / "config").exists():
        return candidate
    return Path.cwd()


class LLMProfileConfig(BaseModel):
    provider: str = "ollama"
    base_url: str = "http://127.0.0.1:11434"
    api_key_env: str | None = None
    model: str = "qwen2.5-coder:14b"
    temperature: float = 0.0
    timeout_seconds: int = 120
    zero_data_retention: bool = True
    fallback_to_heuristic: bool = True


class ModelsConfig(BaseModel):
    default_profile: str = "ollama_local"
    profiles: dict[str, LLMProfileConfig] = Field(default_factory=dict)
    observability: dict[str, Any] = Field(default_factory=dict)

    def resolve_profile(self, name: str | None = None) -> tuple[str, LLMProfileConfig]:
        selected = name or os.environ.get("PSIRT_LLM_PROFILE") or self.default_profile
        if selected not in self.profiles:
            available = ", ".join(sorted(self.profiles.keys()))
            raise ValueError(f"Unknown LLM profile '{selected}'. Available: {available}")
        return selected, self.profiles[selected]


class OrganizationConfig(BaseModel):
    name: str = "Example Product Security Incident Response Team (PSIRT)"
    short_name: str = "example-psirt"
    cna_org_id: str = "550e8400-e29b-41d4-a716-446655440000"
    namespace: str = "https://security.example.com"
    advisory_base_url: str = "https://security.example.com/advisories"
    contact_email: str = "psirt@example.com"
    publisher_category: str = "vendor"
    csaf_tlp: str = "WHITE"


class GovernanceConfig(BaseModel):
    require_human_approval: bool = True
    max_guardrail_retries: int = 2
    min_confidence_for_auto_vex_draft: float = 0.70
    block_on_secret_leak: bool = True


class CNAProfileConfig(BaseModel):
    organization: OrganizationConfig = Field(default_factory=OrganizationConfig)
    advisory_id_prefix: str = "EXSA"
    cve_id_placeholder_year: int = 2026
    severity_slas_days: dict[str, int] = Field(
        default_factory=lambda: {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 90, "LOW": 180}
    )
    governance: GovernanceConfig = Field(default_factory=GovernanceConfig)


def load_models_config(path: Path | None = None) -> ModelsConfig:
    cfg_path = path or (get_project_root() / "config" / "models.yaml")
    if not cfg_path.exists():
        return ModelsConfig(
            default_profile="offline_heuristic",
            profiles={"offline_heuristic": LLMProfileConfig(provider="heuristic")},
        )
    data = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    return ModelsConfig.model_validate(data)


def load_cna_profile(path: Path | None = None) -> CNAProfileConfig:
    cfg_path = path or (get_project_root() / "config" / "cna_profile.yaml")
    if not cfg_path.exists():
        return CNAProfileConfig()
    data = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    return CNAProfileConfig.model_validate(data)
