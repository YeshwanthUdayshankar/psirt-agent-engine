"""Enterprise Jira Defect-Tracker Adapter with Schema-Drift YAML Mapping, Idempotency & CODEOWNERS Routing."""

from __future__ import annotations

import fnmatch
import hashlib
import os
import random
import time
from pathlib import Path
from typing import Any

import httpx
import yaml

from psirt_engine.config import get_project_root
from psirt_engine.intake.sanitizer import redact_secrets_and_pii
from psirt_engine.models.canonical import TriageCase


def load_jira_mapping_config(path: Path | None = None) -> dict[str, Any]:
    cfg_path = path or (get_project_root() / "config" / "jira_mapping.yaml")
    if not cfg_path.exists():
        return {"default_project": {"project_key": "PSIRT", "issue_type": "Bug", "custom_fields": {}}}
    return yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}


def resolve_codeowner(repo_path: Path, rel_file_path: str | None) -> str | None:
    """Resolve owning engineering team from .github/CODEOWNERS or CODEOWNERS (last match wins)."""
    if not rel_file_path:
        return None
    root = repo_path.resolve()
    candidates = [
        root / ".github" / "CODEOWNERS",
        root / "CODEOWNERS",
        root / "docs" / "CODEOWNERS",
    ]
    codeowners_file = next((p for p in candidates if p.exists() and p.is_file()), None)
    if codeowners_file is None:
        return None

    normalized = rel_file_path.lstrip("/")
    owner: str | None = None
    for raw_line in codeowners_file.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        pattern, owners = parts[0], parts[1:]
        if _codeowners_match(pattern, normalized):
            owner = owners[0]
    return owner


def _codeowners_match(pattern: str, rel_path: str) -> bool:
    pat = pattern.lstrip("/")
    if pat == "*":
        return True
    if pat.endswith("/"):
        return rel_path.startswith(pat) or f"/{pat}" in f"/{rel_path}"
    if "/" not in pat:
        return fnmatch.fnmatch(Path(rel_path).name, pat) or fnmatch.fnmatch(rel_path, pat)
    return fnmatch.fnmatch(rel_path, pat)


def compute_idempotency_key(run_id: str, case_id: str, action: str = "upsert_ticket") -> str:
    """Deterministic idempotency key preventing duplicate Jira tickets across retries."""
    raw = f"{run_id}:{case_id}:{action}".encode()
    return "psirt-idem-" + hashlib.sha256(raw).hexdigest()[:24]


def build_jira_ticket_payload(
    case: TriageCase,
    run_id: str,
    mapping_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Translate canonical TriageCase into a team-specific Jira REST API v3 issue payload."""
    cfg = mapping_config or load_jira_mapping_config()
    default_proj = dict(cfg.get("default_project") or {})
    team_overrides = cfg.get("team_overrides") or {}
    override = team_overrides.get(case.owning_team or "", {})

    project_key = override.get("project_key") or default_proj.get("project_key", "PSIRT")
    issue_type = override.get("issue_type") or default_proj.get("issue_type", "Security Vulnerability")
    cf = dict(default_proj.get("custom_fields") or {})
    cf.update(override.get("custom_fields") or {})
    prio_map = default_proj.get("priority_map") or {
        "CRITICAL": "Highest",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
    }

    severity = case.cvss_v4.severity if case.cvss_v4 else "MEDIUM"
    vex_status = case.vex.status.value if case.vex else "under_investigation"
    cna_decision = case.cna.decision.value if case.cna else "unknown"
    idem_key = compute_idempotency_key(run_id, case.case_id)

    summary_clean, _ = redact_secrets_and_pii(
        f"[{case.case_id}] {case.primary_cve_id or case.cwe_id or case.category.value}: {case.title}"
    )
    desc_lines = [
        f"PSIRT Case: {case.case_id}",
        f"Owning Team: {case.owning_team or 'unassigned'}",
        f"VEX Status: {vex_status}",
        f"CNA Decision: {cna_decision}",
        f"Root-Cause CWE: {case.cwe_id or 'N/A'} ({case.cwe_name or ''})",
    ]
    if case.cvss_v4:
        desc_lines.append(
            f"CVSS v4.0: {case.cvss_v4.score} ({case.cvss_v4.severity}) — {case.cvss_v4.vector_string}"
        )
    if case.threat_intel:
        desc_lines.append(
            f"Threat Intel: CISA KEV={'YES' if case.threat_intel.in_cisa_kev else 'NO'} | "
            f"EPSS={case.threat_intel.epss_score if case.threat_intel.epss_score is not None else 'N/A'} | "
            f"Priority Tier={case.threat_intel.priority_tier}"
        )
    if case.remediation:
        desc_lines.append(f"Track A Fix: {case.remediation.track_a.summary}")
        desc_lines.append(f"Track B Workaround: {case.remediation.track_b.summary}")
        desc_lines.append(f"Verification Harness: {case.remediation.verification_harness.filename}")
    desc_clean, _ = redact_secrets_and_pii("\n".join(desc_lines))

    fields: dict[str, Any] = {
        "project": {"key": project_key},
        "issuetype": {"name": issue_type},
        "summary": summary_clean[:240],
        "description": desc_clean,
        "priority": {"name": prio_map.get(severity, "Medium")},
        "labels": [
            "psirt-automated",
            f"vex-{vex_status}",
            f"cna-{cna_decision}",
            *(["cisa-kev"] if (case.threat_intel and case.threat_intel.in_cisa_kev) else []),
        ],
    }

    # Apply team-specific custom field IDs (isolating schema drift)
    if "cve_id" in cf and case.primary_cve_id:
        fields[cf["cve_id"]] = case.primary_cve_id
    if "cwe_id" in cf and case.cwe_id:
        fields[cf["cwe_id"]] = case.cwe_id
    if "cvss_v4_score" in cf and case.cvss_v4:
        fields[cf["cvss_v4_score"]] = case.cvss_v4.score
    if "cvss_v4_vector" in cf and case.cvss_v4:
        fields[cf["cvss_v4_vector"]] = case.cvss_v4.vector_string
    if "vex_status" in cf:
        fields[cf["vex_status"]] = vex_status
    if "cna_decision" in cf:
        fields[cf["cna_decision"]] = cna_decision
    if "cisa_kev" in cf and case.threat_intel:
        fields[cf["cisa_kev"]] = case.threat_intel.in_cisa_kev
    if "epss_score" in cf and case.threat_intel and case.threat_intel.epss_score is not None:
        fields[cf["epss_score"]] = case.threat_intel.epss_score
    if "idempotency_key" in cf:
        fields[cf["idempotency_key"]] = idem_key

    return {
        "idempotency_key": idem_key,
        "case_id": case.case_id,
        "owning_team": case.owning_team,
        "project_key": project_key,
        "fields": fields,
    }


def sync_jira_ticket(
    payload: dict[str, Any],
    dry_run: bool = True,
    max_retries: int = 3,
    base_backoff_seconds: float = 0.5,
) -> dict[str, Any]:
    """Post a Jira ticket with exponential backoff + jitter on 429/5xx, or dry-run offline."""
    jira_base = os.environ.get("JIRA_BASE_URL", "").rstrip("/")
    jira_token = os.environ.get("JIRA_API_TOKEN", "")
    if dry_run or not jira_base or not jira_token:
        return {
            "status": "dry_run",
            "idempotency_key": payload["idempotency_key"],
            "project_key": payload["project_key"],
            "case_id": payload["case_id"],
        }

    url = f"{jira_base}/rest/api/3/issue"
    headers = {
        "Authorization": f"Bearer {jira_token}",
        "Content-Type": "application/json",
        "X-Idempotency-Key": payload["idempotency_key"],
    }
    body = {"fields": payload["fields"]}

    for attempt in range(max_retries):
        with httpx.Client(timeout=30) as client:
            resp = client.post(url, headers=headers, json=body)
        if resp.status_code in (200, 201):
            data = resp.json()
            return {
                "status": "created",
                "issue_key": data.get("key"),
                "idempotency_key": payload["idempotency_key"],
            }
        if resp.status_code in (429, 500, 502, 503, 504) and attempt < max_retries - 1:
            retry_after = resp.headers.get("Retry-After")
            delay = (
                float(retry_after)
                if retry_after and retry_after.replace(".", "", 1).isdigit()
                else base_backoff_seconds * (2**attempt) + random.uniform(0, 0.2)
            )
            time.sleep(delay)
            continue
        resp.raise_for_status()

    raise RuntimeError(f"Failed to sync Jira ticket for {payload['case_id']} after {max_retries} attempts")
