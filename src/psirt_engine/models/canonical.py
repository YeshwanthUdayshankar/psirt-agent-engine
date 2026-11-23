"""Canonical Pydantic models for findings, triage cases, remediations, and artifacts."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class FindingCategory(str, Enum):
    FIRST_PARTY_SAST = "first_party_sast"
    THIRD_PARTY_CVE = "third_party_cve"
    SECRET = "secret"
    IAC = "iac"


class VEXStatus(str, Enum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


class VEXJustification(str, Enum):
    COMPONENT_NOT_PRESENT = "component_not_present"
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = (
        "vulnerable_code_cannot_be_controlled_by_adversary"
    )
    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"


class SBOMComponent(BaseModel):
    name: str
    version: str
    purl: str
    ecosystem: str = "pypi"
    bom_ref: str = ""
    manifest_path: str = ""
    direct: bool = True
    licenses: list[str] = Field(default_factory=list)


class EvidenceCitation(BaseModel):
    file_path: str
    line_start: int = 1
    line_end: int = 1
    symbol: str | None = None
    commit_sha: str | None = None
    snippet_hash: str | None = None
    note: str = ""


class CanonicalFinding(BaseModel):
    finding_id: str
    scanner_source: str
    category: FindingCategory
    title: str
    description: str
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    symbol: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    fixed_version: str | None = None
    purl: str | None = None
    cve_id: str | None = None
    ghsa_id: str | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    raw_severity: str = "MEDIUM"
    raw_cvss_score: float | None = None
    raw_cvss_vector: str | None = None
    commit_sha: str = "HEAD"
    code_snippet: str | None = None
    vulnerable_symbols: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CVSSv4Assessment(BaseModel):
    vector_string: str
    score: float
    severity: str
    base_score_from_nvd: float | None = None
    delta_from_base: float | None = None
    environmental_rationale: str = ""


class AttackMapping(BaseModel):
    tactic_id: str
    tactic_name: str
    technique_id: str
    technique_name: str
    impact_summary: str
    detection_opportunity: str


class VEXDetermination(BaseModel):
    status: VEXStatus
    justification: VEXJustification | None = None
    impact_statement: str = ""
    action_statement: str = ""
    reachable: bool = False
    call_path: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)
    citations: list[EvidenceCitation] = Field(default_factory=list)


class RemediationTrackA(BaseModel):
    kind: str = "code_patch"  # code_patch | dependency_upgrade
    summary: str
    target_file: str | None = None
    patch_diff: str = ""
    package_name: str | None = None
    current_version: str | None = None
    target_version: str | None = None
    breaking_change_risk: str = "low"  # low | medium | high
    breaking_change_notes: str = ""


class RemediationTrackB(BaseModel):
    summary: str
    controls: list[str] = Field(default_factory=list)
    config_snippet: str = ""


class VerificationHarness(BaseModel):
    framework: str = "pytest"
    filename: str = "test_repro_vuln.py"
    code: str
    expected_before_fix: str = "FAIL (reproduces vulnerable behavior)"
    expected_after_fix: str = "PASS (vulnerability mitigated)"


class RemediationPlan(BaseModel):
    track_a: RemediationTrackA
    track_b: RemediationTrackB
    verification_harness: VerificationHarness
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)
    citations: list[EvidenceCitation] = Field(default_factory=list)


class DraftArtifacts(BaseModel):
    openvex: dict[str, Any] | None = None
    csaf_vex: dict[str, Any] | None = None
    csaf_advisory: dict[str, Any] | None = None
    cve_json_5_1: dict[str, Any] | None = None
    advisory_markdown: str = ""


class GuardrailIssue(BaseModel):
    gate: str
    severity: str = "error"  # error | warning
    artifact: str
    message: str
    path: str = ""


class GuardrailReport(BaseModel):
    passed: bool
    issues: list[GuardrailIssue] = Field(default_factory=list)
    checked_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    retry_count: int = 0


class TriageCase(BaseModel):
    case_id: str
    cluster_key: str
    title: str
    category: FindingCategory
    findings: list[CanonicalFinding] = Field(default_factory=list)
    primary_cve_id: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    fixed_version: str | None = None
    purl: str | None = None
    cwe_id: str | None = None
    cwe_name: str | None = None
    cwe_rationale: str = ""
    cvss_v4: CVSSv4Assessment | None = None
    attack_mappings: list[AttackMapping] = Field(default_factory=list)
    vex: VEXDetermination | None = None
    remediation: RemediationPlan | None = None
    artifacts: DraftArtifacts | None = None
    guardrail_report: GuardrailReport | None = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    citations: list[EvidenceCitation] = Field(default_factory=list)
    needs_manual_triage: bool = False
    human_approved: bool = False
    human_reviewer: str | None = None
    human_approved_at: str | None = None
    human_notes: str = ""
    agent_traces: list[dict[str, Any]] = Field(default_factory=list)
