"""Layer 3: Deterministic cross-artifact consistency, SBOM alignment, CVSS math, and leak gates."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from psirt_engine.guardrails.cvss_math import verify_cvss4_score
from psirt_engine.guardrails.schema_validator import validate_artifact_schema
from psirt_engine.intake.sanitizer import scan_for_secret_leaks
from psirt_engine.models.canonical import (
    CNADecision,
    FindingCategory,
    GuardrailIssue,
    GuardrailReport,
    SBOMComponent,
    TriageCase,
    VEXStatus,
)

INTERNAL_PROSE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("internal_jira_url", re.compile(r"(?i)https?://[^\s\"']*(?:jira\.internal|\.corp\.|\.internal\b)")),
    ("local_dev_url", re.compile(r"(?i)https?://(?:localhost|127\.0\.0\.1)(?::\d+)?")),
    ("local_filesystem_path", re.compile(r"(?:^|[\s`\"'(])(?:/tmp/|/home/[a-zA-Z0-9_.-]+/|/Users/[a-zA-Z0-9_.-]+/)")),
)


def _version_tuple(version_str: str) -> tuple[int, ...]:
    nums = re.findall(r"\d+", version_str.strip().lstrip("vV"))
    return tuple(int(n) for n in nums) if nums else (0,)


def _version_gt(fixed: str, affected: str) -> bool:
    tf = _version_tuple(fixed)
    ta = _version_tuple(affected)
    max_len = max(len(tf), len(ta))
    tf = tf + (0,) * (max_len - len(tf))
    ta = ta + (0,) * (max_len - len(ta))
    return tf > ta


def scan_public_prose_hygiene(obj: Any, path: str = "$") -> list[str]:
    """Verify no internal URLs, staging hostnames, or local filesystem paths leak into public artifacts."""
    hits: list[str] = []
    if isinstance(obj, str):
        for rule_name, regex in INTERNAL_PROSE_PATTERNS:
            if regex.search(obj):
                hits.append(f"{path} matched {rule_name}")
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            hits.extend(scan_public_prose_hygiene(item, f"{path}[{idx}]"))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            hits.extend(scan_public_prose_hygiene(v, f"{path}.{k}"))
    return hits


def run_guardrails_for_case(
    case: TriageCase,
    sbom_components: list[SBOMComponent],
    retry_count: int = 0,
    schemas_dir: Path | None = None,
) -> GuardrailReport:
    """Run all deterministic Layer 3 validation gates on a TriageCase before human review."""
    issues: list[GuardrailIssue] = []
    artifacts = case.artifacts

    if artifacts is None:
        issues.append(
            GuardrailIssue(
                gate="artifacts_present",
                severity="error",
                artifact="draft_artifacts",
                message="DraftArtifacts missing; cannot proceed to HITL review.",
            )
        )
        return GuardrailReport(passed=False, issues=issues, retry_count=retry_count)

    # 1. Official JSON Schema compliance (OpenVEX, CSAF 2.0, CVE JSON 5.1)
    for name in ("openvex", "csaf_vex", "csaf_advisory", "cve_json_5_1"):
        doc = getattr(artifacts, name, None)
        if doc is not None:
            issues.extend(validate_artifact_schema(name, doc, schemas_dir=schemas_dir))

    if artifacts.openvex is None:
        issues.append(
            GuardrailIssue(
                gate="artifacts_present",
                severity="error",
                artifact="openvex",
                message="OpenVEX artifact is required for every triaged case.",
            )
        )
    if artifacts.csaf_vex is None:
        issues.append(
            GuardrailIssue(
                gate="artifacts_present",
                severity="error",
                artifact="csaf_vex",
                message="CSAF 2.0 VEX artifact is required for every triaged case.",
            )
        )

    # 2. Deterministic CVSS v4.0 math verification
    if case.cvss_v4 is not None:
        ok, msg, _ = verify_cvss4_score(
            case.cvss_v4.vector_string,
            case.cvss_v4.score,
            case.cvss_v4.severity,
        )
        if not ok:
            issues.append(
                GuardrailIssue(
                    gate="cvss_math",
                    severity="error",
                    artifact="case.cvss_v4",
                    message=msg,
                )
            )

    if artifacts.cve_json_5_1 is not None:
        cna = (artifacts.cve_json_5_1.get("containers") or {}).get("cna") or {}
        for idx, m in enumerate(cna.get("metrics") or []):
            cv4 = m.get("cvssV4_0")
            if cv4:
                ok, msg, _ = verify_cvss4_score(
                    cv4.get("vectorString", ""),
                    float(cv4.get("baseScore", -1)),
                    cv4.get("baseSeverity"),
                )
                if not ok:
                    issues.append(
                        GuardrailIssue(
                            gate="cvss_math",
                            severity="error",
                            artifact="cve_json_5_1",
                            path=f"$.containers.cna.metrics[{idx}].cvssV4_0",
                            message=msg,
                        )
                    )
                if case.cvss_v4 and cv4.get("vectorString") != case.cvss_v4.vector_string:
                    issues.append(
                        GuardrailIssue(
                            gate="cross_consistency",
                            severity="error",
                            artifact="cve_json_5_1",
                            path=f"$.containers.cna.metrics[{idx}].cvssV4_0.vectorString",
                            message="CVE 5.1 CVSS vector does not match canonical case CVSS v4.0 vector",
                        )
                    )

    # 3. SBOM version & PURL cross-check (prevent hallucinated package versions)
    if case.category == FindingCategory.THIRD_PARTY_CVE and case.package_name:
        sbom_map = {(c.name.lower(), c.version): c for c in sbom_components}
        key = (case.package_name.lower(), case.package_version or "")
        if key not in sbom_map:
            issues.append(
                GuardrailIssue(
                    gate="sbom_consistency",
                    severity="error",
                    artifact="canonical_state",
                    message=(
                        f"Package {case.package_name}@{case.package_version} does not match "
                        f"any component in the repository SBOM."
                    ),
                )
            )
        else:
            sbom_purl = sbom_map[key].purl
            if artifacts.openvex:
                stmts = artifacts.openvex.get("statements") or []
                if stmts:
                    vex_purls = {
                        (p.get("identifiers") or {}).get("purl") or p.get("@id")
                        for p in stmts[0].get("products") or []
                    }
                    if sbom_purl not in vex_purls:
                        issues.append(
                            GuardrailIssue(
                                gate="sbom_consistency",
                                severity="error",
                                artifact="openvex",
                                path="$.statements[0].products",
                                message=f"OpenVEX product PURLs {sorted(vex_purls)} do not contain SBOM PURL '{sbom_purl}'",
                            )
                        )

    # 4. Cross-artifact CVE, CWE, and VEX status consistency
    if case.vex is not None:
        if case.vex.status == VEXStatus.NOT_AFFECTED and case.vex.justification is None:
            issues.append(
                GuardrailIssue(
                    gate="vex_provenance",
                    severity="error",
                    artifact="case.vex",
                    message="not_affected VEX determination requires a standardized VEX justification code.",
                )
            )
        if not case.vex.citations and not case.citations:
            issues.append(
                GuardrailIssue(
                    gate="vex_provenance",
                    severity="error",
                    artifact="case.vex",
                    message="VEX determination must include at least one verifiable code/manifest citation.",
                )
            )
        if artifacts.openvex and artifacts.openvex.get("statements"):
            stmt = artifacts.openvex["statements"][0]
            if stmt.get("status") != case.vex.status.value:
                issues.append(
                    GuardrailIssue(
                        gate="cross_consistency",
                        severity="error",
                        artifact="openvex",
                        path="$.statements[0].status",
                        message=f"OpenVEX status '{stmt.get('status')}' != canonical status '{case.vex.status.value}'",
                    )
                )
            if case.primary_cve_id:
                vuln_name = (stmt.get("vulnerability") or {}).get("name")
                if vuln_name != case.primary_cve_id:
                    issues.append(
                        GuardrailIssue(
                            gate="cross_consistency",
                            severity="error",
                            artifact="openvex",
                            path="$.statements[0].vulnerability.name",
                            message=f"OpenVEX vulnerability '{vuln_name}' != canonical CVE '{case.primary_cve_id}'",
                        )
                    )

        if artifacts.csaf_vex and artifacts.csaf_vex.get("vulnerabilities"):
            cvuln = artifacts.csaf_vex["vulnerabilities"][0]
            if case.primary_cve_id and cvuln.get("cve") != case.primary_cve_id:
                issues.append(
                    GuardrailIssue(
                        gate="cross_consistency",
                        severity="error",
                        artifact="csaf_vex",
                        path="$.vulnerabilities[0].cve",
                        message=f"CSAF VEX CVE '{cvuln.get('cve')}' != canonical CVE '{case.primary_cve_id}'",
                    )
                )
            if case.cwe_id and (cvuln.get("cwe") or {}).get("id") != case.cwe_id:
                issues.append(
                    GuardrailIssue(
                        gate="cross_consistency",
                        severity="error",
                        artifact="csaf_vex",
                        path="$.vulnerabilities[0].cwe.id",
                        message=f"CSAF VEX CWE '{(cvuln.get('cwe') or {}).get('id')}' != canonical CWE '{case.cwe_id}'",
                    )
                )

    if artifacts.cve_json_5_1 is not None and case.cwe_id:
        cna = (artifacts.cve_json_5_1.get("containers") or {}).get("cna") or {}
        pt_cwes = [
            d.get("cweId")
            for pt in (cna.get("problemTypes") or [])
            for d in (pt.get("descriptions") or [])
            if d.get("cweId")
        ]
        if case.cwe_id not in pt_cwes:
            issues.append(
                GuardrailIssue(
                    gate="cross_consistency",
                    severity="error",
                    artifact="cve_json_5_1",
                    path="$.containers.cna.problemTypes",
                    message=f"CVE 5.1 problemTypes {pt_cwes} does not match canonical CWE '{case.cwe_id}'",
                )
            )

    # 5. Logical Version Ordering Check (fixed_version must be strictly greater than affected version)
    if (
        case.category == FindingCategory.THIRD_PARTY_CVE
        and case.package_version
        and case.fixed_version
        and case.vex
        and case.vex.status == VEXStatus.AFFECTED
        and not _version_gt(case.fixed_version, case.package_version)
    ):
        issues.append(
            GuardrailIssue(
                gate="version_ordering",
                severity="error",
                artifact="canonical_state",
                message=(
                    f"Fixed version '{case.fixed_version}' is not strictly greater than "
                    f"affected version '{case.package_version}' for {case.package_name}."
                ),
            )
        )

    # 6. CNA Policy Enforcement (never emit CVE JSON 5.1 unless CNA policy approves new CVE assignment)
    if (
        case.cna is not None
        and case.cna.decision != CNADecision.ASSIGN_NEW_CVE
        and artifacts.cve_json_5_1 is not None
    ):
        issues.append(
            GuardrailIssue(
                gate="cna_policy",
                severity="error",
                artifact="cve_json_5_1",
                message=(
                    f"CVE JSON 5.1 draft must not be generated when CNA decision is "
                    f"'{case.cna.decision.value}'."
                ),
            )
        )

    # 7. Public Prose Hygiene Check (no internal Jira URLs, localhost, or local filesystem paths)
    public_targets = {
        "openvex": artifacts.openvex,
        "csaf_vex": artifacts.csaf_vex,
        "csaf_advisory": artifacts.csaf_advisory,
        "cve_json_5_1": artifacts.cve_json_5_1,
        "advisory_markdown": artifacts.advisory_markdown,
    }
    for art_name, payload in public_targets.items():
        if payload is None:
            continue
        for hit in scan_public_prose_hygiene(payload):
            issues.append(
                GuardrailIssue(
                    gate="public_prose_hygiene",
                    severity="error",
                    artifact=art_name,
                    message=f"Internal URL/path leaked into public disclosure artifact: {hit}",
                )
            )

    # 8. Zero-Leakage Secret Scan across all drafted artifacts & remediation plans
    leak_targets = {
        "openvex": artifacts.openvex,
        "csaf_vex": artifacts.csaf_vex,
        "csaf_advisory": artifacts.csaf_advisory,
        "cve_json_5_1": artifacts.cve_json_5_1,
        "advisory_markdown": artifacts.advisory_markdown,
        "remediation": case.remediation.model_dump() if case.remediation else None,
    }
    for art_name, payload in leak_targets.items():
        if payload is None:
            continue
        for leak in scan_for_secret_leaks(payload):
            issues.append(
                GuardrailIssue(
                    gate="secret_leak_scan",
                    severity="error",
                    artifact=art_name,
                    message=f"Unredacted secret detected in output artifact: {leak}",
                )
            )

    has_errors = any(i.severity == "error" for i in issues)
    return GuardrailReport(
        passed=not has_errors,
        issues=issues,
        checked_at=datetime.now(UTC).isoformat(),
        retry_count=retry_count,
    )
