"""PSIRT Advisory & Artifact Drafting Agent: OpenVEX v0.2.0, CSAF 2.0, CVE JSON 5.1, and Markdown Bulletin."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Any

from psirt_engine.config import CNAProfileConfig
from psirt_engine.guardrails.cvss_math import build_cve5_cvss4_object
from psirt_engine.intake.sanitizer import redact_secrets_and_pii
from psirt_engine.models.canonical import (
    DraftArtifacts,
    FindingCategory,
    GuardrailIssue,
    TriageCase,
    VEXStatus,
)


def _utc_rfc3339() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_text(text: str) -> str:
    clean, _ = redact_secrets_and_pii(text)
    return clean


def _product_id_and_purl(case: TriageCase, repo_name: str) -> tuple[str, str, str]:
    if case.package_name and case.package_version:
        purl = case.purl or f"pkg:generic/{case.package_name}@{case.package_version}"
        pid = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{case.package_name}-{case.package_version}")
        display = f"{case.package_name} {case.package_version}"
        return pid, purl, display
    pid = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{repo_name}-HEAD")
    purl = f"pkg:generic/{repo_name}@HEAD"
    return pid, purl, f"{repo_name} (HEAD)"


def _draft_cve_id(case: TriageCase, cna: CNAProfileConfig) -> str:
    if case.primary_cve_id and re.match(r"^CVE-[0-9]{4}-[0-9]{4,}$", case.primary_cve_id):
        return case.primary_cve_id
    # Deterministic placeholder CVE ID for first-party CNA drafts prior to MITRE reservation
    seq = int(hashlib.sha256(case.case_id.encode("utf-8")).hexdigest()[:5], 16) % 90000 + 10000
    return f"CVE-{cna.cve_id_placeholder_year}-{seq}"


def build_openvex(case: TriageCase, cna: CNAProfileConfig, repo_name: str, now: str) -> dict[str, Any]:
    vex = case.vex
    status = vex.status if vex else VEXStatus.UNDER_INVESTIGATION
    _, purl, _ = _product_id_and_purl(case, repo_name)
    vuln_name = case.primary_cve_id or case.case_id

    stmt: dict[str, Any] = {
        "vulnerability": {
            "name": vuln_name,
            "description": _safe_text(case.title),
        },
        "timestamp": now,
        "products": [
            {
                "@id": purl,
                "identifiers": {"purl": purl},
            }
        ],
        "status": status.value,
    }
    if case.primary_cve_id:
        stmt["vulnerability"]["@id"] = f"https://nvd.nist.gov/vuln/detail/{case.primary_cve_id}"

    if status == VEXStatus.NOT_AFFECTED:
        if vex and vex.justification:
            stmt["justification"] = vex.justification.value
        else:
            stmt["justification"] = "vulnerable_code_not_in_execute_path"
        stmt["impact_statement"] = _safe_text(
            (vex.impact_statement if vex else "")
            or f"Verified not affected via static AST reachability analysis in {repo_name}."
        )
    elif status == VEXStatus.AFFECTED:
        action = (vex.action_statement if vex else "") or (
            case.remediation.track_a.summary if case.remediation else "Apply vendor remediation."
        )
        stmt["action_statement"] = _safe_text(action)
        stmt["action_statement_timestamp"] = now

    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"{cna.organization.advisory_base_url.rstrip('/')}/vex/{case.case_id.lower()}",
        "author": cna.organization.name,
        "role": "Product Security Incident Response Team (PSIRT)",
        "timestamp": now,
        "version": 1,
        "tooling": "psirt-agent-engine/0.1.0",
        "statements": [stmt],
    }


def build_csaf_document(
    case: TriageCase,
    cna: CNAProfileConfig,
    repo_name: str,
    now: str,
    category: str,
) -> dict[str, Any]:
    """Build OASIS CSAF 2.0 compliant csaf_vex or csaf_security_advisory document."""
    vex = case.vex
    status = vex.status if vex else VEXStatus.UNDER_INVESTIGATION
    pid, purl, display_name = _product_id_and_purl(case, repo_name)
    tracking_id = f"{cna.advisory_id_prefix}-{case.case_id}"
    if category == "csaf_vex":
        tracking_id = f"{tracking_id}-VEX"

    pstatus_map = {
        VEXStatus.AFFECTED: "known_affected",
        VEXStatus.NOT_AFFECTED: "known_not_affected",
        VEXStatus.FIXED: "fixed",
        VEXStatus.UNDER_INVESTIGATION: "under_investigation",
    }

    vuln_obj: dict[str, Any] = {
        "title": _safe_text(case.title),
        "ids": [{"system_name": "psirt-agent-engine", "text": case.case_id}],
        "product_status": {pstatus_map[status]: [pid]},
        "notes": [
            {
                "category": "description",
                "title": "Technical Summary",
                "text": _safe_text(case.cwe_rationale or case.title),
            }
        ],
    }
    if case.primary_cve_id and re.match(r"^CVE-[0-9]{4}-[0-9]{4,}$", case.primary_cve_id):
        vuln_obj["cve"] = case.primary_cve_id
    if case.cwe_id and re.match(r"^CWE-[1-9]\d{0,5}$", case.cwe_id):
        vuln_obj["cwe"] = {"id": case.cwe_id, "name": case.cwe_name or case.cwe_id}

    if case.cvss_v4:
        vuln_obj["notes"].append(
            {
                "category": "other",
                "title": "CVSS v4.0 Environmental Assessment",
                "text": (
                    f"Vector: {case.cvss_v4.vector_string} | Score: {case.cvss_v4.score} "
                    f"({case.cvss_v4.severity}) | Base Delta: {case.cvss_v4.delta_from_base:+.1f}. "
                    f"{_safe_text(case.cvss_v4.environmental_rationale)}"
                ),
            }
        )

    if status == VEXStatus.NOT_AFFECTED:
        just = (
            vex.justification.value
            if vex and vex.justification
            else "vulnerable_code_not_in_execute_path"
        )
        vuln_obj["flags"] = [{"label": just, "product_ids": [pid], "date": now}]
        vuln_obj["threats"] = [
            {
                "category": "impact",
                "details": _safe_text(
                    (vex.impact_statement if vex else "")
                    or "Vulnerable code path is not reachable."
                ),
                "product_ids": [pid],
            }
        ]
    elif status == VEXStatus.AFFECTED:
        remediations: list[dict[str, Any]] = []
        if case.remediation:
            remediations.append(
                {
                    "category": "vendor_fix",
                    "details": _safe_text(case.remediation.track_a.summary),
                    "product_ids": [pid],
                }
            )
            remediations.append(
                {
                    "category": "workaround",
                    "details": _safe_text(
                        case.remediation.track_b.summary
                        + " Controls: "
                        + "; ".join(case.remediation.track_b.controls)
                    ),
                    "product_ids": [pid],
                }
            )
        else:
            remediations.append(
                {
                    "category": "mitigation",
                    "details": _safe_text(
                        (vex.action_statement if vex else "") or "Apply vendor fix or workaround."
                    ),
                    "product_ids": [pid],
                }
            )
        vuln_obj["remediations"] = remediations

        if case.attack_mappings:
            vuln_obj["threats"] = [
                {
                    "category": "impact",
                    "details": (
                        f"MITRE ATT&CK {m.technique_id} ({m.technique_name} / {m.tactic_name}): "
                        f"{_safe_text(m.impact_summary)}"
                    ),
                    "product_ids": [pid],
                }
                for m in case.attack_mappings
            ]

    doc: dict[str, Any] = {
        "document": {
            "category": category,
            "csaf_version": "2.0",
            "title": _safe_text(f"{cna.advisory_id_prefix} {case.case_id}: {case.title}"),
            "lang": "en-US",
            "publisher": {
                "category": cna.organization.publisher_category,
                "name": cna.organization.name,
                "namespace": cna.organization.namespace,
                "contact_details": cna.organization.contact_email,
            },
            "distribution": {
                "tlp": {"label": cna.organization.csaf_tlp},
            },
            "tracking": {
                "id": tracking_id,
                "status": "draft",
                "version": "1.0.0",
                "initial_release_date": now,
                "current_release_date": now,
                "generator": {
                    "date": now,
                    "engine": {"name": "psirt-agent-engine", "version": "0.1.0"},
                },
                "revision_history": [
                    {
                        "date": now,
                        "number": "1.0.0",
                        "summary": "Initial automated PSIRT draft pending HITL approval.",
                    }
                ],
            },
            "notes": [
                {
                    "category": "summary",
                    "title": "Executive Summary",
                    "text": _safe_text(
                        f"PSIRT assessment for {display_name} ({case.primary_cve_id or case.case_id}). "
                        f"VEX Status: {status.value}."
                    ),
                }
            ],
        },
        "product_tree": {
            "full_product_names": [
                {
                    "name": display_name,
                    "product_id": pid,
                    "product_identification_helper": {"purl": purl},
                }
            ]
        },
        "vulnerabilities": [vuln_obj],
    }

    if case.cvss_v4:
        doc["document"]["aggregate_severity"] = {
            "text": case.cvss_v4.severity,
        }

    return doc


def build_cve_json_5_1(
    case: TriageCase, cna: CNAProfileConfig, repo_name: str, now: str
) -> dict[str, Any]:
    """Build schema-valid CVE JSON 5.1 CNA container draft for first-party affected vulnerabilities."""
    cve_id = _draft_cve_id(case, cna)
    product_name = repo_name
    version_entry: dict[str, Any] = {"version": "0", "status": "affected", "versionType": "custom"}
    if case.fixed_version:
        version_entry["lessThan"] = case.fixed_version

    cna_container: dict[str, Any] = {
        "providerMetadata": {
            "orgId": cna.organization.cna_org_id,
            "shortName": cna.organization.short_name,
            "dateUpdated": now,
        },
        "title": _safe_text(case.title)[:256],
        "descriptions": [
            {
                "lang": "en",
                "value": _safe_text(
                    f"{case.title}. {case.cwe_rationale} "
                    f"Affected component: {product_name}."
                ),
            }
        ],
        "affected": [
            {
                "vendor": cna.organization.name,
                "product": product_name,
                "defaultStatus": "unaffected",
                "versions": [version_entry],
            }
        ],
        "references": [
            {
                "url": f"{cna.organization.advisory_base_url.rstrip('/')}/{case.case_id.lower()}",
                "name": f"{cna.advisory_id_prefix}-{case.case_id}",
                "tags": ["vendor-advisory"],
            }
        ],
        "x_generator": {"engine": "psirt-agent-engine 0.1.0"},
    }

    if case.cwe_id and re.match(r"^CWE-[1-9]\d*$", case.cwe_id):
        cna_container["problemTypes"] = [
            {
                "descriptions": [
                    {
                        "type": "CWE",
                        "cweId": case.cwe_id,
                        "lang": "en",
                        "description": f"{case.cwe_id}: {case.cwe_name or case.cwe_id}",
                    }
                ]
            }
        ]

    if case.cvss_v4:
        cna_container["metrics"] = [
            {
                "format": "CVSS",
                "scenarios": [{"lang": "en", "value": "GENERAL"}],
                "cvssV4_0": build_cve5_cvss4_object(case.cvss_v4.vector_string),
            }
        ]

    if case.remediation:
        cna_container["solutions"] = [
            {"lang": "en", "value": _safe_text(case.remediation.track_a.summary)}
        ]
        cna_container["workarounds"] = [
            {
                "lang": "en",
                "value": _safe_text(
                    case.remediation.track_b.summary
                    + " "
                    + "; ".join(case.remediation.track_b.controls)
                ),
            }
        ]

    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {
            "cveId": cve_id,
            "assignerOrgId": cna.organization.cna_org_id,
            "assignerShortName": cna.organization.short_name,
            "state": "PUBLISHED",
            "dateReserved": now,
            "datePublished": now,
            "dateUpdated": now,
        },
        "containers": {"cna": cna_container},
    }


def build_advisory_markdown(
    case: TriageCase, cna: CNAProfileConfig, repo_name: str, now: str
) -> str:
    """Build FR-4.3 customer-facing structured Markdown Security Advisory."""
    status = case.vex.status.value if case.vex else "under_investigation"
    just = (
        f" (`{case.vex.justification.value}`)"
        if case.vex and case.vex.justification
        else ""
    )
    advisory_id = f"{cna.advisory_id_prefix}-{case.case_id}"
    lines = [
        f"# Security Advisory: {advisory_id} — {_safe_text(case.title)}",
        "",
        f"- **Publisher:** {cna.organization.name}",
        f"- **Published (Draft):** {now}",
        f"- **Case ID:** `{case.case_id}`",
        f"- **CVE ID:** `{case.primary_cve_id or 'Pending CNA Assignment'}`",
        f"- **Root-Cause CWE:** `{case.cwe_id or 'Unclassified'}` — {case.cwe_name or ''}",
        f"- **VEX Status:** `{status}`{just}",
        f"- **Confidence Score:** {case.confidence:.2f}",
        "",
        "## 1. Executive Summary",
        "",
        _safe_text(
            (case.vex.impact_statement if case.vex else "")
            or f"Vulnerability assessment for `{repo_name}` regarding {case.title}."
        ),
        "",
        "## 2. Technical Description & Severity (CVSS v4.0)",
        "",
        _safe_text(case.cwe_rationale or case.title),
        "",
    ]
    if case.cvss_v4:
        lines.extend(
            [
                f"- **CVSS v4.0 Score:** `{case.cvss_v4.score}` (**{case.cvss_v4.severity}**)",
                f"- **CVSS v4.0 Vector:** `{case.cvss_v4.vector_string}`",
                f"- **Base Reference Score:** `{case.cvss_v4.base_score_from_nvd}` (Environmental Delta: `{case.cvss_v4.delta_from_base:+.1f}`)",
                f"- **Environmental Rationale:** {_safe_text(case.cvss_v4.environmental_rationale)}",
                "",
            ]
        )

    lines.extend(["## 3. Affected & Fixed Versions", ""])
    if case.package_name:
        lines.append(
            f"- **Affected Package:** `{case.package_name}@{case.package_version}` (`{case.purl or 'N/A'}`)"
        )
        lines.append(f"- **Fixed Version:** `{case.fixed_version or 'See vendor advisory'}`")
    else:
        primary_file = case.findings[0].file_path if case.findings else repo_name
        lines.append(f"- **Affected Product:** `{repo_name}` (`{primary_file}`)")
        lines.append("- **Fixed Version:** Apply Track A patch below")
    lines.append("")

    if case.remediation:
        lines.extend(
            [
                "## 4. Remediation & Workarounds",
                "",
                "### Track A — Primary Fix",
                _safe_text(case.remediation.track_a.summary),
                f"- **Breaking-Change Risk:** `{case.remediation.track_a.breaking_change_risk}` — {_safe_text(case.remediation.track_a.breaking_change_notes)}",
                "",
                "```diff",
                _safe_text(case.remediation.track_a.patch_diff).strip(),
                "```",
                "",
                "### Track B — Compensating Controls & Workarounds",
                _safe_text(case.remediation.track_b.summary),
                "",
            ]
        )
        for ctrl in case.remediation.track_b.controls:
            lines.append(f"- {_safe_text(ctrl)}")
        if case.remediation.track_b.config_snippet:
            lines.extend(["", "```", _safe_text(case.remediation.track_b.config_snippet).strip(), "```"])
        lines.append("")

    lines.extend(["## 5. Detection & Indicator of Compromise (IoC) Guidance (MITRE ATT&CK)", ""])
    if case.attack_mappings:
        for m in case.attack_mappings:
            lines.append(
                f"- **{m.technique_id} ({m.technique_name} — {m.tactic_name})**: "
                f"{_safe_text(m.impact_summary)} *Detection:* {_safe_text(m.detection_opportunity)}"
            )
    else:
        lines.append("- Not applicable (case triaged as `not_affected`).")
    lines.append("")

    lines.extend(["## 6. Verifiable Evidence Citations", ""])
    for cit in case.citations[:6]:
        lines.append(
            f"- `{cit.file_path}:{cit.line_start}-{cit.line_end}` "
            f"(symbol=`{cit.symbol or 'n/a'}`, commit=`{cit.commit_sha or 'HEAD'}`): {_safe_text(cit.note)}"
        )
    lines.append("")
    return "\n".join(lines)


def run_advisory_agent(
    case: TriageCase,
    cna: CNAProfileConfig,
    repo_name: str,
    guardrail_feedback: list[GuardrailIssue] | None = None,
) -> TriageCase:
    """Synthesize OpenVEX, CSAF 2.0 (VEX & Advisory), CVE JSON 5.1, and Markdown Bulletin."""
    now = _utc_rfc3339()
    status = case.vex.status if case.vex else VEXStatus.UNDER_INVESTIGATION

    openvex = build_openvex(case, cna, repo_name, now)
    csaf_vex = build_csaf_document(case, cna, repo_name, now, category="csaf_vex")
    csaf_advisory = (
        build_csaf_document(case, cna, repo_name, now, category="csaf_security_advisory")
        if status == VEXStatus.AFFECTED
        else None
    )
    cve_json_5_1 = (
        build_cve_json_5_1(case, cna, repo_name, now)
        if status == VEXStatus.AFFECTED
        and case.category in (FindingCategory.FIRST_PARTY_SAST, FindingCategory.IAC)
        else None
    )
    advisory_md = build_advisory_markdown(case, cna, repo_name, now)

    case.artifacts = DraftArtifacts(
        openvex=openvex,
        csaf_vex=csaf_vex,
        csaf_advisory=csaf_advisory,
        cve_json_5_1=cve_json_5_1,
        advisory_markdown=advisory_md,
    )
    case.agent_traces.append(
        {
            "agent": "advisory_agent",
            "retry_feedback_count": len(guardrail_feedback or []),
            "generated": [
                name
                for name, val in (
                    ("openvex", openvex),
                    ("csaf_vex", csaf_vex),
                    ("csaf_advisory", csaf_advisory),
                    ("cve_json_5_1", cve_json_5_1),
                )
                if val is not None
            ],
        }
    )
    return case
