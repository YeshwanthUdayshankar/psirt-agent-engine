"""Layer 4 Post-Approval Publishers: Exports validated VEX/CSAF/CVE/Advisory/Audit bundles.

Strictly enforces FR-5.1: refuses to publish any external disclosure artifact or open
a remediation PR unless explicit signed human approval is recorded AND guardrails passed.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from psirt_engine.hitl.jira_adapter import build_jira_ticket_payload
from psirt_engine.intake.sanitizer import scan_for_secret_leaks
from psirt_engine.models.audit import DecisionAuditLog
from psirt_engine.models.canonical import TriageCase


class ApprovalGateViolationError(PermissionError):
    """Raised when an attempt is made to publish unapproved or unvalidated artifacts."""


def publish_approved_bundle(
    cases: list[TriageCase],
    audit_log: DecisionAuditLog,
    output_dir: Path,
    sbom: dict[str, Any] | None = None,
    open_github_pr: bool = False,
    run_id: str | None = None,
) -> list[str]:
    """Export all approved, guardrail-validated PSIRT disclosure artifacts and immutable audit log."""
    unapproved = [c.case_id for c in cases if not c.human_approved or not c.human_reviewer]
    if unapproved:
        raise ApprovalGateViolationError(
            f"FR-5.1 Violation: Cannot publish artifacts without explicit human approval for cases: {unapproved}"
        )

    failed_guardrails = [
        c.case_id
        for c in cases
        if c.guardrail_report is None or not c.guardrail_report.passed
    ]
    if failed_guardrails:
        raise ApprovalGateViolationError(
            f"FR-5.3 Violation: Cannot publish cases that failed deterministic guardrails: {failed_guardrails}"
        )

    ok_integrity, integrity_errs = audit_log.verify_integrity()
    if not ok_integrity:
        raise ApprovalGateViolationError(
            f"FR-5.4 Violation: Audit log hash chain integrity check failed: {integrity_errs}"
        )

    out = output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    if sbom is not None:
        sbom_path = out / "sbom.cdx.json"
        sbom_path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
        written.append(str(sbom_path))

    # Also build a merged OpenVEX document aggregating all statements for downstream scanners
    merged_statements: list[dict[str, Any]] = []
    openvex_header: dict[str, Any] | None = None

    for case in cases:
        if case.artifacts is None:
            continue
        case_dir = out / case.case_id.lower()
        case_dir.mkdir(parents=True, exist_ok=True)

        # Final zero-leakage assertion before writing to disk
        leaks = scan_for_secret_leaks(case.artifacts.model_dump())
        if leaks:
            raise ApprovalGateViolationError(
                f"NFR-2 Violation: Blocked export of {case.case_id} due to secret leak: {leaks}"
            )

        if case.artifacts.openvex is not None:
            p = case_dir / f"{case.case_id.lower()}.vex.json"
            p.write_text(json.dumps(case.artifacts.openvex, indent=2), encoding="utf-8")
            written.append(str(p))
            if openvex_header is None:
                openvex_header = {k: v for k, v in case.artifacts.openvex.items() if k != "statements"}
            merged_statements.extend(case.artifacts.openvex.get("statements", []))

        if case.artifacts.csaf_vex is not None:
            p = case_dir / f"{case.case_id.lower()}.csaf-vex.json"
            # Transition CSAF tracking status from draft -> final on signed human publication
            final_doc = json.loads(json.dumps(case.artifacts.csaf_vex))
            final_doc["document"]["tracking"]["status"] = "final"
            p.write_text(json.dumps(final_doc, indent=2), encoding="utf-8")
            written.append(str(p))

        if case.artifacts.csaf_advisory is not None:
            p = case_dir / f"{case.case_id.lower()}.csaf.json"
            final_adv = json.loads(json.dumps(case.artifacts.csaf_advisory))
            final_adv["document"]["tracking"]["status"] = "final"
            p.write_text(json.dumps(final_adv, indent=2), encoding="utf-8")
            written.append(str(p))

        if case.artifacts.cve_json_5_1 is not None:
            p = case_dir / f"{case.case_id.lower()}.cve5.json"
            p.write_text(json.dumps(case.artifacts.cve_json_5_1, indent=2), encoding="utf-8")
            written.append(str(p))

        if case.artifacts.advisory_markdown:
            p = case_dir / "ADVISORY.md"
            p.write_text(case.artifacts.advisory_markdown, encoding="utf-8")
            written.append(str(p))

        if case.remediation:
            if case.remediation.track_a.patch_diff:
                diff_p = case_dir / "remediation_track_a.diff"
                diff_p.write_text(case.remediation.track_a.patch_diff, encoding="utf-8")
                written.append(str(diff_p))
            if case.remediation.verification_harness.code:
                test_p = case_dir / Path(case.remediation.verification_harness.filename).name
                test_p.write_text(case.remediation.verification_harness.code, encoding="utf-8")
                written.append(str(test_p))

    if openvex_header is not None:
        merged_vex = dict(openvex_header)
        merged_vex["statements"] = merged_statements
        merged_path = out / "bundle.vex.json"
        merged_path.write_text(json.dumps(merged_vex, indent=2), encoding="utf-8")
        written.append(str(merged_path))

    # Export schema-drift-mapped Jira payloads (dry-run ready with deterministic idempotency keys)
    effective_run_id = run_id or audit_log.run_id
    jira_payloads = [build_jira_ticket_payload(c, run_id=effective_run_id) for c in cases]
    if jira_payloads:
        jira_path = out / "jira_tickets.json"
        jira_path.write_text(json.dumps(jira_payloads, indent=2), encoding="utf-8")
        written.append(str(jira_path))

    # Record publication event and write immutable decision_audit.yaml + .json
    audit_log.append_event(
        actor="system:publisher",
        action="bundle_published",
        summary=f"Published {len(written)} validated artifacts for {len(cases)} human-approved cases.",
        details={"output_dir": str(out), "file_count": len(written)},
    )
    audit_yaml = out / "decision_audit.yaml"
    audit_yaml.write_text(audit_log.to_yaml(), encoding="utf-8")
    written.append(str(audit_yaml))

    audit_json = out / "decision_audit.json"
    audit_json.write_text(audit_log.to_json(), encoding="utf-8")
    written.append(str(audit_json))

    if open_github_pr and os.environ.get("GITHUB_TOKEN"):
        _maybe_open_remediation_pr(cases, out)

    return written


def _maybe_open_remediation_pr(cases: list[TriageCase], out: Path) -> None:
    """Optional GitHub CLI PR creation invoked strictly post-approval."""
    affected = [c for c in cases if c.vex and c.vex.status.value == "affected"]
    if not affected:
        return
    body_path = out / "pr_body.md"
    lines = ["# PSIRT Approved Remediation Bundle", ""]
    for c in affected:
        lines.append(f"- **{c.case_id}** ({c.primary_cve_id or c.cwe_id}): approved by `{c.human_reviewer}`")
    body_path.write_text("\n".join(lines), encoding="utf-8")
    subprocess.run(
        [
            "gh",
            "pr",
            "create",
            "--title",
            f"security: PSIRT approved remediations ({len(affected)} cases)",
            "--body-file",
            str(body_path),
            "--draft",
        ],
        check=False,
    )
