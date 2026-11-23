"""Deterministic CVE Program CNA Assignment Rules Engine (Section 7 Counting Rules).

Encodes core CNA governance decisions:
1. Third-party dependency CVEs -> DO NOT mint duplicate CVE; reference upstream CVE + publish VEX.
2. Not-affected findings -> DO NOT mint CVE; emit OpenVEX/CSAF VEX not_affected statement.
3. Multi-tenant SaaS backend flaws (zero customer action) -> Excluded from CVE assignment under CNA rules.
4. On-prem / hybrid customer-deployed first-party flaws -> Assign new CVE (split by distinct root-cause CWE/code path).
5. Hardcoded repo secrets -> Credential rotation / secret hygiene workflow (not a product CVE unless universal default backdoor).
"""

from __future__ import annotations

from psirt_engine.models.canonical import (
    CNAAssessment,
    CNADecision,
    DeploymentMode,
    FindingCategory,
    TriageCase,
    VEXStatus,
)


def evaluate_cna_assignment(
    case: TriageCase, deployment_mode: DeploymentMode = DeploymentMode.ON_PREM
) -> CNAAssessment:
    """Deterministically decide whether a TriageCase warrants a new CVE under CNA rules."""
    vex_status = case.vex.status if case.vex else VEXStatus.UNDER_INVESTIGATION

    if vex_status == VEXStatus.NOT_AFFECTED:
        return CNAAssessment(
            decision=CNADecision.NO_CVE_NOT_AFFECTED,
            deployment_mode=deployment_mode,
            rationale=(
                "Triaged as not_affected via AST reachability analysis. Do not mint a CVE; "
                "publish OpenVEX/CSAF VEX not_affected statement to suppress downstream SBOM noise."
            ),
            split_group=f"vex-only:{case.case_id}",
        )

    if case.category == FindingCategory.THIRD_PARTY_CVE:
        upstream = case.primary_cve_id or "upstream advisory"
        return CNAAssessment(
            decision=CNADecision.REFERENCE_UPSTREAM_CVE,
            deployment_mode=deployment_mode,
            rationale=(
                f"Root cause resides in third-party dependency ({case.package_name}@{case.package_version}) "
                f"already tracked under {upstream}. Per CVE Program CNA counting rules, do not mint "
                f"a duplicate CVE; reference upstream ID and publish product VEX/CSAF."
            ),
            split_group=f"upstream:{upstream}:{case.package_name}",
        )

    if case.category == FindingCategory.SECRET:
        return CNAAssessment(
            decision=CNADecision.NO_CVE_SECRET_HYGIENE,
            deployment_mode=deployment_mode,
            rationale=(
                "Hardcoded credential detected in repository source. Route to immediate credential "
                "revocation/rotation workflow; only escalate to a CVE if the static secret ships as "
                "a universal hardcoded backdoor across customer releases."
            ),
            split_group=f"secret:{case.case_id}",
        )

    # First-party SAST / IaC affected vulnerability: apply SaaS vs. On-Prem/Hybrid CNA rule
    primary_file = case.findings[0].file_path if case.findings else "product"
    split_key = f"root-cause:{case.cwe_id or 'CWE-UNKNOWN'}:{primary_file}"

    if deployment_mode == DeploymentMode.SAAS:
        return CNAAssessment(
            decision=CNADecision.NO_CVE_SAAS_EXCLUDED,
            deployment_mode=deployment_mode,
            rationale=(
                "Deployment mode is multi-tenant SaaS where the vendor patches the backend centrally "
                "with zero customer action required. Per CVE Program CNA rules, vendor-managed cloud/SaaS "
                "vulnerabilities are excluded from CVE issuance; remediate via push rollout, run "
                "centralized log forensics (IoAs), and issue targeted customer notice if SLA-impacting."
            ),
            split_group=split_key,
        )

    return CNAAssessment(
        decision=CNADecision.ASSIGN_NEW_CVE,
        deployment_mode=deployment_mode,
        rationale=(
            f"Confirmed first-party affected vulnerability ({case.cwe_id or 'unclassified'}) in "
            f"{deployment_mode.value} customer-deployed software requiring customer patch/action. "
            f"Warrants CNA CVE assignment (CVE JSON 5.1 draft) under independent root-cause group '{split_key}'."
        ),
        split_group=split_key,
    )
