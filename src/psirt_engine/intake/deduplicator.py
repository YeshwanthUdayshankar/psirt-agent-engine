"""FR-1.3 Semantic & Structural Deduplication into consolidated TriageCase objects."""

from __future__ import annotations

import hashlib
import re

from psirt_engine.models.canonical import CanonicalFinding, FindingCategory, TriageCase


def _tokenize(text: str) -> set[str]:
    return {t for t in re.findall(r"[a-z0-9_]{3,}", text.lower())}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _structural_key(f: CanonicalFinding) -> str:
    if f.category == FindingCategory.THIRD_PARTY_CVE:
        vuln_id = f.cve_id or f.ghsa_id or f.title.lower()
        pkg = (f.package_name or "unknown").lower()
        ver = f.package_version or "unknown"
        return f"cve::{vuln_id}::{pkg}@{ver}"
    if f.category == FindingCategory.SECRET:
        rule = str(f.metadata.get("rule_id") or "secret")
        return f"secret::{f.file_path or 'unknown'}::{rule}"
    # First-party SAST / IaC: cluster by file + CWE (or symbol) + 5-line window
    cwe = f.cwe_ids[0] if f.cwe_ids else (f.symbol or "generic")
    bucket = (f.line_start or 0) // 5
    return f"sast::{f.file_path or 'unknown'}::{cwe}::L{bucket}"


def deduplicate_findings(
    findings: list[CanonicalFinding], semantic_threshold: float = 0.65
) -> list[TriageCase]:
    """Cluster duplicate findings structurally and semantically into TriageCases."""
    clusters: list[tuple[str, list[CanonicalFinding]]] = []
    key_to_idx: dict[str, int] = {}

    for finding in findings:
        skey = _structural_key(finding)
        if skey in key_to_idx:
            clusters[key_to_idx[skey]][1].append(finding)
            continue

        # Secondary semantic check for same-file SAST findings from different scanners
        merged = False
        if finding.category == FindingCategory.FIRST_PARTY_SAST and finding.file_path:
            f_tokens = _tokenize(f"{finding.title} {finding.description}")
            for _, group in clusters:
                rep = group[0]
                if (
                    rep.category == FindingCategory.FIRST_PARTY_SAST
                    and rep.file_path == finding.file_path
                    and abs((rep.line_start or 0) - (finding.line_start or 0)) <= 5
                ):
                    r_tokens = _tokenize(f"{rep.title} {rep.description}")
                    if _jaccard(f_tokens, r_tokens) >= semantic_threshold:
                        group.append(finding)
                        merged = True
                        break
        if not merged:
            key_to_idx[skey] = len(clusters)
            clusters.append((skey, [finding]))

    cases: list[TriageCase] = []
    for idx, (skey, group) in enumerate(clusters, start=1):
        primary = group[0]
        digest = hashlib.sha256(skey.encode("utf-8")).hexdigest()[:6].upper()
        case_id = f"PSIRT-{idx:03d}-{digest}"

        # Pick richest metadata across merged duplicates
        cve_id = next((f.cve_id for f in group if f.cve_id), None)
        cwe_id = next((f.cwe_ids[0] for f in group if f.cwe_ids), None)
        fixed_ver = next((f.fixed_version for f in group if f.fixed_version), None)
        purl = next((f.purl for f in group if f.purl), None)

        cases.append(
            TriageCase(
                case_id=case_id,
                cluster_key=skey,
                title=primary.title,
                category=primary.category,
                findings=group,
                primary_cve_id=cve_id,
                package_name=primary.package_name,
                package_version=primary.package_version,
                fixed_version=fixed_ver,
                purl=purl,
                cwe_id=cwe_id,
            )
        )

    return cases
