"""Deterministic JSON Schema validation for OpenVEX v0.2.0, CSAF 2.0, and CVE JSON 5.1."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from psirt_engine.config import get_project_root
from psirt_engine.models.canonical import GuardrailIssue

SCHEMA_FILES: dict[str, str] = {
    "openvex": "openvex.json",
    "csaf_vex": "csaf_2.0.json",
    "csaf_advisory": "csaf_2.0.json",
    "cve_json_5_1": "cve_5.1.json",
}


@lru_cache(maxsize=8)
def _load_validator(schema_name: str, schemas_dir: str) -> Draft202012Validator:
    filename = SCHEMA_FILES[schema_name]
    schema_path = Path(schemas_dir) / filename
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _collect_csaf_product_ids(product_tree: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    for prod in product_tree.get("full_product_names", []):
        if pid := prod.get("product_id"):
            ids.add(str(pid))

    def _walk_branches(branches: list[dict[str, Any]]) -> None:
        for br in branches:
            prod = br.get("product")
            if isinstance(prod, dict) and prod.get("product_id"):
                ids.add(str(prod["product_id"]))
            if isinstance(br.get("branches"), list):
                _walk_branches(br["branches"])

    _walk_branches(product_tree.get("branches", []))
    return ids


def validate_csaf_profile_rules(doc: dict[str, Any], artifact_name: str) -> list[GuardrailIssue]:
    """Enforce OASIS CSAF 2.0 semantic profile checks beyond structural JSON Schema."""
    issues: list[GuardrailIssue] = []
    category = (doc.get("document") or {}).get("category")
    known_pids = _collect_csaf_product_ids(doc.get("product_tree") or {})

    for v_idx, vuln in enumerate(doc.get("vulnerabilities", [])):
        pstatus = vuln.get("product_status") or {}
        all_ref_pids: list[tuple[str, str]] = []
        for bucket, pids in pstatus.items():
            for pid in pids or []:
                all_ref_pids.append((f"$.vulnerabilities[{v_idx}].product_status.{bucket}", pid))
        for f_idx, flag in enumerate(vuln.get("flags") or []):
            for pid in flag.get("product_ids") or []:
                all_ref_pids.append((f"$.vulnerabilities[{v_idx}].flags[{f_idx}].product_ids", pid))
        for r_idx, rem in enumerate(vuln.get("remediations") or []):
            for pid in rem.get("product_ids") or []:
                all_ref_pids.append((f"$.vulnerabilities[{v_idx}].remediations[{r_idx}].product_ids", pid))

        for path, pid in all_ref_pids:
            if pid not in known_pids:
                issues.append(
                    GuardrailIssue(
                        gate="csaf_profile",
                        severity="error",
                        artifact=artifact_name,
                        path=path,
                        message=f"Referenced product_id '{pid}' is not declared in product_tree",
                    )
                )

        # CSAF 2.0 VEX profile: known_not_affected requires either flags or impact threat
        if category == "csaf_vex":
            not_affected = set(pstatus.get("known_not_affected") or [])
            if not_affected:
                flagged = {
                    pid
                    for fl in (vuln.get("flags") or [])
                    for pid in (fl.get("product_ids") or [])
                }
                impact_pids = {
                    pid
                    for th in (vuln.get("threats") or [])
                    if th.get("category") == "impact"
                    for pid in (th.get("product_ids") or [])
                }
                missing = not_affected - (flagged | impact_pids)
                if missing:
                    issues.append(
                        GuardrailIssue(
                            gate="csaf_profile",
                            severity="error",
                            artifact=artifact_name,
                            path=f"$.vulnerabilities[{v_idx}].product_status.known_not_affected",
                            message=f"CSAF VEX known_not_affected products {sorted(missing)} lack justification flag or impact statement",
                        )
                    )
            affected = set(pstatus.get("known_affected") or [])
            if affected and not (vuln.get("remediations") or []):
                issues.append(
                    GuardrailIssue(
                        gate="csaf_profile",
                        severity="error",
                        artifact=artifact_name,
                        path=f"$.vulnerabilities[{v_idx}].remediations",
                        message="CSAF VEX known_affected product requires at least one remediation/action statement",
                    )
                )

    return issues


def validate_artifact_schema(
    artifact_name: str,
    document: dict[str, Any],
    schemas_dir: Path | None = None,
) -> list[GuardrailIssue]:
    """Validate a generated JSON artifact against its vendored official JSON Schema."""
    if artifact_name not in SCHEMA_FILES:
        raise ValueError(f"Unknown artifact schema '{artifact_name}'")

    sdir = str((schemas_dir or (get_project_root() / "schemas")).resolve())
    validator = _load_validator(artifact_name, sdir)
    issues: list[GuardrailIssue] = []

    for err in sorted(validator.iter_errors(document), key=lambda e: list(e.path)):
        json_path = "$" + "".join(
            f"[{p}]" if isinstance(p, int) else f".{p}" for p in err.path
        )
        issues.append(
            GuardrailIssue(
                gate="json_schema",
                severity="error",
                artifact=artifact_name,
                path=json_path,
                message=err.message,
            )
        )

    if not issues and artifact_name in ("csaf_vex", "csaf_advisory"):
        issues.extend(validate_csaf_profile_rules(document, artifact_name))

    return issues
