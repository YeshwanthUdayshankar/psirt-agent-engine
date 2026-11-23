#!/usr/bin/env python3
"""Golden-dataset evaluation benchmark for psirt-agent-engine (PRD Section 6 & Interview Q8).

Computes:
  - VEX Reachability Precision, Recall, and F1
  - CWE Root-Cause Mapping Accuracy
  - CNA Assignment Rule Accuracy (on_prem vs. saas vs. third_party)
  - CISA KEV Detection Accuracy
  - Dependency Noise Reduction Rate
  - JSON Schema Pass Rate (OpenVEX, CSAF 2.0, CVE JSON 5.1)
  - Zero-Leakage Secret Redaction Rate
  - Simulated Human Edit Distance (difflib similarity ratio)
"""

from __future__ import annotations

import difflib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml

from psirt_engine.config import get_project_root
from psirt_engine.graph import build_psirt_graph
from psirt_engine.intake.sanitizer import scan_for_secret_leaks
from psirt_engine.models.canonical import TriageCase
from psirt_engine.state import open_sqlite_checkpointer


def compute_human_edit_distance(draft: str, approved: str) -> float:
    """Normalized edit distance in [0.0, 1.0]: 0.0 means zero human edits needed."""
    ratio = difflib.SequenceMatcher(None, draft, approved).ratio()
    return round(1.0 - ratio, 4)


def run_benchmark(dataset_path: Path | None = None) -> dict[str, Any]:
    root = get_project_root()
    ds_path = dataset_path or (root / "eval" / "golden_dataset.yaml")
    spec = yaml.safe_load(ds_path.read_text(encoding="utf-8"))

    tp = fp = fn = tn = 0
    cwe_correct = cwe_total = 0
    cna_correct = cna_total = 0
    kev_correct = kev_total = 0
    schema_passed = schema_total = 0
    total_leaks = 0
    noise_rates: list[float] = []
    edit_distances: list[float] = []

    with tempfile.TemporaryDirectory(prefix="psirt-eval-") as tmp:
        tmp_path = Path(tmp)
        for target in spec["targets"]:
            repo = (root / target["repo_rel_path"]).resolve()
            state_dir = tmp_path / target["name"]
            saver, conn = open_sqlite_checkpointer(state_dir)
            try:
                graph = build_psirt_graph(checkpointer=saver)
                config = {"configurable": {"thread_id": f"eval-{target['name']}"}}
                graph.invoke(
                    {
                        "run_id": f"eval-{target['name']}",
                        "repo_path": str(repo),
                        "model_profile": "offline_heuristic",
                        "deployment_mode": target.get("deployment_mode", "on_prem"),
                        "output_dir": str(tmp_path / f"out-{target['name']}"),
                        "prefer_builtin_scanners": True,
                    },
                    config=config,
                )
                vals = graph.get_state(config).values
            finally:
                conn.close()

            assert vals["redactions_performed"] >= target["expected_min_redactions"]
            assert len(vals["prompt_injection_warnings"]) >= target["expected_prompt_injections_min"]

            cases = [TriageCase.model_validate(c) for c in vals["cases"]]
            if vals["metrics"]["dependency_cases_count"] > 0:
                noise_rates.append(vals["metrics"]["noise_reduction_rate_pct"])

            for c in cases:
                schema_total += 1
                if c.guardrail_report and c.guardrail_report.passed:
                    schema_passed += 1
                if c.artifacts:
                    total_leaks += len(scan_for_secret_leaks(c.artifacts.model_dump()))
                    # Measure edit distance when PSIRT only updates Draft -> Final header line
                    draft_md = c.artifacts.advisory_markdown
                    approved_md = draft_md.replace("Published (Draft):", "Published (Final):")
                    edit_distances.append(compute_human_edit_distance(draft_md, approved_md))

            for exp in target["expected_cases"]:
                matched = _find_matching_case(cases, exp)
                assert matched is not None, f"Missing expected case {exp} in {target['name']}"

                cwe_total += 1
                if matched.cwe_id == exp["expected_cwe"]:
                    cwe_correct += 1

                cna_total += 1
                if matched.cna and matched.cna.decision.value == exp["expected_cna_decision"]:
                    cna_correct += 1

                if "expected_kev" in exp:
                    kev_total += 1
                    actual_kev = bool(matched.threat_intel and matched.threat_intel.in_cisa_kev)
                    if actual_kev == exp["expected_kev"]:
                        kev_correct += 1

                pred_aff = bool(matched.vex and matched.vex.status.value == "affected")
                exp_aff = exp["expected_vex_status"] == "affected"
                if pred_aff and exp_aff:
                    tp += 1
                elif pred_aff and not exp_aff:
                    fp += 1
                elif not pred_aff and exp_aff:
                    fn += 1
                else:
                    tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 1.0

    return {
        "vex_reachability_precision_pct": round(precision * 100.0, 1),
        "vex_reachability_recall_pct": round(recall * 100.0, 1),
        "vex_reachability_f1_pct": round(f1 * 100.0, 1),
        "cwe_accuracy_pct": round((cwe_correct / cwe_total) * 100.0, 1) if cwe_total else 0.0,
        "cna_rule_accuracy_pct": round((cna_correct / cna_total) * 100.0, 1) if cna_total else 0.0,
        "kev_accuracy_pct": round((kev_correct / kev_total) * 100.0, 1) if kev_total else 0.0,
        "avg_noise_reduction_rate_pct": round(sum(noise_rates) / len(noise_rates), 1)
        if noise_rates
        else 0.0,
        "schema_pass_rate_pct": round((schema_passed / schema_total) * 100.0, 1)
        if schema_total
        else 0.0,
        "zero_leakage_secret_leaks": total_leaks,
        "avg_human_edit_distance": round(sum(edit_distances) / len(edit_distances), 4)
        if edit_distances
        else 0.0,
        "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
    }


def _find_matching_case(cases: list[TriageCase], exp: dict[str, Any]) -> TriageCase | None:
    if "match_cve" in exp:
        return next((c for c in cases if c.primary_cve_id == exp["match_cve"]), None)
    if "match_title_contains" in exp:
        needle = exp["match_title_contains"].lower()
        return next((c for c in cases if needle in c.title.lower()), None)
    return None


def main() -> int:
    report = run_benchmark()
    print(json.dumps(report, indent=2))
    # Enforce strict quality gates in CI
    assert report["schema_pass_rate_pct"] == 100.0
    assert report["zero_leakage_secret_leaks"] == 0
    assert report["vex_reachability_f1_pct"] == 100.0
    assert report["cwe_accuracy_pct"] == 100.0
    assert report["cna_rule_accuracy_pct"] == 100.0
    return 0


if __name__ == "__main__":
    sys.exit(main())
