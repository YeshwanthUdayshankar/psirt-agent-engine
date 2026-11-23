"""LangGraph TypedDict state and SQLite checkpoint persistence."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, TypedDict

from langgraph.checkpoint.sqlite import SqliteSaver


class PSIRTGraphState(TypedDict, total=False):
    run_id: str
    repo_path: str
    commit_sha: str
    model_profile: str
    deployment_mode: str  # on_prem | hybrid | saas
    output_dir: str
    extra_scanner_reports: list[str]
    prefer_builtin_scanners: bool

    # Lifecycle stage tracking
    current_stage: str  # 1_SCAN_AND_SANITIZE .. 7_PUBLISHED | CLOSED

    # Layer 1 outputs (serialized dicts for clean SQLite checkpointing)
    sbom: dict[str, Any]
    sbom_sha256: str
    sbom_components: list[dict[str, Any]]
    raw_findings_count: int
    scanners_used: list[str]
    scanner_warnings: list[str]
    redactions_performed: int
    prompt_injection_warnings: list[str]

    # Consolidated cases across Layers 2, 3, 4
    cases: list[dict[str, Any]]

    # Layer 3 Guardrail loop control
    guardrail_retry_count: int
    guardrails_passed: bool

    # Layer 4 HITL Review state
    human_review_completed: bool
    human_reviewer: str
    human_decision: str  # pending | approved | overridden | rejected
    human_notes: str
    recheck_requested: bool

    # Audit log & published outputs
    audit_log: dict[str, Any]
    published_files: list[str]
    metrics: dict[str, Any]


def open_sqlite_checkpointer(state_dir: Path) -> tuple[SqliteSaver, sqlite3.Connection]:
    """Open a persistent SQLite checkpointer for local CLI or CI/CD artifact state."""
    state_dir.mkdir(parents=True, exist_ok=True)
    db_path = state_dir / "checkpoints.db"
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    saver = SqliteSaver(conn)
    saver.setup()
    return saver, conn
