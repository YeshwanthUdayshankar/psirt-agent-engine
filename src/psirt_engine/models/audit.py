"""Immutable, hash-chained PSIRT decision audit log models."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

import yaml
from pydantic import BaseModel, Field


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _compute_entry_hash(payload: dict[str, Any], prev_hash: str) -> str:
    canonical = json.dumps(
        {"prev_hash": prev_hash, "payload": payload},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class HumanOverride(BaseModel):
    case_id: str
    field_path: str
    old_value: Any
    new_value: Any
    reason: str
    reviewer: str
    timestamp: str = Field(default_factory=_utc_now)


class HumanApproval(BaseModel):
    case_id: str
    reviewer: str
    decision: str  # approved | rejected | overridden
    notes: str = ""
    timestamp: str = Field(default_factory=_utc_now)
    artifact_hashes: dict[str, str] = Field(default_factory=dict)


class AuditEvent(BaseModel):
    event_id: int
    timestamp: str = Field(default_factory=_utc_now)
    actor: str
    action: str
    case_id: str | None = None
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str = ""
    entry_hash: str = ""


class DecisionAuditLog(BaseModel):
    run_id: str
    repo_path: str
    commit_sha: str
    created_at: str = Field(default_factory=_utc_now)
    model_profile: str = "ollama_local"
    sbom_sha256: str = ""
    redactions_performed: int = 0
    prompt_injection_warnings: list[str] = Field(default_factory=list)
    events: list[AuditEvent] = Field(default_factory=list)
    overrides: list[HumanOverride] = Field(default_factory=list)
    approvals: list[HumanApproval] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)

    def append_event(
        self,
        actor: str,
        action: str,
        summary: str,
        case_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        prev_hash = self.events[-1].entry_hash if self.events else "GENESIS"
        event_id = len(self.events) + 1
        timestamp = _utc_now()
        payload = {
            "event_id": event_id,
            "timestamp": timestamp,
            "actor": actor,
            "action": action,
            "case_id": case_id,
            "summary": summary,
            "details": details or {},
        }
        entry_hash = _compute_entry_hash(payload, prev_hash)
        event = AuditEvent(
            event_id=event_id,
            timestamp=timestamp,
            actor=actor,
            action=action,
            case_id=case_id,
            summary=summary,
            details=details or {},
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        self.events.append(event)
        return event

    def record_override(self, override: HumanOverride) -> None:
        self.overrides.append(override)
        self.append_event(
            actor=f"human:{override.reviewer}",
            action="human_override",
            case_id=override.case_id,
            summary=f"Overrode {override.field_path}: {override.old_value!r} -> {override.new_value!r}",
            details={
                "field_path": override.field_path,
                "old_value": override.old_value,
                "new_value": override.new_value,
                "reason": override.reason,
            },
        )

    def record_approval(self, approval: HumanApproval) -> None:
        self.approvals.append(approval)
        self.append_event(
            actor=f"human:{approval.reviewer}",
            action=f"human_{approval.decision}",
            case_id=approval.case_id,
            summary=f"Reviewer {approval.reviewer} marked case {approval.case_id} as {approval.decision}",
            details={
                "decision": approval.decision,
                "notes": approval.notes,
                "artifact_hashes": approval.artifact_hashes,
            },
        )

    def verify_integrity(self) -> tuple[bool, list[str]]:
        errors: list[str] = []
        prev_hash = "GENESIS"
        for event in self.events:
            if event.prev_hash != prev_hash:
                errors.append(
                    f"Event {event.event_id} prev_hash mismatch: expected {prev_hash}, got {event.prev_hash}"
                )
            payload = {
                "event_id": event.event_id,
                "timestamp": event.timestamp,
                "actor": event.actor,
                "action": event.action,
                "case_id": event.case_id,
                "summary": event.summary,
                "details": event.details,
            }
            expected = _compute_entry_hash(payload, event.prev_hash)
            if event.entry_hash != expected:
                errors.append(f"Event {event.event_id} entry_hash tampered or corrupted")
            prev_hash = event.entry_hash
        return (len(errors) == 0, errors)

    def to_yaml(self) -> str:
        return yaml.safe_dump(self.model_dump(mode="json"), sort_keys=False, width=110)

    def to_json(self) -> str:
        return json.dumps(self.model_dump(mode="json"), indent=2)
