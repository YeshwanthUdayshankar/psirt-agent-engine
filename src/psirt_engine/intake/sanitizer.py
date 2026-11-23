"""Deterministic secret/PII redaction and prompt-injection isolation (NFR-1 & NFR-2).

Zero LLM involvement. Runs strictly before any repository text or scanner output enters
agent context, and again inside Layer 3 Guardrails to verify zero secret leakage.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from psirt_engine.models.canonical import CanonicalFinding


@dataclass(frozen=True)
class SecretPattern:
    rule_id: str
    regex: re.Pattern[str]
    replacement: str


SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        "aws_access_key_id",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "[REDACTED:AWS_ACCESS_KEY_ID]",
    ),
    SecretPattern(
        "aws_secret_access_key",
        re.compile(
            r"""(?i)(aws[_-]?secret[_-]?(?:access[_-]?)?key\s*[:=]\s*['"]?)([A-Za-z0-9/+=]{40})(['"]?)"""
        ),
        r"\1[REDACTED:AWS_SECRET_ACCESS_KEY]\3",
    ),
    SecretPattern(
        "github_pat",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,255}\b"),
        "[REDACTED:GITHUB_TOKEN]",
    ),
    SecretPattern(
        "github_fine_grained_pat",
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b"),
        "[REDACTED:GITHUB_FINE_GRAINED_TOKEN]",
    ),
    SecretPattern(
        "anthropic_api_key",
        re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b"),
        "[REDACTED:ANTHROPIC_API_KEY]",
    ),
    SecretPattern(
        "openai_api_key",
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9\-_]{20,}\b"),
        "[REDACTED:OPENAI_API_KEY]",
    ),
    SecretPattern(
        "google_api_key",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        "[REDACTED:GOOGLE_API_KEY]",
    ),
    SecretPattern(
        "slack_token",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
        "[REDACTED:SLACK_TOKEN]",
    ),
    SecretPattern(
        "stripe_key",
        re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b"),
        "[REDACTED:STRIPE_KEY]",
    ),
    SecretPattern(
        "jwt_token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        "[REDACTED:JWT_TOKEN]",
    ),
    SecretPattern(
        "pem_private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----.*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[REDACTED:PRIVATE_KEY_BLOCK]",
    ),
    SecretPattern(
        "uri_credentials",
        re.compile(r"\b((?:postgres|postgresql|mysql|mongodb|redis|amqp|https?)://[^:\s/]+:)([^@\s/]+)(@)"),
        r"\1[REDACTED:URI_PASSWORD]\3",
    ),
    SecretPattern(
        "generic_secret_assignment",
        re.compile(
            r"""(?i)((?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|db[_-]?password|password)\s*[:=]\s*['"])([^'"\n]{8,})(['"])"""
        ),
        r"\1[REDACTED:SECRET_VALUE]\3",
    ),
    SecretPattern(
        "pii_ssn",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "[REDACTED:PII_SSN]",
    ),
)

PROMPT_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "ignore_previous_instructions",
        re.compile(r"(?i)ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions"),
    ),
    (
        "force_not_affected_override",
        re.compile(r"(?i)(?:mark|classify|set)\s+(?:this|all|every).*?(?:not_affected|false\s+positive|safe)"),
    ),
    (
        "system_prompt_exfiltration",
        re.compile(r"(?i)(?:reveal|print|dump|exfiltrate)\s+(?:your\s+)?(?:system\s+prompt|secrets|env|credentials)"),
    ),
    (
        "tool_hijack_directive",
        re.compile(r"(?i)(?:execute\s+shell|run\s+bash|curl\s+http|push\s+commit|bypass\s+approval|skip\s+human)"),
    ),
    (
        "xml_fence_breakout",
        re.compile(r"(?i)</\s*untrusted_repo_data\s*>"),
    ),
)


@dataclass
class RedactionHit:
    rule_id: str
    fingerprint: str  # SHA-256 prefix of matched value; raw value is never persisted.


def redact_secrets_and_pii(text: str) -> tuple[str, list[RedactionHit]]:
    """Deterministically redact secrets and PII from arbitrary text."""
    if not text:
        return text, []

    hits: list[RedactionHit] = []
    current = text

    for pattern in SECRET_PATTERNS:
        matches = list(pattern.regex.finditer(current))
        if not matches:
            continue
        for match in matches:
            # Never store raw secret in audit logs; store only a short hash fingerprint.
            matched_val = match.group(0)
            if "[REDACTED:" in matched_val:
                continue
            fp = hashlib.sha256(matched_val.encode("utf-8")).hexdigest()[:12]
            hits.append(RedactionHit(rule_id=pattern.rule_id, fingerprint=fp))
        current = pattern.regex.sub(pattern.replacement, current)

    return current, hits


def detect_prompt_injection_patterns(text: str) -> list[str]:
    """Identify suspected prompt-injection payloads embedded in untrusted repository data."""
    if not text:
        return []
    detected: list[str] = []
    for name, regex in PROMPT_INJECTION_PATTERNS:
        if regex.search(text):
            detected.append(name)
    return detected


def wrap_untrusted_data(content: str, source_label: str) -> str:
    """Wrap repository text in non-escapable XML fences after redacting secrets.

    Escapes any embedded closing tag to neutralize fence-breakout attacks.
    """
    redacted, _ = redact_secrets_and_pii(content)
    safe_body = re.sub(
        r"(?i)</\s*untrusted_repo_data\s*>",
        "&lt;/untrusted_repo_data&gt;",
        redacted,
    )
    safe_label = re.sub(r'["<>]', "_", source_label)
    return (
        f'<untrusted_repo_data source="{safe_label}" trust_level="untrusted">\n'
        f"{safe_body}\n"
        f"</untrusted_repo_data>"
    )


def sanitize_findings(
    findings: list[CanonicalFinding],
) -> tuple[list[CanonicalFinding], int, list[str]]:
    """Sanitize all CanonicalFinding fields before they enter Layer 2 agents."""
    sanitized: list[CanonicalFinding] = []
    total_redactions = 0
    injection_warnings: list[str] = []

    for finding in findings:
        data = finding.model_dump()
        for field_name in ("title", "description", "code_snippet"):
            val = data.get(field_name)
            if isinstance(val, str) and val:
                inj = detect_prompt_injection_patterns(val)
                if inj:
                    injection_warnings.append(
                        f"{finding.finding_id}:{field_name} matched {','.join(inj)}"
                    )
                clean, hits = redact_secrets_and_pii(val)
                data[field_name] = clean
                total_redactions += len(hits)

        if isinstance(data.get("metadata"), dict):
            clean_meta, meta_redactions, meta_inj = _sanitize_obj(
                data["metadata"], prefix=finding.finding_id
            )
            data["metadata"] = clean_meta
            total_redactions += meta_redactions
            injection_warnings.extend(meta_inj)

        sanitized.append(CanonicalFinding.model_validate(data))

    return sanitized, total_redactions, injection_warnings


def _sanitize_obj(obj: Any, prefix: str = "") -> tuple[Any, int, list[str]]:
    if isinstance(obj, str):
        inj = [f"{prefix}:{name}" for name in detect_prompt_injection_patterns(obj)]
        clean, hits = redact_secrets_and_pii(obj)
        return clean, len(hits), inj
    if isinstance(obj, list):
        items = []
        total = 0
        warnings: list[str] = []
        for idx, item in enumerate(obj):
            c, r, w = _sanitize_obj(item, prefix=f"{prefix}[{idx}]")
            items.append(c)
            total += r
            warnings.extend(w)
        return items, total, warnings
    if isinstance(obj, dict):
        out = {}
        total = 0
        warnings = []
        for k, v in obj.items():
            c, r, w = _sanitize_obj(v, prefix=f"{prefix}.{k}")
            out[k] = c
            total += r
            warnings.extend(w)
        return out, total, warnings
    return obj, 0, []


def scan_repo_for_prompt_injections(repo_path: Path) -> list[str]:
    """Scan text source/doc files in the target repo for embedded prompt-injection payloads."""
    ignore_dirs = {".git", ".venv", "venv", "node_modules", "__pycache__", ".psirt-state", "dist", "build"}
    text_exts = {".py", ".go", ".js", ".ts", ".md", ".txt", ".yaml", ".yml", ".json", ".toml", ".sh", ""}
    warnings: list[str] = []
    root = repo_path.resolve()
    for p in sorted(root.rglob("*")):
        if p.is_dir() or any(part in ignore_dirs for part in p.parts):
            continue
        if p.suffix.lower() not in text_exts and p.name != "Dockerfile":
            continue
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        hits = detect_prompt_injection_patterns(content)
        if hits:
            rel = str(p.relative_to(root))
            warnings.append(f"{rel}: matched {','.join(hits)}")
    return warnings


def scan_for_secret_leaks(obj: Any, path: str = "$") -> list[str]:
    """Deterministically verify no raw secrets exist anywhere in a nested object or string."""
    leaks: list[str] = []
    if isinstance(obj, str):
        for pattern in SECRET_PATTERNS:
            for match in pattern.regex.finditer(obj):
                if "[REDACTED:" not in match.group(0):
                    leaks.append(f"{path} matched {pattern.rule_id}")
                    break
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            leaks.extend(scan_for_secret_leaks(item, f"{path}[{idx}]"))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            leaks.extend(scan_for_secret_leaks(v, f"{path}.{k}"))
    return leaks
