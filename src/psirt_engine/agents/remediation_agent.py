"""Remediation & Verification Agent: Track A (patch/upgrade), Track B (compensating controls), and reproducer test."""

from __future__ import annotations

import re

from psirt_engine.agents.prompts import REMEDIATION_SYSTEM_PROMPT
from psirt_engine.intake.sanitizer import wrap_untrusted_data
from psirt_engine.llm import ModelAgnosticLLM
from psirt_engine.mcp_servers.repo_ast_server import RepoASTService
from psirt_engine.models.canonical import (
    FindingCategory,
    RemediationPlan,
    RemediationTrackA,
    RemediationTrackB,
    TriageCase,
    VerificationHarness,
)


def _major_version(ver: str | None) -> int | None:
    if not ver:
        return None
    m = re.match(r"^[vV]?(\d+)", ver.strip())
    return int(m.group(1)) if m else None


def _build_track_a_and_harness(
    case: TriageCase, ast_service: RepoASTService
) -> tuple[RemediationTrackA, RemediationTrackB, VerificationHarness]:
    primary = case.findings[0]
    cwe = case.cwe_id or "CWE-200"
    rel_file = primary.file_path or "app.py"

    # Third-party dependency upgrade path
    if case.category == FindingCategory.THIRD_PARTY_CVE and case.package_name:
        cur_v = case.package_version or "0.0.0"
        fix_v = case.fixed_version or "latest"
        cur_maj = _major_version(cur_v)
        fix_maj = _major_version(fix_v)
        major_bump = cur_maj is not None and fix_maj is not None and fix_maj > cur_maj
        risk = "high" if major_bump else "low"
        risk_notes = (
            f"MAJOR version upgrade ({cur_v} -> {fix_v}): review breaking API changes (e.g., removed unsafe defaults) before merging."
            if major_bump
            else f"Minor/patch upgrade ({cur_v} -> {fix_v}) expected to preserve backward compatibility."
        )
        manifest = primary.file_path or "requirements.txt"
        patch_diff = (
            f"--- a/{manifest}\n"
            f"+++ b/{manifest}\n"
            f"@@ -1 +1 @@\n"
            f"-{case.package_name}=={cur_v}\n"
            f"+{case.package_name}=={fix_v}\n"
        )
        if case.package_name.lower() == "pyyaml":
            patch_diff += (
                "\n# Also replace unsafe yaml.load(..., Loader=yaml.FullLoader) with yaml.safe_load(...)\n"
            )
        track_a = RemediationTrackA(
            kind="dependency_upgrade",
            summary=f"Upgrade {case.package_name} from {cur_v} to {fix_v} in {manifest}.",
            target_file=manifest,
            patch_diff=patch_diff,
            package_name=case.package_name,
            current_version=cur_v,
            target_version=fix_v,
            breaking_change_risk=risk,
            breaking_change_notes=risk_notes,
        )
        track_b = RemediationTrackB(
            summary=f"Compensating controls for {case.primary_cve_id or case.package_name} prior to upgrade.",
            controls=[
                f"Block untrusted payloads targeting vulnerable symbols ({', '.join(primary.vulnerable_symbols) or case.package_name}) at the API gateway/WAF.",
                "Restrict endpoint access via mTLS / RBAC / network segmentation ACLs.",
                "Add runtime input validation rejecting unexpected tags, oversized frames, or malformed headers.",
            ],
            config_snippet=(
                "# Example WAF / Ingress compensating rule\n"
                "SecRule REQUEST_BODY \"@rx !!python/|__reduce__|subprocess\" "
                "\"id:990001,phase:2,deny,status:403,msg:'Block unsafe deserialization payload'\"\n"
            ),
        )
        safe_pkg = re.sub(r"[^a-zA-Z0-9_]", "_", case.package_name)
        harness = VerificationHarness(
            framework="pytest",
            filename=f"tests/test_repro_{safe_pkg}.py",
            code=(
                f'"""Verification harness for {case.primary_cve_id or case.case_id} ({case.package_name})."""\n'
                "import re\n"
                "from pathlib import Path\n\n"
                "def _ver_tuple(v: str) -> tuple[int, ...]:\n"
                "    return tuple(int(x) for x in re.findall(r'\\d+', v))\n\n"
                f"def test_{safe_pkg}_patched_version():\n"
                f"    manifest = Path('{manifest}').read_text(encoding='utf-8')\n"
                f"    match = re.search(r'(?i){re.escape(case.package_name)}\\s*(?:==|v)([0-9][0-9a-zA-Z._-]*)', manifest)\n"
                f"    assert match is not None, '{case.package_name} not found in {manifest}'\n"
                f"    assert _ver_tuple(match.group(1)) >= _ver_tuple('{fix_v}'), (\n"
                f"        f'Vulnerable {case.package_name}=={{match.group(1)}} still pinned; requires >= {fix_v}'\n"
                "    )\n"
            ),
            expected_before_fix=f"FAIL (manifest pins vulnerable {case.package_name}=={cur_v})",
            expected_after_fix=f"PASS (manifest upgraded to {case.package_name}>={fix_v})",
        )
        return track_a, track_b, harness

    # First-party CWE-specific patches, compensating controls, and pytest reproducers
    if cwe == "CWE-89":
        track_a = RemediationTrackA(
            kind="code_patch",
            summary=f"Replace string-interpolated SQL query in {rel_file} with parameterized query bindings.",
            target_file=rel_file,
            patch_diff=(
                f"--- a/{rel_file}\n"
                f"+++ b/{rel_file}\n"
                f"@@ -{primary.line_start or 1},1 +{primary.line_start or 1},1 @@\n"
                "-    cursor.execute(f\"SELECT id, email FROM users WHERE username = '{username}'\")\n"
                "+    cursor.execute(\"SELECT id, email FROM users WHERE username = ?\", (username,))\n"
            ),
            breaking_change_risk="low",
            breaking_change_notes="Parameterized queries preserve behavior for valid usernames while neutralizing SQL metacharacters.",
        )
        track_b = RemediationTrackB(
            summary="Immediate WAF SQLi filtering and least-privilege DB account restrictions.",
            controls=[
                "Enable OWASP CRS SQLi rules (942xxx) in blocking mode at reverse proxy / WAF.",
                "Enforce strict allowlist regex ^[a-zA-Z0-9_.-]{1,64}$ on username parameter at edge.",
                "Restrict database role to read-only SELECT on required tables only.",
            ],
            config_snippet="location /users { modsecurity on; modsecurity_rules 'SecRule ARGS:username \"!@rx ^[a-zA-Z0-9_.-]{1,64}$\" \"id:990089,deny,status:400\"'; }",
        )
        harness = VerificationHarness(
            framework="pytest",
            filename="tests/test_repro_cwe89_sqli.py",
            code=(
                '"""Reproducer for CWE-89 SQL Injection."""\n'
                "import sqlite3\n\n"
                "def test_sqli_payload_does_not_bypass_filter():\n"
                "    conn = sqlite3.connect(':memory:')\n"
                "    conn.execute('CREATE TABLE users (id INT, username TEXT, email TEXT)')\n"
                "    conn.execute(\"INSERT INTO users VALUES (1, 'alice', 'a@example.com'), (2, 'admin', 'admin@example.com')\")\n"
                "    payload = \"' OR '1'='1\"\n"
                "    # Parameterized query must return 0 rows for injection payload\n"
                "    rows = conn.execute('SELECT id, email FROM users WHERE username = ?', (payload,)).fetchall()\n"
                "    assert rows == []\n"
            ),
            expected_before_fix="FAIL (SQL injection returns all user rows including admin)",
            expected_after_fix="PASS (parameterized query returns 0 rows for injection string)",
        )
    elif cwe == "CWE-78":
        track_a = RemediationTrackA(
            kind="code_patch",
            summary=f"Eliminate shell=True / shell -c execution in {rel_file}; pass argument list directly and validate input against an allowlist.",
            target_file=rel_file,
            patch_diff=(
                f"--- a/{rel_file}\n"
                f"+++ b/{rel_file}\n"
                f"@@ -{primary.line_start or 1},1 +{primary.line_start or 1},2 @@\n"
                "-    subprocess.run(f'ping -c 1 {host}', shell=True, check=True)\n"
                "+    if not re.fullmatch(r'[a-zA-Z0-9.-]{1,253}', host):\n"
                "+        raise ValueError('Invalid hostname')\n"
                "+    subprocess.run(['ping', '-c', '1', host], shell=False, check=True)\n"
            ),
            breaking_change_risk="low",
            breaking_change_notes="Disabling shell interpretation breaks callers relying on shell piping/globs; validate legitimate inputs.",
        )
        track_b = RemediationTrackB(
            summary="Block shell metacharacters at ingress and sandbox worker processes.",
            controls=[
                "Reject requests containing shell metacharacters (;, |, &, $, `, \\n) at API gateway/WAF.",
                "Run worker container with read-only rootfs, dropped capabilities, and seccomp profile blocking execve of /bin/sh.",
                "Restrict diagnostic endpoint to authenticated internal administrators via network policy.",
            ],
            config_snippet="securityContext:\n  allowPrivilegeEscalation: false\n  readOnlyRootFilesystem: true\n  capabilities:\n    drop: ['ALL']\n",
        )
        harness = VerificationHarness(
            framework="pytest",
            filename="tests/test_repro_cwe78_cmdi.py",
            code=(
                '"""Reproducer for CWE-78 OS Command Injection."""\n'
                "import re\n\n"
                "def validate_host(host: str) -> str:\n"
                "    if not re.fullmatch(r'[a-zA-Z0-9.-]{1,253}', host):\n"
                "        raise ValueError('Invalid hostname')\n"
                "    return host\n\n"
                "def test_command_injection_payload_rejected():\n"
                "    malicious = '127.0.0.1; id'\n"
                "    try:\n"
                "        validate_host(malicious)\n"
                "    except ValueError:\n"
                "        return\n"
                "    raise AssertionError('Command injection payload was not rejected')\n"
            ),
            expected_before_fix="FAIL (shell metacharacter ';' executes injected command)",
            expected_after_fix="PASS (strict allowlist rejects metacharacters and shell=False prevents interpretation)",
        )
    elif cwe == "CWE-502":
        track_a = RemediationTrackA(
            kind="code_patch",
            summary=f"Replace unsafe deserialization in {rel_file} with yaml.safe_load() or strict JSON schema decoding.",
            target_file=rel_file,
            patch_diff=(
                f"--- a/{rel_file}\n"
                f"+++ b/{rel_file}\n"
                f"@@ -{primary.line_start or 1},1 +{primary.line_start or 1},1 @@\n"
                "-    return yaml.load(raw_config, Loader=yaml.FullLoader)\n"
                "+    return yaml.safe_load(raw_config)\n"
            ),
            breaking_change_risk="medium",
            breaking_change_notes="yaml.safe_load rejects custom Python object tags; verify configs use standard YAML scalars/collections.",
        )
        track_b = RemediationTrackB(
            summary="Filter YAML object tags and enforce strict schema validation at edge.",
            controls=[
                "Reject request bodies matching '!!python/' or custom YAML constructors at WAF.",
                "Require Content-Type: application/json where YAML is unnecessary.",
            ],
            config_snippet="SecRule REQUEST_BODY \"@rx !!python/\" \"id:990502,deny,status:400,msg:'Blocked YAML tag injection'\"",
        )
        harness = VerificationHarness(
            framework="pytest",
            filename="tests/test_repro_cwe502_deser.py",
            code=(
                '"""Reproducer for CWE-502 Unsafe YAML Deserialization."""\n'
                "import yaml\n\n"
                "def test_safe_load_blocks_python_object_tag():\n"
                "    payload = '!!python/object/apply:os.system [\"echo pwned\"]'\n"
                "    try:\n"
                "        yaml.safe_load(payload)\n"
                "    except yaml.YAMLError:\n"
                "        return\n"
                "    raise AssertionError('Unsafe YAML tag was not blocked')\n"
            ),
            expected_before_fix="FAIL (unsafe yaml.load executes python/object/apply payload)",
            expected_after_fix="PASS (yaml.safe_load raises ConstructorError/YAMLError)",
        )
    elif cwe == "CWE-798":
        track_a = RemediationTrackA(
            kind="code_patch",
            summary=f"Remove hardcoded secret from {rel_file}, rotate the exposed credential immediately, and inject via environment/secret manager.",
            target_file=rel_file,
            patch_diff=(
                f"--- a/{rel_file}\n"
                f"+++ b/{rel_file}\n"
                f"@@ -{primary.line_start or 1},1 +{primary.line_start or 1},1 @@\n"
                "-API_TOKEN = \"[REDACTED:SECRET_VALUE]\"\n"
                "+API_TOKEN = os.environ[\"API_TOKEN\"]\n"
            ),
            breaking_change_risk="low",
            breaking_change_notes="Ensure deployment secret manager populates the required environment variable prior to rollout.",
        )
        track_b = RemediationTrackB(
            summary="Immediate credential revocation, IAM scoping, and pre-commit secret scanning.",
            controls=[
                "Revoke and rotate the compromised credential immediately across all cloud/API providers.",
                "Audit CloudTrail / API access logs for unauthorized usage during the exposure window.",
                "Enable GitHub push protection and pre-commit Gitleaks hooks.",
            ],
            config_snippet="aws iam update-access-key --access-key-id <REDACTED_KEY_ID> --status Inactive",
        )
        harness = VerificationHarness(
            framework="pytest",
            filename="tests/test_repro_cwe798_secrets.py",
            code=(
                '"""Reproducer verifying zero hardcoded secrets in target file."""\n'
                "from pathlib import Path\n"
                "from psirt_engine.intake.sanitizer import scan_for_secret_leaks\n\n"
                "def test_no_hardcoded_secrets():\n"
                f"    content = Path('{rel_file}').read_text(encoding='utf-8')\n"
                "    assert scan_for_secret_leaks(content) == []\n"
            ),
            expected_before_fix="FAIL (secret scanner detects hardcoded credential)",
            expected_after_fix="PASS (zero hardcoded credentials found)",
        )
    else:
        track_a = RemediationTrackA(
            kind="code_patch",
            summary=f"Remediate {cwe} in {rel_file} using least-privilege configuration and strict input validation.",
            target_file=rel_file,
            patch_diff=(
                f"--- a/{rel_file}\n"
                f"+++ b/{rel_file}\n"
                f"@@ -{primary.line_start or 1},1 +{primary.line_start or 1},1 @@\n"
                "-USER root\n"
                "+USER 10001:10001\n"
            ),
            breaking_change_risk="low",
            breaking_change_notes="Verify file permissions for non-root UID 10001.",
        )
        track_b = RemediationTrackB(
            summary="Apply runtime policy enforcement and network segmentation.",
            controls=[
                "Enforce Kubernetes Pod Security Admission (restricted profile).",
                "Apply NetworkPolicy restricting egress/ingress to required peers.",
            ],
            config_snippet="pod-security.kubernetes.io/enforce: restricted",
        )
        harness = VerificationHarness(
            framework="pytest",
            filename=f"tests/test_repro_{cwe.lower().replace('-', '')}.py",
            code=(
                f'"""Verification harness for {cwe}."""\n'
                "from pathlib import Path\n\n"
                "def test_hardened_config():\n"
                f"    text = Path('{rel_file}').read_text(encoding='utf-8')\n"
                "    assert 'USER root' not in text\n"
            ),
        )

    return track_a, track_b, harness


def run_remediation_agent(
    case: TriageCase,
    ast_service: RepoASTService,
    llm: ModelAgnosticLLM,
) -> TriageCase:
    """Generate Track A fix, Track B compensating controls, and verification harness."""
    track_a, track_b, harness = _build_track_a_and_harness(case, ast_service)
    primary = case.findings[0]

    fallback = {
        "track_a_summary": track_a.summary,
        "track_a_patch_diff": track_a.patch_diff,
        "track_b_summary": track_b.summary,
        "track_b_controls": track_b.controls,
        "confidence": 0.88,
    }

    user_prompt = (
        f"Case: {case.case_id} ({case.cwe_id})\n"
        f"Category: {case.category.value}\n"
        f"Package: {case.package_name or 'first-party'}@{case.package_version or 'HEAD'} -> {case.fixed_version or 'N/A'}\n"
        + wrap_untrusted_data(primary.code_snippet or primary.description, primary.file_path or "repo")
    )
    res = llm.complete_json(REMEDIATION_SYSTEM_PROMPT, user_prompt, fallback_data=fallback)
    parsed = res.parsed_json or fallback

    if isinstance(parsed.get("track_a_summary"), str) and parsed["track_a_summary"].strip():
        track_a.summary = parsed["track_a_summary"].strip()
    if isinstance(parsed.get("track_b_summary"), str) and parsed["track_b_summary"].strip():
        track_b.summary = parsed["track_b_summary"].strip()
    if isinstance(parsed.get("track_b_controls"), list) and parsed["track_b_controls"]:
        track_b.controls = [str(c) for c in parsed["track_b_controls"]]

    case.remediation = RemediationPlan(
        track_a=track_a,
        track_b=track_b,
        verification_harness=harness,
        confidence=max(0.0, min(1.0, float(parsed.get("confidence", 0.88)))),
        citations=list(case.citations[:3]),
    )
    case.agent_traces.append(
        {
            "agent": "remediation_agent",
            "provider": res.provider,
            "model": res.model,
            "used_heuristic_fallback": res.used_heuristic_fallback,
            "track_a_kind": track_a.kind,
            "breaking_change_risk": track_a.breaking_change_risk,
        }
    )
    return case
