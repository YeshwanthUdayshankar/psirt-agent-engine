"""Layer 1: Deterministic subprocess scanner adapters + built-in fallback scanners.

Integrates Syft (SBOM), Grype / OSV-Scanner (third-party CVEs), Semgrep (SAST),
and Gitleaks (secrets). When external scanner binaries are not installed on PATH,
cleanly falls back to deterministic local parsers/scanners so the full pipeline
runs offline and in CI without requiring external tooling.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from psirt_engine.intake.sanitizer import SECRET_PATTERNS
from psirt_engine.models.canonical import CanonicalFinding, FindingCategory, SBOMComponent


@dataclass
class ScanResult:
    repo_path: str
    commit_sha: str
    sbom: dict[str, Any]
    sbom_sha256: str
    components: list[SBOMComponent]
    findings: list[CanonicalFinding]
    scanners_used: list[str] = field(default_factory=list)
    scanner_warnings: list[str] = field(default_factory=list)


# Curated local vulnerability database used when grype/osv-scanner are unavailable
# or during offline evaluation/testing.
BUILTIN_VULN_DB: dict[str, list[dict[str, Any]]] = {
    "pyyaml": [
        {
            "cve_id": "CVE-2020-14343",
            "ghsa_id": "GHSA-8q59-q68h-6hv4",
            "affected_below": "5.4",
            "fixed_version": "6.0.1",
            "cwe_ids": ["CWE-502"],
            "raw_severity": "CRITICAL",
            "raw_cvss_score": 9.8,
            "raw_cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "title": "PyYAML arbitrary code execution via unsafe yaml.load / FullLoader",
            "description": "PyYAML versions prior to 5.4 allow arbitrary code execution when processing untrusted YAML via full_load or FullLoader.",
            "vulnerable_symbols": ["yaml.load", "yaml.full_load", "yaml.unsafe_load", "FullLoader"],
            "import_names": ["yaml"],
        }
    ],
    "jinja2": [
        {
            "cve_id": "CVE-2024-34064",
            "ghsa_id": "GHSA-h75v-3vvj-5mfj",
            "affected_below": "3.1.4",
            "fixed_version": "3.1.4",
            "cwe_ids": ["CWE-79"],
            "raw_severity": "MEDIUM",
            "raw_cvss_score": 6.1,
            "raw_cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N",
            "title": "Jinja2 xmlattr filter HTML attribute injection (XSS)",
            "description": "Jinja2 xmlattr filter accepts keys containing non-attribute characters allowing XSS when rendering untrusted keys.",
            "vulnerable_symbols": ["xmlattr", "do_xmlattr"],
            "import_names": ["jinja2"],
        }
    ],
    "urllib3": [
        {
            "cve_id": "CVE-2023-45803",
            "ghsa_id": "GHSA-g4mx-q9vg-27p4",
            "affected_below": "2.0.7",
            "fixed_version": "2.2.2",
            "cwe_ids": ["CWE-200"],
            "raw_severity": "MEDIUM",
            "raw_cvss_score": 4.2,
            "raw_cvss_vector": "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
            "title": "urllib3 request body not stripped on HTTP 303 redirect",
            "description": "urllib3 does not remove the HTTP request body when an HTTP redirect response using status 301, 302, or 303 is received.",
            "vulnerable_symbols": ["PoolManager", "HTTPConnectionPool", "request"],
            "import_names": ["urllib3"],
        }
    ],
    "pillow": [
        {
            "cve_id": "CVE-2023-50447",
            "ghsa_id": "GHSA-3f63-hfp8-52jq",
            "affected_below": "10.2.0",
            "fixed_version": "10.3.0",
            "cwe_ids": ["CWE-94"],
            "raw_severity": "HIGH",
            "raw_cvss_score": 8.1,
            "raw_cvss_vector": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "title": "Pillow ImageMath.eval arbitrary code execution",
            "description": "Pillow through 10.1.0 allows arbitrary code execution via the environment parameter of PIL.ImageMath.eval.",
            "vulnerable_symbols": ["ImageMath.eval", "ImageMath"],
            "import_names": ["PIL", "ImageMath"],
        }
    ],
    "requests": [
        {
            "cve_id": "CVE-2023-32681",
            "ghsa_id": "GHSA-j8r2-6x86-q33q",
            "affected_below": "2.31.0",
            "fixed_version": "2.32.3",
            "cwe_ids": ["CWE-200"],
            "raw_severity": "MEDIUM",
            "raw_cvss_score": 6.1,
            "raw_cvss_vector": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            "title": "Requests Proxy-Authorization header leaked to destination servers on redirect",
            "description": "Requests leaks Proxy-Authorization headers to destination servers when redirected to an HTTPS endpoint.",
            "vulnerable_symbols": ["requests.get", "requests.post", "requests.Session"],
            "import_names": ["requests"],
        }
    ],
    "golang.org/x/net": [
        {
            "cve_id": "CVE-2023-44487",
            "ghsa_id": "GHSA-qppj-fm5r-hxr3",
            "affected_below": "0.17.0",
            "fixed_version": "0.23.0",
            "cwe_ids": ["CWE-400"],
            "raw_severity": "HIGH",
            "raw_cvss_score": 7.5,
            "raw_cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
            "title": "HTTP/2 Rapid Reset Denial of Service in golang.org/x/net/http2",
            "description": "The HTTP/2 protocol allows rapid stream resets causing excessive server resource consumption.",
            "vulnerable_symbols": ["http2.ConfigureServer", "http2.Server"],
            "import_names": ["golang.org/x/net/http2"],
        }
    ],
    "golang.org/x/crypto": [
        {
            "cve_id": "CVE-2024-45337",
            "ghsa_id": "GHSA-v778-237x-gjrc",
            "affected_below": "0.31.0",
            "fixed_version": "0.31.0",
            "cwe_ids": ["CWE-287"],
            "raw_severity": "CRITICAL",
            "raw_cvss_score": 9.1,
            "raw_cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
            "title": "Misuse of ServerConfig.PublicKeyCallback in golang.org/x/crypto/ssh",
            "description": "Applications using PublicKeyCallback may make authorization decisions based on unauthenticated public keys.",
            "vulnerable_symbols": ["ssh.ServerConfig", "PublicKeyCallback"],
            "import_names": ["golang.org/x/crypto/ssh"],
        }
    ],
}


# Deterministic SAST rules used when Semgrep is not installed on PATH.
BUILTIN_SAST_RULES: list[dict[str, Any]] = [
    {
        "id": "psirt.python.sql-injection-fstring",
        "extensions": (".py",),
        "regex": re.compile(
            r"""cursor\.execute\(\s*(?:f["'].*?(?:SELECT|INSERT|UPDATE|DELETE).*?\{|["'].*?(?:SELECT|INSERT|UPDATE|DELETE).*?["']\s*(?:\+|%|\.format\())""",
            re.IGNORECASE,
        ),
        "title": "SQL Injection via unsanitized string interpolation in SQL query",
        "description": "User-controlled input is interpolated directly into an SQL query string passed to cursor.execute().",
        "cwe_ids": ["CWE-89"],
        "raw_severity": "HIGH",
        "raw_cvss_score": 8.6,
        "symbol_hint": "cursor.execute",
    },
    {
        "id": "psirt.python.os-command-injection",
        "extensions": (".py",),
        "regex": re.compile(
            r"""(?:subprocess\.(?:run|Popen|call|check_output)\([^\n]*shell\s*=\s*True|os\.system\()"""
        ),
        "title": "OS Command Injection via shell=True or os.system",
        "description": "Executing shell commands with shell=True or os.system() allows arbitrary command execution if untrusted input reaches the command string.",
        "cwe_ids": ["CWE-78"],
        "raw_severity": "CRITICAL",
        "raw_cvss_score": 9.3,
        "symbol_hint": "subprocess.run",
    },
    {
        "id": "psirt.python.unsafe-yaml-load",
        "extensions": (".py",),
        "regex": re.compile(r"""yaml\.load\([^)]*(?:Loader\s*=\s*yaml\.(?:Loader|UnsafeLoader|FullLoader)|,\s*Loader\s*=|\))"""),
        "exclude_regex": re.compile(r"""SafeLoader|CSafeLoader|yaml\.safe_load"""),
        "title": "Unsafe YAML deserialization using yaml.load",
        "description": "Calling yaml.load() without SafeLoader can instantiate arbitrary Python objects and execute code.",
        "cwe_ids": ["CWE-502"],
        "raw_severity": "CRITICAL",
        "raw_cvss_score": 9.3,
        "symbol_hint": "yaml.load",
    },
    {
        "id": "psirt.python.pickle-deserialization",
        "extensions": (".py",),
        "regex": re.compile(r"""pickle\.loads?\("""),
        "title": "Insecure Deserialization via Python pickle",
        "description": "Deserializing untrusted bytes with pickle.loads/load enables arbitrary code execution.",
        "cwe_ids": ["CWE-502"],
        "raw_severity": "HIGH",
        "raw_cvss_score": 8.7,
        "symbol_hint": "pickle.loads",
    },
    {
        "id": "psirt.go.command-injection",
        "extensions": (".go",),
        "regex": re.compile(r"""exec\.Command\(\s*"(?:sh|bash)"\s*,\s*"-c"\s*,"""),
        "title": "OS Command Injection via exec.Command with shell -c",
        "description": "Passing dynamic strings to sh -c via exec.Command allows shell metacharacter injection.",
        "cwe_ids": ["CWE-78"],
        "raw_severity": "HIGH",
        "raw_cvss_score": 8.6,
        "symbol_hint": "exec.Command",
    },
    {
        "id": "psirt.iac.dockerfile-root",
        "extensions": ("Dockerfile",),
        "regex": re.compile(r"""^\s*USER\s+root\s*$""", re.IGNORECASE),
        "title": "Container explicitly configured to run as root user",
        "description": "Running container workloads as root expands blast radius on container escape or RCE.",
        "cwe_ids": ["CWE-250"],
        "raw_severity": "MEDIUM",
        "raw_cvss_score": 5.3,
        "symbol_hint": "USER root",
    },
]


def get_git_commit_sha(repo_path: Path) -> str:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        ).strip()
        if out:
            return out
    except (OSError, subprocess.SubprocessError):
        out = ""
    # Deterministic content digest fallback when target is not a git repo
    digest = hashlib.sha256(str(repo_path.resolve()).encode("utf-8")).hexdigest()[:12]
    return f"uncommitted-{digest}"


def _parse_version_tuple(version_str: str) -> tuple[int, ...]:
    cleaned = version_str.strip().lstrip("vV")
    nums = re.findall(r"\d+", cleaned)
    return tuple(int(n) for n in nums) if nums else (0,)


def _version_lt(a: str, b: str) -> bool:
    ta = _parse_version_tuple(a)
    tb = _parse_version_tuple(b)
    max_len = max(len(ta), len(tb))
    ta = ta + (0,) * (max_len - len(ta))
    tb = tb + (0,) * (max_len - len(tb))
    return ta < tb


def _make_finding_id(seed: str) -> str:
    return "FND-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:10].upper()


def _iter_repo_files(repo_path: Path) -> list[Path]:
    ignore_dirs = {".git", ".venv", "venv", "node_modules", "__pycache__", ".psirt-state", "dist", "build"}
    files: list[Path] = []
    for p in sorted(repo_path.rglob("*")):
        if p.is_dir():
            continue
        if any(part in ignore_dirs for part in p.parts):
            continue
        files.append(p)
    return files


def _run_syft(repo_path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not shutil.which("syft"):
        return None, "syft not installed; using built-in CycloneDX SBOM generator"
    try:
        proc = subprocess.run(
            ["syft", f"dir:{repo_path}", "-o", "cyclonedx-json"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return json.loads(proc.stdout), None
        return None, f"syft failed (exit {proc.returncode}): {proc.stderr.strip()[:200]}"
    except Exception as exc:  # noqa: BLE001
        return None, f"syft error: {exc}"


def _extract_components_from_manifests(repo_path: Path) -> list[SBOMComponent]:
    components: list[SBOMComponent] = []
    seen: set[tuple[str, str]] = set()

    # 1. Python requirements*.txt
    for req_file in sorted(repo_path.rglob("requirements*.txt")):
        if ".venv" in req_file.parts or "node_modules" in req_file.parts:
            continue
        rel = str(req_file.relative_to(repo_path))
        for raw_line in req_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:==|~=|>=|<=)\s*([A-Za-z0-9_.\-]+)", line)
            if not m:
                continue
            name, ver = m.group(1), m.group(2)
            key = (name.lower(), ver)
            if key in seen:
                continue
            seen.add(key)
            purl = f"pkg:pypi/{name.lower()}@{ver}"
            components.append(
                SBOMComponent(
                    name=name.lower(),
                    version=ver,
                    purl=purl,
                    ecosystem="pypi",
                    bom_ref=purl,
                    manifest_path=rel,
                    direct="transitive" not in raw_line.lower(),
                )
            )

    # 2. Go go.mod
    for gomod in sorted(repo_path.rglob("go.mod")):
        rel = str(gomod.relative_to(repo_path))
        in_require = False
        for raw_line in gomod.read_text(encoding="utf-8", errors="replace").splitlines():
            stripped = raw_line.strip()
            if stripped.startswith("require ("):
                in_require = True
                continue
            if in_require and stripped == ")":
                in_require = False
                continue
            target_line = stripped
            if stripped.startswith("require ") and "(" not in stripped:
                target_line = stripped[len("require ") :].strip()
            elif not in_require:
                continue
            m = re.match(r"^([a-zA-Z0-9._\-/]+)\s+v([0-9][^\s]*)", target_line)
            if not m:
                continue
            mod_name, ver = m.group(1), m.group(2)
            key = (mod_name.lower(), ver)
            if key in seen:
                continue
            seen.add(key)
            purl = f"pkg:golang/{mod_name}@{ver}"
            components.append(
                SBOMComponent(
                    name=mod_name,
                    version=ver,
                    purl=purl,
                    ecosystem="golang",
                    bom_ref=purl,
                    manifest_path=rel,
                    direct="// indirect" not in raw_line,
                )
            )

    return components


def _build_builtin_cyclonedx_sbom(
    repo_path: Path, components: list[SBOMComponent]
) -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "component": {
                "type": "application",
                "name": repo_path.name,
                "bom-ref": f"pkg:generic/{repo_path.name}@HEAD",
            },
            "tools": [{"vendor": "psirt-agent-engine", "name": "builtin-sbom", "version": "0.1.0"}],
        },
        "components": [
            {
                "type": "library",
                "name": c.name,
                "version": c.version,
                "purl": c.purl,
                "bom-ref": c.bom_ref or c.purl,
                "properties": [
                    {"name": "psirt:manifest", "value": c.manifest_path},
                    {"name": "psirt:direct", "value": str(c.direct).lower()},
                ],
            }
            for c in components
        ],
    }


def _components_from_cyclonedx(sbom: dict[str, Any]) -> list[SBOMComponent]:
    comps: list[SBOMComponent] = []
    for item in sbom.get("components", []):
        name = str(item.get("name", "")).strip()
        version = str(item.get("version", "")).strip()
        if not name or not version:
            continue
        purl = str(item.get("purl") or f"pkg:generic/{name}@{version}")
        eco = "pypi" if "pkg:pypi/" in purl else ("golang" if "pkg:golang/" in purl else "generic")
        comps.append(
            SBOMComponent(
                name=name.lower() if eco == "pypi" else name,
                version=version,
                purl=purl,
                ecosystem=eco,
                bom_ref=str(item.get("bom-ref") or purl),
            )
        )
    return comps


def _run_grype(repo_path: Path, commit_sha: str) -> tuple[list[CanonicalFinding] | None, str | None]:
    if not shutil.which("grype"):
        return None, "grype not installed; checking osv-scanner / built-in CVE matcher"
    try:
        proc = subprocess.run(
            ["grype", f"dir:{repo_path}", "-o", "json"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return None, f"grype failed (exit {proc.returncode})"
        return parse_grype_json(json.loads(proc.stdout), commit_sha), None
    except Exception as exc:  # noqa: BLE001
        return None, f"grype error: {exc}"


def parse_grype_json(data: dict[str, Any], commit_sha: str = "HEAD") -> list[CanonicalFinding]:
    findings: list[CanonicalFinding] = []
    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {})
        art = match.get("artifact", {})
        cve_id = vuln.get("id", "")
        pkg_name = art.get("name", "")
        pkg_ver = art.get("version", "")
        purl = art.get("purl") or f"pkg:generic/{pkg_name}@{pkg_ver}"
        fix_versions = (vuln.get("fix") or {}).get("versions") or []
        fixed_ver = fix_versions[0] if fix_versions else None
        cvss_list = vuln.get("cvss") or []
        raw_score = None
        raw_vec = None
        if cvss_list:
            raw_score = (cvss_list[0].get("metrics") or {}).get("baseScore")
            raw_vec = cvss_list[0].get("vector")
        findings.append(
            CanonicalFinding(
                finding_id=_make_finding_id(f"grype:{cve_id}:{purl}"),
                scanner_source="grype",
                category=FindingCategory.THIRD_PARTY_CVE,
                title=f"{cve_id} in {pkg_name} {pkg_ver}",
                description=vuln.get("description") or f"Vulnerability {cve_id} in {pkg_name}@{pkg_ver}",
                package_name=pkg_name,
                package_version=pkg_ver,
                fixed_version=fixed_ver,
                purl=purl,
                cve_id=cve_id if cve_id.startswith("CVE-") else None,
                ghsa_id=cve_id if cve_id.startswith("GHSA-") else None,
                raw_severity=str(vuln.get("severity", "MEDIUM")).upper(),
                raw_cvss_score=raw_score,
                raw_cvss_vector=raw_vec,
                commit_sha=commit_sha,
            )
        )
    return findings


def _run_osv_scanner(
    repo_path: Path, commit_sha: str
) -> tuple[list[CanonicalFinding] | None, str | None]:
    if not shutil.which("osv-scanner"):
        return None, "osv-scanner not installed; using built-in CVE matcher"
    try:
        proc = subprocess.run(
            ["osv-scanner", "--format=json", "-r", str(repo_path)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if not proc.stdout.strip():
            return None, f"osv-scanner returned empty output (exit {proc.returncode})"
        return parse_osv_json(json.loads(proc.stdout), commit_sha), None
    except Exception as exc:  # noqa: BLE001
        return None, f"osv-scanner error: {exc}"


def parse_osv_json(data: dict[str, Any], commit_sha: str = "HEAD") -> list[CanonicalFinding]:
    findings: list[CanonicalFinding] = []
    for res in data.get("results", []):
        source_path = (res.get("source") or {}).get("path")
        for pkg_entry in res.get("packages", []):
            pkg = pkg_entry.get("package", {})
            pkg_name = pkg.get("name", "")
            pkg_ver = pkg.get("version", "")
            eco = str(pkg.get("ecosystem", "generic")).lower()
            purl = f"pkg:{'pypi' if eco == 'pypi' else 'golang' if eco == 'go' else eco}/{pkg_name}@{pkg_ver}"
            for vuln in pkg_entry.get("vulnerabilities", []):
                aliases = vuln.get("aliases") or []
                cve_id = next((a for a in [vuln.get("id", ""), *aliases] if str(a).startswith("CVE-")), None)
                ghsa_id = next((a for a in [vuln.get("id", ""), *aliases] if str(a).startswith("GHSA-")), None)
                findings.append(
                    CanonicalFinding(
                        finding_id=_make_finding_id(f"osv:{cve_id or vuln.get('id')}:{purl}"),
                        scanner_source="osv-scanner",
                        category=FindingCategory.THIRD_PARTY_CVE,
                        title=vuln.get("summary") or f"{cve_id or vuln.get('id')} in {pkg_name} {pkg_ver}",
                        description=vuln.get("details") or vuln.get("summary") or "",
                        file_path=source_path,
                        package_name=pkg_name,
                        package_version=pkg_ver,
                        purl=purl,
                        cve_id=cve_id,
                        ghsa_id=ghsa_id,
                        raw_severity="HIGH",
                        commit_sha=commit_sha,
                    )
                )
    return findings


def _run_builtin_cve_matcher(
    components: list[SBOMComponent], commit_sha: str
) -> list[CanonicalFinding]:
    findings: list[CanonicalFinding] = []
    for comp in components:
        lookup_key = comp.name.lower() if comp.ecosystem == "pypi" else comp.name
        entries = BUILTIN_VULN_DB.get(lookup_key, [])
        for entry in entries:
            if _version_lt(comp.version, entry["affected_below"]):
                findings.append(
                    CanonicalFinding(
                        finding_id=_make_finding_id(f"builtin-cve:{entry['cve_id']}:{comp.purl}"),
                        scanner_source="builtin-osv-matcher",
                        category=FindingCategory.THIRD_PARTY_CVE,
                        title=entry["title"],
                        description=entry["description"],
                        file_path=comp.manifest_path or None,
                        package_name=comp.name,
                        package_version=comp.version,
                        fixed_version=entry["fixed_version"],
                        purl=comp.purl,
                        cve_id=entry["cve_id"],
                        ghsa_id=entry.get("ghsa_id"),
                        cwe_ids=list(entry.get("cwe_ids", [])),
                        raw_severity=entry["raw_severity"],
                        raw_cvss_score=entry.get("raw_cvss_score"),
                        raw_cvss_vector=entry.get("raw_cvss_vector"),
                        commit_sha=commit_sha,
                        vulnerable_symbols=list(entry.get("vulnerable_symbols", [])),
                        metadata={"import_names": entry.get("import_names", [comp.name])},
                    )
                )
    return findings


def _run_semgrep(
    repo_path: Path, commit_sha: str
) -> tuple[list[CanonicalFinding] | None, str | None]:
    if not shutil.which("semgrep"):
        return None, "semgrep not installed; using built-in deterministic SAST rules"
    try:
        proc = subprocess.run(
            ["semgrep", "--config", "auto", "--json", "--quiet", str(repo_path)],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        if not proc.stdout.strip():
            return None, f"semgrep returned no JSON (exit {proc.returncode})"
        return parse_semgrep_json(json.loads(proc.stdout), repo_path, commit_sha), None
    except Exception as exc:  # noqa: BLE001
        return None, f"semgrep error: {exc}"


def parse_semgrep_json(
    data: dict[str, Any], repo_path: Path, commit_sha: str = "HEAD"
) -> list[CanonicalFinding]:
    findings: list[CanonicalFinding] = []
    for res in data.get("results", []):
        path = res.get("path", "")
        try:
            rel = str(Path(path).resolve().relative_to(repo_path.resolve()))
        except Exception:  # noqa: BLE001
            rel = path
        extra = res.get("extra", {})
        meta = extra.get("metadata", {})
        raw_cwes = meta.get("cwe") or []
        if isinstance(raw_cwes, str):
            raw_cwes = [raw_cwes]
        cwe_ids = [m.group(0) for c in raw_cwes if (m := re.search(r"CWE-\d+", str(c)))]
        start_line = (res.get("start") or {}).get("line", 1)
        end_line = (res.get("end") or {}).get("line", start_line)
        sev = str(extra.get("severity", "WARNING")).upper()
        sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
        findings.append(
            CanonicalFinding(
                finding_id=_make_finding_id(f"semgrep:{res.get('check_id')}:{rel}:{start_line}"),
                scanner_source="semgrep",
                category=FindingCategory.FIRST_PARTY_SAST,
                title=str(res.get("check_id", "SAST Finding")),
                description=str(extra.get("message", "")),
                file_path=rel,
                line_start=start_line,
                line_end=end_line,
                cwe_ids=cwe_ids,
                raw_severity=sev_map.get(sev, sev),
                commit_sha=commit_sha,
                code_snippet=str(extra.get("lines", "")),
            )
        )
    return findings


def _run_builtin_sast(repo_path: Path, commit_sha: str) -> list[CanonicalFinding]:
    findings: list[CanonicalFinding] = []
    for file_path in _iter_repo_files(repo_path):
        rel = str(file_path.relative_to(repo_path))
        if file_path.name.startswith("test_") or "/tests/" in f"/{rel}":
            continue
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        for rule in BUILTIN_SAST_RULES:
            exts = rule["extensions"]
            if not (file_path.suffix in exts or file_path.name in exts):
                continue
            for idx, line in enumerate(lines, start=1):
                if rule["regex"].search(line):
                    excl = rule.get("exclude_regex")
                    if excl and excl.search(line):
                        continue
                    ctx_start = max(1, idx - 2)
                    ctx_end = min(len(lines), idx + 2)
                    snippet = "\n".join(lines[ctx_start - 1 : ctx_end])
                    cat = (
                        FindingCategory.IAC
                        if file_path.name == "Dockerfile"
                        else FindingCategory.FIRST_PARTY_SAST
                    )
                    findings.append(
                        CanonicalFinding(
                            finding_id=_make_finding_id(f"sast:{rule['id']}:{rel}:{idx}"),
                            scanner_source="builtin-sast",
                            category=cat,
                            title=rule["title"],
                            description=rule["description"],
                            file_path=rel,
                            line_start=idx,
                            line_end=idx,
                            symbol=rule.get("symbol_hint"),
                            cwe_ids=list(rule["cwe_ids"]),
                            raw_severity=rule["raw_severity"],
                            raw_cvss_score=rule.get("raw_cvss_score"),
                            commit_sha=commit_sha,
                            code_snippet=snippet,
                            metadata={"rule_id": rule["id"]},
                        )
                    )
    return findings


def _run_gitleaks(
    repo_path: Path, commit_sha: str
) -> tuple[list[CanonicalFinding] | None, str | None]:
    if not shutil.which("gitleaks"):
        return None, "gitleaks not installed; using built-in deterministic secret scanner"
    try:
        proc = subprocess.run(
            [
                "gitleaks",
                "detect",
                "--no-git",
                "--source",
                str(repo_path),
                "--report-format",
                "json",
                "--report-path",
                "/dev/stdout",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if not proc.stdout.strip():
            return [], None
        raw = json.loads(proc.stdout)
        findings: list[CanonicalFinding] = []
        for item in raw:
            rel = str(item.get("File", ""))
            line = int(item.get("StartLine", 1))
            rule_id = str(item.get("RuleID", "secret"))
            findings.append(
                CanonicalFinding(
                    finding_id=_make_finding_id(f"gitleaks:{rule_id}:{rel}:{line}"),
                    scanner_source="gitleaks",
                    category=FindingCategory.SECRET,
                    title=f"Hardcoded secret detected ({rule_id})",
                    description=f"Secret pattern '{rule_id}' detected in {rel} at line {line}. Value redacted.",
                    file_path=rel,
                    line_start=line,
                    line_end=int(item.get("EndLine", line)),
                    cwe_ids=["CWE-798"],
                    raw_severity="HIGH",
                    raw_cvss_score=7.5,
                    commit_sha=commit_sha,
                    code_snippet=str(item.get("Match", "")),
                    metadata={"rule_id": rule_id},
                )
            )
        return findings, None
    except Exception as exc:  # noqa: BLE001
        return None, f"gitleaks error: {exc}"


def _run_builtin_secret_scanner(repo_path: Path, commit_sha: str) -> list[CanonicalFinding]:
    findings: list[CanonicalFinding] = []
    for file_path in _iter_repo_files(repo_path):
        if file_path.suffix in {".png", ".jpg", ".gif", ".pdf", ".zip", ".db", ".lock"}:
            continue
        rel = str(file_path.relative_to(repo_path))
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for idx, line in enumerate(text.splitlines(), start=1):
            for pat in SECRET_PATTERNS:
                if pat.rule_id == "pii_ssn":
                    continue
                if pat.regex.search(line):
                    findings.append(
                        CanonicalFinding(
                            finding_id=_make_finding_id(f"secret:{pat.rule_id}:{rel}:{idx}"),
                            scanner_source="builtin-secret-scanner",
                            category=FindingCategory.SECRET,
                            title=f"Hardcoded credential detected ({pat.rule_id})",
                            description=f"Potential hardcoded secret matching '{pat.rule_id}' found in {rel}:{idx}.",
                            file_path=rel,
                            line_start=idx,
                            line_end=idx,
                            cwe_ids=["CWE-798"],
                            raw_severity="HIGH",
                            raw_cvss_score=7.5,
                            commit_sha=commit_sha,
                            code_snippet=line,  # Sanitizer will deterministically redact this before Layer 2!
                            metadata={"rule_id": pat.rule_id},
                        )
                    )
                    break
    return findings


def run_all_scanners(
    repo_path: Path,
    extra_scanner_reports: list[Path] | None = None,
    prefer_builtin: bool = False,
) -> ScanResult:
    """Run all Layer 1 deterministic intake scanners and return canonical findings + CycloneDX SBOM."""
    repo = repo_path.resolve()
    commit_sha = get_git_commit_sha(repo)
    scanners_used: list[str] = []
    warnings: list[str] = []
    findings: list[CanonicalFinding] = []

    # 1. SBOM (Syft -> fallback manifest parser)
    sbom: dict[str, Any] | None = None
    manifest_components = _extract_components_from_manifests(repo)
    if not prefer_builtin:
        sbom, warn = _run_syft(repo)
        if warn:
            warnings.append(warn)
    if sbom is not None:
        scanners_used.append("syft")
        components = _components_from_cyclonedx(sbom) or manifest_components
    else:
        scanners_used.append("builtin-sbom")
        components = manifest_components
        sbom = _build_builtin_cyclonedx_sbom(repo, components)

    sbom_sha256 = hashlib.sha256(
        json.dumps(sbom, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    # 2. Third-party CVEs (Grype / OSV-Scanner -> fallback built-in matcher)
    cve_findings: list[CanonicalFinding] | None = None
    if not prefer_builtin:
        cve_findings, warn = _run_grype(repo, commit_sha)
        if warn:
            warnings.append(warn)
        if cve_findings is not None:
            scanners_used.append("grype")
        else:
            cve_findings, warn = _run_osv_scanner(repo, commit_sha)
            if warn:
                warnings.append(warn)
            if cve_findings is not None:
                scanners_used.append("osv-scanner")
    if cve_findings is None:
        cve_findings = _run_builtin_cve_matcher(components, commit_sha)
        scanners_used.append("builtin-osv-matcher")
    findings.extend(cve_findings)

    # 3. First-party SAST (Semgrep -> fallback built-in SAST)
    sast_findings: list[CanonicalFinding] | None = None
    if not prefer_builtin:
        sast_findings, warn = _run_semgrep(repo, commit_sha)
        if warn:
            warnings.append(warn)
        if sast_findings is not None:
            scanners_used.append("semgrep")
    if sast_findings is None:
        sast_findings = _run_builtin_sast(repo, commit_sha)
        scanners_used.append("builtin-sast")
    findings.extend(sast_findings)

    # 4. Secrets (Gitleaks -> fallback built-in secret scanner)
    secret_findings: list[CanonicalFinding] | None = None
    if not prefer_builtin:
        secret_findings, warn = _run_gitleaks(repo, commit_sha)
        if warn:
            warnings.append(warn)
        if secret_findings is not None:
            scanners_used.append("gitleaks")
    if secret_findings is None:
        secret_findings = _run_builtin_secret_scanner(repo, commit_sha)
        scanners_used.append("builtin-secret-scanner")
    findings.extend(secret_findings)

    # 5. Optional pre-generated scanner JSON reports (Grype / OSV / Semgrep)
    for report_path in extra_scanner_reports or []:
        data = json.loads(report_path.read_text(encoding="utf-8"))
        if "matches" in data:
            findings.extend(parse_grype_json(data, commit_sha))
            scanners_used.append(f"import:grype:{report_path.name}")
        elif "results" in data and data["results"] and "packages" in data["results"][0]:
            findings.extend(parse_osv_json(data, commit_sha))
            scanners_used.append(f"import:osv:{report_path.name}")
        elif "results" in data:
            findings.extend(parse_semgrep_json(data, repo, commit_sha))
            scanners_used.append(f"import:semgrep:{report_path.name}")

    return ScanResult(
        repo_path=str(repo),
        commit_sha=commit_sha,
        sbom=sbom,
        sbom_sha256=sbom_sha256,
        components=components,
        findings=findings,
        scanners_used=scanners_used,
        scanner_warnings=warnings,
    )
