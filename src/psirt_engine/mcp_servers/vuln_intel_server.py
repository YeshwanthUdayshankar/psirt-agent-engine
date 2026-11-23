"""Read-only MCP Server: Vulnerability Intelligence (CWE, MITRE ATT&CK, OSV/NVD, VEX justifications).

Provides deterministic, curated threat & weakness intelligence locally with optional
read-only OSV API enrichment when PSIRT_ALLOW_ONLINE_INTEL=1.
"""

from __future__ import annotations

import os
from typing import Any

import httpx

try:
    from mcp.server.mcpserver import MCPServer as FastMCP
except ImportError:  # pragma: no cover - mcp 1.x compatibility
    from mcp.server.fastmcp import FastMCP  # type: ignore[no-redef]

CWE_CATALOG: dict[str, dict[str, Any]] = {
    "CWE-78": {
        "id": "CWE-78",
        "name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "default_cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "attack_techniques": ["T1190", "T1059"],
    },
    "CWE-79": {
        "id": "CWE-79",
        "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "default_cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N",
        "attack_techniques": ["T1190", "T1189"],
    },
    "CWE-89": {
        "id": "CWE-89",
        "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "default_cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
        "attack_techniques": ["T1190", "T1213"],
    },
    "CWE-94": {
        "id": "CWE-94",
        "name": "Improper Control of Generation of Code ('Code Injection')",
        "default_cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "attack_techniques": ["T1190", "T1059"],
    },
    "CWE-200": {
        "id": "CWE-200",
        "name": "Exposure of Sensitive Information to an Unauthorized Actor",
        "default_cvss4_vector": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        "attack_techniques": ["T1552.001"],
    },
    "CWE-250": {
        "id": "CWE-250",
        "name": "Execution with Unnecessary Privileges",
        "default_cvss4_vector": "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
        "attack_techniques": ["T1611"],
    },
    "CWE-287": {
        "id": "CWE-287",
        "name": "Improper Authentication",
        "default_cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
        "attack_techniques": ["T1190", "T1078"],
    },
    "CWE-400": {
        "id": "CWE-400",
        "name": "Uncontrolled Resource Consumption",
        "default_cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
        "attack_techniques": ["T1499"],
    },
    "CWE-502": {
        "id": "CWE-502",
        "name": "Deserialization of Untrusted Data",
        "default_cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "attack_techniques": ["T1190", "T1059"],
    },
    "CWE-798": {
        "id": "CWE-798",
        "name": "Use of Hard-coded Credentials",
        "default_cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
        "attack_techniques": ["T1552.001", "T1552.005"],
    },
}

ATTACK_CATALOG: dict[str, dict[str, str]] = {
    "T1190": {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "impact_summary": "Remote adversary exploits an exposed application endpoint to gain unauthorized access or execution.",
        "detection_opportunity": "Monitor WAF/API gateway logs for anomalous payloads, unexpected 5xx spikes, and input validation violations.",
    },
    "T1059": {
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "impact_summary": "Adversary executes arbitrary OS commands or interpreter payloads within the application runtime context.",
        "detection_opportunity": "Alert on unexpected child shell processes (sh/bash/python) spawned by web/application server PIDs via eBPF/Falco/auditd.",
    },
    "T1078": {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "impact_summary": "Adversary bypasses authentication checks or abuses valid credentials to gain privileged access.",
        "detection_opportunity": "Correlate anomalous authentication events, unexpected key fingerprints, and impossible-travel sign-ins.",
    },
    "T1189": {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise",
        "impact_summary": "Injected client-side markup/scripts execute in victim browser sessions.",
        "detection_opportunity": "Enforce strict Content-Security-Policy (CSP) with violation reporting endpoints.",
    },
    "T1213": {
        "tactic_id": "TA0009",
        "tactic_name": "Collection",
        "technique_id": "T1213",
        "technique_name": "Data from Information Repositories",
        "impact_summary": "Adversary extracts or modifies sensitive database records through injected SQL statements.",
        "detection_opportunity": "Alert on abnormal query patterns, UNION SELECT/boolean-blind probes, and bulk table scans in DB audit logs.",
    },
    "T1499": {
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "impact_summary": "Adversary exhausts CPU, memory, or connection pools to degrade service availability.",
        "detection_opportunity": "Track HTTP/2 RST_STREAM rates, request concurrency anomalies, and ingress rate-limit triggers.",
    },
    "T1552.001": {
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "technique_id": "T1552.001",
        "technique_name": "Unsecured Credentials: Credentials In Files",
        "impact_summary": "Hardcoded secrets in source repositories grant attackers unauthorized access to APIs, databases, or cloud accounts.",
        "detection_opportunity": "Run pre-commit secret scanning, rotate exposed credentials immediately, and audit CloudTrail/IAM access logs.",
    },
    "T1552.005": {
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "technique_id": "T1552.005",
        "technique_name": "Unsecured Credentials: Cloud Instance Metadata API",
        "impact_summary": "Leaked cloud tokens/keys enable lateral movement into cloud control planes and storage buckets.",
        "detection_opportunity": "Alert on IAM key usage from unrecognized source IPs/ASNs and enforce short-lived workload identity (OIDC/SPIFFE).",
    },
    "T1611": {
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
        "technique_id": "T1611",
        "technique_name": "Escape to Host",
        "impact_summary": "Root container execution increases risk of kernel exploit or host filesystem breakout.",
        "detection_opportunity": "Enforce Kubernetes Pod Security Standards (restricted) and alert on root UID container launches.",
    },
}

VEX_JUSTIFICATION_DOCS: dict[str, str] = {
    "component_not_present": "The vulnerable software component is not included in the product.",
    "vulnerable_code_not_present": "The component is present, but the vulnerable code/module was stripped or not compiled.",
    "vulnerable_code_not_in_execute_path": "The vulnerable function/symbol is never imported or invoked along any reachable execution path.",
    "vulnerable_code_cannot_be_controlled_by_adversary": "The vulnerable code executes only with trusted/static inputs unreachable by untrusted adversaries.",
    "inline_mitigations_already_exist": "Existing inline input validation, guards, or configurations fully prevent exploitation.",
}


class VulnIntelService:
    """Read-only threat & vulnerability intelligence lookup service."""

    def lookup_cwe(self, cwe_id: str) -> dict[str, Any]:
        norm = cwe_id.upper().strip()
        if norm in CWE_CATALOG:
            return dict(CWE_CATALOG[norm])
        return {
            "id": norm,
            "name": f"Software Weakness ({norm})",
            "default_cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
            "attack_techniques": ["T1190"],
        }

    def lookup_attack(self, technique_id: str) -> dict[str, str] | None:
        return ATTACK_CATALOG.get(technique_id.upper().strip())

    def get_attack_mappings_for_cwe(self, cwe_id: str) -> list[dict[str, str]]:
        info = self.lookup_cwe(cwe_id)
        out: list[dict[str, str]] = []
        for tid in info.get("attack_techniques", ["T1190"]):
            entry = self.lookup_attack(tid)
            if entry:
                out.append(dict(entry))
        return out

    def list_vex_justifications(self) -> dict[str, str]:
        return dict(VEX_JUSTIFICATION_DOCS)

    def lookup_osv_advisory(self, vuln_id: str) -> dict[str, Any]:
        """Optional read-only OSV lookup when PSIRT_ALLOW_ONLINE_INTEL=1; offline safe by default."""
        if os.environ.get("PSIRT_ALLOW_ONLINE_INTEL") == "1":
            try:
                with httpx.Client(timeout=10) as client:
                    resp = client.get(f"https://api.osv.dev/v1/vulns/{vuln_id}")
                    if resp.status_code == 200:
                        return resp.json()
            except httpx.HTTPError:
                return {"id": vuln_id, "source": "offline_cache", "available": False}
        return {"id": vuln_id, "source": "offline_cache", "available": False}


def create_vuln_intel_mcp_server() -> FastMCP:
    service = VulnIntelService()
    mcp = FastMCP("psirt-vuln-intel-readonly")

    @mcp.tool()
    def lookup_cwe(cwe_id: str) -> dict[str, Any]:
        """Look up MITRE CWE metadata and default CVSS v4.0 baseline (read-only)."""
        return service.lookup_cwe(cwe_id)

    @mcp.tool()
    def lookup_attack(technique_id: str) -> dict[str, str] | None:
        """Look up MITRE ATT&CK tactic/technique impact and detection guidance (read-only)."""
        return service.lookup_attack(technique_id)

    @mcp.tool()
    def get_attack_mappings_for_cwe(cwe_id: str) -> list[dict[str, str]]:
        """Return relevant MITRE ATT&CK techniques for a CWE identifier (read-only)."""
        return service.get_attack_mappings_for_cwe(cwe_id)

    @mcp.tool()
    def list_vex_justifications() -> dict[str, str]:
        """List official OpenVEX / CSAF 2.0 not_affected justification codes (read-only)."""
        return service.list_vex_justifications()

    @mcp.tool()
    def lookup_osv_advisory(vuln_id: str) -> dict[str, Any]:
        """Look up vulnerability details from OSV (read-only)."""
        return service.lookup_osv_advisory(vuln_id)

    return mcp


def main() -> None:
    server = create_vuln_intel_mcp_server()
    server.run()


if __name__ == "__main__":
    main()
