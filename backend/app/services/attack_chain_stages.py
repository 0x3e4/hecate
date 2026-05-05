"""CWE → ATT&CK kill-chain stage mapping for the Cross-CVE Attack Chain feature.

Hardcoded for the MVP. Phase 3 will replace this with the real
``Taxonomy_Mapping[Taxonomy_Name="ATT&CK"]/Entry_ID`` block already present in
``CAPECEntry.raw_data`` (currently unparsed). Until then, this map is the
authoritative bucketing rule.

Stages follow the ATT&CK Enterprise tactics most security teams already speak:
- ``foothold``           — Initial Access / Execution / Resource Dev
- ``credential_access``  — Credential Access / Discovery
- ``priv_escalation``    — Privilege Escalation / Defense Evasion
- ``lateral_movement``   — Lateral Movement
- ``impact``             — Impact / Exfiltration / Command & Control

Order is the chain order. The graph builder lays stages out left-to-right.
"""
from __future__ import annotations

from typing import Final, Literal

AttackStage = Literal[
    "foothold",
    "credential_access",
    "priv_escalation",
    "lateral_movement",
    "impact",
]


STAGE_ORDER: Final[tuple[AttackStage, ...]] = (
    "foothold",
    "credential_access",
    "priv_escalation",
    "lateral_movement",
    "impact",
)


STAGE_LABELS_EN: Final[dict[AttackStage, str]] = {
    "foothold": "Foothold",
    "credential_access": "Credential access",
    "priv_escalation": "Privilege escalation",
    "lateral_movement": "Lateral movement",
    "impact": "Impact",
}


STAGE_LABELS_DE: Final[dict[AttackStage, str]] = {
    "foothold": "Erstzugang",
    "credential_access": "Anmeldedaten-Zugriff",
    "priv_escalation": "Rechteausweitung",
    "lateral_movement": "Querbewegung",
    "impact": "Auswirkung",
}


# Hardcoded CWE → stage map. Keep CWE IDs as bare numeric strings (e.g. "79"
# not "CWE-79") to match the normalisation done in the graph builder.
CWE_TO_ATTACK_STAGE: Final[dict[str, AttackStage]] = {
    # --- Foothold (initial access via input handling) ---
    "20": "foothold",  # Improper Input Validation
    "22": "foothold",  # Path Traversal
    "73": "foothold",  # External Control of File Name or Path
    "77": "foothold",  # Command Injection
    "78": "foothold",  # OS Command Injection
    "79": "foothold",  # XSS
    "88": "foothold",  # Argument Injection
    "89": "foothold",  # SQL Injection
    "91": "foothold",  # XML Injection
    "94": "foothold",  # Code Injection
    "434": "foothold",  # Unrestricted File Upload
    "502": "foothold",  # Deserialization of Untrusted Data
    "611": "foothold",  # XML External Entity
    "917": "foothold",  # EL Injection
    "918": "foothold",  # SSRF
    "1336": "foothold",  # Improper Neutralization of Special Elements

    # --- Credential access ---
    "200": "credential_access",  # Information Disclosure
    "256": "credential_access",  # Plaintext Stored Credentials
    "257": "credential_access",  # Reversible Stored Credentials
    "319": "credential_access",  # Cleartext Transmission of Sensitive Information
    "321": "credential_access",  # Hard-coded Cryptographic Key
    "522": "credential_access",  # Insufficiently Protected Credentials
    "532": "credential_access",  # Insertion of Sensitive Information into Log
    "798": "credential_access",  # Hard-coded Credentials
    "916": "credential_access",  # Use of Password Hash With Insufficient Computational Effort

    # --- Privilege escalation ---
    "250": "priv_escalation",  # Execution with Unnecessary Privileges
    "266": "priv_escalation",  # Incorrect Privilege Assignment
    "269": "priv_escalation",  # Improper Privilege Management
    "272": "priv_escalation",  # Least Privilege Violation
    "276": "priv_escalation",  # Incorrect Default Permissions
    "352": "priv_escalation",  # CSRF (also fits foothold but more often used to chain to priv-esc actions)
    "426": "priv_escalation",  # Untrusted Search Path
    "427": "priv_escalation",  # Uncontrolled Search Path
    "732": "priv_escalation",  # Incorrect Permission Assignment
    "862": "priv_escalation",  # Missing Authorization
    "863": "priv_escalation",  # Incorrect Authorization

    # --- Lateral movement ---
    "284": "lateral_movement",  # Improper Access Control
    "285": "lateral_movement",  # Improper Authorization
    "287": "lateral_movement",  # Improper Authentication
    "288": "lateral_movement",  # Authentication Bypass Using an Alternate Path
    "295": "lateral_movement",  # Improper Certificate Validation
    "302": "lateral_movement",  # Authentication Bypass by Assumed-Immutable Data
    "306": "lateral_movement",  # Missing Authentication for Critical Function
    "346": "lateral_movement",  # Origin Validation Error
    "384": "lateral_movement",  # Session Fixation

    # --- Impact (data tampering, RCE, DoS, supply chain payload) ---
    "119": "impact",  # Buffer Errors
    "125": "impact",  # Out-of-bounds Read
    "190": "impact",  # Integer Overflow
    "362": "impact",  # Race Condition
    "400": "impact",  # Uncontrolled Resource Consumption (DoS)
    "416": "impact",  # Use After Free
    "476": "impact",  # NULL Pointer Dereference
    "770": "impact",  # Allocation of Resources Without Limits
    "787": "impact",  # Out-of-bounds Write
    "1188": "impact",  # Insecure Default Initialization of Resource
    "1395": "impact",  # Dependency on Vulnerable Third-Party Component
}


_SEVERITY_FALLBACK: Final[dict[str, AttackStage]] = {
    "critical": "impact",
    "high": "impact",
    "medium": "priv_escalation",
    "low": "credential_access",
}


def _normalize_cwe(cwe: str) -> str:
    return str(cwe).upper().replace("CWE-", "").strip()


def categorize_cve(cwes: list[str] | None, severity: str | None) -> AttackStage:
    """Return the most likely kill-chain stage for a finding.

    Walks the CWEs in the order they appear (NVD lists "primary" CWEs first)
    and returns the stage of the first hit in ``CWE_TO_ATTACK_STAGE``. Falls
    back to severity-based bucketing when no CWE matches; this guarantees we
    never silently drop a finding from the chain.
    """
    if cwes:
        for cwe in cwes:
            normalized = _normalize_cwe(cwe)
            if normalized in CWE_TO_ATTACK_STAGE:
                return CWE_TO_ATTACK_STAGE[normalized]
    sev = (severity or "").lower().strip()
    return _SEVERITY_FALLBACK.get(sev, "credential_access")


def stage_label(stage: AttackStage, language: str | None = "en") -> str:
    if (language or "").lower().startswith("de"):
        return STAGE_LABELS_DE.get(stage, stage)
    return STAGE_LABELS_EN.get(stage, stage)
