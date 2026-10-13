"""
PrivacyVault AI - Remediation & Privacy Guidance Engine
Translates detected privacy risks into structured, regulation-mapped remediation workflows
aligned with GDPR, PCI-DSS, HIPAA, and DPDP Act 2023.
"""

from typing import List, Dict, Any


def generate_remediation_plan(findings: List[Dict[str, Any]], leakage_alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate an actionable remediation plan based on findings and leakage alerts.
    """
    categories = set(f["category"] for f in findings)
    severities = set(f["severity"] for f in findings)
    
    immediate_actions = []
    policy_recommendations = []
    compliance_frameworks = []
    
    # 1. Immediate Actions
    if "Authentication Secrets" in categories or any(a["alert_type"] == "CONFIG_CREDENTIAL" for a in leakage_alerts):
        immediate_actions.append({
            "action": "Credential Invalidation & Key Rotation",
            "priority": "CRITICAL",
            "steps": [
                "Immediately revoke and rotate all exposed AWS access keys, GitHub tokens, and API secrets.",
                "Inspect cloud audit logs (AWS CloudTrail, GitHub audit log) for unauthorized calls during the exposure window.",
                "Migrate static secrets from document/code files to an encrypted secret vault (AWS Secrets Manager, HashiCorp Vault)."
            ]
        })
        compliance_frameworks.append("NIST SP 800-57 (Key Management)")
        
    if "Financial Information" in categories:
        immediate_actions.append({
            "action": "Cardholder Data Scrubbing & PCI-DSS Enforcement",
            "priority": "HIGH",
            "steps": [
                "Mask or truncate all credit/debit card numbers so only the last 4 digits remain visible.",
                "Ensure full Primary Account Numbers (PAN) and CVV codes are never stored in unencrypted spreadsheets or text documents.",
                "Implement AES-256 field-level encryption for transaction databases."
            ]
        })
        compliance_frameworks.append("PCI-DSS v4.0 (Requirement 3.4)")
        
    if "PII" in categories:
        immediate_actions.append({
            "action": "Direct Identifier Pseudonymization & Masking",
            "priority": "MEDIUM" if "CRITICAL" not in severities else "HIGH",
            "steps": [
                "Apply pseudonymization (e.g., replace personal names with synthetic user tokens).",
                "Mask government identifiers (SSN, Aadhaar, PAN) before distributing datasets.",
                "Implement role-based access control (RBAC) so only authorized compliance officers can view direct identity attributes."
            ]
        })
        compliance_frameworks.append("GDPR (Art. 32) & India DPDP Act 2023")
        
    if any(a["alert_type"] == "METADATA_LEAK" for a in leakage_alerts):
        immediate_actions.append({
            "action": "Document Property & Metadata Sanitization",
            "priority": "LOW",
            "steps": [
                "Strip author names, creator software signatures, and local file paths from PDF and DOCX properties.",
                "Configure office software templates to remove personal metadata upon document saving."
            ]
        })
        
    # 2. General Policy Guidance
    policy_recommendations = [
        "Enforce automated pre-commit scanning hooks in software development pipelines to prevent credentials entering version control.",
        "Implement Data Loss Prevention (DLP) gateways on corporate email and cloud storage endpoints.",
        "Conduct periodic data minimization audits to delete legacy files containing sensitive records past retention periods (GDPR Art. 5(1)(e)).",
        "Adopt least-privilege sharing models: share aggregated analytics summaries rather than raw operational datasets."
    ]
    
    return {
        "immediate_actions": immediate_actions,
        "policy_recommendations": policy_recommendations,
        "compliance_frameworks": list(set(compliance_frameworks))
    }
