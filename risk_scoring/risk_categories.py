"""
PrivacyVault AI - Risk Category & Severity Definitions
Standard classification tiers, descriptions, color indicators, and regulatory thresholds.
"""

from typing import Dict, Any

RISK_TIERS: Dict[str, Dict[str, Any]] = {
    "CRITICAL": {
        "tier": "CRITICAL",
        "min_score": 76,
        "max_score": 100,
        "badge_color": "danger",
        "hex_color": "#ff1744",
        "description": "Immediate privacy violation risk. Contains exposed private credentials, full identity dossiers, or unencrypted payment instruments.",
        "action_required": "Halt sharing immediately. Revoke exposed credentials and scrub sensitive fields."
    },
    "HIGH": {
        "tier": "HIGH",
        "min_score": 51,
        "max_score": 75,
        "badge_color": "warning",
        "hex_color": "#ff9100",
        "description": "High privacy exposure risk. Contains sensitive PII (SSN, Aadhaar), direct financial data, or restricted insider documents.",
        "action_required": "Mask all direct identifiers before publication. Verify recipient authorization."
    },
    "MEDIUM": {
        "tier": "MEDIUM",
        "min_score": 26,
        "max_score": 50,
        "badge_color": "info",
        "hex_color": "#00d2ff",
        "description": "Moderate exposure risk. Contains personal contact details (email, phone), business NDA notices, or internal compensation remarks.",
        "action_required": "Apply pseudonymization or column-level masking where practical."
    },
    "LOW": {
        "tier": "LOW",
        "min_score": 0,
        "max_score": 25,
        "badge_color": "success",
        "hex_color": "#00e676",
        "description": "Low privacy risk. Contains public information, isolated network addresses, or non-sensitive general content.",
        "action_required": "Document is generally safe for internal sharing; routine review recommended."
    }
}


def get_risk_level_for_score(score: float) -> str:
    """Map a numerical risk score (0-100) to its severity tier."""
    if score >= 76:
        return "CRITICAL"
    elif score >= 51:
        return "HIGH"
    elif score >= 26:
        return "MEDIUM"
    else:
        return "LOW"
