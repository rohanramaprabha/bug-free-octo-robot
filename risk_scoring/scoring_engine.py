"""
PrivacyVault AI - Explainable Risk Scoring Engine
Calculates transparent, mathematically grounded privacy risk scores (0-100)
based on severity weights, logarithmic frequency dampening, co-occurrence multipliers, and file sensitivity.
"""

import math
from typing import List, Dict, Any, Tuple
from config.settings import Config
from .risk_categories import get_risk_level_for_score, RISK_TIERS


def calculate_risk_score(findings: List[Dict[str, Any]], file_type: str = "txt", metadata: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Compute explainable risk score and detailed classification breakdown.
    
    Returns: {
        "score": float (0-100),
        "level": str (LOW, MEDIUM, HIGH, CRITICAL),
        "reasons": list[str],
        "tier_info": dict,
        "breakdown": {
            "critical_count": int,
            "high_count": int,
            "medium_count": int,
            "low_count": int,
            "categories_detected": list[str],
            "co_occurrence_penalty": float
        }
    }
    """
    if not findings:
        return {
            "score": 0.0,
            "level": "LOW",
            "reasons": ["No sensitive data patterns, secrets, or high-risk identifiers detected."],
            "tier_info": RISK_TIERS["LOW"],
            "breakdown": {
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "categories_detected": [],
                "co_occurrence_penalty": 1.0
            }
        }
        
    counts_by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    categories = set()
    secrets_present = False
    critical_secret_present = False
    
    for f in findings:
        sev = f.get("severity", "LOW").upper()
        if sev in counts_by_severity:
            counts_by_severity[sev] += 1
            
        cat = f.get("category", "")
        if cat:
            categories.add(cat)
            
        if cat == "Authentication Secrets":
            secrets_present = True
            if sev == "CRITICAL":
                critical_secret_present = True
                
    weights = Config.SEVERITY_WEIGHTS
    
    # 1. Base Score calculation with logarithmic frequency dampening
    raw_subtotal = 0.0
    for sev, count in counts_by_severity.items():
        if count > 0:
            base_w = weights.get(sev, 5)
            # Logarithmic dampening: base_w * (1 + 0.5 * log2(count))
            dampened = base_w * (1.0 + 0.5 * math.log2(count))
            raw_subtotal += dampened
            
    reasons = []
    reasons.append(
        f"Base score: {counts_by_severity['CRITICAL']} Critical, {counts_by_severity['HIGH']} High, "
        f"{counts_by_severity['MEDIUM']} Medium, and {counts_by_severity['LOW']} Low findings."
    )
    
    # 2. Multipliers
    multiplier = 1.0
    
    # Check Co-occurrence: PII + Financial = high identity theft threat
    if "PII" in categories and "Financial Information" in categories:
        multiplier *= 1.25
        reasons.append("Co-occurrence of PII and Financial Information detected (+25% risk multiplier for identity theft).")
        
    # Check 3+ categories detected
    if len(categories) >= 3:
        multiplier *= 1.15
        reasons.append(f"Broad disclosure scope: Findings span {len(categories)} distinct sensitivity categories (+15% modifier).")
        
    # Check secrets & file context
    if secrets_present:
        multiplier *= 1.30
        if file_type.lower() in ["txt", "json"]:
            reasons.append(f"Authentication secrets located inside plain {file_type.upper()} configuration/data file (+30% credential exposure penalty).")
        else:
            reasons.append("Active authentication secrets or API tokens detected (+30% credential penalty).")
            
    # Calculate initial score
    final_score = raw_subtotal * multiplier
    
    # 3. Floor guarantees for critical assets
    if critical_secret_present and final_score < 80.0:
        final_score = 80.0
        reasons.append("Floor score set to 80 (CRITICAL) due to presence of active cryptographic private key or cloud credentials.")
    elif secrets_present and final_score < 55.0:
        final_score = 55.0
        reasons.append("Floor score set to 55 (HIGH) due to presence of exposed API tokens or passwords.")
    elif counts_by_severity["CRITICAL"] > 0 and final_score < 65.0:
        final_score = 65.0
        reasons.append("Floor score set to 65 (HIGH) due to presence of direct critical identifiers (e.g. Card, SSN, Aadhaar).")
        
    # Clamp to [0, 100]
    final_score = min(100.0, max(0.0, final_score))
    final_score = round(final_score, 1)
    
    risk_level = get_risk_level_for_score(final_score)
    
    return {
        "score": final_score,
        "level": risk_level,
        "reasons": reasons,
        "tier_info": RISK_TIERS[risk_level],
        "breakdown": {
            "critical_count": counts_by_severity["CRITICAL"],
            "high_count": counts_by_severity["HIGH"],
            "medium_count": counts_by_severity["MEDIUM"],
            "low_count": counts_by_severity["LOW"],
            "categories_detected": sorted(list(categories)),
            "co_occurrence_penalty": round(multiplier, 2)
        }
    }
