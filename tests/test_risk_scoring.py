"""
PrivacyVault AI - Unit Tests for Explainable Risk Scoring Engine
"""

from risk_scoring import calculate_risk_score, get_risk_level_for_score


def test_empty_findings_returns_zero_risk():
    """Verify clean document with 0 findings evaluates to 0 score and LOW risk."""
    res = calculate_risk_score([], file_type="txt")
    assert res["score"] == 0.0
    assert res["level"] == "LOW"
    assert len(res["reasons"]) > 0


def test_critical_secret_triggers_high_floor():
    """Verify presence of AWS or Private Key pushes score to CRITICAL (>= 80)."""
    findings = [
        {
            "category": "Authentication Secrets",
            "finding_type": "AWS Access Key ID",
            "severity": "CRITICAL",
            "masked_value": "AKIA************"
        }
    ]
    res = calculate_risk_score(findings, file_type="json")
    assert res["score"] >= 80.0
    assert res["level"] == "CRITICAL"


def test_co_occurrence_multiplier_applied():
    """Verify that file with both PII and Financial information applies multiplier penalty."""
    findings_pii_only = [
        {"category": "PII", "finding_type": "Email Address", "severity": "MEDIUM", "masked_value": "a***@b.com"}
    ]
    res_pii = calculate_risk_score(findings_pii_only)
    
    findings_both = [
        {"category": "PII", "finding_type": "Email Address", "severity": "MEDIUM", "masked_value": "a***@b.com"},
        {"category": "Financial Information", "finding_type": "Compensation Record", "severity": "MEDIUM", "masked_value": "$100,000"}
    ]
    res_both = calculate_risk_score(findings_both)
    
    # Co-occurrence multiplier should increase the combined penalty
    assert res_both["breakdown"]["co_occurrence_penalty"] >= 1.25


def test_risk_level_mapping():
    """Verify numerical thresholds correctly map to risk tiers."""
    assert get_risk_level_for_score(85.0) == "CRITICAL"
    assert get_risk_level_for_score(60.0) == "HIGH"
    assert get_risk_level_for_score(35.0) == "MEDIUM"
    assert get_risk_level_for_score(15.0) == "LOW"
