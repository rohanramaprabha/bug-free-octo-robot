"""
PrivacyVault AI - Unit Tests for Data Leakage Analysis Engine
"""

from leakage_analysis import analyze_data_leakage
from document_processing.extractor_base import ExtractedDocument


def test_co_occurrence_alert_detected():
    """Verify co-occurrence of identity and financial card in same row triggers alert."""
    doc = ExtractedDocument(filename="data.csv", file_type="csv")
    findings = [
        {
            "finding_type": "Personal Name",
            "category": "PII",
            "severity": "LOW",
            "location_ref": "Row 5, Column 'name'",
            "masked_value": "R*** V****"
        },
        {
            "finding_type": "Credit Card Number",
            "category": "Financial Information",
            "severity": "CRITICAL",
            "location_ref": "Row 5, Column 'card_no'",
            "masked_value": "****-****-****-0366"
        }
    ]
    
    alerts = analyze_data_leakage(doc, findings)
    alert_types = [a["alert_type"] for a in alerts]
    
    assert "CO_OCCURRENCE" in alert_types
    co_alert = [a for a in alerts if a["alert_type"] == "CO_OCCURRENCE"][0]
    assert co_alert["severity"] == "CRITICAL"
    assert "Row 5" in co_alert["location_ref"]


def test_public_column_exposure_alert_detected():
    """Verify sensitive value inside public-facing column triggers exposure alert."""
    doc = ExtractedDocument(filename="dataset.csv", file_type="csv")
    findings = [
        {
            "finding_type": "Email Address",
            "category": "PII",
            "severity": "MEDIUM",
            "location_ref": "Row 2, Column 'public_notes'",
            "masked_value": "sec***@work.com"
        }
    ]
    
    alerts = analyze_data_leakage(doc, findings)
    alert_types = [a["alert_type"] for a in alerts]
    
    assert "PUBLIC_COLUMN_EXPOSURE" in alert_types


def test_config_credentials_alert_detected():
    """Verify plaintext secrets in config file trigger static credential alert."""
    doc = ExtractedDocument(filename="settings.json", file_type="json")
    findings = [
        {
            "finding_type": "AWS Access Key ID",
            "category": "Authentication Secrets",
            "severity": "CRITICAL",
            "location_ref": "Path: $.security.aws_key",
            "masked_value": "AKIA************"
        }
    ]
    
    alerts = analyze_data_leakage(doc, findings)
    alert_types = [a["alert_type"] for a in alerts]
    
    assert "CONFIG_CREDENTIAL" in alert_types
