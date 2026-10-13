"""
PrivacyVault AI - Core Scanning & Orchestration Service
Orchestrates document extraction, regex detection, ML classification,
risk calculation, leakage analysis, and persistent database storage.
"""

import uuid
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

from config.settings import Config
from document_processing import extract_document
from detection import detect_sensitive_data, get_ml_classifier
from risk_scoring import calculate_risk_score
from leakage_analysis import analyze_data_leakage
from database import save_scan, get_rule_configs

logger = logging.getLogger(__name__)


def run_privacy_scan(file_path: Path, original_filename: str) -> Dict[str, Any]:
    """
    Execute full end-to-end privacy and leakage scan on a target file.
    Returns: Complete scan summary dictionary.
    """
    scan_id = f"scan_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:6]}"
    file_size_bytes = file_path.stat().st_size if file_path.exists() else 0
    file_ext = file_path.suffix.lstrip(".").lower()
    
    # 1. Document Extraction
    doc = extract_document(file_path, original_filename)
    if doc.error and not doc.segments:
        # Extraction failed completely
        scan_dict = {
            "id": scan_id,
            "filename": file_path.name,
            "original_filename": original_filename,
            "file_type": file_ext,
            "file_size_bytes": file_size_bytes,
            "scan_timestamp": datetime.utcnow().isoformat(),
            "risk_score": 0.0,
            "risk_level": "LOW",
            "finding_count": 0,
            "ml_category": "Error",
            "ml_confidence": 0.0,
            "status": "FAILED",
            "metadata": {"extraction_error": doc.error},
            "risk_reasons": [f"Extraction failed: {doc.error}"]
        }
        save_scan(scan_dict, [], [])
        return scan_dict

    # 2. Get active detection rules
    rule_configs = get_rule_configs()
    active_rules = [r["rule_id"] for r in rule_configs if r.get("enabled", 1) == 1]
    
    # 3. Detect sensitive information
    findings = detect_sensitive_data(doc, active_rules=active_rules)
    
    # 4. Machine Learning classification
    ml_classifier = get_ml_classifier()
    full_text = doc.get_full_text()
    ml_result = ml_classifier.predict(full_text)
    
    # 5. Risk Scoring Calculation
    risk_assessment = calculate_risk_score(findings, file_type=file_ext, metadata=doc.metadata)
    
    # 6. Data Leakage Analysis
    leakage_alerts = analyze_data_leakage(doc, findings)
    
    # 7. Package Scan Record
    scan_dict = {
        "id": scan_id,
        "filename": file_path.name,
        "original_filename": original_filename,
        "file_type": file_ext,
        "file_size_bytes": file_size_bytes,
        "scan_timestamp": datetime.utcnow().isoformat(),
        "risk_score": risk_assessment["score"],
        "risk_level": risk_assessment["level"],
        "finding_count": len(findings),
        "ml_category": ml_result["predicted_category"],
        "ml_confidence": ml_result["confidence"],
        "status": "COMPLETED",
        "metadata": {
            **doc.metadata,
            "ml_top_keywords": ml_result.get("top_keywords", []),
            "total_segments_scanned": len(doc.segments)
        },
        "risk_reasons": risk_assessment["reasons"]
    }
    
    # 8. Save transactionally to SQLite
    save_scan(scan_dict, findings, leakage_alerts)
    
    return {
        "scan": scan_dict,
        "findings": findings,
        "leakage_alerts": leakage_alerts,
        "risk_assessment": risk_assessment
    }
