"""
PrivacyVault AI - Integration Tests for End-to-End Pipeline & Flask Routes
"""

import json
from pathlib import Path
from app import create_app
from config.settings import Config
from database import (
    init_db, get_scan_by_id, get_scan_findings, get_dashboard_stats, delete_scan
)
from services import run_privacy_scan
from reports import generate_pdf_report, generate_csv_report, generate_json_report
from samples.sample_generator import generate_all_samples


def setup_module():
    """Initialize test environment, DB, and sample files."""
    Config.ensure_directories()
    init_db()
    generate_all_samples()


def test_end_to_end_customer_csv_scan():
    """Verify scanning synthetic CSV produces findings, risk score, and DB record."""
    csv_file = Config.SAMPLES_FOLDER / "sample_customer_records.csv"
    result = run_privacy_scan(csv_file, "sample_customer_records.csv")
    
    scan = result["scan"]
    findings = result["findings"]
    alerts = result["leakage_alerts"]
    
    assert scan["id"] is not None
    assert scan["status"] == "COMPLETED"
    assert scan["finding_count"] > 0
    assert scan["risk_score"] > 0
    
    # Check persistence in database
    db_scan = get_scan_by_id(scan["id"])
    assert db_scan is not None
    assert db_scan["original_filename"] == "sample_customer_records.csv"
    
    db_findings = get_scan_findings(scan["id"])
    assert len(db_findings) == len(findings)
    
    # Test Report Exports
    pdf_bytes = generate_pdf_report(db_scan, db_findings, alerts)
    assert len(pdf_bytes) > 500  # Valid non-empty PDF binary
    assert pdf_bytes.startswith(b"%PDF")
    
    csv_str = generate_csv_report(db_findings)
    assert "Finding ID" in csv_str
    assert "Masked Evidence" in csv_str
    
    json_str = generate_json_report(db_scan, db_findings, alerts)
    audit_data = json.loads(json_str)
    assert audit_data["audit_metadata"]["application"] == "PrivacyVault AI"


def test_flask_web_routes():
    """Verify all primary HTML pages and JSON endpoints return HTTP 200 OK."""
    app = create_app({"TESTING": True})
    with app.test_client() as client:
        # 1. Home
        res_home = client.get("/")
        assert res_home.status_code == 200
        assert b"PrivacyVault" in res_home.data
        
        # 2. Dashboard
        res_dash = client.get("/dashboard")
        assert res_dash.status_code == 200
        assert b"Privacy Intelligence Dashboard" in res_dash.data
        
        # 3. Upload
        res_upload = client.get("/upload")
        assert res_upload.status_code == 200
        assert b"Document &amp; Dataset Upload" in res_upload.data or b"Document & Dataset Upload" in res_upload.data
        
        # 4. History
        res_hist = client.get("/history")
        assert res_hist.status_code == 200
        assert b"Scan History" in res_hist.data
        
        # 5. Settings
        res_sett = client.get("/settings")
        assert res_sett.status_code == 200
        assert b"Active Detection Rules" in res_sett.data
        
        # 6. API Stats
        res_stats = client.get("/api/stats")
        assert res_stats.status_code == 200
        stats_json = res_stats.get_json()
        assert "total_scans" in stats_json
        assert "total_findings" in stats_json


def test_scan_deletion_workflow():
    """Verify scan record and its findings can be deleted completely."""
    txt_file = Config.SAMPLES_FOLDER / "sample_developer_credentials.txt"
    result = run_privacy_scan(txt_file, "sample_developer_credentials.txt")
    scan_id = result["scan"]["id"]
    
    assert get_scan_by_id(scan_id) is not None
    
    # Delete scan
    delete_scan(scan_id)
    assert get_scan_by_id(scan_id) is None
    assert len(get_scan_findings(scan_id)) == 0
