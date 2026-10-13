"""
PrivacyVault AI - REST API & Export Endpoints
Handles file uploads, sample triggers, async stats, rule toggles, and report downloads.
"""

import shutil
import uuid
from pathlib import Path
from flask import (
    Blueprint, request, jsonify, send_file, Response, render_template, abort
)
from werkzeug.utils import secure_filename

from config.settings import Config
from database import (
    get_scan_by_id,
    get_scan_findings,
    get_scan_leakage_alerts,
    delete_scan,
    get_dashboard_stats,
    update_rule_status,
    get_all_scans
)
from services import run_privacy_scan
from reports import (
    generate_pdf_report,
    generate_csv_report,
    generate_json_report,
    generate_redacted_document
)
from remediation.ai_assistant import explain_finding_with_ai

api_bp = Blueprint("api", __name__)


@api_bp.route("/api/upload", methods=["POST"])
def handle_upload():
    """Accept and process uploaded document or dataset."""
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file payload provided in request."}), 400
        
    file = request.files["file"]
    if not file or file.filename == "":
        return jsonify({"success": False, "error": "No file selected."}), 400
        
    original_filename = file.filename
    clean_filename = secure_filename(original_filename)
    if not clean_filename:
        clean_filename = f"uploaded_file_{uuid.uuid4().hex[:6]}.txt"
        
    ext = clean_filename.rsplit(".", 1)[-1].lower() if "." in clean_filename else ""
    if ext not in Config.ALLOWED_EXTENSIONS:
        return jsonify({
            "success": False,
            "error": f"Unsupported format '.{ext}'. Supported formats are: PDF, DOCX, TXT, CSV, JSON."
        }), 400
        
    # Save file to uploads folder with unique prefix to avoid collisions
    unique_name = f"{uuid.uuid4().hex[:8]}_{clean_filename}"
    save_path = Config.UPLOAD_FOLDER / unique_name
    file.save(str(save_path))
    
    # Run scan pipeline
    try:
        scan_result = run_privacy_scan(save_path, original_filename)
        scan_id = scan_result["scan"]["id"]
        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "filename": original_filename,
            "risk_score": scan_result["scan"]["risk_score"],
            "risk_level": scan_result["scan"]["risk_level"],
            "finding_count": scan_result["scan"]["finding_count"],
            "redirect_url": f"/scan/{scan_id}"
        })
    except Exception as e:
        return jsonify({"success": False, "error": f"Scanning error: {str(e)}"}), 500


@api_bp.route("/api/scan-sample", methods=["POST"])
def handle_scan_sample():
    """Trigger an instant scan on one of the pre-generated synthetic sample files."""
    data = request.get_json() or {}
    sample_key = data.get("sample_key", "csv")
    
    mapping = {
        "csv": "sample_customer_records.csv",
        "json": "sample_cloud_infrastructure.json",
        "txt": "sample_developer_credentials.txt",
        "docx": "sample_confidential_contract.docx",
        "pdf": "sample_patient_records.pdf"
    }
    
    filename = mapping.get(sample_key, "sample_customer_records.csv")
    sample_source = Config.SAMPLES_FOLDER / filename
    
    if not sample_source.exists():
        # Generate samples if not already created
        from samples.sample_generator import generate_all_samples
        generate_all_samples()
        
    # Copy sample to uploads
    unique_name = f"sample_{uuid.uuid4().hex[:6]}_{filename}"
    dest_path = Config.UPLOAD_FOLDER / unique_name
    shutil.copyfile(str(sample_source), str(dest_path))
    
    try:
        scan_result = run_privacy_scan(dest_path, filename)
        scan_id = scan_result["scan"]["id"]
        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "filename": filename,
            "risk_score": scan_result["scan"]["risk_score"],
            "risk_level": scan_result["scan"]["risk_level"],
            "finding_count": scan_result["scan"]["finding_count"],
            "redirect_url": f"/scan/{scan_id}"
        })
    except Exception as e:
        return jsonify({"success": False, "error": f"Scanning failure: {str(e)}"}), 500


@api_bp.route("/api/stats", methods=["GET"])
def get_stats():
    """Return dashboard analytics metrics as JSON."""
    return jsonify(get_dashboard_stats())


@api_bp.route("/api/scans", methods=["GET"])
def get_scans_list():
    """Return scans with optional filtering."""
    severity = request.args.get("severity")
    file_type = request.args.get("file_type")
    search = request.args.get("search")
    scans = get_all_scans(severity_filter=severity, file_type_filter=file_type, search_term=search)
    return jsonify({"scans": scans})


@api_bp.route("/api/scan/<scan_id>", methods=["DELETE", "POST"])
def delete_scan_record(scan_id):
    """Delete a scan record and its uploaded file from database and disk."""
    success = delete_scan(scan_id)
    return jsonify({"success": success})


@api_bp.route("/api/rules/<rule_id>/toggle", methods=["POST"])
def toggle_rule(rule_id):
    """Enable or disable a detection rule."""
    data = request.get_json() or {}
    enabled = bool(data.get("enabled", True))
    success = update_rule_status(rule_id, enabled)
    return jsonify({"success": success, "rule_id": rule_id, "enabled": enabled})


@api_bp.route("/api/explain-finding", methods=["POST"])
def explain_finding():
    """Fetch an in-depth threat and compliance explanation for a finding."""
    data = request.get_json() or {}
    api_key = data.get("api_key")
    result = explain_finding_with_ai(data, api_key=api_key)
    return jsonify(result)


# ----------------- Export Endpoints -----------------

@api_bp.route("/export/<scan_id>/pdf")
def export_pdf(scan_id):
    """Generate and download a professional PDF audit report."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        abort(404)
        
    findings = get_scan_findings(scan_id)
    leakage_alerts = get_scan_leakage_alerts(scan_id)
    pdf_bytes = generate_pdf_report(scan, findings, leakage_alerts)
    
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=PrivacyVault_Audit_{scan_id}.pdf"}
    )


@api_bp.route("/export/<scan_id>/csv")
def export_csv(scan_id):
    """Download CSV file containing all masked findings."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        abort(404)
        
    findings = get_scan_findings(scan_id)
    csv_str = generate_csv_report(findings)
    
    return Response(
        csv_str,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=findings_{scan_id}.csv"}
    )


@api_bp.route("/export/<scan_id>/json")
def export_json(scan_id):
    """Download machine-readable JSON compliance report."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        abort(404)
        
    findings = get_scan_findings(scan_id)
    leakage_alerts = get_scan_leakage_alerts(scan_id)
    json_str = generate_json_report(scan, findings, leakage_alerts)
    
    return Response(
        json_str,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=audit_{scan_id}.json"}
    )


@api_bp.route("/export/<scan_id>/print")
def print_view(scan_id):
    """Render a print-optimized executive report page."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        abort(404)
        
    findings = get_scan_findings(scan_id)
    leakage_alerts = get_scan_leakage_alerts(scan_id)
    return render_template(
        "export_print.html",
        scan=scan,
        findings=findings,
        leakage_alerts=leakage_alerts
    )


@api_bp.route("/export/<scan_id>/redacted")
def export_redacted(scan_id):
    """Download a sanitized copy of the uploaded file with sensitive items masked."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        abort(404)
        
    file_path = Config.UPLOAD_FOLDER / scan["filename"]
    if not file_path.exists():
        abort(404, description="Original file no longer available on server.")
        
    findings = get_scan_findings(scan_id)
    file_bytes, download_name = generate_redacted_document(file_path, scan["file_type"], findings)
    
    return Response(
        file_bytes,
        mimetype="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={download_name}"}
    )
