"""
PrivacyVault AI - Scan Result Routes
Renders dedicated analytical views for scan summaries, findings, risk models, leakage, and exports.
"""

from flask import Blueprint, render_template, abort, request
from database import (
    get_scan_by_id,
    get_scan_findings,
    get_scan_leakage_alerts
)
from remediation.recommender import generate_remediation_plan

scan_bp = Blueprint("scan", __name__, url_prefix="/scan")


@scan_bp.route("/<scan_id>")
def summary(scan_id):
    """4. Scan Progress & Executive Summary Page."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        abort(404, description="Scan record not found.")
        
    findings = get_scan_findings(scan_id)
    leakage_alerts = get_scan_leakage_alerts(scan_id)
    remediation_plan = generate_remediation_plan(findings, leakage_alerts)
    
    return render_template(
        "scan_progress.html",
        scan=scan,
        findings=findings,
        leakage_alerts=leakage_alerts,
        remediation_plan=remediation_plan
    )


@scan_bp.route("/<scan_id>/findings")
def findings(scan_id):
    """5. Detailed Findings Page with filters, search, and expandable cards."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        abort(404, description="Scan record not found.")
        
    category_filter = request.args.get("category")
    severity_filter = request.args.get("severity")
    search_query = request.args.get("search")
    
    findings_list = get_scan_findings(
        scan_id,
        category=category_filter,
        severity=severity_filter,
        search=search_query
    )
    
    return render_template(
        "findings.html",
        scan=scan,
        findings=findings_list,
        current_category=category_filter or "ALL",
        current_severity=severity_filter or "ALL",
        current_search=search_query or ""
    )


@scan_bp.route("/<scan_id>/risk")
def risk_analysis(scan_id):
    """6. Privacy Risk Analysis Page: scoring formula, weights, ML classification vs rules."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        abort(404, description="Scan record not found.")
        
    findings = get_scan_findings(scan_id)
    return render_template("risk_analysis.html", scan=scan, findings=findings)


@scan_bp.route("/<scan_id>/leakage")
def leakage_analysis(scan_id):
    """7. Data Leakage Analysis Page: co-occurrence, public columns, credential exposure."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        abort(404, description="Scan record not found.")
        
    findings = get_scan_findings(scan_id)
    leakage_alerts = get_scan_leakage_alerts(scan_id)
    return render_template(
        "leakage_analysis.html",
        scan=scan,
        findings=findings,
        leakage_alerts=leakage_alerts
    )


@scan_bp.route("/<scan_id>/export")
def export(scan_id):
    """9. Report Export Center: PDF, CSV, JSON, and Redacted File download options."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        abort(404, description="Scan record not found.")
        
    findings = get_scan_findings(scan_id)
    leakage_alerts = get_scan_leakage_alerts(scan_id)
    return render_template(
        "export.html",
        scan=scan,
        findings=findings,
        leakage_alerts=leakage_alerts
    )
