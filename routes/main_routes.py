"""
PrivacyVault AI - Main Page Routes
Handles navigation for Home, Dashboard, Upload, History, and Settings.
"""

from flask import Blueprint, render_template, request
from database import get_dashboard_stats, get_all_scans, get_rule_configs

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    """1. Home / Landing Page with feature highlights and quick scan launcher."""
    stats = get_dashboard_stats()
    return render_template("index.html", stats=stats)


@main_bp.route("/dashboard")
def dashboard():
    """2. Privacy Dashboard with real database-derived Chart.js visualizations."""
    stats = get_dashboard_stats()
    return render_template("dashboard.html", stats=stats)


@main_bp.route("/upload")
def upload():
    """3. Document and Dataset Upload Page with format validator & sample file triggers."""
    return render_template("upload.html")


@main_bp.route("/history")
def history():
    """8. Scan History Page with searchable table, risk levels, and actions."""
    severity = request.args.get("severity")
    file_type = request.args.get("file_type")
    search = request.args.get("search")
    
    scans = get_all_scans(severity_filter=severity, file_type_filter=file_type, search_term=search)
    return render_template(
        "history.html",
        scans=scans,
        current_severity=severity or "ALL",
        current_file_type=file_type or "ALL",
        current_search=search or ""
    )


@main_bp.route("/settings")
def settings():
    """10. Settings & Detection Rule Configuration Page."""
    rules = get_rule_configs()
    return render_template("settings.html", rules=rules)
