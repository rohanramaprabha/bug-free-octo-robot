"""
PrivacyVault AI — Intelligent Data Privacy and Leakage Prevention
Main Application Entrypoint & Factory
"""

import os
from datetime import datetime
from flask import Flask, render_template
from flask_cors import CORS

from config.settings import Config, get_config
from database import init_db
from routes import main_bp, scan_bp, api_bp


def create_app(test_config=None):
    """Application factory function."""
    app = Flask(__name__)
    
    # Load settings
    cfg = get_config()
    app.config.from_object(cfg)
    if test_config:
        app.config.update(test_config)
        
    CORS(app)
    
    # Initialize database tables and seed rules
    with app.app_context():
        init_db()
        
    # Register blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(api_bp)
    
    # Custom Jinja Template Filters
    @app.template_filter("format_date")
    def format_date(value):
        if not value:
            return "N/A"
        try:
            dt = datetime.fromisoformat(value)
            return dt.strftime("%b %d, %Y • %H:%M:%S")
        except Exception:
            return str(value)

    @app.template_filter("filesize_kb")
    def filesize_kb(bytes_val):
        if not bytes_val:
            return "0 KB"
        kb = bytes_val / 1024
        if kb > 1024:
            return f"{round(kb / 1024, 2)} MB"
        return f"{round(kb, 1)} KB"

    @app.template_filter("risk_badge_class")
    def risk_badge_class(level):
        mapping = {
            "CRITICAL": "badge-critical",
            "HIGH": "badge-high",
            "MEDIUM": "badge-medium",
            "LOW": "badge-low"
        }
        return mapping.get(str(level).upper(), "badge-secondary")

    # Error handlers
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template("404.html", error=str(e)), 404

    @app.errorhandler(413)
    def request_entity_too_large(e):
        return render_template("404.html", error=f"File exceeds maximum allowed upload size of {Config.MAX_CONTENT_LENGTH_MB}MB."), 413

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template("404.html", error=f"Internal Server Error: {str(e)}"), 500

    return app


app = create_app()

if __name__ == "__main__":
    # Ensure sample files exist on first startup
    try:
        from samples.sample_generator import generate_all_samples
        generate_all_samples()
    except Exception as e:
        print(f"Sample generator note: {e}")
        
    print("\n=======================================================")
    print("  PrivacyVault AI — Intelligent Data Privacy Server")
    print("  Running locally at: http://127.0.0.1:5000")
    print("=======================================================\n")
    app.run(host="127.0.0.1", port=5000, debug=True)
