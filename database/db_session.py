"""
PrivacyVault AI - Database Manager & Session Handler
Uses SQLite with strictly parameterized queries for persistent, lightweight, and secure storage.
"""

import sqlite3
import json
import logging
from datetime import datetime
from pathlib import Path
from config.settings import Config

logger = logging.getLogger(__name__)


def get_db_connection():
    """Create and return a configured SQLite connection with row factories."""
    Config.ensure_directories()
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    """Initialize database tables and seed baseline detection rules."""
    Config.ensure_directories()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                file_type TEXT NOT NULL,
                file_size_bytes INTEGER NOT NULL,
                scan_timestamp TEXT NOT NULL,
                risk_score REAL NOT NULL,
                risk_level TEXT NOT NULL,
                finding_count INTEGER NOT NULL,
                ml_category TEXT DEFAULT 'Unclassified',
                ml_confidence REAL DEFAULT 0.0,
                status TEXT NOT NULL DEFAULT 'COMPLETED',
                metadata_json TEXT DEFAULT '{}',
                risk_reasons_json TEXT DEFAULT '[]'
            );
        """)
        
        # Findings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                category TEXT NOT NULL,
                finding_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                masked_value TEXT NOT NULL,
                raw_value_hash TEXT NOT NULL,
                location_type TEXT NOT NULL,
                location_ref TEXT NOT NULL,
                context_snippet TEXT,
                confidence REAL DEFAULT 1.0,
                rule_id TEXT NOT NULL,
                remediation_hint TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
            );
        """)
        
        # Data leakage alerts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS leakage_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                alert_title TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                location_ref TEXT NOT NULL,
                description TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
            );
        """)
        
        # Rule configurations table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rule_configs (
                rule_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                description TEXT NOT NULL,
                pattern_summary TEXT NOT NULL
            );
        """)
        
        conn.commit()
        
    _seed_default_rules()
    logger.info("Database initialized successfully.")


def _seed_default_rules():
    """Seed detection rules if rule_configs table is empty."""
    default_rules = [
        # PII
        ("RULE_EMAIL_01", "Email Address", "PII", "MEDIUM", 1, "Detects personal and corporate email addresses", "RFC 5322 standard email regex"),
        ("RULE_PHONE_INTL", "Phone Number (International & US)", "PII", "MEDIUM", 1, "Detects standard international and US phone numbers", "E.164 and standard format (+1, xxx-xxx-xxxx)"),
        ("RULE_PHONE_IN", "Phone Number (India Mobile)", "PII", "MEDIUM", 1, "Detects Indian 10-digit mobile numbers with/without +91", "(\\+91[\\-\\s]?)?[6-9]\\d{9}"),
        ("RULE_SSN_US", "US Social Security Number", "PII", "CRITICAL", 1, "Detects 9-digit US SSN with group validation", "\\d{3}-\\d{2}-\\d{4} with area/group rule checks"),
        ("RULE_AADHAAR_IN", "India Aadhaar Number", "PII", "CRITICAL", 1, "Detects 12-digit Indian Aadhaar with Verhoeff checksum", "12 digits with 4-4-4 spacing and checksum validation"),
        ("RULE_PAN_IN", "India PAN Card Number", "PII", "HIGH", 1, "Detects 10-character Permanent Account Number", "[A-Z]{5}[0-9]{4}[A-Z]"),
        ("RULE_PASSPORT", "Passport Number Format", "PII", "HIGH", 1, "Detects alphanumeric passport number identifiers", "Standard passport patterns with contextual validation"),
        ("RULE_PERSON_NAME", "Personal Name in Record", "PII", "LOW", 1, "Identifies full names preceding or following identity labels", "Contextual prefix matching ('Name:', 'Customer:', etc.)"),
        ("RULE_IP_ADDRESS", "IPv4 & IPv6 Address", "PII", "LOW", 1, "Detects external host network IP addresses", "Standard IPv4 octet and IPv6 pattern with valid range check"),
        
        # Financial
        ("RULE_CREDIT_CARD", "Credit / Debit Card Number", "Financial Information", "CRITICAL", 1, "Detects 13-19 digit card numbers validated with Luhn Algorithm", "Visa, MC, Amex, Discover, RuPay + Luhn checksum"),
        ("RULE_IBAN_BANK", "International Bank Account (IBAN)", "Financial Information", "CRITICAL", 1, "Detects international bank account number format", "2-letter country code + 2 check digits + up to 30 alphanumeric"),
        ("RULE_ROUTING_ABA", "US Bank Routing Transit Number", "Financial Information", "HIGH", 1, "Detects 9-digit ABA routing numbers", "Context-anchored 9-digit routing numbers"),
        ("RULE_SALARY_FIN", "Compensation / Salary Record", "Financial Information", "MEDIUM", 1, "Detects salary statements, CTC figures, and payroll figures", "Currency anchors with compensation keywords"),
        
        # Authentication Secrets
        ("RULE_AWS_KEY_ID", "AWS Access Key ID", "Authentication Secrets", "CRITICAL", 1, "Detects active AWS access key identifiers", "AKIA[0-9A-Z]{16}"),
        ("RULE_AWS_SECRET", "AWS Secret Access Key", "Authentication Secrets", "CRITICAL", 1, "Detects 40-character base64 AWS secret keys", "40-character high-entropy secret token in AWS context"),
        ("RULE_GITHUB_PAT", "GitHub Personal Access Token", "Authentication Secrets", "CRITICAL", 1, "Detects classic and fine-grained GitHub authentication tokens", "ghp_[a-zA-Z0-9]{36} and github_pat_ prefix"),
        ("RULE_SLACK_TOKEN", "Slack API Bot / User Token", "Authentication Secrets", "CRITICAL", 1, "Detects Slack bot and user bearer tokens", "xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"),
        ("RULE_PRIVATE_KEY", "Private Cryptographic Key", "Authentication Secrets", "CRITICAL", 1, "Detects RSA, DSA, EC, and OpenSSH private key headers", "-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        ("RULE_JWT_TOKEN", "JSON Web Token (JWT)", "Authentication Secrets", "HIGH", 1, "Detects signed bearer JWTs in requests and configuration", "eyJ[a-zA-Z0-9_-]+\\.eyJ[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+"),
        ("RULE_ASSIGNED_PASSWD", "Hardcoded Password in Assignment", "Authentication Secrets", "HIGH", 1, "Detects raw passwords and secrets assigned in text/code", "(?i)(password|secret|api_key|token)\\s*[:=]\\s*['\"][^'\"]+['\"]"),
        
        # Confidential Business
        ("RULE_CONFIDENTIAL_LABEL", "Confidential / Restricted Marking", "Confidential Business Information", "MEDIUM", 1, "Detects explicit corporate sensitivity classification banners", "CONFIDENTIAL, RESTRICTED, PROPRIETARY, STRICTLY PRIVATE"),
        ("RULE_NDA_TERMS", "Non-Disclosure & Trade Secret Terms", "Confidential Business Information", "MEDIUM", 1, "Detects legal protection and trade secret clauses", "NDA, Trade Secret, Intellectual Property, Non-Disclosure"),
        ("RULE_MERGER_ACQUISITION", "M&A / Insider Financial Project", "Confidential Business Information", "HIGH", 1, "Detects pre-market merger, acquisition, or financial audit disclosures", "Project code names, acquisition terms, Q-earnings preview")
    ]
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        for rule in default_rules:
            cursor.execute("""
                INSERT OR IGNORE INTO rule_configs 
                (rule_id, name, category, severity, enabled, description, pattern_summary)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, rule)
        conn.commit()


def save_scan(scan_dict, findings_list, leakage_alerts_list):
    """Save scan record and related findings and leakage alerts in a single transaction."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO scans (
                id, filename, original_filename, file_type, file_size_bytes,
                scan_timestamp, risk_score, risk_level, finding_count,
                ml_category, ml_confidence, status, metadata_json, risk_reasons_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_dict["id"],
            scan_dict["filename"],
            scan_dict["original_filename"],
            scan_dict["file_type"],
            scan_dict["file_size_bytes"],
            scan_dict.get("scan_timestamp", datetime.utcnow().isoformat()),
            scan_dict["risk_score"],
            scan_dict["risk_level"],
            scan_dict["finding_count"],
            scan_dict.get("ml_category", "Unclassified"),
            scan_dict.get("ml_confidence", 0.0),
            scan_dict.get("status", "COMPLETED"),
            json.dumps(scan_dict.get("metadata", {})),
            json.dumps(scan_dict.get("risk_reasons", []))
        ))
        
        for f in findings_list:
            cursor.execute("""
                INSERT INTO findings (
                    scan_id, category, finding_type, severity, masked_value,
                    raw_value_hash, location_type, location_ref, context_snippet,
                    confidence, rule_id, remediation_hint
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_dict["id"],
                f["category"],
                f["finding_type"],
                f["severity"],
                f["masked_value"],
                f.get("raw_value_hash", ""),
                f["location_type"],
                f["location_ref"],
                f.get("context_snippet", ""),
                f.get("confidence", 1.0),
                f["rule_id"],
                f.get("remediation_hint", "")
            ))
            
        for a in leakage_alerts_list:
            cursor.execute("""
                INSERT INTO leakage_alerts (
                    scan_id, alert_title, alert_type, severity,
                    location_ref, description, recommendation
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_dict["id"],
                a["alert_title"],
                a["alert_type"],
                a["severity"],
                a["location_ref"],
                a["description"],
                a["recommendation"]
            ))
            
        conn.commit()


def get_scan_by_id(scan_id):
    """Retrieve a single scan record with parsed JSON fields."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        if not row:
            return None
        
        scan = dict(row)
        try:
            scan["metadata"] = json.loads(scan.get("metadata_json") or "{}")
        except Exception:
            scan["metadata"] = {}
            
        try:
            scan["risk_reasons"] = json.loads(scan.get("risk_reasons_json") or "[]")
        except Exception:
            scan["risk_reasons"] = []
            
        return scan


def get_all_scans(limit=100, offset=0, severity_filter=None, file_type_filter=None, search_term=None):
    """Retrieve all scans with optional filtering."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM scans WHERE 1=1"
        params = []
        
        if severity_filter and severity_filter.upper() != "ALL":
            query += " AND risk_level = ?"
            params.append(severity_filter.upper())
            
        if file_type_filter and file_type_filter.lower() != "all":
            query += " AND file_type = ?"
            params.append(file_type_filter.lower())
            
        if search_term:
            query += " AND (original_filename LIKE ? OR ml_category LIKE ?)"
            params.extend([f"%{search_term}%", f"%{search_term}%"])
            
        query += " ORDER BY scan_timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        scans = []
        for r in rows:
            s = dict(r)
            try:
                s["metadata"] = json.loads(s.get("metadata_json") or "{}")
                s["risk_reasons"] = json.loads(s.get("risk_reasons_json") or "[]")
            except Exception:
                s["metadata"] = {}
                s["risk_reasons"] = []
            scans.append(s)
            
        return scans


def get_scan_findings(scan_id, category=None, severity=None, search=None):
    """Retrieve findings for a specific scan with optional filters."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM findings WHERE scan_id = ?"
        params = [scan_id]
        
        if category and category.upper() != "ALL":
            query += " AND category = ?"
            params.append(category)
            
        if severity and severity.upper() != "ALL":
            query += " AND severity = ?"
            params.append(severity.upper())
            
        if search:
            query += " AND (finding_type LIKE ? OR masked_value LIKE ? OR location_ref LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
            
        query += " ORDER BY id ASC"
        cursor.execute(query, params)
        return [dict(r) for r in cursor.fetchall()]


def get_scan_leakage_alerts(scan_id):
    """Retrieve data leakage alerts for a specific scan."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM leakage_alerts WHERE scan_id = ? ORDER BY id ASC", (scan_id,))
        return [dict(r) for r in cursor.fetchall()]


def delete_scan(scan_id):
    """Delete a scan record and all associated findings and alerts from the database."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT filename FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        
        # Remove physical file if it exists
        if row and row["filename"]:
            file_path = Config.UPLOAD_FOLDER / row["filename"]
            if file_path.exists():
                try:
                    file_path.unlink()
                except Exception as e:
                    logger.warning(f"Failed to delete physical file {file_path}: {e}")
                    
        cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        return True


def get_rule_configs():
    """Retrieve all rule configurations."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM rule_configs ORDER BY category ASC, rule_id ASC")
        return [dict(r) for r in cursor.fetchall()]


def update_rule_status(rule_id, enabled):
    """Enable or disable a specific detection rule."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE rule_configs SET enabled = ? WHERE rule_id = ?", (1 if enabled else 0, rule_id))
        conn.commit()
        return cursor.rowcount > 0


def get_dashboard_stats():
    """Compute aggregate statistics directly from SQLite for the Privacy Dashboard."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # 1. High-level totals
        cursor.execute("SELECT COUNT(*) AS total_scans FROM scans")
        total_scans = cursor.fetchone()["total_scans"]
        
        cursor.execute("SELECT COUNT(*) AS total_findings FROM findings")
        total_findings = cursor.fetchone()["total_findings"]
        
        cursor.execute("SELECT COUNT(*) AS critical_count FROM findings WHERE severity = 'CRITICAL'")
        critical_count = cursor.fetchone()["critical_count"]
        
        cursor.execute("SELECT COUNT(*) AS high_count FROM findings WHERE severity = 'HIGH'")
        high_count = cursor.fetchone()["high_count"]
        
        cursor.execute("SELECT COUNT(*) AS total_alerts FROM leakage_alerts")
        total_alerts = cursor.fetchone()["total_alerts"]
        
        # Average risk score across completed scans
        cursor.execute("SELECT AVG(risk_score) AS avg_risk FROM scans WHERE status = 'COMPLETED'")
        row = cursor.fetchone()
        avg_risk_score = round(row["avg_risk"], 1) if row and row["avg_risk"] is not None else 0.0
        
        # 2. Findings by category
        cursor.execute("""
            SELECT category, COUNT(*) as count 
            FROM findings 
            GROUP BY category 
            ORDER BY count DESC
        """)
        findings_by_category = {r["category"]: r["count"] for r in cursor.fetchall()}
        
        # 3. Findings by severity
        cursor.execute("""
            SELECT severity, COUNT(*) as count 
            FROM findings 
            GROUP BY severity
        """)
        severity_map = {r["severity"]: r["count"] for r in cursor.fetchall()}
        findings_by_severity = {
            "CRITICAL": severity_map.get("CRITICAL", 0),
            "HIGH": severity_map.get("HIGH", 0),
            "MEDIUM": severity_map.get("MEDIUM", 0),
            "LOW": severity_map.get("LOW", 0)
        }
        
        # 4. Top sensitive data types
        cursor.execute("""
            SELECT finding_type, COUNT(*) as count 
            FROM findings 
            GROUP BY finding_type 
            ORDER BY count DESC 
            LIMIT 7
        """)
        top_data_types = [{"type": r["finding_type"], "count": r["count"]} for r in cursor.fetchall()]
        
        # 5. Scans by risk tier
        cursor.execute("""
            SELECT risk_level, COUNT(*) as count 
            FROM scans 
            GROUP BY risk_level
        """)
        risk_level_map = {r["risk_level"]: r["count"] for r in cursor.fetchall()}
        scans_by_risk = {
            "CRITICAL": risk_level_map.get("CRITICAL", 0),
            "HIGH": risk_level_map.get("HIGH", 0),
            "MEDIUM": risk_level_map.get("MEDIUM", 0),
            "LOW": risk_level_map.get("LOW", 0)
        }
        
        # 6. Recent 5 scans
        cursor.execute("""
            SELECT id, original_filename, file_type, scan_timestamp, risk_score, risk_level, finding_count 
            FROM scans 
            ORDER BY scan_timestamp DESC 
            LIMIT 5
        """)
        recent_scans = [dict(r) for r in cursor.fetchall()]
        
        return {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "critical_findings": critical_count,
            "high_findings": high_count,
            "total_leakage_alerts": total_alerts,
            "avg_risk_score": avg_risk_score,
            "findings_by_category": findings_by_category,
            "findings_by_severity": findings_by_severity,
            "top_data_types": top_data_types,
            "scans_by_risk": scans_by_risk,
            "recent_scans": recent_scans
        }
