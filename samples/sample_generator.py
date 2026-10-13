"""
PrivacyVault AI - Synthetic Sample Data Generator
Generates realistic, completely synthetic test files across all 5 supported formats (CSV, JSON, TXT, DOCX, PDF)
strictly using non-real dummy credentials, Luhn-valid test cards, and dummy PII.
"""

import csv
import json
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import Config
import docx
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet


def generate_all_samples():
    """Create synthetic test files in the samples directory for immediate demonstration."""
    Config.ensure_directories()
    samples_dir = Config.SAMPLES_FOLDER
    
    # 1. Synthetic CSV: Customer & Financial Records
    csv_path = samples_dir / "sample_customer_records.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "customer_id", "full_name", "email_address", "phone_number",
            "pan_number", "credit_card_no", "public_notes"
        ])
        # Note: 4532015112830366 is a standard Luhn-valid test Visa number
        writer.writerow([
            "CUST-1001", "Rohan Verma", "rohan.verma@example.com", "+91 98765 43210",
            "ABCDE1234F", "4532015112830366", "User requested priority shipping. Contacted via phone."
        ])
        # 5424180123456789 is a standard Luhn-valid test MasterCard number
        writer.writerow([
            "CUST-1002", "Priya Sharma", "priya.sharma@domain.org", "+91 87654 32109",
            "BKZPS8821K", "5424180123456789", "User provided backup email priya.work@example.com in comments."
        ])
        writer.writerow([
            "CUST-1003", "Amitabh Sen", "amitabh.sen@testmail.com", "9123456780",
            "XYZPA9988C", "4000123456789010", "Billing address verified. No remarks."
        ])

    # 2. Synthetic JSON: Cloud Infrastructure & API Config
    json_path = samples_dir / "sample_cloud_infrastructure.json"
    json_data = {
        "environment": "staging-us-east-1",
        "cluster_name": "k8s-prod-cluster",
        "cloud_provider": "AWS",
        "security": {
           "aws_access_key_id": "YOUR_AWS_ACCESS_KEY_ID",
           "aws_secret_context": "YOUR_AWS_SECRET_KEY",
           "slack_webhook_bot": "YOUR_SLACK_WEBHOOK_TOKEN"
        },
        "database": {
            "host": "192.168.1.150",
            "port": 5432,
            "username": "db_admin",
            "password": "SuperSecretDbPassword2026!"
        },
        "authorized_engineers": [
            {"name": "Vikram Malhotra", "email": "vikram.m@techcorp.internal", "role": "DevOps Lead"},
            {"name": "Ananya Roy", "email": "ananya.roy@techcorp.internal", "role": "Security Architect"}
        ]
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2)

    # 3. Synthetic TXT: Developer Configuration & Environment Notes
    txt_path = samples_dir / "sample_developer_credentials.txt"
    txt_content = """# Microservice Deployment Configuration Notes
# Internal use only - DO NOT COMMIT TO PUBLIC REPO

PROJECT_NAME=UserAuthenticationService
ENVIRONMENT=production
DEPLOY_IP=10.0.4.88

# Cloud Tokens for CI/CD
GITHUB_DEPLOY_TOKEN=ghp_SyntheticDevToken1234567890abcdef12345
SLACK_ALERT_CHANNEL=#security-alerts
CONTACT_EMAIL=devops-admin@enterprise-service.org

# Authentication Private Key
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y9lK7mZ1T2N8x4syntheticPrivateKeyHeaderExampleOnly
MIIEowIBAAKCAQEA0Y9lK7mZ1T2N8x4syntheticPrivateKeyHeaderExampleOnly
-----END RSA PRIVATE KEY-----

# Local Test Credentials
ADMIN_LOGIN=sysadmin
DATABASE_PASSWORD="P@ssw0rdSecureProd2026#"
"""
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(txt_content)

    # 4. Synthetic DOCX: Confidential Executive M&A Contract
    docx_path = samples_dir / "sample_confidential_contract.docx"
    doc = docx.Document()
    doc.core_properties.author = "Executive Vice President - Strategy"
    doc.core_properties.title = "Project Apollo Acquisition Discussion"
    
    doc.add_heading("CONFIDENTIAL — NON-DISCLOSURE & MERGER EVALUATION", level=0)
    p1 = doc.add_paragraph("STRICTLY CONFIDENTIAL AND PROPRIETARY INFORMATION")
    p1.runs[0].bold = True
    
    doc.add_paragraph(
        "This Non-Disclosure Agreement (NDA) is entered into between FinCorp Ltd. and TargetTech Innovations. "
        "The following preliminary compensation and merger terms are subject to SEC regulatory approval."
    )
    
    doc.add_paragraph("Key Executive Stakeholders:")
    doc.add_paragraph("Lead Negotiator: Name: Rajesh K. Singhania, Email: r.singhania@fincorporation.org, Phone: +91 99887 76655")
    
    table = doc.add_table(rows=1, cols=3)
    hdr_cells = table.rows[0].cells
    hdr_cells[0].text = "Executive Role"
    hdr_cells[1].text = "Proposed Compensation (CTC)"
    hdr_cells[2].text = "Direct Contact"
    
    r1 = table.add_row().cells
    r1[0].text = "Chief Technology Officer"
    r1[1].text = "Salary: $350,000 per annum"
    r1[2].text = "cto-confidential@fincorporation.org"
    
    r2 = table.add_row().cells
    r2[0].text = "Chief Financial Officer"
    r2[1].text = "Salary: $320,000 per annum"
    r2[2].text = "cfo-confidential@fincorporation.org"
    
    doc.save(str(docx_path))

    # 5. Synthetic PDF: Medical & PII Intake Dossier
    pdf_path = samples_dir / "sample_patient_records.pdf"
    pdf_doc = SimpleDocTemplate(str(pdf_path), pagesize=letter)
    styles = getSampleStyleSheet()
    
    pdf_story = []
    pdf_story.append(Paragraph("<b>Metropolitan Health Institute — Patient Intake Record</b>", styles["Heading1"]))
    pdf_story.append(Paragraph("CONFIDENTIAL MEDICAL RECORD — Protected Health Information (HIPAA)", styles["Normal"]))
    pdf_story.append(Spacer(1, 14))
    
    pdf_story.append(Paragraph("<b>Patient Demographics:</b>", styles["Heading2"]))
    pdf_story.append(Paragraph("Patient Name: David Miller", styles["Normal"]))
    pdf_story.append(Paragraph("Social Security Number: 123-45-6789", styles["Normal"]))
    pdf_story.append(Paragraph("Contact Email: david.miller@healthpatient.org", styles["Normal"]))
    pdf_story.append(Paragraph("Primary Phone: 212-555-0199", styles["Normal"]))
    pdf_story.append(Paragraph("Billing Account Routing: Routing ABA: 121000358", styles["Normal"]))
    pdf_story.append(Spacer(1, 10))
    
    pdf_story.append(Paragraph("<b>Clinical Summary & Diagnosis:</b>", styles["Heading2"]))
    pdf_story.append(Paragraph(
        "Patient presented with chronic hypertension. Prescribed standard beta-blockers. "
        "Next clinical evaluation scheduled for next quarter. Emergency contact phone: 212-555-0144.",
        styles["Normal"]
    ))
    
    pdf_doc.build(pdf_story)
    
    return {
        "csv": str(csv_path),
        "json": str(json_path),
        "txt": str(txt_path),
        "docx": str(docx_path),
        "pdf": str(pdf_path)
    }


if __name__ == "__main__":
    generate_all_samples()
    print("All synthetic sample files generated successfully.")
