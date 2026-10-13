"""
PrivacyVault AI - Regular Expression Definitions & Rules
Comprehensive, modular patterns covering PII, Financial records, Secrets, and Confidential Business terms.
"""

import re
from typing import Dict, Any

# Precompiled regex patterns with metadata
DETECTION_RULES: Dict[str, Dict[str, Any]] = {
    # 1. PII
    "RULE_EMAIL_01": {
        "rule_id": "RULE_EMAIL_01",
        "name": "Email Address",
        "category": "PII",
        "severity": "MEDIUM",
        "pattern": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", re.IGNORECASE),
        "finding_type": "Email Address",
        "remediation": "Redact or pseudonymize email addresses before public sharing (GDPR Art. 6 / DPDP Act 2023)."
    },
    "RULE_PHONE_IN": {
        "rule_id": "RULE_PHONE_IN",
        "name": "Phone Number (India Mobile)",
        "category": "PII",
        "severity": "MEDIUM",
        "pattern": re.compile(r"(?:\+91[\-\s]?)?[6-9]\d{4}[\-\s]?\d{5}\b"),
        "finding_type": "Phone Number",
        "remediation": "Mask personal telephone numbers with leading/trailing digit preservation."
    },
    "RULE_PHONE_INTL": {
        "rule_id": "RULE_PHONE_INTL",
        "name": "Phone Number (US / International)",
        "category": "PII",
        "severity": "MEDIUM",
        "pattern": re.compile(r"(?:\+1[\-\s]?)?\(?\b[2-9]\d{2}\)?[\-\s]\d{3}[\-\s]\d{4}\b"),
        "finding_type": "Phone Number",
        "remediation": "Mask telephone numbers before sharing datasets across external teams."
    },
    "RULE_SSN_US": {
        "rule_id": "RULE_SSN_US",
        "name": "US Social Security Number (SSN)",
        "category": "PII",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "finding_type": "Social Security Number",
        "remediation": "Strictly encrypt or remove Social Security Numbers. Unauthorized exposure violates state and federal privacy mandates."
    },
    "RULE_AADHAAR_IN": {
        "rule_id": "RULE_AADHAAR_IN",
        "name": "India Aadhaar Number",
        "category": "PII",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\b[2-9]\d{3}[\s\-]\d{4}[\s\-]\d{4}\b"),
        "finding_type": "Aadhaar Number",
        "remediation": "Use Masked Aadhaar (showing only last 4 digits) as mandated by UIDAI regulations."
    },
    "RULE_PAN_IN": {
        "rule_id": "RULE_PAN_IN",
        "name": "India PAN Card Number",
        "category": "PII",
        "severity": "HIGH",
        "pattern": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
        "finding_type": "PAN Card Number",
        "remediation": "Mask PAN numbers to prevent tax identity exposure and fraudulent loan applications."
    },
    "RULE_IP_ADDRESS": {
        "rule_id": "RULE_IP_ADDRESS",
        "name": "IPv4 Address",
        "category": "PII",
        "severity": "LOW",
        "pattern": re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
        "finding_type": "IP Address",
        "remediation": "Anonymize or truncate IP address octets in public network logs and analytics."
    },
    "RULE_PERSON_NAME": {
        "rule_id": "RULE_PERSON_NAME",
        "name": "Identified Person Name",
        "category": "PII",
        "severity": "LOW",
        "pattern": re.compile(r"(?i)\b(?:Name|Patient|Employee|Student|Customer|Beneficiary|Cardholder)\s*[:=]\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b"),
        "finding_type": "Personal Name",
        "remediation": "Replace direct person names with synthetic or pseudonymized identifiers (e.g., USER_102)."
    },

    # 2. Financial Information
    "RULE_CREDIT_CARD": {
        "rule_id": "RULE_CREDIT_CARD",
        "name": "Credit / Debit Card Number",
        "category": "Financial Information",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11}|(?:508[5-9]|6521|6522)\d{12})\b"),
        "finding_type": "Credit Card Number",
        "remediation": "Never store full Primary Account Numbers (PAN) in unencrypted storage. Comply with PCI-DSS Req. 3.4."
    },
    "RULE_IBAN_BANK": {
        "rule_id": "RULE_IBAN_BANK",
        "name": "Bank Account (IBAN)",
        "category": "Financial Information",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b"),
        "finding_type": "Bank Account (IBAN)",
        "remediation": "Mask bank account routing and account numbers to prevent unauthorized direct debits."
    },
    "RULE_SALARY_FIN": {
        "rule_id": "RULE_SALARY_FIN",
        "name": "Salary / Compensation Record",
        "category": "Financial Information",
        "severity": "MEDIUM",
        "pattern": re.compile(r"(?i)\b(?:salary|ctc|compensation|payroll|annual package)\s*[:=]?\s*[\$€£₹]?\s*(\d{1,3}(?:,\d{3})*(?:\.\d{2})?|\d{5,9})\b"),
        "finding_type": "Compensation Record",
        "remediation": "Restrict compensation and payroll tables strictly to authorized HR personnel."
    },

    # 3. Authentication Secrets
    "RULE_AWS_KEY_ID": {
        "rule_id": "RULE_AWS_KEY_ID",
        "name": "AWS Access Key ID",
        "category": "Authentication Secrets",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "finding_type": "AWS Access Key ID",
        "remediation": "Revoke and rotate this AWS access key immediately via the AWS IAM Console to prevent cloud resource takeover."
    },
    "RULE_GITHUB_PAT": {
        "rule_id": "RULE_GITHUB_PAT",
        "name": "GitHub Personal Access Token",
        "category": "Authentication Secrets",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\b(?:ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b"),
        "finding_type": "GitHub Token",
        "remediation": "Revoke token from GitHub Developer Settings immediately to protect private code repositories."
    },
    "RULE_SLACK_TOKEN": {
        "rule_id": "RULE_SLACK_TOKEN",
        "name": "Slack API Bot / User Token",
        "category": "Authentication Secrets",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b"),
        "finding_type": "Slack API Token",
        "remediation": "Invalidate compromised Slack token via Slack App Management to prevent internal workspace surveillance."
    },
    "RULE_PRIVATE_KEY": {
        "rule_id": "RULE_PRIVATE_KEY",
        "name": "Private Cryptographic Key",
        "category": "Authentication Secrets",
        "severity": "CRITICAL",
        "pattern": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "finding_type": "Private Key",
        "remediation": "Never commit private keys to source control or shared files. Store secrets in HashiCorp Vault or AWS Secrets Manager."
    },
    "RULE_JWT_TOKEN": {
        "rule_id": "RULE_JWT_TOKEN",
        "name": "JSON Web Token (JWT)",
        "category": "Authentication Secrets",
        "severity": "HIGH",
        "pattern": re.compile(r"\beyJ[a-zA-Z0-9_-]{12,}\.eyJ[a-zA-Z0-9_-]{12,}\.[a-zA-Z0-9_-]{12,}\b"),
        "finding_type": "JWT Token",
        "remediation": "Expedite session expiry and invalidate active JWT token signatures to prevent replay attacks."
    },
    "RULE_ASSIGNED_PASSWD": {
        "rule_id": "RULE_ASSIGNED_PASSWD",
        "name": "Hardcoded Password in Assignment",
        "category": "Authentication Secrets",
        "severity": "HIGH",
        "pattern": re.compile(r"(?i)\b(?:password|passwd|secret|api_key|access_token|auth_token|client_secret)\s*[:=]\s*['\"]([^'\"]{6,64})['\"]"),
        "finding_type": "Hardcoded Password",
        "remediation": "Extract hardcoded passwords into environment variables or dedicated secret management systems."
    },

    # 4. Confidential Business Information
    "RULE_CONFIDENTIAL_LABEL": {
        "rule_id": "RULE_CONFIDENTIAL_LABEL",
        "name": "Confidential / Proprietary Marking",
        "category": "Confidential Business Information",
        "severity": "MEDIUM",
        "pattern": re.compile(r"\b(?:CONFIDENTIAL|STRICTLY CONFIDENTIAL|PROPRIETARY|INTERNAL ONLY|RESTRICTED USE|TRADE SECRET|PRIVILEGED & CONFIDENTIAL|DO NOT DISTRIBUTE)\b", re.IGNORECASE),
        "finding_type": "Confidentiality Marking",
        "remediation": "Verify authorized recipient clearance and obtain sign-off before sharing restricted business documents."
    },
    "RULE_NDA_TERMS": {
        "rule_id": "RULE_NDA_TERMS",
        "name": "NDA & Trade Secret Term",
        "category": "Confidential Business Information",
        "severity": "MEDIUM",
        "pattern": re.compile(r"\b(?:Non-Disclosure Agreement|NDA|Intellectual Property Assignment|Proprietary Information Agreement|Commercial Secret)\b", re.IGNORECASE),
        "finding_type": "NDA Legal Term",
        "remediation": "Check if an active mutual NDA covers external disclosures of this document."
    },
    "RULE_MERGER_ACQUISITION": {
        "rule_id": "RULE_MERGER_ACQUISITION",
        "name": "M&A / Insider Financial Project",
        "category": "Confidential Business Information",
        "severity": "HIGH",
        "pattern": re.compile(r"(?i)\b(?:merger target|acquisition talks|insider trading|q[1-4] pre-announcement|unannounced round|series [a-e] pitch deck)\b"),
        "finding_type": "M&A Insider Information",
        "remediation": "Classify document under SEC / SEBI insider trading blackout guidelines."
    }
}
