"""
PrivacyVault AI - Privacy AI Assistant & Knowledge Engine
Provides contextual risk explanations, regulatory cross-references, and remediation advice.
Works 100% offline out-of-the-box, with optional Gemini API integration if configured.

SECURITY NOTICE: Unmasked sensitive data is NEVER transmitted to external models.
Only masked, sanitized metadata is processed.
"""

import os
import logging
from typing import Dict, Any, List
from config.settings import Config

logger = logging.getLogger(__name__)


def generate_local_explanation(finding: Dict[str, Any]) -> str:
    """Generate offline expert privacy analysis and regulatory assessment for a finding."""
    category = finding.get("category", "")
    ftype = finding.get("finding_type", "")
    severity = finding.get("severity", "")
    location = finding.get("location_ref", "")
    masked_val = finding.get("masked_value", "")
    
    analysis_parts = []
    
    # 1. Threat scenario
    if category == "Authentication Secrets":
        analysis_parts.append(
            f"**Threat Scenario**: The exposed {ftype} (`{masked_val}`) located at {location} provides direct, unauthenticated access "
            f"to critical cloud infrastructure or private APIs. In automated adversary scans, exposed tokens are compromised in under 60 seconds, "
            f"enabling lateral movement, data exfiltration, or cryptomining extortion."
        )
        analysis_parts.append(
            f"**Regulatory & Security Impact**: Violates SOC2 Access Control standards and NIST SP 800-63B. Immediate revocation required."
        )
    elif category == "Financial Information":
        analysis_parts.append(
            f"**Threat Scenario**: Exposure of {ftype} (`{masked_val}`) at {location} facilitates unauthorized card-not-present fraud "
            f"and account takeover. If distributed outside PCI boundaries, this constitutes a non-compliance event."
        )
        analysis_parts.append(
            f"**Regulatory & Security Impact**: Directly governed by PCI-DSS v4.0 Requirement 3.4. Unencrypted storage of PAN triggers audit penalties and merchant account suspension."
        )
    elif category == "PII":
        analysis_parts.append(
            f"**Threat Scenario**: Personal identity element `{masked_val}` ({ftype}) discovered at {location}. "
            f"When combined with other demographic or contact attributes, this data enables targeted phishing, SIM swapping, and identity theft."
        )
        analysis_parts.append(
            f"**Regulatory & Security Impact**: Governed by GDPR Article 6 & 32 (EU), California CCPA, and India DPDP Act 2023. "
            f"Failure to protect personal identity records mandates breach notification within 72 hours."
        )
    else:
        analysis_parts.append(
            f"**Threat Scenario**: The proprietary label or confidential term `{masked_val}` ({ftype}) at {location} reveals "
            f"restricted commercial strategies, trade secrets, or non-public corporate deliberations."
        )
        analysis_parts.append(
            f"**Regulatory & Security Impact**: Potential breach of contractual Non-Disclosure Agreements (NDAs) or trade secret protections."
        )
        
    # 2. Remediation recommendation
    hint = finding.get("remediation_hint", "Apply data masking or redact this value.")
    analysis_parts.append(f"**Recommended Remediation**: {hint}")
    
    return "\n\n".join(analysis_parts)


def explain_finding_with_ai(finding: Dict[str, Any], api_key: str = None) -> Dict[str, Any]:
    """
    Explain a specific finding using either local privacy expert knowledge base
    or optional Gemini generative AI if API key is provided and requested.
    """
    key = api_key or Config.GEMINI_API_KEY or os.environ.get("GEMINI_API_KEY", "")
    
    # If no API key, use offline privacy expert
    if not key or not key.strip():
        explanation = generate_local_explanation(finding)
        return {
            "source": "Local Privacy Engine (Offline)",
            "explanation": explanation
        }
        
    try:
        # Optional Google Gemini call using official google-genai or urllib request
        import urllib.request
        import json
        
        prompt = (
            f"You are a certified Data Privacy Officer and Cybersecurity Auditor. "
            f"Analyze the following detected privacy finding: \n"
            f"- Finding Type: {finding.get('finding_type')}\n"
            f"- Sensitivity Category: {finding.get('category')}\n"
            f"- Severity Level: {finding.get('severity')}\n"
            f"- Masked Evidence: {finding.get('masked_value')}\n"
            f"- Document Location: {finding.get('location_ref')}\n\n"
            f"Provide a concise 3-part response:\n"
            f"1. Threat Scenario & Exploit Vector\n"
            f"2. Applicable Compliance Mandates (GDPR, PCI-DSS, HIPAA, DPDP Act)\n"
            f"3. Concrete Engineering Remediation Steps\n"
            f"Do not mention any unmasked credentials."
        )
        
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={key}"
        payload = {
            "contents": [{
                "parts": [{"text": prompt}]
            }]
        }
        
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        
        with urllib.request.urlopen(req, timeout=10) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            ai_text = res_data["candidates"][0]["content"]["parts"][0]["text"]
            return {
                "source": "Gemini AI Assistant (Cloud)",
                "explanation": ai_text
            }
            
    except Exception as e:
        logger.warning(f"AI Assistant cloud fallback to local engine: {e}")
        explanation = generate_local_explanation(finding)
        return {
            "source": "Local Privacy Engine (Offline Fallback)",
            "explanation": explanation
        }
