"""
PrivacyVault AI - Core Detection Engine
Executes modular regex rules, applies cryptographic and structural validators to eliminate false positives,
and outputs masked findings with location references.
"""

import hashlib
import logging
from typing import List, Dict, Any, Optional
from document_processing.extractor_base import ExtractedDocument
from .regex_patterns import DETECTION_RULES
from .validators import luhn_check, verhoeff_check, is_valid_ssn, is_valid_ipv4
from .masking import mask_by_finding_type

logger = logging.getLogger(__name__)


def create_context_snippet(full_text: str, start_idx: int, end_idx: int, masked_val: str, window: int = 40) -> str:
    """Generate a sanitized snippet around the match for inspection."""
    prefix_start = max(0, start_idx - window)
    suffix_end = min(len(full_text), end_idx + window)
    
    prefix = full_text[prefix_start:start_idx]
    suffix = full_text[end_idx:suffix_end]
    
    snippet = f"...{prefix}{masked_val}{suffix}..." if prefix_start > 0 or suffix_end < len(full_text) else f"{prefix}{masked_val}{suffix}"
    return " ".join(snippet.split())  # Normalize whitespaces


def detect_sensitive_data(doc: ExtractedDocument, active_rules: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """
    Scan an extracted document's segments across all active detection rules.
    Returns a list of structured findings.
    """
    findings = []
    seen_hashes = set()  # Dedup identical findings in exact same location
    
    rules_to_run = DETECTION_RULES
    if active_rules is not None:
        rules_to_run = {k: v for k, v in DETECTION_RULES.items() if k in active_rules}
        
    for segment in doc.segments:
        text = segment.text
        if not text:
            continue
            
        for rule_id, rule_def in rules_to_run.items():
            pattern = rule_def["pattern"]
            
            for match in pattern.finditer(text):
                # If regex has capture group 1 (e.g. for Name or Password assignment), use group 1
                if match.lastindex and match.lastindex >= 1:
                    raw_val = match.group(1).strip()
                    start_idx = match.start(1)
                    end_idx = match.end(1)
                else:
                    raw_val = match.group(0).strip()
                    start_idx = match.start()
                    end_idx = match.end()
                    
                if not raw_val:
                    continue
                    
                # ----------------- False Positive Validation -----------------
                # 1. Credit Card Luhn Check
                if rule_id == "RULE_CREDIT_CARD":
                    if not luhn_check(raw_val):
                        continue
                        
                # 2. Aadhaar Checksum
                elif rule_id == "RULE_AADHAAR_IN":
                    clean_digits = raw_val.replace(" ", "").replace("-", "")
                    if len(clean_digits) != 12 or not verhoeff_check(clean_digits):
                        continue
                        
                # 3. US SSN Structure
                elif rule_id == "RULE_SSN_US":
                    if not is_valid_ssn(raw_val):
                        continue
                        
                # 4. IPv4 Check
                elif rule_id == "RULE_IP_ADDRESS":
                    if not is_valid_ipv4(raw_val):
                        continue
                    # Ignore loopback 127.0.0.1 or broadcast
                    if raw_val.startswith("127.0.0."):
                        continue
                        
                # 5. Assigned password length sanity check
                elif rule_id == "RULE_ASSIGNED_PASSWD":
                    if len(raw_val) < 6:
                        continue
                # --------------------------------------------------------------
                
                # Mask the value
                masked_val = mask_by_finding_type(rule_def["finding_type"], raw_val)
                
                # Context snippet
                context = create_context_snippet(text, start_idx, end_idx, masked_val)
                
                # Hash raw value for verification & deduplication
                raw_hash = hashlib.sha256(raw_val.encode("utf-8")).hexdigest()
                dedup_key = f"{rule_id}:{segment.location_ref}:{raw_hash}"
                
                if dedup_key in seen_hashes:
                    continue
                seen_hashes.add(dedup_key)
                
                findings.append({
                    "category": rule_def["category"],
                    "finding_type": rule_def["finding_type"],
                    "severity": rule_def["severity"],
                    "masked_value": masked_val,
                    "raw_value_hash": raw_hash,
                    "location_type": segment.location_type,
                    "location_ref": segment.location_ref,
                    "context_snippet": context,
                    "confidence": 0.95 if rule_id in ["RULE_CREDIT_CARD", "RULE_SSN_US", "RULE_AWS_KEY_ID"] else 0.85,
                    "rule_id": rule_id,
                    "remediation_hint": rule_def.get("remediation", "Review and restrict exposure of this item.")
                })
                
    return findings
