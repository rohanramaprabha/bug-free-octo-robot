"""
PrivacyVault AI - Data Leakage Analysis Engine
Evaluates documents for privacy exposure vectors: multi-field co-occurrence, public column leaks,
config credentials, metadata fingerprints, and mass data density.

IMPORTANT: Strictly distinguishes potential exposure risks from confirmed external data leaks.
"""

from collections import defaultdict
from typing import List, Dict, Any
from document_processing.extractor_base import ExtractedDocument

# Keywords that commonly denote public or user-facing fields
PUBLIC_COLUMN_KEYWORDS = [
    "public", "comment", "comments", "description", "user_bio", "bio",
    "notes", "feedback", "review", "social", "message", "forum",
    "post", "blog", "public_notes", "remark", "remarks"
]


def analyze_data_leakage(doc: ExtractedDocument, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Evaluate extracted document and its findings to detect privacy leakage vulnerabilities.
    Returns a list of structured leakage alerts.
    """
    alerts = []
    
    if not findings:
        return alerts
        
    # ---------------------------------------------------------
    # 1. Multi-Field Co-Occurrence Analysis
    # Group findings by their structural location (same row, page, paragraph)
    # ---------------------------------------------------------
    location_groups = defaultdict(list)
    for f in findings:
        loc = f.get("location_ref", "")
        # Normalize location prefix (e.g. "Row 14", "Page 2", "Paragraph 5")
        loc_group_key = loc.split(",")[0].strip() if "," in loc else loc
        location_groups[loc_group_key].append(f)
        
    for group_key, group_findings in location_groups.items():
        if len(group_findings) >= 2:
            types = set(f["finding_type"] for f in group_findings)
            categories = set(f["category"] for f in group_findings)
            
            # Direct identifier + High-impact sensitive data
            has_identity = any(t in ["Personal Name", "Email Address", "Phone Number"] for t in types)
            has_financial_or_secret = any(c in ["Financial Information", "Authentication Secrets"] for c in categories) or \
                                      any(t in ["Social Security Number", "Aadhaar Number", "PAN Card Number"] for t in types)
                                      
            if has_identity and has_financial_or_secret:
                masked_samples = ", ".join(f["masked_value"] for f in group_findings[:3])
                alerts.append({
                    "alert_title": "Direct Identity & Sensitive Data Co-occurrence",
                    "alert_type": "CO_OCCURRENCE",
                    "severity": "CRITICAL",
                    "location_ref": group_key,
                    "description": (
                        f"Personal identity elements co-occur directly alongside high-impact sensitive identifiers "
                        f"({', '.join(types)}) within {group_key}. This creates a severe identity linking risk where "
                        f"an adversary can associate the individual with financial or credential data."
                    ),
                    "recommendation": (
                        "Decouple direct personal identifiers from financial and sensitive attributes. "
                        "Employ pseudonymization or separate relational tables with tokenized references."
                    )
                })

    # ---------------------------------------------------------
    # 2. Public Column Exposure Analysis (Tabular CSV / Table cells)
    # ---------------------------------------------------------
    for f in findings:
        loc = f.get("location_ref", "").lower()
        for kw in PUBLIC_COLUMN_KEYWORDS:
            if f"column '{kw}'" in loc or f"col '{kw}'" in loc or f"column '{kw}_" in loc:
                alerts.append({
                    "alert_title": f"Sensitive Data in Public-Facing Column '{kw}'",
                    "alert_type": "PUBLIC_COLUMN_EXPOSURE",
                    "severity": "HIGH",
                    "location_ref": f.get("location_ref", ""),
                    "description": (
                        f"The column name implies this field is public-facing or intended for comments/descriptions, "
                        f"yet it contains sensitive {f['finding_type']} ({f['masked_value']}). "
                        f"If this dataset is exposed via public APIs or web views, this data will leak."
                    ),
                    "recommendation": (
                        f"Review ingestion forms to prevent free-text leakage of sensitive attributes into '{kw}'. "
                        "Apply data masking or omit this column from public exports."
                    )
                })
                break

    # ---------------------------------------------------------
    # 3. Credential in Plaintext Configuration / Code File
    # ---------------------------------------------------------
    if doc.file_type in ["txt", "json"]:
        secret_findings = [f for f in findings if f["category"] == "Authentication Secrets"]
        if secret_findings:
            sample_locs = ", ".join(f["location_ref"] for f in secret_findings[:2])
            alerts.append({
                "alert_title": "Static Authentication Secrets in Plaintext Config",
                "alert_type": "CONFIG_CREDENTIAL",
                "severity": "CRITICAL",
                "location_ref": sample_locs,
                "description": (
                    f"Found {len(secret_findings)} authentication secrets/passwords stored unencrypted in a "
                    f"plaintext {doc.file_type.upper()} file. Storing secrets in plain configuration or text files "
                    f"creates significant exposure risk if files are shared, backed up, or committed to version control."
                ),
                "recommendation": (
                    "Immediately migrate credentials to secure environment variables or vault services "
                    "(e.g., AWS Secrets Manager, HashiCorp Vault). Invalidate and rotate exposed keys."
                )
            })

    # ---------------------------------------------------------
    # 4. Document Metadata Leakage Analysis
    # ---------------------------------------------------------
    meta = doc.metadata or {}
    meta_author = meta.get("author") or meta.get("last_modified_by") or ""
    if meta_author and len(meta_author) > 2:
        # Check if author looks like a full name, email, or internal path
        if "@" in meta_author or "\\" in meta_author or "/" in meta_author or len(meta_author.split()) >= 2:
            alerts.append({
                "alert_title": "Author Identity Exposed in Document Metadata",
                "alert_type": "METADATA_LEAK",
                "severity": "MEDIUM",
                "location_ref": "Document Metadata Header",
                "description": (
                    f"Document properties contain author/creator identity information: '{meta_author}'. "
                    f"Publishing or distributing this document externally reveals internal usernames or creator identity."
                ),
                "recommendation": (
                    "Sanitize document properties and remove metadata before sharing files outside the organization."
                )
            })

    # ---------------------------------------------------------
    # 5. High Density / Mass Data Exposure Analysis
    # ---------------------------------------------------------
    if len(findings) >= 15:
        alerts.append({
            "alert_title": "High Concentration Unredacted Dataset",
            "alert_type": "HIGH_DENSITY",
            "severity": "HIGH",
            "location_ref": f"Document ({len(findings)} Total Findings)",
            "description": (
                f"Document contains a high concentration of sensitive findings ({len(findings)} items). "
                f"This indicates a bulk unredacted database export or raw dump rather than incidental data. "
                f"The impact of accidental exposure is multiplied by the high volume of records."
            ),
            "recommendation": (
                "Apply aggregate reporting, data generalization, or complete suppression for non-essential columns."
            )
        })

    # ---------------------------------------------------------
    # 6. Cross-Record Identifier Repetition
    # ---------------------------------------------------------
    hash_counts = defaultdict(list)
    for f in findings:
        h = f.get("raw_value_hash")
        if h:
            hash_counts[h].append(f)
            
    for h, flist in hash_counts.items():
        if len(flist) >= 3 and flist[0]["severity"] in ["CRITICAL", "HIGH"]:
            alerts.append({
                "alert_title": f"Repeated Sensitive Identifier ({flist[0]['finding_type']})",
                "alert_type": "REPEATED_IDENTIFIER",
                "severity": "MEDIUM",
                "location_ref": f"{len(flist)} distinct locations (e.g. {flist[0]['location_ref']})",
                "description": (
                    f"The exact same sensitive value ({flist[0]['masked_value']}) is duplicated across {len(flist)} "
                    f"different entries in this document, multiplying the likelihood of discovery."
                ),
                "recommendation": (
                    "Consolidate duplicate records and enforce single-source storage with strict access controls."
                )
            })
            break  # Report only once to avoid cluttering

    return alerts
