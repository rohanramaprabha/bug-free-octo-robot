"""
PrivacyVault AI - Sensitive Value Masking Utilities
Sanitizes raw sensitive findings to prevent exposing secrets in logs, reports, and UI.
"""

import re


def mask_email(email: str) -> str:
    """Mask email: 'rohan.sharma@example.com' -> 'roh***@example.com'."""
    email = email.strip()
    if "@" not in email:
        return mask_generic(email)
    user, domain = email.split("@", 1)
    if len(user) <= 2:
        masked_user = user[0] + "***" if user else "***"
    else:
        masked_user = user[:3] + "***"
    return f"{masked_user}@{domain}"


def mask_phone(phone: str) -> str:
    """Mask phone: '+1 (555) 234-5678' -> '***-***-5678', '+91 9876543210' -> '+91 ***** 43210'."""
    digits = re.sub(r"\D", "", phone)
    if len(digits) >= 10:
        last4 = digits[-4:]
        prefix = phone[:3] if phone.startswith("+") else ""
        return f"{prefix}***-***-{last4}".strip()
    return "***-***-" + digits[-2:] if len(digits) >= 2 else "********"


def mask_credit_card(card: str) -> str:
    """Mask card: '4111 2222 3333 4444' -> '****-****-****-4444'."""
    digits = re.sub(r"\D", "", card)
    if len(digits) >= 4:
        last4 = digits[-4:]
        return f"****-****-****-{last4}"
    return "****************"


def mask_ssn(ssn: str) -> str:
    """Mask SSN: '123-45-6789' -> '***-**-6789'."""
    digits = re.sub(r"\D", "", ssn)
    if len(digits) == 9:
        return f"***-**-{digits[-4:]}"
    return "***-**-****"


def mask_aadhaar(aadhaar: str) -> str:
    """Mask Indian Aadhaar: '1234 5678 9012' -> '**** **** 9012'."""
    digits = re.sub(r"\D", "", aadhaar)
    if len(digits) == 12:
        return f"**** **** {digits[-4:]}"
    return "************"


def mask_pan(pan: str) -> str:
    """Mask Indian PAN: 'ABCDE1234F' -> '*****1234*'."""
    clean = pan.strip().upper()
    if len(clean) == 10:
        return f"*****{clean[5:9]}*"
    return "**********"


def mask_secret(secret: str) -> str:
    """Mask API key, token, or password: 'AKIAIOSFODNN7EXAMPLE' -> 'AKIA************'."""
    clean = secret.strip()
    if clean.startswith("AKIA"):
        return "AKIA" + "*" * (len(clean) - 4)
    if clean.startswith("ghp_"):
        return "ghp_" + "*" * (len(clean) - 4)
    if clean.startswith("xoxb-"):
        return "xoxb-" + "*" * (len(clean) - 5)
    if clean.startswith("Bearer "):
        return "Bearer " + "*" * 16
    if len(clean) > 8:
        return clean[:3] + "*" * (len(clean) - 5) + clean[-2:]
    return "********"


def mask_ip(ip: str) -> str:
    """Mask IP: '192.168.1.105' -> '192.168.***.***'."""
    parts = ip.strip().split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.***.***"
    return "**.**.**.**"


def mask_name(name: str) -> str:
    """Mask name: 'John Alexander Doe' -> 'J*** A*** D**'."""
    parts = name.strip().split()
    masked_parts = []
    for p in parts:
        if len(p) <= 2:
            masked_parts.append(p[0] + "*")
        else:
            masked_parts.append(p[0] + "***")
    return " ".join(masked_parts)


def mask_generic(text: str) -> str:
    """Generic masking for arbitrary text."""
    s = text.strip()
    if len(s) <= 4:
        return "*" * len(s)
    return s[:2] + "*" * (len(s) - 4) + s[-2:]


def mask_by_finding_type(finding_type: str, raw_val: str) -> str:
    """Router to dispatch appropriate masking function according to finding type."""
    ft = finding_type.lower()
    if "email" in ft:
        return mask_email(raw_val)
    elif "phone" in ft:
        return mask_phone(raw_val)
    elif "card" in ft:
        return mask_credit_card(raw_val)
    elif "ssn" in ft:
        return mask_ssn(raw_val)
    elif "aadhaar" in ft:
        return mask_aadhaar(raw_val)
    elif "pan" in ft:
        return mask_pan(raw_val)
    elif "ip" in ft or "address" in ft and "ipv" in ft:
        return mask_ip(raw_val)
    elif any(k in ft for k in ["secret", "key", "token", "password", "pat", "jwt"]):
        return mask_secret(raw_val)
    elif "name" in ft:
        return mask_name(raw_val)
    else:
        return mask_generic(raw_val)
