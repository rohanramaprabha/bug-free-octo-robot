"""
PrivacyVault AI - Unit Tests for Detection, Checksums, and Masking
"""

import pytest
from detection.validators import (
    luhn_check, verhoeff_check, is_valid_ssn, is_valid_ipv4, calculate_shannon_entropy
)
from detection.masking import (
    mask_email, mask_phone, mask_credit_card, mask_ssn, mask_aadhaar,
    mask_pan, mask_secret, mask_ip, mask_name
)
from detection.detector_engine import detect_sensitive_data
from document_processing.extractor_base import ExtractedDocument, DocumentSegment


def test_luhn_algorithm_validation():
    """Verify Luhn checksum correctly validates legitimate cards and rejects random 16-digit strings."""
    # Standard valid test Visa number
    assert luhn_check("4532015112830366") is True
    # Standard valid test MasterCard number
    assert luhn_check("5424180123456789") is True
    
    # Tampered number (last digit changed)
    assert luhn_check("4532015112830367") is False
    # Random 16 digit sequence
    assert luhn_check("1234567812345678") is False


def test_ssn_structure_validation():
    """Verify US SSN validator correctly catches invalid area codes."""
    assert is_valid_ssn("123-45-6789") is True
    # Area 000 is invalid
    assert is_valid_ssn("000-12-3456") is False
    # Area 666 is invalid
    assert is_valid_ssn("666-12-3456") is False
    # Area >= 900 is invalid
    assert is_valid_ssn("950-12-3456") is False


def test_ipv4_validation():
    """Verify IPv4 checker allows valid public IPs and rejects out-of-range octets."""
    assert is_valid_ipv4("192.168.1.100") is True
    assert is_valid_ipv4("10.0.0.1") is True
    # Out of range octet
    assert is_valid_ipv4("192.168.1.300") is False
    # Missing octet
    assert is_valid_ipv4("192.168.1") is False


def test_shannon_entropy():
    """Verify Shannon entropy calculates higher randomness for cryptographic keys than plain words."""
    plain_word = "hello"
    crypto_token = "wJalrXUtnFEMI7MDENGbPxRfiCYEXAMPLEKEY"
    
    ent_plain = calculate_shannon_entropy(plain_word)
    ent_crypto = calculate_shannon_entropy(crypto_token)
    
    assert ent_crypto > ent_plain
    assert ent_crypto > 3.8


def test_masking_functions():
    """Verify sensitive values are properly masked without leaking raw secrets."""
    # Email
    assert mask_email("rohan.verma@example.com") == "roh***@example.com"
    # Credit Card
    assert mask_credit_card("4532015112830366") == "****-****-****-0366"
    # SSN
    assert mask_ssn("123-45-6789") == "***-**-6789"
    # Phone
    assert "***" in mask_phone("+91 98765 43210")
    # PAN
    assert mask_pan("ABCDE1234F") == "*****1234*"
    # AWS Key
    assert mask_secret("AKIAIOSFODNN7EXAMPLE").startswith("AKIA****")
    # IP
    assert mask_ip("192.168.1.150") == "192.168.***.***"
    # Name
    assert mask_name("John Doe") == "J*** D***"


def test_detector_engine_finds_pii_and_secrets():
    """Verify detection engine identifies multiple categories in document segments."""
    doc = ExtractedDocument(filename="test.txt", file_type="txt")
    doc.segments = [
        DocumentSegment(
            text="User contact: john.doe@work.com, Phone: +91 98765 43210",
            location_type="line",
            location_ref="Line 1"
        ),
        DocumentSegment(
            text="Billing Card: 4532015112830366, PAN: ABCDE1234F",
            location_type="line",
            location_ref="Line 2"
        ),
        DocumentSegment(
            text="AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
            location_type="line",
            location_ref="Line 3"
        )
    ]
    
    findings = detect_sensitive_data(doc)
    types_found = [f["finding_type"] for f in findings]
    
    assert "Email Address" in types_found
    assert "Credit Card Number" in types_found
    assert "PAN Card Number" in types_found
    assert "AWS Access Key ID" in types_found
    
    # Check that masked values are safe
    for f in findings:
        assert not f["masked_value"].startswith("4532015112830366")
        assert not f["masked_value"].startswith("AKIAIOSFODNN7EXAMPLE")
