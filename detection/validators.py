"""
PrivacyVault AI - Detection Validators & Checksums
Includes Luhn algorithm, Verhoeff checksum, Shannon entropy calculation, and IP format validation.
"""

import math
import re
from typing import Tuple


def luhn_check(card_number: str) -> bool:
    """
    Validate credit card number using the Luhn checksum formula (Mod 10).
    Filters out non-credit card 13-19 digit strings.
    """
    digits = re.sub(r"\D", "", card_number)
    if not (13 <= len(digits) <= 19):
        return False
        
    total = 0
    reverse_digits = digits[::-1]
    
    for i, char in enumerate(reverse_digits):
        d = int(char)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        
    return total % 10 == 0


def calculate_shannon_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of a string (in bits per symbol).
    High entropy (> 3.5 - 4.0) indicates high randomness characteristic of cryptographic keys and tokens.
    """
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    char_counts = {}
    for c in data:
        char_counts[c] = char_counts.get(c, 0) + 1
    for count in char_counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return entropy


# Verhoeff algorithm multiplication and permutation tables for Indian Aadhaar verification
VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
]

VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
]

VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_check(number_str: str) -> bool:
    """Validate Indian 12-digit Aadhaar number using the Verhoeff check algorithm."""
    digits = re.sub(r"\D", "", number_str)
    if len(digits) != 12:
        return False
        
    c = 0
    reversed_digits = digits[::-1]
    for i, char in enumerate(reversed_digits):
        val = int(char)
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][val]]
        
    return c == 0


def is_valid_ssn(ssn_str: str) -> bool:
    """
    Validate US Social Security Number structure:
    - Area number cannot be 000, 666, or in 900-999
    - Group number cannot be 00
    - Serial number cannot be 0000
    """
    clean = re.sub(r"\D", "", ssn_str)
    if len(clean) != 9:
        return False
        
    area = int(clean[0:3])
    group = int(clean[3:5])
    serial = int(clean[5:9])
    
    if area == 0 or area == 666 or area >= 900:
        return False
    if group == 0:
        return False
    if serial == 0:
        return False
        
    return True


def is_valid_ipv4(ip_str: str) -> bool:
    """Check if string is a valid IPv4 address with octets in 0-255."""
    parts = ip_str.split(".")
    if len(parts) != 4:
        return False
    try:
        for p in parts:
            val = int(p)
            if val < 0 or val > 255:
                return False
            if p != str(val):  # Reject leading zeroes like 01.02.03.04
                return False
        # Filter out 0.0.0.0 or 255.255.255.255 as typically non-sensitive broadcast/default
        if ip_str in ["0.0.0.0", "255.255.255.255"]:
            return False
        return True
    except ValueError:
        return False
