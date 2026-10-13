"""
PrivacyVault AI - Application Configuration
Centralized configuration management for file parsing, risk scoring, detection rules, and storage.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent.parent

# Load .env if present
load_dotenv(BASE_DIR / ".env")


class Config:
    """Base application settings."""
    SECRET_KEY = os.environ.get("SECRET_KEY", "privacyvault-dev-secret-key-2026-cse-secure")
    
    # Upload limits & directories
    MAX_CONTENT_LENGTH_MB = int(os.environ.get("MAX_CONTENT_LENGTH_MB", 25))
    MAX_CONTENT_LENGTH = MAX_CONTENT_LENGTH_MB * 1024 * 1024  # in bytes
    UPLOAD_FOLDER = BASE_DIR / os.environ.get("UPLOAD_FOLDER", "uploads")
    REPORTS_FOLDER = BASE_DIR / "reports_cache"
    DATA_FOLDER = BASE_DIR / "data"
    SAMPLES_FOLDER = BASE_DIR / "samples"
    
    # Database
    DATABASE_PATH = BASE_DIR / os.environ.get("DATABASE_PATH", "data/privacyvault.db")
    
    # Supported document formats
    ALLOWED_EXTENSIONS = {
        "pdf": "application/pdf",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "txt": "text/plain",
        "csv": "text/csv",
        "json": "application/json"
    }
    
    # Risk Scoring Weight Configuration
    SEVERITY_WEIGHTS = {
        "CRITICAL": 25,
        "HIGH": 15,
        "MEDIUM": 8,
        "LOW": 3
    }
    
    # Risk Tier Thresholds (0 - 100)
    RISK_THRESHOLDS = {
        "LOW": (0, 25),
        "MEDIUM": (26, 50),
        "HIGH": (51, 75),
        "CRITICAL": (76, 100)
    }
    
    # AI Assistant configuration
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
    
    @classmethod
    def ensure_directories(cls):
        """Create necessary directories if they do not exist."""
        cls.UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
        cls.REPORTS_FOLDER.mkdir(parents=True, exist_ok=True)
        cls.DATA_FOLDER.mkdir(parents=True, exist_ok=True)
        cls.SAMPLES_FOLDER.mkdir(parents=True, exist_ok=True)


def get_config():
    """Retrieve config instance and ensure directories."""
    Config.ensure_directories()
    return Config
