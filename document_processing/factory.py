"""
PrivacyVault AI - Extractor Factory & File Validator
Validates file formats, sizes, and binary signatures before dispatching to extractors.
"""

from pathlib import Path
from typing import Tuple, Optional
from werkzeug.utils import secure_filename
from config.settings import Config
from .extractor_base import ExtractedDocument
from .pdf_extractor import extract_pdf
from .docx_extractor import extract_docx
from .txt_extractor import extract_txt
from .csv_extractor import extract_csv
from .json_extractor import extract_json


class ExtractionError(Exception):
    """Raised when file validation or extraction encounters an unrecoverable issue."""
    pass


def validate_file(file_path: Path, filename: str) -> Tuple[bool, Optional[str], str]:
    """
    Validate file extension, size, and magic signatures safely.
    Returns: (is_valid, error_message, detected_extension)
    """
    if not file_path.exists():
        return False, "Uploaded file does not exist on disk.", ""
        
    file_size = file_path.stat().st_size
    if file_size == 0:
        return False, "File is empty (0 bytes).", ""
        
    if file_size > Config.MAX_CONTENT_LENGTH:
        return False, f"File exceeds maximum allowed size of {Config.MAX_CONTENT_LENGTH_MB}MB.", ""
        
    # Check extension
    ext = file_path.suffix.lower().lstrip(".")
    if ext not in Config.ALLOWED_EXTENSIONS:
        return False, f"Unsupported file format '.{ext}'. Supported formats are: PDF, DOCX, TXT, CSV, JSON.", ""
        
    # Signature / Magic header checks
    try:
        with open(file_path, "rb") as f:
            header = f.read(16)
            
        if ext == "pdf":
            if not header.startswith(b"%PDF-"):
                return False, "Invalid PDF file: Missing standard '%PDF-' file signature.", ext
                
        elif ext == "docx":
            # DOCX is an OOXML ZIP archive starting with PK\x03\x04
            if not header.startswith(b"PK\x03\x04"):
                return False, "Invalid DOCX file: Missing valid OpenXML/ZIP container signature.", ext
                
    except Exception as e:
        return False, f"Error validating file header: {str(e)}", ext
        
    return True, None, ext


def extract_document(file_path: Path, filename: str) -> ExtractedDocument:
    """Validate and dispatch file extraction to the specialized parser."""
    is_valid, error_msg, ext = validate_file(file_path, filename)
    if not is_valid:
        doc = ExtractedDocument(filename=filename, file_type=ext or "unknown")
        doc.error = error_msg
        return doc
        
    if ext == "pdf":
        return extract_pdf(file_path, filename)
    elif ext == "docx":
        return extract_docx(file_path, filename)
    elif ext == "txt":
        return extract_txt(file_path, filename)
    elif ext == "csv":
        return extract_csv(file_path, filename)
    elif ext == "json":
        return extract_json(file_path, filename)
    else:
        doc = ExtractedDocument(filename=filename, file_type=ext)
        doc.error = f"No extractor registered for file type '.{ext}'"
        return doc
