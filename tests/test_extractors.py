"""
PrivacyVault AI - Unit Tests for Document Processing & Extractors
"""

from pathlib import Path
from config.settings import Config
from document_processing import extract_document, validate_file
from samples.sample_generator import generate_all_samples


def setup_module():
    """Ensure sample files exist before testing extractors."""
    generate_all_samples()


def test_txt_extractor():
    """Verify TXT extractor parses lines with line numbers."""
    txt_file = Config.SAMPLES_FOLDER / "sample_developer_credentials.txt"
    doc = extract_document(txt_file, "sample_developer_credentials.txt")
    
    assert doc.error is None
    assert doc.file_type == "txt"
    assert len(doc.segments) > 0
    assert "Line" in doc.segments[0].location_ref
    assert doc.metadata["total_lines"] > 0


def test_csv_extractor():
    """Verify CSV extractor parses rows and columns."""
    csv_file = Config.SAMPLES_FOLDER / "sample_customer_records.csv"
    doc = extract_document(csv_file, "sample_customer_records.csv")
    
    assert doc.error is None
    assert doc.file_type == "csv"
    assert doc.metadata["total_rows"] >= 3
    assert "Row" in doc.segments[0].location_ref
    assert "Column" in doc.segments[0].location_ref


def test_json_extractor():
    """Verify JSON extractor traverses tree and tracks pointer paths."""
    json_file = Config.SAMPLES_FOLDER / "sample_cloud_infrastructure.json"
    doc = extract_document(json_file, "sample_cloud_infrastructure.json")
    
    assert doc.error is None
    assert doc.file_type == "json"
    assert len(doc.segments) > 0
    assert "Path:" in doc.segments[0].location_ref


def test_docx_extractor():
    """Verify DOCX extractor parses paragraphs, tables, and metadata."""
    docx_file = Config.SAMPLES_FOLDER / "sample_confidential_contract.docx"
    doc = extract_document(docx_file, "sample_confidential_contract.docx")
    
    assert doc.error is None
    assert doc.file_type == "docx"
    assert len(doc.segments) > 0
    assert "total_tables" in doc.metadata
    assert doc.metadata["author"] != ""


def test_pdf_extractor():
    """Verify PDF extractor parses pages and metadata."""
    pdf_file = Config.SAMPLES_FOLDER / "sample_patient_records.pdf"
    doc = extract_document(pdf_file, "sample_patient_records.pdf")
    
    assert doc.error is None
    assert doc.file_type == "pdf"
    assert len(doc.segments) > 0
    assert "Page 1" in doc.segments[0].location_ref


def test_unsupported_file_rejection():
    """Verify validate_file safely rejects unsupported extensions."""
    fake_exe = Config.DATA_FOLDER / "test_malicious.exe"
    fake_exe.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00")
    
    is_valid, err_msg, ext = validate_file(fake_exe, "test_malicious.exe")
    assert is_valid is False
    assert "Unsupported file format" in err_msg
    fake_exe.unlink()
