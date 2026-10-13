# document_processing/__init__.py
from .extractor_base import DocumentSegment, ExtractedDocument
from .factory import validate_file, extract_document, ExtractionError

__all__ = [
    "DocumentSegment",
    "ExtractedDocument",
    "validate_file",
    "extract_document",
    "ExtractionError"
]
