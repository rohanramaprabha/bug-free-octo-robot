"""
PrivacyVault AI - PDF Document Extractor
Extracts text and metadata from PDF files page-by-page using pypdf.
"""

from pathlib import Path
import pypdf
from .extractor_base import ExtractedDocument, DocumentSegment


def extract_pdf(file_path: Path, filename: str) -> ExtractedDocument:
    """Extract page text and document metadata from a PDF file."""
    doc = ExtractedDocument(filename=filename, file_type="pdf")
    try:
        reader = pypdf.PdfReader(str(file_path))
        
        # Check encryption
        if reader.is_encrypted:
            try:
                reader.decrypt("")
            except Exception:
                doc.error = "PDF is password-protected and cannot be read without credentials."
                return doc
                
        # Extract metadata
        meta = reader.metadata
        if meta:
            metadata_dict = {}
            for k, v in meta.items():
                clean_k = str(k).lstrip("/").lower()
                metadata_dict[clean_k] = str(v) if v is not None else ""
            doc.metadata = metadata_dict
            
        doc.metadata["total_pages"] = len(reader.pages)
        
        # Extract page by page
        segments = []
        full_text_parts = []
        for page_idx, page in enumerate(reader.pages, start=1):
            page_text = page.extract_text() or ""
            page_text = page_text.strip()
            if page_text:
                full_text_parts.append(page_text)
                # Split page into lines for finer location reporting
                lines = page_text.splitlines()
                for line_idx, line in enumerate(lines, start=1):
                    line_clean = line.strip()
                    if line_clean:
                        segments.append(DocumentSegment(
                            text=line_clean,
                            location_type="page",
                            location_ref=f"Page {page_idx}, Line {line_idx}",
                            meta={"page": page_idx, "line": line_idx}
                        ))
                        
        doc.segments = segments
        doc.raw_text = "\n".join(full_text_parts)
        doc.is_empty = len(segments) == 0
        
    except Exception as e:
        doc.error = f"PDF extraction failure: {str(e)}"
        
    return doc
