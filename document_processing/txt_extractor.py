"""
PrivacyVault AI - Plaintext & Source Code Extractor
Extracts lines and character positions from .txt, config, log, and script files.
"""

from pathlib import Path
from .extractor_base import ExtractedDocument, DocumentSegment


def extract_txt(file_path: Path, filename: str) -> ExtractedDocument:
    """Extract line-by-line text segments from a text file."""
    doc = ExtractedDocument(filename=filename, file_type="txt")
    
    encodings_to_try = ["utf-8", "utf-8-sig", "latin-1", "cp1252"]
    content = None
    
    for enc in encodings_to_try:
        try:
            with open(file_path, "r", encoding=enc, errors="replace") as f:
                content = f.read()
            break
        except Exception:
            continue
            
    if content is None:
        doc.error = "Could not decode text file with standard encodings."
        return doc
        
    lines = content.splitlines()
    segments = []
    
    for line_idx, line in enumerate(lines, start=1):
        clean_line = line.strip()
        if clean_line:
            segments.append(DocumentSegment(
                text=clean_line,
                location_type="line",
                location_ref=f"Line {line_idx}",
                meta={"line": line_idx}
            ))
            
    doc.segments = segments
    doc.raw_text = content
    doc.metadata["total_lines"] = len(lines)
    doc.metadata["character_count"] = len(content)
    doc.is_empty = len(segments) == 0
    
    return doc
