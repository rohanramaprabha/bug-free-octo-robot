"""
PrivacyVault AI - Base Document Extractor Models & Interfaces
Defines standard representations of extracted document text, metadata, and coordinates.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class DocumentSegment:
    """Represents a discrete segment of extracted content with exact location coordinates."""
    text: str
    location_type: str  # 'page', 'line', 'row_col', 'key_path', 'section'
    location_ref: str   # e.g., 'Page 2', 'Line 45', 'Row 12, Column email', 'Path: users[0].token'
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExtractedDocument:
    """Standardized representation of a parsed document or dataset."""
    filename: str
    file_type: str
    segments: List[DocumentSegment] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw_text: str = ""
    is_empty: bool = False
    error: Optional[str] = None
    
    def get_full_text(self) -> str:
        """Return combined raw text from all segments for ML classification."""
        if self.raw_text:
            return self.raw_text
        return "\n".join(seg.text for seg in self.segments if seg.text)
