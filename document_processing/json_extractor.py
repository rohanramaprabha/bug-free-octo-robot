"""
PrivacyVault AI - JSON Dataset Extractor
Traverses structured JSON objects and arrays, tracking the exact JSON-pointer path of each value.
"""

from pathlib import Path
import json
from .extractor_base import ExtractedDocument, DocumentSegment


def extract_json(file_path: Path, filename: str) -> ExtractedDocument:
    """Extract leaf values from hierarchical JSON structures with full path references."""
    doc = ExtractedDocument(filename=filename, file_type="json")
    
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
            
        segments = []
        raw_text_parts = []
        
        def traverse(node, path="$"):
            if isinstance(node, dict):
                for k, v in node.items():
                    subpath = f"{path}.{k}"
                    traverse(v, subpath)
            elif isinstance(node, list):
                for idx, item in enumerate(node):
                    subpath = f"{path}[{idx}]"
                    traverse(item, subpath)
            else:
                val_str = str(node).strip()
                if val_str:
                    segments.append(DocumentSegment(
                        text=val_str,
                        location_type="key_path",
                        location_ref=f"Path: {path}",
                        meta={"path": path, "key": path.split(".")[-1]}
                    ))
                    raw_text_parts.append(f"{path}: {val_str}")
                    
        traverse(data)
        
        doc.segments = segments
        doc.raw_text = "\n".join(raw_text_parts)
        doc.metadata["top_level_type"] = type(data).__name__
        doc.metadata["total_extracted_leaves"] = len(segments)
        doc.is_empty = len(segments) == 0
        
    except json.JSONDecodeError as e:
        doc.error = f"Malformed JSON syntax at line {e.lineno}, col {e.colno}: {e.msg}"
    except Exception as e:
        doc.error = f"JSON extraction failure: {str(e)}"
        
    return doc
