"""
PrivacyVault AI - CSV Dataset Extractor
Parses tabular CSV files using pandas, recording row and column coordinates for every cell.
"""

from pathlib import Path
import pandas as pd
from .extractor_base import ExtractedDocument, DocumentSegment


def extract_csv(file_path: Path, filename: str) -> ExtractedDocument:
    """Extract cell values and column schemas from a CSV dataset."""
    doc = ExtractedDocument(filename=filename, file_type="csv")
    
    try:
        # Read CSV with pandas, tolerating various delimiters
        df = None
        for sep in [",", ";", "\t", "|"]:
            try:
                df_trial = pd.read_csv(file_path, sep=sep, nrows=5)
                if len(df_trial.columns) > 1 or sep == ",":
                    df = pd.read_csv(file_path, sep=sep, dtype=str, keep_default_na=False)
                    break
            except Exception:
                continue
                
        if df is None:
            df = pd.read_csv(file_path, dtype=str, keep_default_na=False)
            
        columns = [str(c).strip() for c in df.columns]
        doc.metadata["total_rows"] = len(df)
        doc.metadata["total_columns"] = len(columns)
        doc.metadata["columns"] = columns
        
        # Check for empty dataframe
        if df.empty or len(columns) == 0:
            doc.is_empty = True
            return doc
            
        segments = []
        raw_text_parts = [" | ".join(columns)]
        
        # Extract row by row
        for row_idx, row in df.iterrows():
            display_row = row_idx + 1  # 1-indexed for users
            row_items = []
            
            for col in columns:
                val = str(row[col]).strip()
                if val:
                    row_items.append(f"{col}: {val}")
                    segments.append(DocumentSegment(
                        text=val,
                        location_type="row_col",
                        location_ref=f"Row {display_row}, Column '{col}'",
                        meta={"row": display_row, "column": col, "header": col}
                    ))
                    
            if row_items:
                raw_text_parts.append(" ; ".join(row_items))
                
        doc.segments = segments
        doc.raw_text = "\n".join(raw_text_parts)
        doc.is_empty = len(segments) == 0
        
    except Exception as e:
        doc.error = f"CSV dataset extraction failure: {str(e)}"
        
    return doc
