"""
Cygor Module Exporters
======================

Export functions for converting module results to various formats:
- CSV: Flat tabular export
- XML: Structured export
- TXT: Human-readable table (using tabulate)

Usage:
    from cygor.modules.exporters import export_to_csv, export_to_xml, export_to_txt

    export_to_csv(results, "output.csv", columns)
    export_to_xml(results, "output.xml", "smbexplorer")
    export_to_txt(results, "output.txt", columns)
"""

from __future__ import annotations

import csv
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# Conditional import for tabulate
try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False


# ANSI escape code regex for stripping colors
ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')


def strip_ansi(value: Any) -> str:
    """Remove ANSI escape codes from a string."""
    if value is None:
        return ""
    return ANSI_RE.sub('', str(value))


def sanitize_value(value: Any) -> str:
    """Sanitize a value for export (strip ANSI, handle None)."""
    if value is None:
        return ""
    if isinstance(value, (list, dict)):
        import json
        return json.dumps(value)
    return strip_ansi(str(value))


# -------------------------------------------------------------------------
# CSV Export
# -------------------------------------------------------------------------
def export_to_csv(
    results: List[Dict[str, Any]],
    output_path: Union[str, Path],
    columns: Optional[List] = None,
    include_all_keys: bool = True,
) -> Path:
    """
    Export results to CSV format.

    Args:
        results: List of result dictionaries
        output_path: Path to output CSV file
        columns: Optional list of ColumnDefinition or dicts with 'key' and 'label'
        include_all_keys: If True, include keys not in columns

    Returns:
        Path to the created file
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not results:
        output_path.write_text("", encoding="utf-8")
        return output_path

    # Determine headers
    if columns:
        # Use column definitions for order and labels
        headers = []
        keys = []
        for col in columns:
            if hasattr(col, 'key'):
                keys.append(col.key)
                headers.append(col.label)
            elif isinstance(col, dict):
                keys.append(col['key'])
                headers.append(col.get('label', col['key']))

        # Optionally add keys not in columns
        if include_all_keys:
            all_keys = set()
            for r in results:
                all_keys.update(r.keys())
            for k in sorted(all_keys - set(keys)):
                keys.append(k)
                headers.append(k.replace("_", " ").title())
    else:
        # Auto-detect keys from results
        all_keys = set()
        for r in results:
            all_keys.update(r.keys())
        keys = sorted(all_keys)
        headers = [k.replace("_", " ").title() for k in keys]

    # Write CSV
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for row in results:
            writer.writerow([sanitize_value(row.get(k)) for k in keys])

    return output_path


# -------------------------------------------------------------------------
# XML Export
# -------------------------------------------------------------------------
def export_to_xml(
    results: List[Dict[str, Any]],
    output_path: Union[str, Path],
    root_name: str = "results",
    item_name: str = "item",
) -> Path:
    """
    Export results to XML format.

    Args:
        results: List of result dictionaries
        output_path: Path to output XML file
        root_name: Name of root element
        item_name: Name of each result element

    Returns:
        Path to the created file
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    root = ET.Element(root_name)

    for row in results:
        item = ET.SubElement(root, item_name)
        for key, value in row.items():
            # Sanitize key for XML element name
            safe_key = re.sub(r'[^a-zA-Z0-9_]', '_', str(key))
            if safe_key[0].isdigit():
                safe_key = f"_{safe_key}"

            child = ET.SubElement(item, safe_key)
            child.text = sanitize_value(value)

    # Write with declaration
    tree = ET.ElementTree(root)
    tree.write(output_path, encoding="utf-8", xml_declaration=True)

    return output_path


# -------------------------------------------------------------------------
# TXT Export (Human-readable table)
# -------------------------------------------------------------------------
def export_to_txt(
    results: List[Dict[str, Any]],
    output_path: Union[str, Path],
    columns: Optional[List] = None,
    tablefmt: str = "pretty",
    max_col_width: int = 50,
) -> Path:
    """
    Export results to human-readable text table format.

    Args:
        results: List of result dictionaries
        output_path: Path to output TXT file
        columns: Optional list of ColumnDefinition or dicts with 'key' and 'label'
        tablefmt: Table format for tabulate (pretty, grid, simple, etc.)
        max_col_width: Maximum column width before truncation

    Returns:
        Path to the created file
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not results:
        output_path.write_text("No results.\n", encoding="utf-8")
        return output_path

    # Determine headers and keys
    if columns:
        headers = []
        keys = []
        for col in columns:
            if hasattr(col, 'key'):
                keys.append(col.key)
                headers.append(col.label)
            elif isinstance(col, dict):
                keys.append(col['key'])
                headers.append(col.get('label', col['key']))
    else:
        # Auto-detect keys from results
        all_keys = set()
        for r in results:
            all_keys.update(r.keys())
        keys = sorted(all_keys)
        headers = [k.replace("_", " ").title() for k in keys]

    # Build rows with truncation
    def truncate(val: str, max_len: int) -> str:
        if len(val) > max_len:
            return val[:max_len - 3] + "..."
        return val

    rows = []
    for row in results:
        row_values = []
        for k in keys:
            val = sanitize_value(row.get(k))
            val = truncate(val, max_col_width)
            row_values.append(val)
        rows.append(row_values)

    # Generate table
    if HAS_TABULATE:
        table_str = tabulate(rows, headers=headers, tablefmt=tablefmt)
    else:
        # Fallback: simple format without tabulate
        table_str = _simple_table(headers, rows)

    output_path.write_text(table_str + "\n", encoding="utf-8")
    return output_path


def _simple_table(headers: List[str], rows: List[List[str]]) -> str:
    """Simple table formatter when tabulate is not available."""
    if not headers and not rows:
        return ""

    # Calculate column widths
    widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(str(val)))
            else:
                widths.append(len(str(val)))

    # Build format string
    fmt = " | ".join(f"{{:<{w}}}" for w in widths)
    sep = "-+-".join("-" * w for w in widths)

    lines = [fmt.format(*headers), sep]
    for row in rows:
        # Pad row if needed
        padded = list(row) + [""] * (len(headers) - len(row))
        lines.append(fmt.format(*padded[:len(headers)]))

    return "\n".join(lines)


# -------------------------------------------------------------------------
# JSON Export (primarily handled by schema.py, but helper here)
# -------------------------------------------------------------------------
def export_to_json(
    data: Any,
    output_path: Union[str, Path],
    indent: int = 2,
) -> Path:
    """
    Export data to JSON format.

    Args:
        data: Data to export (dict, list, or Pydantic model)
        output_path: Path to output JSON file
        indent: Indentation level

    Returns:
        Path to the created file
    """
    import json

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Handle Pydantic models
    if hasattr(data, 'model_dump'):
        data = data.model_dump(by_alias=True)

    output_path.write_text(
        json.dumps(data, indent=indent, default=str),
        encoding="utf-8"
    )

    return output_path


# -------------------------------------------------------------------------
# Multi-format export convenience function
# -------------------------------------------------------------------------
def export_results(
    results: List[Dict[str, Any]],
    output_dir: Union[str, Path],
    basename: str,
    columns: Optional[List] = None,
    formats: Optional[List[str]] = None,
) -> Dict[str, Path]:
    """
    Export results to multiple formats at once.

    Args:
        results: List of result dictionaries
        output_dir: Directory for output files
        basename: Base filename (without extension)
        columns: Optional column definitions
        formats: List of formats (json, csv, xml, txt). Default: all

    Returns:
        Dictionary mapping format to output path
    """
    if formats is None:
        formats = ["json", "csv", "xml", "txt"]

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    saved = {}

    if "json" in formats:
        saved["json"] = export_to_json(results, output_dir / f"{basename}.json")

    if "csv" in formats:
        saved["csv"] = export_to_csv(results, output_dir / f"{basename}.csv", columns)

    if "xml" in formats:
        saved["xml"] = export_to_xml(results, output_dir / f"{basename}.xml", basename)

    if "txt" in formats:
        saved["txt"] = export_to_txt(results, output_dir / f"{basename}.txt", columns)

    return saved
