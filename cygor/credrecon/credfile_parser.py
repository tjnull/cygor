"""
Credential file parser for credrecon credfile attack mode.

Parses CSV, delimited text, JSON, and XML files containing per-target credentials.
Each row maps an IP/host to a username and password, with optional port and service.
"""
import csv
import json
import io
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

# Recognized column names (case-insensitive) mapped to canonical field names
COLUMN_ALIASES = {
    # ip field
    "ip": "ip", "host": "ip", "target": "ip", "address": "ip",
    # port field
    "port": "port",
    # username field
    "username": "username", "user": "username", "login": "username",
    # password field
    "password": "password", "pass": "password", "passwd": "password",
    # service field
    "service": "service", "protocol": "service", "proto": "service",
}

REQUIRED_FIELDS = {"ip", "username", "password"}


@dataclass
class CredFileEntry:
    """A single credential entry parsed from a file."""
    ip: str
    username: str
    password: str
    port: Optional[int] = None
    service: Optional[str] = None


@dataclass
class ParseResult:
    """Result of parsing a credential file."""
    entries: List[CredFileEntry] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    total_lines: int = 0
    skipped: int = 0


def _detect_delimiter(line: str) -> str:
    """Detect the most likely delimiter in a line of text."""
    for delim in ["\t", ",", "|", ";"]:
        if delim in line:
            return delim
    parts = line.split()
    if len(parts) >= 3:
        return None  # signal to use split() (whitespace)
    return ","


def _map_headers(raw_headers: List[str]) -> dict:
    """Map raw header names to canonical field names. Returns {index: canonical_name}."""
    mapping = {}
    for i, raw in enumerate(raw_headers):
        canonical = COLUMN_ALIASES.get(raw.strip().lower())
        if canonical:
            mapping[i] = canonical
    return mapping


def _parse_csv_content(content: str) -> ParseResult:
    """Parse CSV content with headers."""
    result = ParseResult()
    reader = csv.reader(io.StringIO(content))

    try:
        raw_headers = next(reader)
    except StopIteration:
        result.warnings.append("File is empty")
        return result

    col_map = _map_headers(raw_headers)
    missing = REQUIRED_FIELDS - set(col_map.values())

    if missing:
        return _parse_headerless_content(content)

    for row_num, row in enumerate(reader, start=2):
        result.total_lines += 1
        if not row or all(c.strip() == "" for c in row):
            continue

        entry_data = {}
        for idx, canonical in col_map.items():
            if idx < len(row):
                entry_data[canonical] = row[idx].strip()

        ip = entry_data.get("ip", "").strip()
        username = entry_data.get("username", "").strip()
        password = entry_data.get("password", "")

        if not ip:
            result.warnings.append(f"Row {row_num}: missing IP/host — skipped")
            result.skipped += 1
            continue
        if not username:
            result.warnings.append(f"Row {row_num}: missing username — skipped")
            result.skipped += 1
            continue

        port_str = entry_data.get("port", "").strip()
        port = None
        if port_str:
            try:
                port = int(port_str)
            except ValueError:
                result.warnings.append(f"Row {row_num}: invalid port '{port_str}' — ignored")

        service = entry_data.get("service", "").strip().lower() or None

        result.entries.append(CredFileEntry(
            ip=ip, username=username, password=password,
            port=port, service=service
        ))

    return result


def _parse_headerless_content(content: str) -> ParseResult:
    """Parse delimited text without recognized headers. Uses positional columns."""
    result = ParseResult()
    lines = [l.strip() for l in content.splitlines() if l.strip() and not l.startswith("#")]

    if not lines:
        result.warnings.append("File is empty or contains only comments")
        return result

    delim = _detect_delimiter(lines[0])

    for row_num, line in enumerate(lines, start=1):
        result.total_lines += 1
        if delim is None:
            parts = line.split()
        else:
            parts = line.split(delim)
        parts = [p.strip() for p in parts]

        if len(parts) < 3:
            result.warnings.append(f"Line {row_num}: expected at least 3 columns (ip,username,password) — skipped")
            result.skipped += 1
            continue

        if len(parts) == 3:
            ip, username, password = parts
            port, service = None, None
        elif len(parts) == 4:
            ip, port_str, username, password = parts
            service = None
            try:
                port = int(port_str)
            except ValueError:
                ip, username, password, service = parts[0], parts[1], parts[2], parts[3]
                port = None
        else:
            ip = parts[0]
            try:
                port = int(parts[1])
                username, password = parts[2], parts[3]
                service = parts[4] if len(parts) > 4 else None
            except ValueError:
                username, password = parts[1], parts[2]
                service = parts[3] if len(parts) > 3 else None
                port = None

        if not ip:
            result.warnings.append(f"Line {row_num}: missing IP — skipped")
            result.skipped += 1
            continue
        if not username:
            result.warnings.append(f"Line {row_num}: missing username — skipped")
            result.skipped += 1
            continue

        result.entries.append(CredFileEntry(
            ip=ip, username=username, password=password,
            port=port, service=service.lower() if service else None
        ))

    return result


def _parse_json_content(content: str) -> ParseResult:
    """Parse JSON array of credential objects."""
    result = ParseResult()

    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        result.warnings.append(f"Invalid JSON: {e}")
        return result

    if not isinstance(data, list):
        result.warnings.append("JSON must be an array of objects")
        return result

    for i, obj in enumerate(data):
        result.total_lines += 1
        if not isinstance(obj, dict):
            result.warnings.append(f"Item {i}: not an object — skipped")
            result.skipped += 1
            continue

        normalized = {k.lower(): v for k, v in obj.items()}

        entry_data = {}
        for raw_key, value in normalized.items():
            canonical = COLUMN_ALIASES.get(raw_key)
            if canonical:
                entry_data[canonical] = str(value).strip()

        ip = entry_data.get("ip", "")
        username = entry_data.get("username", "")
        password = entry_data.get("password", "")

        if not ip:
            result.warnings.append(f"Item {i}: missing IP/host — skipped")
            result.skipped += 1
            continue
        if not username:
            result.warnings.append(f"Item {i}: missing username — skipped")
            result.skipped += 1
            continue

        port = None
        port_str = entry_data.get("port", "")
        if port_str:
            try:
                port = int(port_str)
            except ValueError:
                result.warnings.append(f"Item {i}: invalid port '{port_str}' — ignored")

        service = entry_data.get("service") or None

        result.entries.append(CredFileEntry(
            ip=ip, username=username, password=password,
            port=port, service=service.lower() if service else None
        ))

    return result


def _parse_xml_content(content: str) -> ParseResult:
    """Parse XML credential data.

    Accepts any root element containing child elements, where each child has
    sub-elements with recognized tag names (same aliases as CSV headers).
    Example:
        <credentials>
          <entry>
            <ip>10.1.1.1</ip>
            <username>admin</username>
            <password>pass123</password>
            <port>22</port>
            <service>ssh</service>
          </entry>
        </credentials>
    """
    result = ParseResult()

    try:
        root = ET.fromstring(content)
    except ET.ParseError as e:
        result.warnings.append(f"Invalid XML: {e}")
        return result

    # Each direct child of root is treated as a credential entry
    for i, elem in enumerate(root):
        result.total_lines += 1

        # Collect all sub-element text, resolve aliases
        entry_data = {}
        for child in elem:
            tag = child.tag.lower().strip()
            text = (child.text or "").strip()
            canonical = COLUMN_ALIASES.get(tag)
            if canonical:
                entry_data[canonical] = text

        # Also check attributes on the element itself
        for attr_name, attr_value in elem.attrib.items():
            canonical = COLUMN_ALIASES.get(attr_name.lower().strip())
            if canonical and canonical not in entry_data:
                entry_data[canonical] = attr_value.strip()

        ip = entry_data.get("ip", "")
        username = entry_data.get("username", "")
        password = entry_data.get("password", "")

        if not ip:
            result.warnings.append(f"Element {i}: missing IP/host — skipped")
            result.skipped += 1
            continue
        if not username:
            result.warnings.append(f"Element {i}: missing username — skipped")
            result.skipped += 1
            continue

        port = None
        port_str = entry_data.get("port", "")
        if port_str:
            try:
                port = int(port_str)
            except ValueError:
                result.warnings.append(f"Element {i}: invalid port '{port_str}' — ignored")

        service = entry_data.get("service") or None

        result.entries.append(CredFileEntry(
            ip=ip, username=username, password=password,
            port=port, service=service.lower() if service else None
        ))

    return result


def parse(file_path: str) -> ParseResult:
    """
    Parse a credential file (CSV, delimited text, JSON, or XML).

    Auto-detects format based on content. Returns ParseResult with entries and warnings.
    """
    path = Path(file_path)
    if not path.exists():
        return ParseResult(warnings=[f"File not found: {file_path}"])

    content = path.read_text(encoding="utf-8", errors="replace").strip()
    if not content:
        return ParseResult(warnings=["File is empty"])

    return parse_content(content)


def parse_content(content: str) -> ParseResult:
    """
    Parse credential content string (CSV, delimited text, JSON, or XML).

    Auto-detects format. Returns ParseResult with entries and warnings.
    """
    content = content.strip()
    if not content:
        return ParseResult(warnings=["Content is empty"])

    # Detect format
    if content.startswith("<?xml") or content.startswith("<"):
        # Could be XML — try XML first, fall back to other formats if it fails
        if content.startswith("<?xml") or (content.startswith("<") and not content.startswith("[") and not content.startswith("{")):
            xml_result = _parse_xml_content(content)
            if xml_result.entries or not xml_result.warnings or "Invalid XML" not in xml_result.warnings[0]:
                return xml_result
            # XML parse failed — fall through to other formats

    if content.startswith("[") or content.startswith("{"):
        return _parse_json_content(content)

    first_line = content.split("\n")[0].strip().lower()
    # Split by common delimiters and check tokens (not substrings) for header detection
    first_tokens = set()
    for delim in [",", "\t", "|", ";"]:
        if delim in first_line:
            first_tokens = {t.strip() for t in first_line.split(delim)}
            break
    if not first_tokens:
        first_tokens = set(first_line.split())
    has_headers = bool(first_tokens & set(COLUMN_ALIASES.keys()))

    if has_headers:
        return _parse_csv_content(content)
    else:
        return _parse_headerless_content(content)
