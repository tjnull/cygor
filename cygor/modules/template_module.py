"""
Cygor Developer Template Module
===============================

This file serves as a reference example for developers creating new
modules for the Cygor framework.

It demonstrates how to:
  - Define `module_info` metadata
  - Parse JSON, XML, and text-based results
  - Return structured context (rows, items, chart, summary)
  - Work seamlessly with Cygor’s dynamic web UI rendering system

NOTE:
This module is intentionally hidden from the Web UI and will not
appear in /modules/. It exists purely as a developer reference.
"""

from pathlib import Path
import json
import xml.etree.ElementTree as ET
import datetime
import re

# -----------------------------------------------------------------------------
# 1. MODULE METADATA (hidden from registration)
# -----------------------------------------------------------------------------
module_info = {
    "name": "Template Module (Developer Example)",
    "slug": "template_module",  # slug will be ignored by the loader
    "author": "Cygor Development Team",
    "version": "1.1",
    "description": (
        "A developer reference module that demonstrates how to structure "
        "Cygor-compatible modules using JSON, XML, and text inputs."
    ),
    "hidden": True,  # prevents this module from being registered in the UI
}


# -----------------------------------------------------------------------------
# 2. HELPER FUNCTIONS
# -----------------------------------------------------------------------------
def _resolve_results_dir():
    """Return Cygor’s active results directory (or ./results fallback)."""
    try:
        from cygor.config import settings  # type: ignore
        return Path(settings.RESULTS_DIR)
    except Exception:
        return Path.cwd() / "results"


def _parse_json_results(path: Path):
    """Example: Load structured JSON result files."""
    rows = []
    if not path.exists():
        return rows

    for file in sorted(path.glob("*.json")):
        try:
            data = json.loads(file.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue

        if isinstance(data, dict):
            data = [data]

        for entry in data:
            rows.append({
                "host": entry.get("host") or entry.get("ip"),
                "port": entry.get("port"),
                "service": entry.get("service", "unknown"),
                "status": entry.get("status", "unknown"),
                "source": file.name,
            })
    return rows


def _parse_xml_results(path: Path):
    """Example: Extract structured data from XML files."""
    rows = []
    for xml_file in sorted(path.glob("*.xml")):
        try:
            root = ET.parse(xml_file).getroot()
        except Exception:
            continue

        for host in root.findall("host"):
            addr = host.find("address")
            ip = addr.get("addr") if addr is not None else "unknown"

            for port_el in host.findall(".//port"):
                portid = port_el.get("portid")
                state = port_el.find("state")
                if state is not None and state.get("state") != "open":
                    continue

                service = port_el.find("service")
                svc_name = service.get("name") if service is not None else "unknown"
                banner = service.get("product", "") if service is not None else ""

                rows.append({
                    "host": ip,
                    "port": portid,
                    "service": svc_name,
                    "banner": banner,
                    "source": xml_file.name,
                })
    return rows


def _parse_text_results(path: Path):
    """Example: Parse plain text output (e.g., Naabu or custom logs)."""
    rows = []
    for file in sorted(path.glob("*.txt")):
        text = file.read_text(errors="ignore")
        for match in re.finditer(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+)", text):
            ip, port = match.groups()
            rows.append({
                "host": ip,
                "port": int(port),
                "service": "tcp",
                "status": "open",
                "source": file.name,
            })
    return rows


# -----------------------------------------------------------------------------
# 3. CONTEXT FUNCTION (reference example)
# -----------------------------------------------------------------------------
def get_context(request=None, session=None):
    """
    Demonstrates how modules can collect and prepare data for visualization.
    This template is not registered by default in the Cygor Web UI.
    """
    base = _resolve_results_dir() / "cygor-enumeration-modules" / "template_module"
    rows = []

    rows += _parse_json_results(base)
    rows += _parse_xml_results(base)
    rows += _parse_text_results(base)

    # Deduplicate results
    seen, deduped = set(), []
    for r in rows:
        key = (r.get("host"), r.get("port"))
        if key not in seen:
            seen.add(key)
            deduped.append(r)

    # Example gallery items
    items = [
        {
            "url": f"http://{r['host']}:{r['port']}",
            "title": f"{r['service'].upper()} Service",
            "status": r["status"],
            "screenshot_url": None,
        }
        for r in deduped[:5]
    ]

    # Example chart
    service_counts = {}
    for r in deduped:
        svc = r.get("service", "unknown")
        service_counts[svc] = service_counts.get(svc, 0) + 1

    chart = {
        "type": "bar",
        "title": "Example Service Breakdown",
        "data": {
            "labels": list(service_counts.keys()),
            "datasets": [{
                "label": "Service Count",
                "data": list(service_counts.values()),
                "backgroundColor": [
                    "#3b82f6", "#10b981", "#f59e0b", "#ef4444", "#8b5cf6"
                ],
            }],
        },
    }

    summary = {
        "Total Hosts": len(set(r["host"] for r in deduped if r.get("host"))),
        "Total Ports": len(deduped),
        "Sources Parsed": len(list(base.glob('*'))),
        "Last Updated": datetime.date.today().isoformat(),
    }

    return {"rows": deduped, "items": items, "chart": chart, "summary": summary}


# -----------------------------------------------------------------------------
# 4. LOCAL TESTING
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    print(json.dumps(get_context(), indent=2))
    print("\nTemplate module context generated successfully (hidden module).")
