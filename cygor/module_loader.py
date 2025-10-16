# cygor/cygor/webapp/module_loader.py
from __future__ import annotations
import importlib.util
import inspect
import json
import os
import pathlib
from dataclasses import dataclass, field
from pathlib import Path
from importlib.resources import files
from typing import Any, Callable, Dict, List, Optional

# The modules/ directory that holds drop-in Python scripts
# Force modules directory to be relative to the Cygor package root
MODULES_DIR = Path(__file__).resolve().parent / "modules"
if not MODULES_DIR.exists():
    alt = Path(__file__).resolve().parent.parent / "modules"
    if alt.exists():
        MODULES_DIR = alt
print(f"[DEBUG] Module loader scanning directory: {MODULES_DIR}")


@dataclass
class ModuleSpec:
    """Lightweight description of a discovered module."""
    name: str
    slug: str
    description: str = ""
    author: str = ""
    version: str = ""
    view: str = "table"      # 'table' or 'gallery' (extensible)
    template: str = "modules_common.html"
    columns: List[Dict[str, str]] = field(default_factory=list)  # [{'key':'ip','label':'IP'}]
    get_context: Optional[Callable[..., Any]] = None             # async/sync fn(request, session) -> dict
    module: Optional[object] = field(default=None, repr=False, compare=False)


def _import_from_path(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    if not spec or not spec.loader:
        raise ImportError(f"Cannot import module from {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return mod

def _defaultize(info: Dict[str, Any], fallback_slug: str) -> ModuleSpec:
    name = info.get("name") or fallback_slug.replace("_", " ").title()
    return ModuleSpec(
        name=name,
        slug=info.get("slug") or fallback_slug,
        description=info.get("description", ""),
        author=info.get("author", ""),
        version=info.get("version", ""),
        view=info.get("view", "table"),
        template=info.get("template", "modules_common.html"),
        columns=info.get("table", {}).get("columns", []),
    )

def discover_modules() -> List[ModuleSpec]:
    """Scan modules/ for .py files and build ModuleSpec objects.

    A module can export either:
      - module_info: dict with metadata (recommended)
      - get_context: function(request, session) -> dict to be passed to template
    """
    found: List[ModuleSpec] = []
    if not MODULES_DIR.exists():
        return found

    for f in sorted(MODULES_DIR.glob("*.py")):
        if f.name == "__init__.py":
            continue
        try:
            mod = _import_from_path(f)
        except Exception as e:
            # Skip broken modules, but leave a breadcrumb
            print(f"[!] Failed to import module {f.name}: {e}")
            continue

        info = getattr(mod, "module_info", {}) or {}
        spec = _defaultize(info, f.stem)
        # attach callable if present
        get_ctx = getattr(mod, "get_context", None)
        if callable(get_ctx):
            spec.get_context = get_ctx  # type: ignore[assignment]
        spec.module = mod
        found.append(spec)

    # Built-in adapters (so legacy modules work without changes)
    found = _inject_builtin_adapters(found)

    return found

def _inject_builtin_adapters(specs: List[ModuleSpec]) -> List[ModuleSpec]:
    """Ensure legacy modules (lockon, smbexplorer, nfsexplorer) have reasonable defaults
    even if their files don't define module_info/get_context.
    """
    slugs = {s.slug for s in specs}

    if "lockon" not in slugs:
        specs.append(ModuleSpec(
            name="Lockon — Web Discovery & Screenshots",
            slug="lockon",
            description="Aggregates discovered web URLs and their screenshots.",
            view="gallery",
            template="modules_common.html",
        ))
    if "smbexplorer" not in slugs:
        specs.append(ModuleSpec(
            name="SMB Explorer",
            slug="smbexplorer",
            description="Parses SMB shares/files enumerated by the SMB explorer module.",
            view="table",
            template="modules_common.html",
            columns=[
                {"key": "ip", "label": "IP"},
                {"key": "share", "label": "Share"},
                {"key": "path", "label": "Path"},
                {"key": "size", "label": "Size"},
            ]
        ))
    if "nfsexplorer" not in slugs:
        specs.append(ModuleSpec(
            name="NFS Explorer",
            slug="nfsexplorer",
            description="Parses NFS exports and files discovered by the NFS explorer module.",
            view="table",
            template="modules_common.html",
            columns=[
                {"key": "ip", "label": "IP"},
                {"key": "export", "label": "Export"},
                {"key": "path", "label": "Path"},
                {"key": "perm", "label": "Perm"},
            ]
        ))
    return specs

# ------------------ Default context providers for legacy modules ------------------

def resolve_legacy_context(slug: str, results_dir: Path) -> Dict[str, Any]:
    """Provide a default 'context' dict for legacy modules."""
    results_dir = Path(results_dir)
    base = results_dir / "cygor-enumeration-modules"
    if slug == "lockon":
        shots_dir = results_dir / "web-screenshots"
        urls_file = results_dir / "lockon" / "urls.txt"
        items = []
        has_shots = shots_dir.exists() and any(shots_dir.glob("*.png"))
        if urls_file.exists():
            for line in urls_file.read_text().splitlines():
                u = line.strip()
                if not u:
                    continue
                # very light port guess for screenshot name convention
                from urllib.parse import urlparse
                parsed = urlparse(u)
                host = parsed.hostname or ""
                port = str(parsed.port or (443 if parsed.scheme == "https" else 80))
                # guess screenshot filename pattern: <ip>_<port>.png
                sf = f"{host}_{port}.png"
                if (shots_dir / sf).exists():
                    screenshot_url = f"/enum/lockon/screenshots/{sf}"
                else:
                    screenshot_url = None
                items.append({"url": u, "screenshot_url": screenshot_url})
        return {"items": items, "has_shots": has_shots, "has_urls": bool(items)}

    elif slug == "smbexplorer":
        import glob, json
        rows, file_rows = [], []
        p = base / "smbexplorer"
        if p.exists():
            for f in p.glob("*.json"):
                try:
                    data = json.loads(f.read_text())
                except Exception:
                    continue
                name = f.name.lower()
                if "smb_results" in name:
                    rows.extend(data)
                elif "smb_files" in name:
                    file_rows.extend(data)
        return {"rows": rows, "file_rows": file_rows}

    elif slug == "nfsexplorer":
        import json
        rows = []
        p = base / "nfsexplorer"
        if p.exists():
            for f in p.glob("*.json"):
                try:
                    rows.extend(json.loads(f.read_text()))
                except Exception:
                    continue
        return {"rows": rows}

    return {}
