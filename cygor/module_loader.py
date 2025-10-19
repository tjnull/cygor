# cygor/module_loader.py
from __future__ import annotations
import importlib.util
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# ----------------------------------------------------------------------
# Locate the correct modules/ directory
# ----------------------------------------------------------------------
MODULES_DIR = Path(__file__).resolve().parent / "modules"
if not MODULES_DIR.exists():
    alt = Path(__file__).resolve().parent.parent / "modules"
    if alt.exists():
        MODULES_DIR = alt
print(f"[DEBUG] Module loader scanning directory: {MODULES_DIR}")


# ----------------------------------------------------------------------
# ModuleSpec dataclass
# ----------------------------------------------------------------------
@dataclass
class ModuleSpec:
    """Lightweight description of a discovered module."""
    name: str
    slug: str
    description: str = ""
    author: str = ""
    version: str = ""
    view: str = "table"      # 'table' or 'gallery'
    template: str = "modules_common.html"
    columns: List[Dict[str, str]] = field(default_factory=list)
    get_context: Optional[Callable[..., Any]] = None
    module: Optional[object] = field(default=None, repr=False, compare=False)


# ----------------------------------------------------------------------
# Internal helpers
# ----------------------------------------------------------------------
def _import_from_path(path: Path):
    """Safely import a Python file as a module from its path."""
    spec = importlib.util.spec_from_file_location(path.stem, path)
    if not spec or not spec.loader:
        raise ImportError(f"Cannot import module from {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return mod


def _defaultize(info: Dict[str, Any], fallback_slug: str) -> ModuleSpec:
    """Fill in missing metadata defaults for modules."""
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


# ----------------------------------------------------------------------
# Main discovery function
# ----------------------------------------------------------------------
def discover_modules() -> List[ModuleSpec]:
    """
    Scan modules/ for .py files and build ModuleSpec objects.

    Modules that include `"hidden": True` in module_info or have
    names starting with "_" or containing "template" are skipped
    and never registered into the Web UI.
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
            print(f"[!] Failed to import module {f.name}: {e}")
            continue

        info = getattr(mod, "module_info", {}) or {}

        # --- Skip hidden/internal/template modules ---
        if info.get("hidden") or f.stem.startswith("_") or "template" in f.stem.lower():
            print(f"[-] Skipping hidden/internal module: {f.stem}")
            continue

        # --- Build clean spec (exclude module reference to avoid deepcopy errors) ---
        spec = _defaultize(info, f.stem)

        get_ctx = getattr(mod, "get_context", None)
        if callable(get_ctx):
            spec.get_context = get_ctx  # safe callable reference

        # Do NOT store the actual module object (prevents deepcopy errors)
        # spec.module = mod  <-- REMOVE THIS LINE COMPLETELY

        found.append(spec)

    # Inject legacy fallbacks (lockon, smbexplorer, nfsexplorer)
    found = _inject_builtin_adapters(found)
    return found



# ----------------------------------------------------------------------
# Built-in legacy adapters (Lockon, SMB, NFS)
# ----------------------------------------------------------------------
def _inject_builtin_adapters(specs: List[ModuleSpec]) -> List[ModuleSpec]:
    """Ensure legacy modules have default definitions without overriding new ones."""
    slugs = {s.slug for s in specs}

    def add_if_missing(slug, **kwargs):
        if slug not in slugs:
            specs.append(ModuleSpec(slug=slug, **kwargs))

    add_if_missing(
        "lockon",
        name="Lockon — Web Discovery & Screenshots",
        description="Aggregates discovered web URLs and their screenshots.",
        view="gallery",
        template="modules_common.html",
    )

    add_if_missing(
        "smbexplorer",
        name="SMB Explorer",
        description="Parses SMB shares/files enumerated by the SMB explorer module.",
        view="table",
        template="modules_common.html",
        columns=[
            {"key": "ip", "label": "IP"},
            {"key": "share", "label": "Share"},
            {"key": "status", "label": "Status"},
            {"key": "smb_version", "label": "SMB Version"},
            {"key": "permissions", "label": "Permissions"},
            {"key": "information", "label": "Information"},
        ]
    )

    add_if_missing(
        "nfsexplorer",
        name="NFS Explorer",
        description="Parses NFS exports and files discovered by the NFS explorer module.",
        view="table",
        template="modules_common.html",
        columns=[
            {"key": "ip", "label": "IP"},
            {"key": "export", "label": "Export"},
            {"key": "path", "label": "Path"},
            {"key": "perm", "label": "Perm"},
        ]
    )

    return specs


# ----------------------------------------------------------------------
# Default JSON-based loader for new modules
# ----------------------------------------------------------------------
def _default_context_loader(slug: str, results_dir: Path):
    """
    Generic loader for new modules that store JSON under:
    results/cygor-enumeration-modules/<slug>/*.json
    """
    base = Path(results_dir) / "cygor-enumeration-modules" / slug
    rows = []

    if base.exists():
        for f in sorted(base.glob("*.json")):
            try:
                data = json.loads(f.read_text())
                if isinstance(data, dict) and "rows" in data:
                    rows.extend(data["rows"])
                elif isinstance(data, list):
                    rows.extend(data)
            except Exception as e:
                print(f"[!] Failed to load {f}: {e}")

    return {"rows": rows}


# ----------------------------------------------------------------------
# Legacy specialized loaders (Lockon, SMB, NFS)
# ----------------------------------------------------------------------
def resolve_legacy_context(slug: str, results_dir: Path) -> Dict[str, Any]:
    """Provide a default 'context' dict for legacy modules."""
    base = Path(results_dir) / "cygor-enumeration-modules"

    if slug == "lockon":
        from urllib.parse import urlparse
        shots_dir = Path(results_dir) / "cygor-enumeration-modules" / "lockon" / "screenshots"
        urls_file = Path(results_dir) / "cygor-enumeration-modules" / "lockon" / "urls.txt"
        items = []
        has_shots = shots_dir.exists() and any(shots_dir.glob("*.png"))

        if urls_file.exists():
            for line in urls_file.read_text().splitlines():
                u = line.strip()
                if not u:
                    continue
                parsed = urlparse(u)
                host = parsed.hostname or ""
                port = str(parsed.port or (443 if parsed.scheme == "https" else 80))
                sf = f"{host}_{port}.png"
                screenshot_url = f"/enum/lockon/screenshots/{sf}" if (shots_dir / sf).exists() else None
                items.append({"url": u, "screenshot_url": screenshot_url})

        return {"items": items, "has_shots": has_shots, "has_urls": bool(items)}

    elif slug == "smbexplorer":
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
