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
    module_type: str = "enumeration"  # enumeration | hidden
    view: str = "table"      # 'table' or 'gallery'
    template: str = "modules_common.html"
    columns: List[Dict[str, str]] = field(default_factory=list)
    get_context: Optional[Callable[..., Any]] = None
    module: Optional[object] = field(default=None, repr=False, compare=False)
    source: str = "builtin"  # 'builtin' or 'plugin'
    plugin_path: str = ""    # filesystem path for plugins
    option_flags: Dict[str, str] = field(default_factory=dict)  # CLI flag overrides for plugins
    requires_cygor: str = ""  # minimum cygor version, e.g. "1.0.0"
    fingerprint: str = ""    # SHA-256 of the plugin file (plugins only)
    options: List[Dict[str, Any]] = field(default_factory=list)  # form-field schema for the Run Module page
    dependencies: List[str] = field(default_factory=list)  # pip requirement strings


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
        module_type=info.get("module_type", "enumeration"),
        view=info.get("view", "table"),
        template=info.get("template", "modules_common.html"),
        columns=info.get("table", {}).get("columns", []),
        requires_cygor=info.get("requires_cygor", ""),
        options=info.get("options", []) or [],
        dependencies=info.get("dependencies", []) or [],
    )


# ----------------------------------------------------------------------
# Main discovery function
# ----------------------------------------------------------------------
def discover_modules() -> List[ModuleSpec]:
    """
    Scan modules/ for .py files and build ModuleSpec objects.

    Modules with module_type="hidden" are skipped and never registered
    into the Web UI.
    """
    # Framework files that are not runnable modules
    FRAMEWORK_FILES = {
        "base",           # Base class for modules
        "schema",         # Pydantic schema definitions
        "exporters",      # Export helper functions
    }

    # Developer examples/templates: the canonical copy lives in
    # docs/examples/modules/, but guard against a stray copy ever landing in
    # cygor/modules/ (e.g. via a stale build) and showing up as a real module.
    EXAMPLE_FILES = {
        "template_module",
        "example_module",
    }

    # Combine all exclusions
    EXCLUDED = FRAMEWORK_FILES | EXAMPLE_FILES

    found: List[ModuleSpec] = []
    if not MODULES_DIR.exists():
        return found

    for f in sorted(MODULES_DIR.glob("*.py")):
        if f.name == "__init__.py":
            continue

        # Skip excluded files (framework, examples, deprecated)
        if f.stem in EXCLUDED:
            continue

        try:
            mod = _import_from_path(f)
        except Exception as e:
            print(f"[!] Failed to import module {f.name}: {e}")
            continue

        info = getattr(mod, "module_info", {}) or {}

        # --- Check module_type instead of name patterns ---
        module_type = info.get("module_type", "enumeration")

        # Skip hidden modules entirely
        if module_type == "hidden":
            # print(f"[-] Skipping hidden module: {f.stem}")
            continue

        # --- Build clean spec (exclude module reference to avoid deepcopy errors) ---
        spec = _defaultize(info, f.stem)
        spec.module_type = module_type

        get_ctx = getattr(mod, "get_context", None)
        if callable(get_ctx):
            spec.get_context = get_ctx  # safe callable reference

        found.append(spec)

    # Inject legacy fallbacks (lockon, smbexplorer, nfsexplorer)
    found = _inject_builtin_adapters(found)

    # Discover external plugins from ~/.cygor/plugins/ etc.
    try:
        from .plugin_loader import discover_plugins
        plugin_specs = discover_plugins()
        existing_slugs = {s.slug for s in found}
        for ps in plugin_specs:
            if ps.slug not in existing_slugs:
                found.append(ps)
    except Exception as e:
        print(f"[!] Plugin discovery failed: {e}")

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
        module_type="enumeration",
        view="gallery",
        template="modules_common.html",
    )

    add_if_missing(
        "smbexplorer",
        name="SMB Explorer",
        description="Parses SMB shares/files enumerated by the SMB explorer module.",
        module_type="enumeration",
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
        module_type="enumeration",
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
# New unified loader for cygor-result.json format
# ----------------------------------------------------------------------
def load_cygor_result(slug: str, results_dir: Path) -> Optional[Dict[str, Any]]:
    """
    Load module results from the new cygor-result.json format.

    Returns None if the file doesn't exist (allowing fallback to legacy loaders).
    Returns a dict with module, metadata, schema, results, and assets if found.
    """
    result_file = Path(results_dir) / "cygor-enumeration-modules" / slug / "cygor-result.json"

    if not result_file.exists():
        return None

    try:
        data = json.loads(result_file.read_text(encoding="utf-8"))

        # Validate basic structure
        if not isinstance(data, dict):
            return None

        # Extract components with defaults
        return {
            "module": data.get("module", {"name": slug, "slug": slug}),
            "metadata": data.get("metadata", {}),
            "schema": data.get("schema", {"view": "table", "columns": []}),
            "results": data.get("results", []),
            "assets": data.get("assets", {"screenshots": [], "files": []}),
        }
    except Exception as e:
        print(f"[!] Failed to load cygor-result.json for {slug}: {e}")
        return None


def get_module_context(slug: str, results_dir: Path) -> Dict[str, Any]:
    """
    Get context for a module, trying new format first then falling back to legacy.

    This is the main entry point for loading module data for web display.

    Returns a dict suitable for passing to templates:
    - For new format: includes module, metadata, schema, results, assets
    - For legacy format: includes rows/items as appropriate for the module
    """
    # Try new cygor-result.json format first
    new_ctx = load_cygor_result(slug, results_dir)
    if new_ctx is not None:
        return new_ctx

    # Fall back to legacy loaders
    legacy_ctx = resolve_legacy_context(slug, results_dir)
    if legacy_ctx:
        return legacy_ctx

    # Final fallback to default loader
    return _default_context_loader(slug, results_dir)


def get_module_spec_from_result(slug: str, results_dir: Path) -> Optional[ModuleSpec]:
    """
    Build a ModuleSpec from a cygor-result.json file.

    This allows dynamically registered modules that only exist as output files.
    """
    result = load_cygor_result(slug, results_dir)
    if not result:
        return None

    module_info = result.get("module", {})
    schema = result.get("schema", {})

    # Convert schema columns to the legacy format
    columns = []
    for col in schema.get("columns", []):
        columns.append({
            "key": col.get("key", ""),
            "label": col.get("label", col.get("key", "")),
        })

    return ModuleSpec(
        name=module_info.get("name", slug),
        slug=module_info.get("slug", slug),
        description=module_info.get("description", ""),
        author=module_info.get("author", ""),
        version=module_info.get("version", ""),
        module_type="enumeration",
        view=schema.get("view", "table"),
        template="modules_unified.html",  # Use new unified template
        columns=columns,
    )


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
