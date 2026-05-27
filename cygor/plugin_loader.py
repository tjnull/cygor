"""
External plugin discovery for Cygor.

Scans user and system plugin directories for CygorModule subclasses
or module_info dicts, and returns ModuleSpec objects that integrate
seamlessly with the existing module system.

Plugin directories:
  - ~/.cygor/plugins/     (user plugins)
  - /etc/cygor/plugins/   (system-wide plugins, optional)

Plugins are standalone Python files that follow the same conventions as
built-in modules in cygor/modules/. They can define either:
  1. A `module_info` dict at module level, or
  2. A CygorModule subclass with class attributes

Plugins execute via subprocess (cygor enum <slug>) just like built-in
modules, so they cannot access internal webapp APIs.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import __version__ as CYGOR_VERSION
from .module_loader import ModuleSpec

logger = logging.getLogger(__name__)

# Plugin directories, scanned in order (first found wins for same slug)
PLUGIN_DIRS = [
    Path.home() / ".cygor" / "plugins",
    Path("/etc/cygor/plugins"),
]

# Allow override via environment variable
_extra_dir = os.environ.get("CYGOR_PLUGIN_DIR")
if _extra_dir:
    PLUGIN_DIRS.insert(0, Path(_extra_dir))

# Framework files to exclude
_EXCLUDED_NAMES = {"__init__", "setup", "conftest"}

# Per-discovery error registry. Reset at the start of every discover_plugins()
# call. Each entry is a dict: {"path", "error", "kind"}.
_PLUGIN_ERRORS: List[Dict[str, str]] = []

# Optional allowlist file. When present, only plugins whose SHA-256 matches
# the recorded fingerprint for their slug are loaded. Format:
#   {"enforce": true, "plugins": {"my_slug": "<sha256-hex>"}}
ALLOWLIST_PATH = Path.home() / ".cygor" / "plugins-allowlist.json"


def _load_allowlist() -> Dict[str, Any]:
    """Read the optional allowlist file. Returns empty dict if absent or malformed."""
    if not ALLOWLIST_PATH.exists():
        return {}
    try:
        return json.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        logger.warning(f"Failed to parse {ALLOWLIST_PATH}: {e}")
        return {}


def _allowlist_check(slug: str, fingerprint: str, allowlist: Dict[str, Any]) -> Optional[str]:
    """
    Apply the allowlist to a plugin spec. Returns an error string if the plugin
    should be rejected, otherwise None.
    """
    if not allowlist or not allowlist.get("enforce"):
        return None
    pinned = (allowlist.get("plugins") or {}).get(slug)
    if not pinned:
        return f"slug '{slug}' is not in the plugin allowlist"
    if pinned.lower() != (fingerprint or "").lower():
        return (
            f"fingerprint mismatch for '{slug}': "
            f"expected {pinned[:16]}..., got {(fingerprint or 'unknown')[:16]}..."
        )
    return None


def _allowlist_pre_exec_check(fingerprint: str, allowlist: Dict[str, Any]) -> Optional[str]:
    """Pre-exec gate: when the allowlist is enforcing, refuse to import any
    file whose hash isn't pinned anywhere in the allowlist.

    The post-exec ``_allowlist_check`` (above) verifies the slug↔fingerprint
    binding only AFTER ``exec_module`` already ran the plugin's top-level
    code. A malicious plugin would have side-effects (file/network/imports)
    by then; the SHA mismatch only stopped it from being registered, not
    from running. This pre-exec check inspects all pinned fingerprints in
    the allowlist and refuses to load any file whose hash doesn't appear --
    so untrusted plugin code never gets executed at all.

    Returns None to allow import; otherwise an error string for rejection.
    """
    if not allowlist or not allowlist.get("enforce"):
        # Allowlist disabled -- skip the pre-exec gate. (The post-exec
        # check also returns None in this mode.)
        return None
    pinned_fps = {
        str(fp).lower()
        for fp in (allowlist.get("plugins") or {}).values()
        if fp
    }
    if (fingerprint or "").lower() not in pinned_fps:
        return (
            f"refusing to import: file fingerprint "
            f"{(fingerprint or 'unknown')[:16]}... is not pinned in the "
            f"allowlist (any of {len(pinned_fps)} entries)"
        )
    return None


def get_plugin_errors() -> List[Dict[str, str]]:
    """Return errors recorded during the most recent plugin discovery."""
    return list(_PLUGIN_ERRORS)


def _record_error(path: Path, error: str, kind: str = "import") -> None:
    _PLUGIN_ERRORS.append({"path": str(path), "error": error, "kind": kind})
    logger.warning(f"Plugin error ({kind}) for {path}: {error}")


def _parse_version(v: str) -> Tuple[int, ...]:
    """Parse a dotted version string into an int tuple. Non-numeric parts → 0."""
    parts: List[int] = []
    for piece in v.strip().split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts) if parts else (0,)


def _check_version_compat(required: str, current: str = CYGOR_VERSION) -> Optional[str]:
    """
    Return None if the current version satisfies the required minimum,
    otherwise return an error string describing the mismatch.
    """
    if not required:
        return None
    try:
        if _parse_version(current) < _parse_version(required):
            return f"requires cygor >= {required}, running {current}"
    except Exception:
        # Malformed version strings shouldn't block load.
        return None
    return None


def _file_fingerprint(path: Path) -> str:
    """SHA-256 of the plugin file contents, truncated to 16 hex chars for display."""
    try:
        h = hashlib.sha256(path.read_bytes()).hexdigest()
        return h
    except Exception:
        return ""


def _requirement_to_module(req: str) -> str:
    """Strip a PEP-508 requirement string down to its top-level package name."""
    # "requests>=2.0,<3" -> "requests"; "package[extras]" -> "package"
    head = req.strip()
    for sep in (";", " ", ">=", "<=", "==", "!=", "~=", ">", "<", "["):
        idx = head.find(sep)
        if idx > 0:
            head = head[:idx]
    return head.strip()


def _check_dependencies(deps: List[str]) -> List[str]:
    """Return the subset of declared dependencies that are not importable."""
    if not deps:
        return []
    missing: List[str] = []
    for dep in deps:
        modname = _requirement_to_module(dep)
        if not modname:
            continue
        try:
            if importlib.util.find_spec(modname) is None:
                missing.append(dep)
        except Exception:
            missing.append(dep)
    return missing


def _read_requirements_txt(plugin_path: Path) -> List[str]:
    """
    Look for a requirements.txt sibling of the plugin file. Returns the list of
    requirement strings (one per line, blank/comment lines stripped).
    """
    candidate = plugin_path.parent / "requirements.txt"
    if not candidate.exists() or not candidate.is_file():
        return []
    try:
        lines = candidate.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []
    out: List[str] = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        out.append(line)
    return out


def _validate_options_schema(options: List[Dict[str, Any]]) -> List[str]:
    """Sanity-check the plugin-declared options[] array. Returns warning strings."""
    warnings: List[str] = []
    if not isinstance(options, list):
        return ["options must be a list of dicts"]
    seen_names = set()
    valid_types = {"text", "number", "select", "checkbox", "textarea", "password"}
    for i, opt in enumerate(options):
        if not isinstance(opt, dict):
            warnings.append(f"options[{i}] is not a dict")
            continue
        nm = opt.get("name")
        if not nm or not isinstance(nm, str):
            warnings.append(f"options[{i}] missing 'name'")
            continue
        if nm in seen_names:
            warnings.append(f"options[{i}] duplicate name: {nm}")
        seen_names.add(nm)
        if not opt.get("label"):
            warnings.append(f"options[{nm}] missing 'label'")
        t = opt.get("type", "text")
        if t not in valid_types:
            warnings.append(f"options[{nm}] unknown type '{t}' (use one of: {sorted(valid_types)})")
        if t == "select" and not opt.get("choices"):
            warnings.append(f"options[{nm}] type=select but no 'choices'")
    return warnings


def _import_plugin(path: Path, allowlist: Optional[Dict[str, Any]] = None):
    """Safely import a plugin file. Returns the module object or None.

    When an allowlist is in enforcing mode, this function hashes the file
    BEFORE calling ``exec_module`` and refuses to import anything whose
    hash isn't pinned in the allowlist. The slug↔fingerprint binding is
    still verified after import by ``_allowlist_check`` -- but the
    pre-exec gate is what actually keeps untrusted plugin code from
    running at all.
    """
    try:
        # Pre-exec allowlist gate. When enforce=False (or no allowlist),
        # this returns None and we fall through to the import.
        if allowlist is None:
            allowlist = _load_allowlist()
        fingerprint = _file_fingerprint(path)
        pre_err = _allowlist_pre_exec_check(fingerprint, allowlist)
        if pre_err:
            _record_error(path, pre_err, kind="allowlist")
            return None

        spec = importlib.util.spec_from_file_location(f"cygor_plugin_{path.stem}", path)
        if not spec or not spec.loader:
            _record_error(path, "spec_from_file_location returned None", kind="import")
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[attr-defined]
        return mod
    except Exception as e:
        # Capture exception type + message (full traceback would be too noisy
        # for the UI panel; user can re-run cygor plugin validate for detail).
        _record_error(path, f"{type(e).__name__}: {e}", kind="import")
        return None


def _build_spec_from_module(mod, file_path: Path, allowlist: Optional[Dict[str, Any]] = None) -> Optional[ModuleSpec]:
    """Build a ModuleSpec from a plugin module."""
    info = getattr(mod, "module_info", None)
    fingerprint = _file_fingerprint(file_path)
    if allowlist is None:
        allowlist = _load_allowlist()

    if info and isinstance(info, dict):
        module_type = info.get("module_type", "enumeration")
        if module_type == "hidden":
            return None

        slug = info.get("slug") or file_path.stem
        name = info.get("name") or slug.replace("_", " ").title()
        columns = info.get("table", {}).get("columns", [])
        requires = info.get("requires_cygor", "")
        options = info.get("options", []) or []
        deps = info.get("dependencies", []) or []

        version_err = _check_version_compat(requires)
        if version_err:
            _record_error(file_path, version_err, kind="version")
            return None

        allow_err = _allowlist_check(slug, fingerprint, allowlist)
        if allow_err:
            _record_error(file_path, allow_err, kind="allowlist")
            return None

        return ModuleSpec(
            name=name,
            slug=slug,
            description=info.get("description", ""),
            author=info.get("author", ""),
            version=info.get("version", ""),
            module_type=module_type,
            view=info.get("view", "table"),
            template=info.get("template", "modules_common.html"),
            columns=columns,
            source="plugin",
            plugin_path=str(file_path),
            requires_cygor=requires,
            fingerprint=fingerprint,
            options=options,
            dependencies=deps,
        )

    # Check for CygorModule subclass
    for attr_name in dir(mod):
        attr = getattr(mod, attr_name, None)
        if (
            isinstance(attr, type)
            and attr_name != "CygorModule"
            and hasattr(attr, "slug")
            and hasattr(attr, "name")
        ):
            # Check it's actually a CygorModule subclass by duck typing
            slug = getattr(attr, "slug", file_path.stem)
            if slug == "unnamed":
                slug = file_path.stem

            columns = getattr(attr, "columns", [])
            option_flags = getattr(attr, "option_flags", {})
            requires = getattr(attr, "requires_cygor", "")
            options = getattr(attr, "options", []) or []
            deps = getattr(attr, "dependencies", []) or []

            version_err = _check_version_compat(requires)
            if version_err:
                _record_error(file_path, version_err, kind="version")
                return None

            allow_err = _allowlist_check(slug, fingerprint, allowlist)
            if allow_err:
                _record_error(file_path, allow_err, kind="allowlist")
                return None

            return ModuleSpec(
                name=getattr(attr, "name", slug.replace("_", " ").title()),
                slug=slug,
                description=getattr(attr, "description", ""),
                author=getattr(attr, "author", ""),
                version=getattr(attr, "version", ""),
                module_type="enumeration",
                view=getattr(attr, "view", "table"),
                template=getattr(attr, "template", "modules_common.html"),
                columns=columns,
                source="plugin",
                plugin_path=str(file_path),
                option_flags=option_flags,
                requires_cygor=requires,
                fingerprint=fingerprint,
                options=options,
                dependencies=deps,
            )

    _record_error(
        file_path,
        "no module_info dict or CygorModule subclass found",
        kind="schema",
    )
    return None


def discover_plugins() -> List[ModuleSpec]:
    """
    Scan plugin directories for module files and return ModuleSpec objects.

    Skips hidden files, __init__.py, and files that fail to import. Resets
    the error registry; callers can read get_plugin_errors() afterward.
    """
    _PLUGIN_ERRORS.clear()
    found: List[ModuleSpec] = []
    seen_slugs: set = set()
    allowlist = _load_allowlist()

    for plugin_dir in PLUGIN_DIRS:
        if not plugin_dir.exists() or not plugin_dir.is_dir():
            continue

        # Scan .py files directly in the plugin directory
        for f in sorted(plugin_dir.glob("*.py")):
            if f.name.startswith("_") or f.stem in _EXCLUDED_NAMES:
                continue

            mod = _import_plugin(f, allowlist=allowlist)
            if mod is None:
                continue

            spec = _build_spec_from_module(mod, f, allowlist=allowlist)
            if not spec:
                continue
            if spec.slug in seen_slugs:
                _record_error(
                    f,
                    f"slug '{spec.slug}' is already registered (shadowed by an earlier plugin or built-in)",
                    kind="collision",
                )
                continue
            found.append(spec)
            seen_slugs.add(spec.slug)
            logger.info(f"Discovered plugin: {spec.name} ({spec.slug}) from {f}")

        # Also scan subdirectories (git-cloned plugins)
        for subdir in sorted(plugin_dir.iterdir()):
            if not subdir.is_dir() or subdir.name.startswith("."):
                continue

            for f in sorted(subdir.glob("*.py")):
                if f.name.startswith("_") or f.stem in _EXCLUDED_NAMES:
                    continue

                mod = _import_plugin(f, allowlist=allowlist)
                if mod is None:
                    continue

                spec = _build_spec_from_module(mod, f)
                if not spec:
                    continue
                if spec.slug in seen_slugs:
                    _record_error(
                        f,
                        f"slug '{spec.slug}' is already registered (shadowed by an earlier plugin or built-in)",
                        kind="collision",
                    )
                    continue
                found.append(spec)
                seen_slugs.add(spec.slug)
                logger.info(f"Discovered plugin: {spec.name} ({spec.slug}) from {f}")

    return found


def validate_plugin(path: Path) -> Dict[str, Any]:
    """
    Validate a plugin file without installing it.

    Returns a dict with:
      - valid: bool
      - name: str (module name if valid)
      - slug: str
      - version: str
      - author: str
      - requires_cygor: str
      - fingerprint: str (sha256)
      - errors: list of error messages
      - warnings: list of warnings
    """
    result: Dict[str, Any] = {
        "valid": False,
        "name": "",
        "slug": "",
        "version": "",
        "author": "",
        "requires_cygor": "",
        "fingerprint": "",
        "errors": [],
        "warnings": [],
    }

    if not path.exists():
        result["errors"].append(f"File not found: {path}")
        return result

    if not path.suffix == ".py":
        result["errors"].append("Plugin must be a .py file")
        return result

    # Capture per-call errors without polluting the discover-time error list.
    saved_errors = list(_PLUGIN_ERRORS)
    _PLUGIN_ERRORS.clear()
    try:
        mod = _import_plugin(path)
        if mod is None:
            details = "; ".join(e["error"] for e in _PLUGIN_ERRORS) or "import failed"
            result["errors"].append(f"Failed to import module: {details}")
            return result

        spec = _build_spec_from_module(mod, path)
        if spec is None:
            details = "; ".join(e["error"] for e in _PLUGIN_ERRORS)
            if details:
                result["errors"].append(details)
            else:
                result["errors"].append(
                    "Module must define either a 'module_info' dict or a CygorModule subclass "
                    "with 'name' and 'slug' attributes"
                )
            return result
    finally:
        _PLUGIN_ERRORS.clear()
        _PLUGIN_ERRORS.extend(saved_errors)

    result["valid"] = True
    result["name"] = spec.name
    result["slug"] = spec.slug
    result["version"] = spec.version
    result["author"] = spec.author
    result["requires_cygor"] = spec.requires_cygor
    result["fingerprint"] = spec.fingerprint
    result["options"] = spec.options
    result["dependencies"] = spec.dependencies

    # Combine declared dependencies with any requirements.txt sibling so that
    # users get a single missing-packages list either way.
    declared_deps = list(spec.dependencies or [])
    txt_deps = _read_requirements_txt(path)
    if txt_deps:
        result["requirements_txt"] = str(path.parent / "requirements.txt")
    combined_deps = list({d.strip(): None for d in (declared_deps + txt_deps) if d.strip()})

    missing = _check_dependencies(combined_deps)
    result["missing_dependencies"] = missing
    if missing:
        result["warnings"].append(
            f"Missing pip packages: {', '.join(missing)} — install with: pip install {' '.join(missing)}"
        )

    # Sanity-check the options schema if the plugin declared one.
    for w in _validate_options_schema(spec.options):
        result["warnings"].append(f"options schema: {w}")

    if not spec.description:
        result["warnings"].append("No description provided")
    if not spec.version:
        result["warnings"].append("No version provided")
    if not spec.columns:
        result["warnings"].append("No columns defined (table view will be empty)")

    return result


def install_plugin(source: str, target_dir: Optional[Path] = None) -> Dict[str, Any]:
    """
    Install a plugin from a file path or git URL.

    Args:
        source: Path to a .py file or a git URL
        target_dir: Override plugin install directory (default: ~/.cygor/plugins/)

    Returns dict with success/error info.
    """
    if target_dir is None:
        target_dir = PLUGIN_DIRS[0]  # ~/.cygor/plugins/

    target_dir.mkdir(parents=True, exist_ok=True)

    # Git URL
    if source.startswith("http://") or source.startswith("https://") or source.startswith("git@"):
        # Defence in depth: even though we already filtered by URL scheme
        # above, a value like 'https://x.com/' wouldn't pass that test BUT
        # 'http://foo' with an embedded null or other surprises could still
        # trick downstream tooling. Reject the obvious argument-injection
        # vectors before handing the value to `git clone`. Note: in this
        # specific code path the scheme filter already eliminates leading
        # '-', but the same `subprocess.run(["git","clone", source, ...])`
        # shape elsewhere in this branch's history was vulnerable.
        if source.startswith("-") or "\x00" in source or "\n" in source:
            return {"success": False,
                    "error": f"Refusing to clone unsafe URL: {source!r}"}

        repo_name = source.rstrip("/").split("/")[-1].replace(".git", "")
        clone_dir = target_dir / repo_name

        if clone_dir.exists():
            return {"success": False, "error": f"Directory already exists: {clone_dir}"}

        try:
            # The '--' separator tells git that everything after is a
            # positional argument, not an option. Without it, a value
            # like '--upload-pack=/tmp/x' would be parsed as a git option
            # (RCE vector). Even though the scheme check above rejects
            # leading '-', the '--' adds a definitive backstop in case
            # the prefix check is ever relaxed.
            subprocess.run(
                ["git", "clone", "--depth", "1", "--", source, str(clone_dir)],
                check=True,
                capture_output=True,
                text=True,
            )
            # Validate cloned files
            py_files = list(clone_dir.glob("*.py"))
            valid_count = 0
            for f in py_files:
                if f.name.startswith("_"):
                    continue
                v = validate_plugin(f)
                if v["valid"]:
                    valid_count += 1

            if valid_count == 0:
                # Clean up
                import shutil
                shutil.rmtree(clone_dir)
                return {"success": False, "error": "No valid plugins found in repository"}

            return {"success": True, "path": str(clone_dir), "plugins_found": valid_count}

        except subprocess.CalledProcessError as e:
            return {"success": False, "error": f"Git clone failed: {e.stderr}"}

    # Local file
    source_path = Path(source)
    if not source_path.exists():
        return {"success": False, "error": f"File not found: {source}"}

    validation = validate_plugin(source_path)
    if not validation["valid"]:
        return {"success": False, "error": "; ".join(validation["errors"])}

    import shutil
    dest = target_dir / source_path.name
    if dest.exists():
        return {"success": False, "error": f"Plugin already exists: {dest}"}

    shutil.copy2(source_path, dest)
    return {"success": True, "path": str(dest), "name": validation["name"], "slug": validation["slug"]}


def list_installed_plugins() -> List[Dict[str, Any]]:
    """List all installed plugins with their metadata."""
    plugins = []
    for spec in discover_plugins():
        plugins.append({
            "name": spec.name,
            "slug": spec.slug,
            "description": spec.description,
            "author": spec.author,
            "version": spec.version,
            "view": spec.view,
            "source": "plugin",
            "path": getattr(spec, "plugin_path", ""),
            "requires_cygor": spec.requires_cygor,
            "fingerprint": spec.fingerprint,
            "options": spec.options,
            "dependencies": spec.dependencies,
        })
    return plugins
