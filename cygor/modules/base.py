"""
Cygor Module Base Class
=======================

Optional base class for creating cygor modules with less boilerplate.
Provides automatic CLI generation, multi-format export, and workspace-aware paths.

Usage:
    from cygor.modules.base import CygorModule

    class MyScanner(CygorModule):
        name = "My Custom Scanner"
        slug = "myscanner"
        version = "1.0.0"
        category = "enumeration"
        view = "table"
        columns = [
            {"key": "host", "label": "Host", "type": "ip"},
            {"key": "finding", "label": "Finding", "type": "string"},
        ]

        def run(self, targets, **kwargs):
            for target in targets:
                # ... do work ...
                self.add_result({"host": target, "finding": "open"})

    if __name__ == "__main__":
        MyScanner().cli()
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import subprocess
import sys
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Type, Union


def parse_host_token(raw: str) -> str:
    """Extract a bare host from a target string, IPv6-safe.

    Accepts every shape modules commonly receive from hostlists, the CLI,
    or the web UI:
        192.168.1.1                 -> '192.168.1.1'
        192.168.1.1:445             -> '192.168.1.1'
        [2001:db8::1]               -> '2001:db8::1'
        [2001:db8::1]:445           -> '2001:db8::1'
        2001:db8::1                 -> '2001:db8::1'      (no-port form)
        host.example.com            -> 'host.example.com'
        host.example.com:445        -> 'host.example.com'
        '   '  or  ''               -> ''

    Modules used to do ``raw.strip().split()[0].split(":")[0]`` which
    mangled bare IPv6 addresses (``2001:db8::1`` -> ``2001``). This
    helper validates the candidate with ``ipaddress`` to decide whether
    a colon means 'IPv6 separator' or 'host:port separator'.
    """
    if not raw:
        return ""
    token = raw.strip().split()[0] if raw.strip() else ""
    if not token:
        return ""

    # Bracketed forms always isolate the IPv6 host: [addr] or [addr]:port.
    if token.startswith("["):
        end = token.find("]")
        if end > 0:
            return token[1:end]
        return ""

    # If the whole token parses as an IP (v4 or v6 with no brackets / no
    # port), return it as-is.
    try:
        ipaddress.ip_address(token)
        return token
    except ValueError:
        pass

    # Multi-colon tokens that aren't bracketed and aren't bare IPv6 are
    # almost certainly a malformed IPv6-with-port like '2001:db8::1:445'.
    # We can't unambiguously split that, but we can detect it and bail.
    if token.count(":") > 1:
        # Probably bare IPv6 that didn't parse for some reason. Return
        # the token unchanged -- the module's downstream connect attempt
        # will produce a clearer error than silently mangling.
        return token

    # Single colon: host:port (IPv4 or hostname). Strip the port.
    return token.split(":", 1)[0]

from .schema import (
    AssetReferences,
    ColumnDefinition,
    ColumnType,
    CygorResult,
    ModuleCategory,
    ModuleInfo,
    RunMetadata,
    SchemaDefinition,
    ViewType,
)
from .exporters import export_to_csv, export_to_xml, export_to_txt


class CygorModule(ABC):
    """
    Base class for cygor enumeration modules.

    Subclass this to create modules with automatic:
    - CLI argument parsing
    - Multi-format export (JSON, CSV, XML, TXT)
    - Workspace-aware output paths
    - Schema-driven web UI rendering

    Class Attributes:
        name: Human-readable module name
        slug: URL-safe identifier (used for output dir and routes)
        version: Module version string
        author: Module author
        description: Module description
        category: Category for UI grouping (screenshots, network-shares, etc.)
        view: Display mode (table, gallery, mixed)
        columns: List of column definitions for the schema
    """

    # Required - subclasses must define these
    name: str = "Unnamed Module"
    slug: str = "unnamed"

    # Optional - have sensible defaults
    version: str = "1.0.0"
    author: str = ""
    description: str = ""
    category: str = "enumeration"
    view: str = "table"
    columns: List[Dict[str, Any]] = []

    # Gallery-specific settings
    thumbnail_key: str = "screenshot_url"
    caption_keys: List[str] = ["host", "port", "protocol"]

    # CLI flag overrides for the web UI task system.
    # Maps option names to CLI flags when they differ from the default
    # --kebab-case convention. Example: {"ntlm_hash": "-H", "use_kerberos": "-k"}
    option_flags: Dict[str, str] = {}

    def __init__(self, output_dir: Optional[Union[str, Path]] = None):
        """
        Initialize the module.

        Args:
            output_dir: Override output directory. If None, uses workspace-aware default.
        """
        self._results: List[Dict[str, Any]] = []
        self._assets = AssetReferences()
        self._started_at: Optional[datetime] = None
        self._completed_at: Optional[datetime] = None
        self._target_count: int = 0
        self._error_count: int = 0
        self._command_line: Optional[str] = None

        # Resolve output directory
        if output_dir:
            self._output_dir = Path(output_dir)
        else:
            self._output_dir = self._get_default_output_dir()

    def _get_default_output_dir(self) -> Path:
        """Get workspace-aware output directory (no implicit ./results)."""
        from cygor.workspace import resolve_workspace, NO_WORKSPACE_MESSAGE
        ws = resolve_workspace()
        if ws is None:
            raise RuntimeError(NO_WORKSPACE_MESSAGE)
        return ws / "cygor-enumeration-modules" / self.slug

    @property
    def output_dir(self) -> Path:
        """Get the output directory, creating if needed."""
        self._output_dir.mkdir(parents=True, exist_ok=True)
        return self._output_dir

    @property
    def screenshots_dir(self) -> Path:
        """Get the screenshots subdirectory."""
        d = self.output_dir / "screenshots"
        d.mkdir(parents=True, exist_ok=True)
        return d

    # -------------------------------------------------------------------------
    # Result collection
    # -------------------------------------------------------------------------
    def add_result(self, result: Dict[str, Any]) -> None:
        """Add a single result row/item."""
        self._results.append(result)

    def add_results(self, results: List[Dict[str, Any]]) -> None:
        """Add multiple result rows/items."""
        self._results.extend(results)

    def add_screenshot(self, filename: str) -> None:
        """Register a screenshot file (relative to module output dir)."""
        # Store relative path
        rel_path = f"screenshots/{filename}"
        if rel_path not in self._assets.screenshots:
            self._assets.screenshots.append(rel_path)

    def add_asset_file(self, filename: str) -> None:
        """Register an additional data file."""
        if filename not in self._assets.files:
            self._assets.files.append(filename)

    @property
    def results(self) -> List[Dict[str, Any]]:
        """Get all collected results."""
        return self._results

    @property
    def result_count(self) -> int:
        """Get number of results collected."""
        return len(self._results)

    # -------------------------------------------------------------------------
    # Schema building
    # -------------------------------------------------------------------------
    def _build_columns(self) -> List[ColumnDefinition]:
        """Convert class columns to ColumnDefinition objects."""
        cols = []
        for col in self.columns:
            if isinstance(col, ColumnDefinition):
                cols.append(col)
            elif isinstance(col, dict):
                col_type = col.get("type", "string")
                if isinstance(col_type, str):
                    col_type = ColumnType(col_type)
                cols.append(ColumnDefinition(
                    key=col["key"],
                    label=col["label"],
                    type=col_type,
                    sortable=col.get("sortable", True),
                    filterable=col.get("filterable", True),
                    hidden=col.get("hidden", False),
                ))
        return cols

    def _build_schema(self) -> SchemaDefinition:
        """Build the schema definition."""
        view_type = ViewType(self.view) if isinstance(self.view, str) else self.view
        return SchemaDefinition(
            view=view_type,
            columns=self._build_columns(),
            thumbnail_key=self.thumbnail_key,
            caption_keys=self.caption_keys,
        )

    def _build_module_info(self) -> ModuleInfo:
        """Build module info."""
        cat = ModuleCategory(self.category) if isinstance(self.category, str) else self.category
        return ModuleInfo(
            name=self.name,
            slug=self.slug,
            version=self.version,
            author=self.author,
            description=self.description,
            category=cat,
        )

    def _build_metadata(self, exported_formats: List[str]) -> RunMetadata:
        """Build run metadata."""
        return RunMetadata(
            started_at=self._started_at,
            completed_at=self._completed_at,
            target_count=self._target_count,
            success_count=len(self._results),
            error_count=self._error_count,
            exported_formats=exported_formats,
            command_line=self._command_line,
            workspace=os.environ.get("CYGOR_WORKSPACE") or os.environ.get("CYGOR_RESULTS_DIR"),
        )

    def build_result(self, exported_formats: Optional[List[str]] = None) -> CygorResult:
        """Build the complete CygorResult object."""
        return CygorResult(
            module=self._build_module_info(),
            metadata=self._build_metadata(exported_formats or ["json"]),
            schema=self._build_schema(),
            results=self._results,
            assets=self._assets,
        )

    # -------------------------------------------------------------------------
    # Export / Save
    # -------------------------------------------------------------------------
    def save(self, formats: Optional[List[str]] = None) -> List[Path]:
        """
        Save results in specified formats.

        Args:
            formats: List of formats to export. Default: ["json", "csv", "xml", "txt"]

        Returns:
            List of paths to saved files.
        """
        if formats is None:
            formats = ["json", "csv", "xml", "txt"]

        saved_files: List[Path] = []
        self._completed_at = datetime.now()

        # Build result object
        result = self.build_result(exported_formats=formats)

        # Always save JSON (primary format with schema)
        if "json" in formats:
            json_path = self.output_dir / "cygor-result.json"
            result.save(json_path)
            saved_files.append(json_path)

        # Always honour the requested csv/xml/txt formats, even when
        # `self._results` is empty: a header-only file is a valid
        # record-of-run that a user can grep to confirm the scan happened.
        # Previously these were silently skipped when there were 0 findings,
        # which made `--format all` look broken on empty runs.
        if "csv" in formats:
            csv_path = self.output_dir / f"{self.slug}-results.csv"
            export_to_csv(self._results, csv_path, self._build_columns())
            saved_files.append(csv_path)

        if "xml" in formats:
            xml_path = self.output_dir / f"{self.slug}-results.xml"
            export_to_xml(self._results, xml_path, self.slug)
            saved_files.append(xml_path)

        if "txt" in formats:
            txt_path = self.output_dir / f"{self.slug}-results.txt"
            export_to_txt(self._results, txt_path, self._build_columns())
            saved_files.append(txt_path)

        return saved_files

    # -------------------------------------------------------------------------
    # Execution
    # -------------------------------------------------------------------------
    def start(self) -> None:
        """Mark execution start time."""
        self._started_at = datetime.now()

    def set_target_count(self, count: int) -> None:
        """Set the number of targets being scanned."""
        self._target_count = count

    def increment_errors(self, count: int = 1) -> None:
        """Increment error count."""
        self._error_count += count

    @abstractmethod
    def run(self, targets: List[str], **kwargs) -> None:
        """
        Execute the module against targets.

        Subclasses must implement this method. Use self.add_result() to
        collect results, and self.save() at the end.

        Args:
            targets: List of target hosts/IPs/URLs
            **kwargs: Additional arguments from CLI
        """
        pass

    # -------------------------------------------------------------------------
    # CLI
    # -------------------------------------------------------------------------
    def setup_argparser(self, parser: argparse.ArgumentParser) -> None:
        """
        Add module-specific arguments to the parser.

        Override this to add custom arguments. Call super().setup_argparser(parser)
        to preserve base arguments.

        Args:
            parser: ArgumentParser to add arguments to
        """
        pass

    def _create_base_parser(self) -> argparse.ArgumentParser:
        """Create the base argument parser with common options."""
        parser = argparse.ArgumentParser(
            prog=f"cygor enum {self.slug}",
            description=self.description or f"{self.name} module",
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )

        # Target options
        target_group = parser.add_argument_group("Targets")
        target_group.add_argument(
            "-t", "--target",
            help="Single target or comma-separated list"
        )
        target_group.add_argument(
            "-f", "--file", "--input-file",
            dest="input_file",
            help="File with targets (one per line)"
        )

        # Output options
        output_group = parser.add_argument_group("Output")
        output_group.add_argument(
            "-o", "--output-dir",
            nargs="?",
            const="",
            help="Output directory (default: workspace-aware)"
        )
        output_group.add_argument(
            "--format",
            default="json,csv,xml,txt",
            help="Output formats (comma-separated): json,csv,xml,txt,all"
        )

        # Verbosity
        parser.add_argument(
            "-v", "--verbose",
            action="count",
            default=0,
            help="Increase verbosity (-v, -vv)"
        )

        return parser

    def cli(self, argv: Optional[List[str]] = None) -> None:
        """
        Run the module from command line arguments.

        Args:
            argv: Command line arguments. If None, uses sys.argv[1:]
        """
        parser = self._create_base_parser()
        self.setup_argparser(parser)
        args = parser.parse_args(argv)

        # Store command line for metadata
        self._command_line = " ".join(sys.argv)

        # Parse targets
        targets = []
        if args.target:
            targets = [t.strip() for t in args.target.split(",") if t.strip()]
        elif args.input_file:
            with open(args.input_file, "r", encoding="utf-8") as f:
                targets = [line.strip() for line in f if line.strip()]

        if not targets:
            parser.error("No targets specified. Use -t or -f")

        # Set output directory if specified
        if hasattr(args, "output_dir") and args.output_dir is not None:
            if args.output_dir == "":
                # Empty string means timestamped subdirectory
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                self._output_dir = self._get_default_output_dir() / ts
            else:
                self._output_dir = Path(args.output_dir)

        # Parse formats
        formats = [f.strip().lower() for f in args.format.split(",") if f.strip()]
        if "all" in formats:
            formats = ["json", "csv", "xml", "txt"]

        # Run the module
        self.start()
        self.set_target_count(len(targets))

        # Convert args to kwargs, excluding base arguments
        kwargs = {k: v for k, v in vars(args).items()
                  if k not in ("target", "input_file", "output_dir", "format", "verbose")}
        kwargs["verbose"] = args.verbose

        try:
            self.run(targets, **kwargs)
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
        finally:
            # Save results
            saved = self.save(formats=formats)
            if saved:
                print(f"\n[+] Results saved to:")
                for p in saved:
                    print(f"    {p}")


# -------------------------------------------------------------------------
# Helper for wrapping external tools
# -------------------------------------------------------------------------
def wrap_external(
    cmd: List[str],
    capture_output: bool = True,
    timeout: Optional[int] = None,
    cwd: Optional[Union[str, Path]] = None,
    env: Optional[Dict[str, str]] = None,
) -> subprocess.CompletedProcess:
    """
    Run an external command and capture output.

    Args:
        cmd: Command and arguments as list
        capture_output: Capture stdout/stderr
        timeout: Timeout in seconds
        cwd: Working directory
        env: Environment variables (merged with current)

    Returns:
        CompletedProcess with stdout/stderr
    """
    run_env = os.environ.copy()
    if env:
        run_env.update(env)

    return subprocess.run(
        cmd,
        capture_output=capture_output,
        timeout=timeout,
        cwd=cwd,
        env=run_env,
        text=True,
    )


def merge_prior_results(
    json_path: Union[str, Path],
    new_results: List[Dict[str, Any]],
    group_key: str,
    refreshed_groups,
) -> List[Dict[str, Any]]:
    """Merge ``new_results`` with rows from an existing ``cygor-result.json``.

    The web UI ingests exactly one ``<slug>/cygor-result.json`` per module, so
    when auto-dispatch runs a single module across several service buckets
    (e.g. dbprobe over redis+postgres, or lockon over http+https) each run would
    otherwise overwrite the last. This keeps prior rows whose ``group_key`` value
    is NOT in ``refreshed_groups`` and appends the current run's rows -- so the
    file accumulates across buckets yet stays idempotent on re-run (each run
    fully replaces the groups it just probed).
    """
    import json as _json
    p = Path(json_path)
    prior: List[Dict[str, Any]] = []
    if p.is_file():
        try:
            data = _json.loads(p.read_text(encoding="utf-8", errors="ignore"))
            prior = data.get("results", []) if isinstance(data, dict) else []
        except Exception:
            prior = []
    refreshed = set(refreshed_groups)
    kept = [r for r in prior if isinstance(r, dict) and r.get(group_key) not in refreshed]
    return kept + list(new_results)


# -------------------------------------------------------------------------
# Module info dict for legacy compatibility
# -------------------------------------------------------------------------
def get_module_info(cls: Type[CygorModule]) -> Dict[str, Any]:
    """
    Generate a module_info dict from a CygorModule subclass.

    This provides backward compatibility with the existing module discovery
    system that looks for module_info dictionaries.
    """
    columns = []
    for col in cls.columns:
        if isinstance(col, ColumnDefinition):
            columns.append({"key": col.key, "label": col.label})
        elif isinstance(col, dict):
            columns.append({"key": col["key"], "label": col["label"]})

    return {
        "name": cls.name,
        "slug": cls.slug,
        "version": cls.version,
        "author": cls.author,
        "description": cls.description,
        "module_type": "enumeration",
        "category": cls.category,
        "view": cls.view,
        "template": "modules_unified.html",
        "table": {"columns": columns},
    }
