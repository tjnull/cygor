"""
CLI commands for managing Cygor plugins.

Usage:
    cygor plugin list              - List installed plugins
    cygor plugin install <source>  - Install from file path or git URL
    cygor plugin validate <path>   - Validate a plugin file
    cygor plugin create <name>     - Scaffold a new plugin
    cygor plugin update [<slug>] [--all]  - Update plugins (git pull / re-validate)
    cygor plugin remove <slug>     - Remove a plugin
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path


PLUGIN_SCAFFOLD = '''"""
{name} - Cygor Plugin
{underline}

A custom Cygor enumeration module.
"""
from cygor.modules.base import CygorModule


class {class_name}(CygorModule):
    """
    {name} plugin for Cygor.

    Subclass CygorModule for automatic CLI argument parsing,
    multi-format export, and web UI integration.
    """

    name = "{name}"
    slug = "{slug}"
    version = "1.0.0"
    author = ""
    description = "{name} enumeration module"
    category = "enumeration"
    view = "table"

    # Minimum cygor version required. Discovery will refuse to load
    # this plugin if the running cygor is older.
    requires_cygor = "1.0.0"

    columns = [
        {{"key": "host", "label": "Host", "type": "ip"}},
        {{"key": "finding", "label": "Finding", "type": "string"}},
        {{"key": "details", "label": "Details", "type": "string"}},
    ]

    # CLI flag overrides (optional).
    # Maps option names from the web UI to CLI flags when they differ
    # from the default --kebab-case convention.
    # Example: option_flags = {{"ntlm_hash": "-H", "use_kerberos": "-k"}}
    option_flags = {{}}

    def run(self, targets, **kwargs):
        """
        Main scan logic. Called with a list of target IPs/hostnames.

        Use self.add_result(dict) to collect results.
        Results are automatically exported when the scan completes.
        """
        for target in targets:
            self.log(f"Scanning {{target}}...")

            # TODO: Replace with your actual scanning logic
            self.add_result({{
                "host": target,
                "finding": "example",
                "details": "Replace this with real scan results",
            }})

        self.log(f"Scan complete. {{len(self._results)}} result(s) found.")


# Also expose module_info for discovery without importing the class
module_info = {{
    "name": "{name}",
    "slug": "{slug}",
    "version": "1.0.0",
    "description": "{name} enumeration module",
    "module_type": "enumeration",
    "view": "table",
    "requires_cygor": "1.0.0",
    "table": {{
        "columns": [
            {{"key": "host", "label": "Host"}},
            {{"key": "finding", "label": "Finding"}},
            {{"key": "details", "label": "Details"}},
        ]
    }},
}}


if __name__ == "__main__":
    {class_name}().cli()
'''


def cmd_list(args):
    """List installed plugins."""
    from .plugin_loader import discover_plugins, PLUGIN_DIRS
    from .module_loader import discover_modules

    print(f"Plugin directories: {', '.join(str(d) for d in PLUGIN_DIRS)}")
    print()

    all_modules = discover_modules()
    builtins = [m for m in all_modules if m.source == "builtin"]
    plugins = [m for m in all_modules if m.source == "plugin"]

    if builtins:
        print(f"Built-in modules ({len(builtins)}):")
        for m in builtins:
            print(f"  {m.slug:<20} {m.name:<35} {m.version}")
        print()

    if plugins:
        print(f"Community plugins ({len(plugins)}):")
        for m in plugins:
            path = getattr(m, "plugin_path", "")
            print(f"  {m.slug:<20} {m.name:<35} {m.version:<10} {path}")
    else:
        print("No community plugins installed.")
        print(f"  Install plugins to: {PLUGIN_DIRS[0]}")


def cmd_install(args):
    """Install a plugin from file or git URL."""
    from .plugin_loader import install_plugin

    result = install_plugin(args.source)
    if result["success"]:
        print(f"[+] Plugin installed successfully: {result.get('path', '')}")
        if result.get("name"):
            print(f"    Name: {result['name']}")
            print(f"    Slug: {result['slug']}")
        if result.get("plugins_found"):
            print(f"    {result['plugins_found']} plugin(s) found in repository")
        print()
        print("    Restart the web server to load the plugin.")
    else:
        print(f"[!] Installation failed: {result['error']}", file=sys.stderr)
        sys.exit(1)


def cmd_validate(args):
    """Validate a plugin file."""
    from .plugin_loader import validate_plugin

    path = Path(args.path)
    result = validate_plugin(path)

    if result["valid"]:
        print(f"[+] Plugin is valid!")
        print(f"    Name:     {result['name']}")
        print(f"    Slug:     {result['slug']}")
        if result.get("version"):
            print(f"    Version:  {result['version']}")
        if result.get("author"):
            print(f"    Author:   {result['author']}")
        if result.get("requires_cygor"):
            print(f"    Requires: cygor >= {result['requires_cygor']}")
        if result.get("fingerprint"):
            print(f"    SHA-256:  {result['fingerprint'][:16]}...")
        if result["warnings"]:
            print("    Warnings:")
            for w in result["warnings"]:
                print(f"      - {w}")
    else:
        print(f"[!] Plugin validation failed:", file=sys.stderr)
        for e in result["errors"]:
            print(f"    - {e}", file=sys.stderr)
        sys.exit(1)


def cmd_create(args):
    """Create a new plugin scaffold."""
    from .plugin_loader import PLUGIN_DIRS

    name = args.name
    slug = name.lower().replace(" ", "_").replace("-", "_")
    class_name = "".join(w.capitalize() for w in slug.split("_"))

    target_dir = PLUGIN_DIRS[0]
    target_dir.mkdir(parents=True, exist_ok=True)

    file_path = target_dir / f"{slug}.py"
    if file_path.exists():
        print(f"[!] Plugin already exists: {file_path}", file=sys.stderr)
        sys.exit(1)

    content = PLUGIN_SCAFFOLD.format(
        name=name,
        slug=slug,
        class_name=class_name,
        underline="=" * (len(name) + len(" - Cygor Plugin")),
    )

    file_path.write_text(content)
    print(f"[+] Plugin created: {file_path}")
    print(f"    Name: {name}")
    print(f"    Slug: {slug}")
    print(f"    Class: {class_name}")
    print()
    print(f"    Edit {file_path} to implement your scan logic.")
    print(f"    Run 'cygor plugin validate {file_path}' to check it.")


def cmd_update(args):
    """Update one or all installed plugins."""
    from .plugin_loader import discover_plugins, validate_plugin
    import subprocess

    targets = []
    if args.all:
        targets = list(discover_plugins())
    elif args.slug:
        for spec in discover_plugins():
            if spec.slug == args.slug:
                targets = [spec]
                break
        if not targets:
            print(f"[!] Plugin '{args.slug}' not found", file=sys.stderr)
            sys.exit(1)
    else:
        print("[!] Specify a slug or --all", file=sys.stderr)
        sys.exit(1)

    updated = 0
    skipped = 0
    failed = 0
    for spec in targets:
        plugin_path = Path(getattr(spec, "plugin_path", ""))
        if not plugin_path.exists():
            print(f"[!] {spec.slug}: plugin file missing ({plugin_path})", file=sys.stderr)
            failed += 1
            continue

        # Detect git checkout: walk up to find a .git directory.
        git_root = None
        for parent in [plugin_path.parent, *plugin_path.parents]:
            if (parent / ".git").exists():
                git_root = parent
                break

        if git_root:
            print(f"[*] {spec.slug}: pulling from git in {git_root}")
            try:
                proc = subprocess.run(
                    ["git", "-C", str(git_root), "pull", "--ff-only"],
                    capture_output=True, text=True, check=False, timeout=60,
                )
                if proc.returncode != 0:
                    print(f"[!] {spec.slug}: git pull failed: {proc.stderr.strip()}", file=sys.stderr)
                    failed += 1
                    continue
                if "Already up to date" in proc.stdout:
                    print(f"    {spec.slug}: already up to date")
                    skipped += 1
                    continue
                v = validate_plugin(plugin_path)
                if not v["valid"]:
                    print(f"[!] {spec.slug}: post-update validation failed: {'; '.join(v['errors'])}", file=sys.stderr)
                    failed += 1
                    continue
                print(f"[+] {spec.slug}: updated to fingerprint {v['fingerprint'][:12]}...")
                updated += 1
            except subprocess.TimeoutExpired:
                print(f"[!] {spec.slug}: git pull timed out", file=sys.stderr)
                failed += 1
        else:
            # Single-file plugin without git history — re-validate so the
            # fingerprint refreshes and any new requires_cygor / dep gates
            # are re-checked against the current cygor version.
            v = validate_plugin(plugin_path)
            if not v["valid"]:
                print(f"[!] {spec.slug}: re-validation failed: {'; '.join(v['errors'])}", file=sys.stderr)
                failed += 1
            else:
                print(f"    {spec.slug}: standalone .py file, no git remote — re-validated only")
                skipped += 1

    print(f"\nDone: {updated} updated, {skipped} unchanged, {failed} failed")
    if failed:
        sys.exit(1)


def cmd_remove(args):
    """Remove a plugin by slug."""
    from .plugin_loader import discover_plugins

    slug = args.slug
    found = None
    for spec in discover_plugins():
        if spec.slug == slug:
            found = spec
            break

    if not found:
        print(f"[!] Plugin '{slug}' not found", file=sys.stderr)
        sys.exit(1)

    plugin_path = Path(getattr(found, "plugin_path", ""))
    if not plugin_path.exists():
        print(f"[!] Plugin file not found: {plugin_path}", file=sys.stderr)
        sys.exit(1)

    confirm = input(f"Remove plugin '{found.name}' ({plugin_path})? [y/N] ").strip().lower()
    if confirm != "y":
        print("Cancelled.")
        return

    plugin_path.unlink()
    print(f"[+] Plugin '{found.name}' removed.")
    print("    Restart the web server to apply changes.")


def main(argv=None):
    """Entry point for 'cygor plugin' subcommand."""
    parser = argparse.ArgumentParser(
        prog="cygor plugin",
        description="Manage Cygor plugins",
    )
    subparsers = parser.add_subparsers(dest="command", help="Plugin command")

    # list
    subparsers.add_parser("list", help="List installed plugins")

    # install
    p_install = subparsers.add_parser("install", help="Install a plugin from file or git URL")
    p_install.add_argument("source", help="Path to .py file or git URL")

    # validate
    p_validate = subparsers.add_parser("validate", help="Validate a plugin file")
    p_validate.add_argument("path", help="Path to plugin .py file")

    # create
    p_create = subparsers.add_parser("create", help="Create a new plugin scaffold")
    p_create.add_argument("name", help="Plugin name (e.g., 'My Scanner')")

    # update
    p_update = subparsers.add_parser("update", help="Update installed plugins (git pull for cloned, re-validate for files)")
    p_update.add_argument("slug", nargs="?", help="Plugin slug to update (omit and pass --all for all plugins)")
    p_update.add_argument("--all", action="store_true", help="Update every installed plugin")

    # remove
    p_remove = subparsers.add_parser("remove", help="Remove a plugin by slug")
    p_remove.add_argument("slug", help="Plugin slug to remove")

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        sys.exit(1)

    commands = {
        "list": cmd_list,
        "install": cmd_install,
        "validate": cmd_validate,
        "create": cmd_create,
        "update": cmd_update,
        "remove": cmd_remove,
    }

    commands[args.command](args)


if __name__ == "__main__":
    main()
