# Cygor Plugins

Cygor's enumeration modules ship in-tree (`cygor/modules/`), but the **same module
format works as a plugin** — drop a Python file into your plugin directory and
it shows up under `cygor enum --list` (and in the Web UI) like any built-in.

Plugins let you extend Cygor without forking it. Use them to wrap your own tools,
add custom enumeration logic, or ship internal scanners across your team.

- [Where plugins live](#where-plugins-live)
- [Quick start](#quick-start)
- [`cygor plugin` commands](#cygor-plugin-commands)
- [Running a plugin](#running-a-plugin)
- [Writing a plugin](#writing-a-plugin)
- [Wrapping external tools](#wrapping-external-tools)
- [Declaring options, columns, and views](#declaring-options-columns-and-views)
- [Dependencies (`requirements.txt`)](#dependencies-requirementstxt)
- [Version compatibility (`requires_cygor`)](#version-compatibility-requires_cygor)
- [Trust: the plugin allowlist](#trust-the-plugin-allowlist)
- [Web UI plugin management](#web-ui-plugin-management)
- [Troubleshooting](#troubleshooting)

---

## Where plugins live

On startup, Cygor scans these directories in order — the first match for a given
slug wins:

| Path | Purpose |
|---|---|
| `$CYGOR_PLUGIN_DIR` (if set) | Override / dev directory; checked first. |
| `~/.cygor/plugins/` | Per-user plugins. This is where `cygor plugin install` drops files. |
| `/etc/cygor/plugins/` | System-wide plugins (root-owned, multi-user installs). |

A plugin is **a single Python file** (e.g. `~/.cygor/plugins/my_scanner.py`) **or
a directory** of Python files (e.g. installed from a git URL). Filenames starting
with `_`, plus `__init__.py`, `setup.py`, and `conftest.py`, are skipped.

---

## Quick start

```bash
# 1. Scaffold a new plugin
cygor plugin create "My Scanner"
# → writes ~/.cygor/plugins/my_scanner.py with a working template

# 2. Edit it
$EDITOR ~/.cygor/plugins/my_scanner.py

# 3. Validate it
cygor plugin validate ~/.cygor/plugins/my_scanner.py

# 4. Confirm cygor sees it
cygor plugin list
cygor enum --list

# 5. Run it
cygor enum my_scanner -t 10.10.10.5
```

Cygor also ships three reference plugins you can copy and adapt:

- [`docs/examples/modules/example_simple.py`](examples/modules/example_simple.py)
  — minimal plugin (pings each target).
- [`docs/examples/modules/example_wrapper.py`](examples/modules/example_wrapper.py)
  — wraps an external CLI tool (`dig`) and parses the output.
- [`docs/examples/modules/template_module.py`](examples/modules/template_module.py)
  — full template with every supported field commented.

---

## `cygor plugin` commands

```text
cygor plugin {list, install, validate, create, update, remove}
```

| Command | What it does |
|---|---|
| `cygor plugin list` | Shows every installed plugin (slug, version, path, status). |
| `cygor plugin install <source>` | Installs from a local `.py` file **or** a git URL (`https://…` / `git@…`). Validates first; rejects on failure. Drops into `~/.cygor/plugins/`. |
| `cygor plugin validate <path>` | Validates a `.py` file without installing it. Reports schema problems, missing fields, syntax errors. |
| `cygor plugin create <name>` | Generates a working plugin scaffold under `~/.cygor/plugins/`. |
| `cygor plugin update [slug] [--all]` | Re-validates installed plugins; for git-cloned plugins runs `git pull`. |
| `cygor plugin remove <slug>` | Removes the plugin file/dir for that slug from `~/.cygor/plugins/`. |

```bash
# Install from a local file
cygor plugin install ./my_scanner.py

# Install from a public git repo
cygor plugin install https://github.com/example/cygor-myscanner

# Pin a version then update later
cygor plugin update my_scanner
cygor plugin update --all
```

---

## Running a plugin

Once a plugin is installed, it's interchangeable with built-in modules:

```bash
cygor enum <slug> -t 192.168.1.0/24
cygor enum <slug> -f targets.txt -o results/<slug>
```

The base class gives every plugin these flags for free: `-t/--target`,
`-f/--file`, `-o/--output-dir`, `--format`, `-v/--verbose`. Anything declared
in your plugin's `setup_argparser()` is added on top.

---

## Writing a plugin

Cygor supports two plugin formats. Use whichever fits.

### Format A — `CygorModule` subclass (recommended)

This is what the built-in modules use. It's the cleanest path and gets the most
features (auto-discovered CLI, output formats, web UI integration).

```python
#!/usr/bin/env python3
"""My Scanner — minimal example."""
from cygor.modules.base import CygorModule


class MyScanner(CygorModule):
    name = "My Scanner"
    slug = "my_scanner"             # used by 'cygor enum my_scanner'
    version = "1.0.0"
    author = "you"
    description = "What it does in one line"
    category = "enumeration"        # screenshots | network-shares | enumeration | credentials | custom
    view = "table"                  # table | gallery | mixed

    columns = [
        {"key": "host",   "label": "Host",   "type": "ip"},
        {"key": "status", "label": "Status", "type": "badge"},
        {"key": "info",   "label": "Info",   "type": "string"},
    ]

    def setup_argparser(self, parser) -> None:
        parser.add_argument("--timeout", type=int, default=5,
                            help="Per-target timeout in seconds")

    def run(self, targets: list, **kwargs) -> None:
        timeout = kwargs.get("timeout", 5)
        for t in targets:
            ok = my_probe(t, timeout)
            self.add_result({"host": t,
                             "status": "up" if ok else "down",
                             "info": ""})
            if not ok:
                self.increment_errors()


# Standalone execution (optional but handy for testing)
if __name__ == "__main__":
    MyScanner().cli()
```

Inside `run()` you have:

| Helper | Use |
|---|---|
| `self.add_result(dict)` | Append one row of results. Keys must match `columns`. |
| `self.add_screenshot(path)` | For `view="gallery"` (or `mixed`) modules — link an image into the gallery. |
| `self.increment_errors()` | Bump the error counter shown in the Web UI. |
| `wrap_external(cmd, timeout=…)` | Run an external tool through the proxy/jumpbox/timeout plumbing. See [Wrapping external tools](#wrapping-external-tools). |

### Format B — `module_info` dict

If you'd rather not subclass, expose a top-level `module_info` dict and a `main()`
function (or use argparse directly). Cygor will pick it up.

```python
module_info = {
    "name": "My Scanner",
    "slug": "my_scanner",
    "version": "1.0.0",
    "author": "you",
    "description": "What it does",
    "module_type": "enumeration",
    "view": "table",
    "table": {"columns": [{"key": "host", "label": "Host", "type": "ip"}]},
    "options": [],
}

def main(argv=None):
    ...   # parse args, do work, emit cygor-result.json
```

The `CygorModule` subclass auto-emits `module_info` for you, so you usually
don't need to write it by hand.

---

## Wrapping external tools

Most plugins are thin wrappers around proven tools (nmap, dig, snmpwalk, etc.).
Cygor's `wrap_external()` handles proxy passthrough, jumpbox routing, and
timeouts for you, and returns a standard `subprocess.CompletedProcess`.

```python
from cygor.modules.base import CygorModule, wrap_external
import shutil

class DigPlugin(CygorModule):
    name = "Dig Plugin"
    slug = "dig_plugin"
    columns = [
        {"key": "host", "label": "Host", "type": "ip"},
        {"key": "a",    "label": "A records", "type": "string"},
    ]

    def run(self, targets, **kwargs):
        if not shutil.which("dig"):
            print("[!] dig not installed — skipping")
            return
        for t in targets:
            proc = wrap_external(["dig", "+short", t, "A"], timeout=10)
            a_records = [l.strip() for l in (proc.stdout or "").splitlines() if l.strip()]
            self.add_result({"host": t, "a": ", ".join(a_records)})
```

The "parse, don't dump" pattern is important: parse tool output into typed rows
so the Web UI can render them in tables, filter by column, and feed findings
into the next-steps engine.

See [`docs/examples/modules/example_wrapper.py`](examples/modules/example_wrapper.py)
for the full pattern.

---

## Declaring options, columns, and views

### Columns

Each column needs a `key`, `label`, and `type`. The `type` controls how the Web
UI renders the cell:

| `type` | Renders as |
|---|---|
| `string` | Plain text. |
| `ip` | IP address (clickable, copyable). |
| `url` | Hyperlink. |
| `badge` | Pill/tag. |
| `code` | Monospace. |
| `screenshot` | Inline image link (used with `view="gallery"` / `"mixed"`). |

### Views

| `view` | Use for |
|---|---|
| `table` | Most modules. Rows + columns. |
| `gallery` | Screenshot-heavy modules (e.g. `lockon`). |
| `mixed` | Tables that also contain images (e.g. `webenum` with `--screenshot`). |

### Options (Web UI form)

Add a `module_info["options"]` list to expose run-time flags in the Web UI's
module form (the same module is runnable from the CLI or the UI):

```python
"options": [
    {"name": "timeout", "label": "Timeout (s)", "type": "number",
     "default": 5, "min": 1, "max": 120},
    {"name": "deep", "label": "Deep mode", "type": "checkbox", "default": False},
    {"name": "community", "label": "Community", "type": "text", "default": "public"},
    {"name": "wordlist", "label": "Wordlist", "type": "select", "default": "medium",
     "choices": [{"value": "quick", "label": "Quick"},
                 {"value": "medium", "label": "Medium"},
                 {"value": "large", "label": "Large"}]},
    {"name": "password", "label": "Password", "type": "password", "default": ""},
    {"name": "notes", "label": "Notes", "type": "textarea", "default": ""},
],
```

Supported `type` values: `text`, `number`, `select`, `checkbox`, `textarea`,
`password`. Option names map to argparse `--kebab-case`: `timeout` → `--timeout`,
`rid_cycle` → `--rid-cycle`. Cygor wires this up automatically when you use
the `CygorModule` base class.

---

## Dependencies (`requirements.txt`)

If your plugin imports third-party packages (other than what Cygor already
depends on), drop a `requirements.txt` next to the plugin file:

```
# ~/.cygor/plugins/requirements.txt
requests>=2.31.0
dnspython>=2.4.0
```

Cygor checks these on discovery and surfaces a clear error in `cygor plugin
list` if anything is missing. Install them into Cygor's pipx venv with:

```bash
pipx inject cygor requests dnspython
```

---

## Version compatibility (`requires_cygor`)

Declare the minimum Cygor version your plugin needs. Plugins requiring a
newer Cygor are skipped (and the reason shown by `cygor plugin list`).

```python
class MyScanner(CygorModule):
    requires_cygor = ">=1.0.0"
    ...
```

The value is treated as a **minimum** Cygor version; the leading `>=` is
optional (`"1.0.0"` and `">=1.0.0"` behave the same). Plugins requiring a
newer Cygor are skipped with a clear reason in `cygor plugin list`.

---

## Trust: the plugin allowlist

For production / shared workstations you can pin which plugins are allowed to
load, by SHA-256 fingerprint of the plugin file. Cygor refuses to load anything
that doesn't match.

Drop an allowlist at `~/.cygor/plugins-allowlist.json`:

```json
{
  "enforce": true,
  "plugins": {
    "my_scanner":   "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "other_plugin": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
  }
}
```

Get a plugin's fingerprint with:

```bash
sha256sum ~/.cygor/plugins/my_scanner.py
```

With `"enforce": true`, unlisted plugins **and** plugins whose fingerprint has
drifted are skipped (the reason is printed). Set `"enforce": false` (or remove
the file) to disable.

---

## Web UI plugin management

Settings → Plugins shows every discovered plugin and any discovery errors. The
same `/api/plugins` endpoint serves the data and lets you reload after a
filesystem change without restarting the web server.

---

## Troubleshooting

`cygor plugin list` (and the Web UI) report discovery errors with the plugin
path and reason. Common ones:

| Error | Fix |
|---|---|
| `no module_info dict or CygorModule subclass found` | Your file isn't a plugin. Subclass `CygorModule` *or* expose a top-level `module_info` dict. |
| `slug 'X' is not in the plugin allowlist` | Allowlist enforce is on; add the slug + fingerprint to `~/.cygor/plugins-allowlist.json`. |
| `fingerprint mismatch for 'X'` | File changed since you pinned it; recompute its SHA-256 and update the allowlist. |
| `requires cygor >= Y, current Z` | Upgrade Cygor (`pipx upgrade cygor`) or relax the plugin's `requires_cygor`. |
| `missing dependency: <pkg>` | `pipx inject cygor <pkg>` to install into Cygor's venv. |

> **Slug collisions.** Built-in modules always win — a plugin that reuses a
> built-in's slug is skipped silently. Between plugins, the first-discovered
> plugin (per the [search order](#where-plugins-live)) wins. Choose a unique
> slug for your plugin to avoid surprises.

For more invasive debugging, run the module standalone — every plugin can be
invoked directly:

```bash
python ~/.cygor/plugins/my_scanner.py -t 10.10.10.5 -v
```
