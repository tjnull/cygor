# Data Ingestion & Web UI

How does a row your module produces end up as a sortable table in the Web UI, with a finding pre-filled and a ready-to-run follow-up command? This page walks the full pipeline:

```
your module ──► cygor-result.json ──► workspace ──► ingest ──► Web UI
                                                      │
                                                      └─► next-steps engine ──► findings panel
```

- [The cygor-result.json schema](#the-cygor-resultjson-schema)
- [How modules emit it](#how-modules-emit-it)
- [Where it lands on disk](#where-it-lands-on-disk)
- [The ingest pipeline](#the-ingest-pipeline)
- [How rows become Web UI tables](#how-rows-become-web-ui-tables)
- [The next-steps engine](#the-next-steps-engine)
- [Worked example end-to-end](#worked-example-end-to-end)

---

## The cygor-result.json schema

Every module Cygor ships, and every plugin you write, emits the same JSON shape. The Web UI doesn't care which module produced the file — it reads the embedded `schema` and renders rows accordingly.

```jsonc
{
  "module": {
    "name": "DNS Explorer",
    "slug": "dnsexplorer",
    "version": "1.0.0",
    "author": "cygor",
    "description": "Enumerate DNS servers: version, open-resolver, AXFR zone transfer",
    "category": "enumeration"
  },
  "metadata": {
    "started_at":    "2026-05-25T20:00:00Z",
    "completed_at":  "2026-05-25T20:01:30Z",
    "target_count":  12,
    "success_count": 12,
    "error_count":   0,
    "exported_formats": ["json","csv","xml","txt"],
    "command_line":  "cygor enum dnsexplorer -i dns-hostlist.txt",
    "workspace":     "/home/tj/cygor-pentest-acme"
  },
  "schema": {
    "view": "table",
    "columns": [
      {"key": "ip",        "label": "IP Address",   "type": "ip"},
      {"key": "version",   "label": "Version",      "type": "string"},
      {"key": "recursion", "label": "Open Resolver","type": "badge"},
      {"key": "axfr",      "label": "AXFR",         "type": "badge"},
      {"key": "records",   "label": "Records",      "type": "string"},
      {"key": "info",      "label": "Info",         "type": "string"}
    ]
  },
  "results": [
    {"ip": "10.10.10.5", "version": "9.11.4",   "recursion": "yes", "axfr": "no",  "records": "0",  "info": ""},
    {"ip": "10.10.10.7", "version": "unknown",  "recursion": "no",  "axfr": "yes", "records": "42", "info": "zone: corp.local"}
  ],
  "assets": {
    "screenshots": [],
    "files": []
  }
}
```

### Top-level keys

| Key | What's inside |
|---|---|
| `module` | Identifies the module (`slug` is the routing key — it's how `/docs`, `/api/modules`, and the sidebar find your data). |
| `metadata` | Timestamps, counts, the command line used, the active workspace. The Web UI shows the duration, success/error ratio, and the command. |
| `schema` | **Drives the UI rendering** — `view` + the `columns` definition. See [How rows become Web UI tables](#how-rows-become-web-ui-tables). |
| `results` | The actual rows: a list of dicts. Each row's keys must match `schema.columns[*].key`. |
| `assets` | Files the module produced — screenshots (linked into the gallery) and other artifacts. Paths are relative to the module's output directory. |

### Column types

`schema.columns[*].type` tells the renderer how to display each cell:

| Type | Renders as |
|---|---|
| `string` | Plain text |
| `ip` | IP address (clickable / copyable, links into host detail) |
| `url` | Hyperlink |
| `badge` | Pill / tag (commonly `yes`/`no`/`open`/severity) |
| `code` | Monospace |
| `screenshot` | Inline image (used by `gallery` and `mixed` views) |

### View modes

| `schema.view` | Use for |
|---|---|
| `table` | Rows + columns — most modules. |
| `gallery` | Screenshot-heavy modules (e.g. `lockon`). |
| `mixed` | Tables that also embed images (e.g. `webenum --screenshot`). |

---

## How modules emit it

If you use the `CygorModule` base class, you never write JSON by hand. You declare the schema once, append rows from `run()`, and call `save()`:

```python
from cygor.modules.base import CygorModule


class MyScanner(CygorModule):
    name = "My Scanner"
    slug = "my_scanner"
    description = "What it does"
    category = "enumeration"
    view = "table"
    columns = [
        {"key": "host",   "label": "Host",   "type": "ip"},
        {"key": "status", "label": "Status", "type": "badge"},
        {"key": "info",   "label": "Info",   "type": "string"},
    ]

    def run(self, targets: list, **kwargs) -> None:
        for t in targets:
            ok = my_probe(t)
            self.add_result({"host": t,
                             "status": "up" if ok else "down",
                             "info": ""})
            if not ok:
                self.increment_errors()
        # self.save() is called automatically by the base CLI plumbing,
        # but you can call it manually mid-run for crash safety.
```

The base class:

- Times the run (`metadata.started_at` / `completed_at`).
- Tracks counts (`target_count`, `success_count`, `error_count`).
- Captures `command_line` and `workspace`.
- Writes `cygor-result.json` plus optional `.csv` / `.xml` / `.txt` companions to the module's output directory.

Helpers available on every module:

| Call | Effect |
|---|---|
| `self.add_result(dict)` | Append one row; keys must match `columns`. |
| `self.add_results([d1, d2, ...])` | Bulk append. |
| `self.add_screenshot("path/to.png")` | Add an asset (relative path); shows up in the gallery. |
| `self.increment_errors(n=1)` | Bump the error counter shown in the Web UI. |
| `self.set_target_count(n)` | Set the total expected so the UI can show progress (optional — the runner sets it from `targets` by default). |

Plugins written without the base class can emit `module_info` + write `cygor-result.json` directly (see [Plugin Development](Plugin-Development.md#format-b--module_info-dict)) — the schema is the contract, the base class is just the easy path.

---

## Where it lands on disk

```
<workspace>/
├── cygor-enumeration-modules/
│   └── <module-slug>/                   ← one directory per module
│       ├── cygor-result.json            ← primary, web-UI-ingested
│       ├── <slug>-results.csv           ← optional companion formats
│       ├── <slug>-results.xml
│       ├── <slug>-results.txt
│       ├── screenshots/                 ← gallery / mixed view modules
│       │   └── *.png
│       └── <module-specific files>      ← e.g. smb_files.json
├── nmap/*.xml                           ← from cygor scan
├── parsed-hostlists/<service>/...       ← from cygor parse
└── cygor.db                             ← SQLite fallback (PostgreSQL when configured)
```

Two ways the directory gets picked:

- **Workspace-aware default** — every module writes under the active workspace (set via `cygor workspace <name>` or `CYGOR_WORKSPACE`). See [Setting Up Workspaces](Setting-Up-Workspaces.md).
- **Explicit override** — pass `-o /custom/path` to any module. The schema is the same; the location changes.

The Web UI follows the same convention, so the moment a module finishes writing, the file is in the right place to be ingested.

---

## The ingest pipeline

When the Web UI starts (or you point `--load-dir` at a directory), it walks the tree looking for ingestible files:

| Extension / filename | Loader | Where it lands |
|---|---|---|
| `*.xml` (Nmap) | `ingest_directory` → Nmap parser | `host`, `port`, `script`, `os_guess` tables |
| `cygor-result.json` | The schema's `module.slug` selects a renderer; rows are stored verbatim under the slug | Module results — appear in the **Modules** sidebar and the host's detail page |
| `*.json` / `*.jsonl` (Nuclei format etc.) | Recognized formats are parsed by their loaders | Vendor-specific tables |

An **mtime cache** lives at `<workspace>/.cygor-ingest-mtimes.json` so subsequent starts only re-read files that changed. To force a full re-ingest:

```bash
cygor web start --reset-db          # destructive: drops the schema
# or just delete the mtime cache:
rm <workspace>/.cygor-ingest-mtimes.json
```

You can also trigger ingest live without restarting via the **Reload** action in the Web UI (Settings → Workspace).

---

## How rows become Web UI tables

When you click a module in the sidebar, the Web UI:

1. Loads `cygor-result.json` for that slug.
2. Reads `schema.view` (`table` / `gallery` / `mixed`) to pick the template.
3. Reads `schema.columns` to build the table header — `label` is the column heading, `type` controls cell rendering.
4. Iterates `results`, rendering each cell with the column's `type`.
5. Wires sorting and filtering off `columns[*].sortable` / `filterable` (both default to `true`).

That's why every module looks consistent in the UI even though they enumerate completely different things — the same schema drives them all.

### Linking screenshots into the gallery

Modules that produce images list them under `assets.screenshots` (relative paths), AND include a column with `"type": "screenshot"` if they want a per-row thumbnail. `lockon`, for instance, has a `screenshot` column on every row pointing at the captured PNG; the gallery view groups by `group_by` (often `target`).

---

## The next-steps engine

[`cygor/nextsteps.py`](https://github.com/tjnull/cygor/blob/dev/cygor/nextsteps.py) reads every module's rows after ingest and turns high-signal observations into **findings**: prioritized rows with a severity, an evidence string, and a ready-to-run follow-up command.

Each module has an **extractor** (`_x_<slug>`) that decides what's worth promoting:

- `dbprobe` → unauthenticated database → `critical`/`high`, command = `redis-cli` / `psql` / `mongosh`
- `nfsexplorer` → world-readable export → `high`, command = `mount -t nfs ...`
- `rpcexplorer` → null session allowed → `high`; weak password policy → `medium`/`low`
- `webenum` → exposed secrets, backups, admin interfaces → `critical`/`high`
- `ldapexplorer` → anonymous bind allowed → `high`
- `snmpexplorer` → default community + writable → `high`
- `smtpexplorer` → open relay → `high`
- `ftpexplorer` → anonymous write → `high`
- `dnsexplorer` → AXFR succeeded → `medium`
- `smbexplorer` → world-readable share → `high`

A finding looks like this:

```json
{
  "kind": "finding",
  "finding_type": "rpc_null_session",
  "severity": "high",
  "title": "RPC null session allowed",
  "evidence": "domain=CORP; users=12",
  "command": "rpcclient -U \"\" -N 10.10.10.5 -c \"enumdomusers\"",
  "service": "smb",
  "port": "445"
}
```

In the Web UI, findings appear in the host's right-rail panel sorted by severity, with the command in a copy-button block. They're also surfaced on the dashboard.

**You don't need to write findings yourself** — the engine is generic: it reads your module's rows and picks out the ones that match known high-signal patterns. If you want your plugin's results to surface as findings, name your columns the way the built-in extractors do (e.g. `unauthenticated`, `anonymous`, `null_session`, `writable`) or contribute a new extractor.

---

## Worked example end-to-end

Say your plugin probes hosts and finds open Redis:

```python
self.add_result({"host": "10.10.10.5", "service": "redis",
                 "port": "6379", "auth_required": "no",
                 "version": "Redis 7.0.5", "info": ""})
```

On disk:

```
<workspace>/cygor-enumeration-modules/my_scanner/
├── cygor-result.json     ← rows above + your declared schema
└── my_scanner-results.csv
```

Web UI ingest:

1. Reads `cygor-result.json`; sees `module.slug = "my_scanner"` and `category = "enumeration"`.
2. Adds **My Scanner** to the sidebar (because rows exist).
3. The host page for `10.10.10.5` shows a row under "My Scanner".
4. The next-steps engine sees `auth_required: "no"` on a row with `service: "redis"` and emits:

   ```
   ⚠️ Unauthenticated database (critical)
       redis on 10.10.10.5:6379 — no auth required
       $ redis-cli -h 10.10.10.5 -p 6379 INFO
   ```

That's the whole pipeline: schema in → row out → finding ready.

## Next Steps

- [Plugin Development](Plugin-Development.md) — write a module that flows through this pipeline
- [Enumeration Modules](Enumeration-Modules.md) — see how the built-ins use the schema
- [Web UI Quick Start](Web-UI-Quick-Start.md) — what the Web UI looks like once rows land
- [`docs/examples/modules/`](https://github.com/tjnull/cygor/tree/dev/docs/examples/modules) — reference plugins, including a full annotated template
