# Contributing to the Docs

The user-facing documentation lives in this `wiki/` directory in the main repository. There's no separate Wiki tab and no auto-publish workflow — what you read on github.com is what's committed here.

## Editing flow

```bash
# Fork & clone the main repo
git clone https://github.com/<you>/cygor
cd cygor

# Branch off dev
git switch dev
git pull origin dev
git switch -c docs/your-change

# Edit any file under wiki/
$EDITOR wiki/Your-Page.md

# Add a new page — and link it from wiki/README.md so readers can find it
$EDITOR wiki/New-Page.md
$EDITOR wiki/README.md

# Commit and push
git add wiki/
git commit -m "docs: describe what you changed"
git push origin docs/your-change

# Open a PR against tjnull/cygor:dev
```

Once merged, the new content is immediately visible at `https://github.com/tjnull/cygor/tree/dev/cygor/wiki`, and in the running web UI at `/docs/<Page-Name>`.

## Page conventions

- **Filename = page title** (with hyphens). `Plugin-Development.md` becomes "Plugin Development".
- **One landing page** — `wiki/README.md` is the index GitHub auto-renders when someone browses to the `wiki/` directory. Keep its links current when you add or remove pages.
- **Internal links** use the `.md` form: `[Plugin Development](Plugin-Development.md)`. Bare wiki-style links (`[Plugin Development](Plugin-Development)`) do **not** resolve in the file viewer.
- **Code/asset links** use repo-relative paths: `[lockon module](../cygor/modules/lockon.py)` (or full GitHub URLs if you prefer absolute).
- **Headings** start at `#` (level 1) once per file (the page title), then `##` for sections.

## What goes here vs. elsewhere

| Location | What goes there |
|---|---|
| `wiki/` *(this directory)* | User-facing guides — installation, modules, plugin development, CLI reference. Read on github.com. |
| [`README.md`](../README.md) *(repo root)* | Short overview + quick-start + links into `wiki/`. |
| [`docs/examples/`](../docs/examples/) | Runnable examples (e.g. plugin scaffolds) that users copy/paste. |
| `docs/plans/` | Internal planning notes. Local-only, never committed. |
| CLI `--help` text | The canonical option reference for every subcommand. Keep `wiki/` in sync with what `--help` actually says. |

## Verifying changes

Before opening a PR, sanity-check your page renders cleanly by viewing it on your fork's branch on github.com (markdown rendering matches the upstream view). Watch out for:

- Broken relative links (open every link in a new tab).
- Code blocks with the wrong language tag (` ```bash`, ` ```python`, ` ```text`).
- Tables with missing alignment row (the `|---|---|` line).
