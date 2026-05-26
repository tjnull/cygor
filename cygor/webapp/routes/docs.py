"""Serve the in-repo wiki/ markdown files as a navigable docs site under /docs.

Pages live at cygor/wiki/*.md (bundled with the package via pyproject's
[tool.setuptools.package-data] so they ship with pipx). This router renders
them on the fly with python-markdown, rewriting `.md` links to clean URLs so
the same source works both in the GitHub file viewer and here.
"""
from __future__ import annotations

import re
from importlib import resources
from pathlib import Path
from typing import Optional

import markdown as md
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

router = APIRouter(prefix="/docs", tags=["docs"])

# Jinja2Templates instance is injected by main.py during startup.
templates = None


def set_templates(tmpl) -> None:
    """Called by the application to inject the Jinja2Templates instance."""
    global templates
    templates = tmpl


# --- page loading -----------------------------------------------------------

# Page slugs are filename stems; allow letters/digits/hyphen/underscore only.
_SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")


def _wiki_dir() -> Path:
    """Return the absolute path to the bundled cygor/wiki/ directory."""
    # cygor.wiki is a package (has __init__.py); resources.files() gives us
    # the on-disk directory whether installed via pipx, pip, or run from source.
    return Path(str(resources.files("cygor.wiki")))


def _load_page(slug: str) -> Optional[str]:
    """Return the raw markdown for the given page slug, or None if missing."""
    if not _SLUG_RE.match(slug):
        return None
    path = _wiki_dir() / f"{slug}.md"
    if not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return None


def _available_pages() -> list[str]:
    """List of page slugs available in cygor/wiki/, sorted, README first."""
    wiki = _wiki_dir()
    if not wiki.is_dir():
        return []
    slugs = sorted(p.stem for p in wiki.glob("*.md")
                   if not p.stem.startswith("_") and p.stem != "__init__")
    # Always surface README first as the landing page link.
    if "README" in slugs:
        slugs = ["README"] + [s for s in slugs if s != "README"]
    return slugs


# --- rendering --------------------------------------------------------------

_MD_EXTENSIONS = [
    "fenced_code",     # triple-backtick code blocks
    "tables",          # GitHub-style tables
    "toc",             # auto-generate header anchors
    "sane_lists",      # consistent list nesting
    "nl2br",           # blank line = paragraph (markdown standard); single \n stays inline
    "attr_list",       # {.class} attributes on elements
]


def _rewrite_internal_links(html: str) -> str:
    """Convert href="<page>.md" / href="<page>.md#anchor" to clean /docs URLs.

    Wiki markdown uses [text](Page-Name.md) so links work in the GitHub file
    viewer. In the webapp we want them to resolve to /docs/Page-Name, so the
    rendered HTML's hrefs get rewritten in place. Absolute and external URLs
    are left untouched.
    """
    def repl(match: re.Match[str]) -> str:
        slug = match.group("slug")
        anchor = match.group("anchor") or ""
        return f'href="/docs/{slug}{anchor}"'

    # Only match relative `.md` hrefs (no scheme, no leading slash).
    return re.sub(
        r'href="(?P<slug>[A-Za-z0-9][A-Za-z0-9_-]*)\.md(?P<anchor>#[^"]*)?"',
        repl,
        html,
    )


def _render_markdown(source: str) -> tuple[str, str]:
    """Render markdown to (html_body, page_title).

    page_title is the first H1's text (if any), else None.
    """
    converter = md.Markdown(extensions=_MD_EXTENSIONS)
    html = converter.convert(source)
    html = _rewrite_internal_links(html)

    # Extract the first H1 for the page title.
    m = re.search(r"<h1[^>]*>(.*?)</h1>", html, re.DOTALL)
    title = re.sub(r"<[^>]+>", "", m.group(1)).strip() if m else ""

    return html, title


# --- routes -----------------------------------------------------------------

@router.get("", include_in_schema=False)
async def docs_root() -> RedirectResponse:
    """Bare /docs redirects to the README landing page."""
    return RedirectResponse(url="/docs/README", status_code=307)


@router.get("/{slug}", response_class=HTMLResponse)
async def docs_page(request: Request, slug: str) -> HTMLResponse:
    """Render cygor/wiki/<slug>.md as a styled page."""
    source = _load_page(slug)
    if source is None:
        # Render a friendly 404 listing available pages.
        if templates is None:
            raise HTTPException(status_code=404, detail=f"docs page '{slug}' not found")
        return templates.TemplateResponse(
            request,
            "docs.html",
            {
                "title": "Page not found",
                "page_title": "Page not found",
                "active_page": slug,
                "pages": _available_pages(),
                "body_html": (
                    f"<p>No documentation page named <code>{slug}</code> is bundled with "
                    f"this build of cygor.</p><p>See the sidebar for available pages, or "
                    f'browse the source at '
                    f'<a href="https://github.com/tjnull/cygor/tree/dev/cygor/wiki" '
                    f'target="_blank" rel="noopener">github.com/tjnull/cygor</a>.</p>'
                ),
            },
            status_code=404,
        )

    body_html, h1_title = _render_markdown(source)
    page_title = h1_title or slug.replace("-", " ")

    if templates is None:
        # Defensive fallback: render without the base template.
        return HTMLResponse(content=body_html)

    return templates.TemplateResponse(
        request,
        "docs.html",
        {
            "title": f"{page_title} · Docs",
            "page_title": page_title,
            "active_page": slug,
            "pages": _available_pages(),
            "body_html": body_html,
        },
    )
