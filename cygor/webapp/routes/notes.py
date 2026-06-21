"""Notes routes: collaborative markdown notes, host-linked, with reader view.

Notes are stored as raw markdown and rendered (sanitized) via the `note_render`
Jinja filter. A note can reference many hosts (NoteHostLink, many-to-many), so a
host's detail page surfaces every note that mentions it. Export emits an
Obsidian/Joplin/Notion compatible markdown "vault" zip (YAML frontmatter).

Author attribution is a lightweight free-text field (cygor has no auth/user
system yet); `last_edited_by` records who last saved a note.
"""

import io
import logging
import re
import uuid
import zipfile
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Request, Depends, Form, Query, File, UploadFile
from fastapi.responses import (
    HTMLResponse, JSONResponse, RedirectResponse, Response, FileResponse,
)
from sqlalchemy import select, or_, delete as sa_delete
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..models import Note, Host, NoteHostLink, NoteAttachment

router = APIRouter(tags=["notes"])

templates = None


def set_templates(tmpl):
    global templates
    templates = tmpl


# -------------------------------------------------------------------
# Image attachments (paste / drag-drop / upload)
# -------------------------------------------------------------------

# static/ is mounted at /static by main.py; uploads live under it for direct
# serving. The DB (NoteAttachment) holds the bytes as the durable source of truth.
_STATIC_DIR = Path(__file__).resolve().parents[1] / "static"
_UPLOAD_DIR = _STATIC_DIR / "uploads" / "notes"
_UPLOAD_URL_PREFIX = "/static/uploads/notes"

# content-type -> file extension. Drives both validation (only images allowed)
# and the on-disk filename.
_ALLOWED_IMAGE_TYPES = {
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/gif": "gif",
    "image/webp": "webp",
    "image/bmp": "bmp",
    "image/svg+xml": "svg",
    "image/avif": "avif",
}
_MAX_IMAGE_BYTES = 10 * 1024 * 1024  # 10 MB, matches EasyMDE's imageMaxSize

# Matches the two URL shapes the editor may embed for an attachment, capturing
# the 32-hex token (and extension, for the /static form).
_ATTACHMENT_URL_RE = re.compile(
    r"/static/uploads/notes/(?P<tok1>[0-9a-f]{32})\.(?P<ext>\w+)"
    r"|/api/notes/img/(?P<tok2>[0-9a-f]{32})"
)


def _iter_attachment_tokens(content):
    """Yield every attachment token referenced in a note's markdown."""
    for m in _ATTACHMENT_URL_RE.finditer(content or ""):
        yield m.group("tok1") or m.group("tok2")


def _rewrite_attachment_links(content, rel_prefix, ext_by_token):
    """Rewrite attachment URLs to a vault-relative ``attachments/<token>.<ext>``
    path so exported markdown points at the bundled image files. Unknown tokens
    (no matching attachment) are left untouched."""
    if not content:
        return content

    def repl(m):
        tok = m.group("tok1") or m.group("tok2")
        ext = ext_by_token.get(tok)
        if not ext:
            return m.group(0)
        return f"{rel_prefix}attachments/{tok}.{ext}"

    return _ATTACHMENT_URL_RE.sub(repl, content)


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------

def _slugify(text: str) -> str:
    """Filesystem-safe slug for export filenames."""
    text = (text or "untitled").strip().lower()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_-]+", "-", text).strip("-")
    return text or "untitled"


def _split_tags(raw):
    if not raw:
        return []
    return [t.strip() for t in raw.split(",") if t.strip()]


def _parse_id_list(raw):
    """Parse a comma-separated list of host ids from a form field."""
    out = []
    for part in (raw or "").split(","):
        part = part.strip()
        if part.isdigit():
            out.append(int(part))
    # de-dupe, preserve order
    seen = set()
    return [i for i in out if not (i in seen or seen.add(i))]


async def _hosts_for_notes(session, note_ids):
    """Return {note_id: [(host_id, address), ...]} for the given notes."""
    if not note_ids:
        return {}
    rows = (await session.execute(
        select(NoteHostLink.note_id, Host.id, Host.address)
        .join(Host, Host.id == NoteHostLink.host_id)
        .where(NoteHostLink.note_id.in_(list(note_ids)))
        .order_by(Host.address)
    )).all()
    out = {}
    for note_id, hid, addr in rows:
        out.setdefault(note_id, []).append((hid, addr))
    return out


async def _sync_note_hosts(session, note_id, host_ids):
    """Reconcile NoteHostLink rows for a note to exactly `host_ids`."""
    # Only keep ids that reference real hosts.
    valid = set()
    if host_ids:
        valid = {hid for (hid,) in (await session.execute(
            select(Host.id).where(Host.id.in_(host_ids))
        )).all()}
    await session.execute(sa_delete(NoteHostLink).where(NoteHostLink.note_id == note_id))
    for hid in host_ids:
        if hid in valid:
            session.add(NoteHostLink(note_id=note_id, host_id=hid))


def _yaml_frontmatter(note, host_addresses):
    """Build YAML frontmatter understood by Obsidian/Joplin/Logseq."""
    lines = ["---", f"title: {note.title or 'Untitled'}"]
    tags = _split_tags(note.tags)
    if tags:
        lines.append("tags:")
        lines.extend(f"  - {t}" for t in tags)
    if note.author:
        lines.append(f"author: {note.author}")
    if note.created_at:
        lines.append(f"created: {note.created_at.isoformat()}")
    if note.updated_at:
        lines.append(f"updated: {note.updated_at.isoformat()}")
    if host_addresses:
        lines.append("hosts:")
        lines.extend(f"  - {a}" for a in host_addresses)
    lines.append("---")
    return "\n".join(lines)


# -------------------------------------------------------------------
# Pages
# -------------------------------------------------------------------

@router.get("/notes", response_class=HTMLResponse)
async def notes_index(
    request: Request,
    session: AsyncSession = Depends(get_session),
    q: str = Query(default=""),
    tag: str = Query(default=""),
    host_id: int | None = Query(default=None),
    archived: int = Query(default=0),
):
    """List notes with search / tag / host filters. Pinned float to the top."""
    query = select(Note)

    if archived:
        query = query.where(Note.archived == True)  # noqa: E712
    else:
        query = query.where(Note.archived == False)  # noqa: E712

    if q.strip():
        pat = f"%{q.strip()}%"
        query = query.where(or_(
            Note.title.ilike(pat),
            Note.content.ilike(pat),
            Note.tags.ilike(pat),
            Note.author.ilike(pat),
        ))
    if tag.strip():
        query = query.where(Note.tags.ilike(f"%{tag.strip()}%"))
    if host_id is not None:
        query = query.where(Note.id.in_(
            select(NoteHostLink.note_id).where(NoteHostLink.host_id == host_id)
        ))

    query = query.order_by(Note.pinned.desc(), Note.updated_at.desc())
    notes = (await session.execute(query)).scalars().all()

    host_links = await _hosts_for_notes(session, [n.id for n in notes])

    # All distinct tags across non-archived notes, for the filter bar.
    tag_rows = (await session.execute(
        select(Note.tags).where(Note.archived == False, Note.tags.isnot(None))  # noqa: E712
    )).all()
    all_tags = sorted({t for (raw,) in tag_rows for t in _split_tags(raw)}, key=str.lower)

    # Count archived for the toggle label.
    archived_count = (await session.execute(
        select(Note.id).where(Note.archived == True)  # noqa: E712
    )).all()

    return templates.TemplateResponse(request, "notes.html", {
        "notes": notes,
        "host_links": host_links,
        "all_tags": all_tags,
        "q": q,
        "active_tag": tag,
        "active_host_id": host_id,
        "showing_archived": bool(archived),
        "archived_count": len(archived_count),
    })


@router.get("/notes/new", response_class=HTMLResponse)
async def note_new(
    request: Request,
    host_id: int | None = Query(default=None),
    session: AsyncSession = Depends(get_session),
):
    """Editor for a new note. Optionally pre-link a host."""
    selected_hosts = []
    if host_id is not None:
        host = (await session.execute(
            select(Host).where(Host.id == host_id)
        )).scalars().first()
        if host:
            selected_hosts.append({"id": host.id, "address": host.address})

    return templates.TemplateResponse(request, "note_edit.html", {
        "note": None,
        "selected_hosts": selected_hosts,
        "origin_host_id": host_id,
    })


@router.get("/notes/{note_id:int}/view", response_class=HTMLResponse)
async def note_view(
    request: Request,
    note_id: int,
    session: AsyncSession = Depends(get_session),
):
    """Read-only reader view of a note."""
    note = (await session.execute(
        select(Note).where(Note.id == note_id)
    )).scalars().first()
    if not note:
        return HTMLResponse(f"<h1>Note {note_id} not found</h1>", status_code=404)

    links = (await _hosts_for_notes(session, [note.id])).get(note.id, [])
    return templates.TemplateResponse(request, "note_view.html", {
        "note": note,
        "linked_hosts": [{"id": hid, "address": addr} for hid, addr in links],
    })


@router.get("/notes/{note_id:int}", response_class=HTMLResponse)
async def note_edit(
    request: Request,
    note_id: int,
    session: AsyncSession = Depends(get_session),
):
    """Editor for an existing note."""
    note = (await session.execute(
        select(Note).where(Note.id == note_id)
    )).scalars().first()
    if not note:
        return HTMLResponse(f"<h1>Note {note_id} not found</h1>", status_code=404)

    links = (await _hosts_for_notes(session, [note.id])).get(note.id, [])
    return templates.TemplateResponse(request, "note_edit.html", {
        "note": note,
        "selected_hosts": [{"id": hid, "address": addr} for hid, addr in links],
        "origin_host_id": note.host_id,
    })


# -------------------------------------------------------------------
# Mutations
# -------------------------------------------------------------------

@router.post("/notes/save")
async def note_save(
    request: Request,
    session: AsyncSession = Depends(get_session),
    note_id: str = Form(default=""),
    title: str = Form(default="Untitled"),
    content: str = Form(default=""),
    tags: str = Form(default=""),
    author: str = Form(default=""),
    host_ids: str = Form(default=""),
    origin_host_id: str = Form(default=""),
    pinned: str = Form(default=""),
    archived: str = Form(default=""),
    redirect: str = Form(default=""),
):
    """Create or update a note (form post)."""
    title = (title or "Untitled").strip() or "Untitled"
    author = author.strip() or None
    is_pinned = pinned.strip().lower() in ("1", "on", "true", "yes")
    is_archived = archived.strip().lower() in ("1", "on", "true", "yes")
    parsed_host_ids = _parse_id_list(host_ids)
    parsed_origin = int(origin_host_id) if origin_host_id.strip().isdigit() else None

    if note_id.strip().isdigit():
        note = (await session.execute(
            select(Note).where(Note.id == int(note_id))
        )).scalars().first()
        if not note:
            return JSONResponse({"error": "note not found"}, status_code=404)
        note.title = title
        note.content = content
        note.tags = tags.strip() or None
        if author and not note.author:
            note.author = author  # keep original author; fill if it was blank
        note.last_edited_by = author
        note.pinned = is_pinned
        note.archived = is_archived
        note.updated_at = datetime.utcnow()
    else:
        note = Note(
            title=title,
            content=content,
            tags=tags.strip() or None,
            author=author,
            last_edited_by=author,
            pinned=is_pinned,
            archived=is_archived,
            host_id=parsed_origin,
            created_by=None,
        )
        session.add(note)

    await session.flush()  # ensure note.id is available for link sync
    await _sync_note_hosts(session, note.id, parsed_host_ids)
    await session.commit()

    target = redirect.strip() or f"/notes/{note.id}/view"
    return RedirectResponse(url=target, status_code=303)


@router.post("/api/notes/upload-image")
async def note_upload_image(
    image: UploadFile = File(...),
    session: AsyncSession = Depends(get_session),
):
    """Receive a pasted/dropped/selected image from the note editor.

    Stores the bytes in the DB (durable) and writes a copy to the static
    uploads folder (fast serving). Responds in EasyMDE's expected shape:
    ``{"data": {"filePath": "<url>"}}`` on success, ``{"error": "<msg>"}`` else.
    """
    data = await image.read()
    if not data:
        return JSONResponse({"error": "The file is empty."}, status_code=400)
    if len(data) > _MAX_IMAGE_BYTES:
        return JSONResponse(
            {"error": "Image is too large (max 10 MB)."}, status_code=413)

    ctype = (image.content_type or "").split(";")[0].strip().lower()
    ext = _ALLOWED_IMAGE_TYPES.get(ctype)
    if not ext:
        return JSONResponse(
            {"error": "Only image files can be attached."}, status_code=415)

    token = uuid.uuid4().hex
    attachment = NoteAttachment(
        token=token,
        filename=(image.filename or f"{token}.{ext}")[:255],
        content_type=ctype,
        ext=ext,
        size=len(data),
        data=data,
    )
    session.add(attachment)
    await session.commit()

    # Best-effort static copy; the DB row remains the source of truth, and the
    # /api/notes/img endpoint can re-materialize the file if this write fails.
    try:
        _UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        (_UPLOAD_DIR / f"{token}.{ext}").write_bytes(data)
    except OSError as e:
        logging.warning("Could not write note image to static dir: %s", e)

    return JSONResponse({"data": {"filePath": f"{_UPLOAD_URL_PREFIX}/{token}.{ext}"}})


@router.get("/api/notes/img/{token}")
async def note_image(token: str, session: AsyncSession = Depends(get_session)):
    """Serve an attachment from disk, healing the static copy from the DB if the
    file is missing (e.g. after a DB-only restore). The editor normally links
    images by their /static URL; this is the durable fallback."""
    token = (token.rsplit(".", 1)[0]).strip()  # tolerate a trailing extension
    attachment = (await session.execute(
        select(NoteAttachment).where(NoteAttachment.token == token)
    )).scalars().first()
    if not attachment:
        return JSONResponse({"error": "not found"}, status_code=404)

    path = _UPLOAD_DIR / f"{attachment.token}.{attachment.ext}"
    if path.is_file():
        return FileResponse(str(path), media_type=attachment.content_type)
    try:
        _UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        path.write_bytes(attachment.data)
    except OSError as e:
        logging.warning("Could not heal note image on disk: %s", e)
    return Response(content=attachment.data, media_type=attachment.content_type)


@router.post("/api/notes/quick")
async def note_quick_add(
    session: AsyncSession = Depends(get_session),
    title: str = Form(default="Untitled"),
    content: str = Form(default=""),
    tags: str = Form(default=""),
    author: str = Form(default=""),
    host_id: str = Form(default=""),
):
    """Create a note tagged to a host in one shot (used by the hosts page
    quick-add modal). Returns JSON with the host's new note count."""
    hid = int(host_id) if host_id.strip().isdigit() else None
    note = Note(
        title=(title or "Untitled").strip() or "Untitled",
        content=content,
        tags=tags.strip() or None,
        author=author.strip() or None,
        last_edited_by=author.strip() or None,
        host_id=hid,
        created_by=None,
    )
    session.add(note)
    await session.flush()

    if hid is not None:
        host_exists = (await session.execute(
            select(Host.id).where(Host.id == hid)
        )).first()
        if host_exists:
            session.add(NoteHostLink(note_id=note.id, host_id=hid))
        else:
            hid = None
    await session.commit()

    count = 0
    if hid is not None:
        count = len((await session.execute(
            select(NoteHostLink.note_id)
            .join(Note, Note.id == NoteHostLink.note_id)
            .where(NoteHostLink.host_id == hid, Note.archived == False)  # noqa: E712
        )).all())

    return JSONResponse({"ok": True, "note_id": note.id, "host_id": hid, "note_count": count})


@router.post("/notes/{note_id:int}/pin")
async def note_pin(
    note_id: int,
    session: AsyncSession = Depends(get_session),
    redirect: str = Form(default="/notes"),
):
    """Toggle a note's pinned flag."""
    note = (await session.execute(select(Note).where(Note.id == note_id))).scalars().first()
    if note:
        note.pinned = not note.pinned
        await session.commit()
    return RedirectResponse(url=(redirect.strip() or "/notes"), status_code=303)


@router.post("/notes/{note_id:int}/archive")
async def note_archive(
    note_id: int,
    session: AsyncSession = Depends(get_session),
    redirect: str = Form(default="/notes"),
):
    """Toggle a note's archived flag."""
    note = (await session.execute(select(Note).where(Note.id == note_id))).scalars().first()
    if note:
        note.archived = not note.archived
        await session.commit()
    return RedirectResponse(url=(redirect.strip() or "/notes"), status_code=303)


@router.post("/notes/{note_id:int}/delete")
async def note_delete(
    request: Request,
    note_id: int,
    session: AsyncSession = Depends(get_session),
    redirect: str = Form(default="/notes"),
):
    """Delete a note and its host links."""
    note = (await session.execute(select(Note).where(Note.id == note_id))).scalars().first()
    if note:
        await session.execute(sa_delete(NoteHostLink).where(NoteHostLink.note_id == note_id))
        await session.delete(note)
        await session.commit()
    return RedirectResponse(url=(redirect.strip() or "/notes"), status_code=303)


# -------------------------------------------------------------------
# Export
# -------------------------------------------------------------------

@router.get("/notes/{note_id:int}/export.md")
async def note_export_single(
    note_id: int,
    session: AsyncSession = Depends(get_session),
):
    """Download a single note as a markdown file with YAML frontmatter."""
    note = (await session.execute(select(Note).where(Note.id == note_id))).scalars().first()
    if not note:
        return JSONResponse({"error": "note not found"}, status_code=404)
    addrs = [addr for _, addr in (await _hosts_for_notes(session, [note.id])).get(note.id, [])]
    body = f"{_yaml_frontmatter(note, addrs)}\n\n{note.content or ''}\n"
    fname = f"{_slugify(note.title)}-{note.id}.md"
    return Response(
        content=body,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@router.get("/notes/export.zip")
async def notes_export(session: AsyncSession = Depends(get_session)):
    """Export all notes as a markdown vault zip (Obsidian/Joplin/Notion-ready)."""
    notes = (await session.execute(
        select(Note).order_by(Note.created_at.asc())
    )).scalars().all()

    host_links = await _hosts_for_notes(session, [n.id for n in notes])

    # Gather every attachment referenced across all notes so we can bundle the
    # image files and rewrite links to vault-relative paths (self-contained zip).
    referenced = set()
    for note in notes:
        referenced.update(_iter_attachment_tokens(note.content))
    attachments = {}
    if referenced:
        rows = (await session.execute(
            select(NoteAttachment).where(NoteAttachment.token.in_(referenced))
        )).scalars().all()
        attachments = {a.token: a for a in rows}
    ext_by_token = {tok: a.ext for tok, a in attachments.items()}

    buf = io.BytesIO()
    used_names = set()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for note in notes:
            addrs = [addr for _, addr in host_links.get(note.id, [])]
            # Group under Hosts/<first-host>/ when linked; globals at root.
            folder = f"Hosts/{_slugify(addrs[0])}/" if addrs else ""
            name = f"{folder}{_slugify(note.title)}-{note.id}.md"
            n = 1
            while name in used_names:
                name = f"{folder}{_slugify(note.title)}-{note.id}-{n}.md"
                n += 1
            used_names.add(name)
            # "../" per folder level so the link resolves to the root attachments/ dir.
            rel_prefix = "../" * name.count("/")
            content_out = _rewrite_attachment_links(note.content or "", rel_prefix, ext_by_token)
            zf.writestr(name, f"{_yaml_frontmatter(note, addrs)}\n\n{content_out}\n")

        # Bundle each referenced image once at the vault root under attachments/.
        for tok, a in attachments.items():
            data = a.data
            if not data:  # bytes missing in DB: fall back to the on-disk copy
                disk = _UPLOAD_DIR / f"{a.token}.{a.ext}"
                data = disk.read_bytes() if disk.is_file() else None
            if data:
                zf.writestr(f"attachments/{tok}.{a.ext}", data)

        if not notes:
            zf.writestr("README.md", "# Cygor notes\n\nNo notes to export yet.\n")

    buf.seek(0)
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="cygor-notes-vault.zip"'},
    )
