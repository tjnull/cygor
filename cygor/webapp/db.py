from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel, select
from typing import Optional
from .config import settings
from .models import Host, Port, Script, OSGuess

engine = create_async_engine(settings.DATABASE_URL, echo=settings.DEBUG, future=True)
SessionLocal = sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

async def get_session():
    async with SessionLocal() as session:
        yield session

async def reset_db():
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)
        await conn.run_sync(SQLModel.metadata.create_all)

async def get_or_create_host(session: AsyncSession, address: str, hostname: str | None = None) -> Host:
    res = await session.execute(select(Host).where(Host.address == address))
    host = res.scalar_one_or_none()
    if host:
        if hostname and (host.hostname or "") != hostname:
            host.hostname = hostname
            await session.flush()
        return host
    host = Host(address=address, hostname=hostname)
    session.add(host)
    await session.flush()
    return host

async def get_or_create_port(session: AsyncSession, host: Host, port: int, service: str | None = None,
                             protocol: str | None = None, banner: str | None = None) -> Port:
    res = await session.execute(select(Port).where(Port.host_id == host.id, Port.port == port))
    p = res.scalar_one_or_none()
    if p:
        changed = False
        if service and p.service != service:
            p.service = service; changed = True
        if protocol and p.protocol != protocol:
            p.protocol = protocol; changed = True
        if banner and p.banner != banner:
            p.banner = banner; changed = True
        if changed:
            await session.flush()
        return p
    p = Port(host_id=host.id, port=port, service=service, protocol=protocol, banner=banner)
    session.add(p)
    await session.flush()
    return p

async def get_or_create_script(
    session: AsyncSession,
    host: Host,
    port: Port | None,
    name: str,
    output: str,
    url: str | None = None,
    status_code: int | None = None,
    screenshot_file: str | None = None,
    screenshot_failed: bool | None = None,
) -> Script:
    q = select(Script).where(
        Script.host_id == host.id,
        Script.name == name,
        Script.output == output
    )
    if port:
        q = q.where(Script.port_id == port.id)
    else:
        q = q.where(Script.port_id.is_(None))

    res = await session.execute(q)
    s = res.scalar_one_or_none()

    if s:
        changed = False
        if url and s.url != url:
            s.url = url; changed = True
        if status_code and s.status_code != status_code:
            s.status_code = status_code; changed = True
        if screenshot_file and s.screenshot_file != screenshot_file:
            s.screenshot_file = screenshot_file; changed = True
        if screenshot_failed is not None and s.screenshot_failed != screenshot_failed:
            s.screenshot_failed = screenshot_failed; changed = True
        if changed:
            await session.flush()
        return s

    s = Script(
        host_id=host.id,
        port_id=(port.id if port else None),
        name=name,
        output=output,
        url=url,
        status_code=status_code,
        screenshot_file=screenshot_file,
        screenshot_failed=screenshot_failed
    )
    session.add(s)
    await session.flush()
    return s



async def get_or_create_osguess(session: AsyncSession, host: Host,
                                name: str, accuracy: int = 0,
                                type: Optional[str] = None,
                                vendor: Optional[str] = None,
                                family: Optional[str] = None,
                                generation: Optional[str] = None,
                                cpe: Optional[str] = None) -> OSGuess:
    """
    De-duplicates by (host_id, name, accuracy, cpe).
    """
    q = select(OSGuess).where(
        OSGuess.host_id == host.id,
        OSGuess.name == name,
        OSGuess.accuracy == accuracy,
        OSGuess.cpe == cpe
    )
    res = await session.execute(q)
    existing = res.scalar_one_or_none()
    if existing:
        return existing

    rec = OSGuess(
        host_id=host.id,
        name=name,
        accuracy=accuracy or 0,
        type=type,
        vendor=vendor,
        family=family,
        generation=generation,
        cpe=cpe
    )
    session.add(rec)
    await session.flush()
    return rec
