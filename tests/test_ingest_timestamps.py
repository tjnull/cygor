"""Scan ingestion supplies timezone-aware timestamps to SQLModel."""

import asyncio

from cygor.webapp.db import IngestionCache, cached_get_or_create_host, get_or_create_host
from cygor.webapp.models import Host


class _Result:
    def scalar_one_or_none(self):
        return None


class _Session:
    def __init__(self):
        self.added = []

    async def execute(self, statement):
        return _Result()

    def add(self, item):
        self.added.append(item)

    async def flush(self):
        pass


def test_host_ingestion_timestamps_are_utc_aware():
    async def check():
        session = _Session()
        regular = await get_or_create_host(session, "192.0.2.1")
        cached = await cached_get_or_create_host(session, IngestionCache(), "192.0.2.2")
        for host in (regular, cached):
            assert host.first_seen.utcoffset().total_seconds() == 0
            assert host.last_seen.utcoffset().total_seconds() == 0
            # This is the SQLModel bind step that rejected the values in the
            # reported SQLite ingestion failure.
            assert Host.__table__.c.first_seen.type.process_bind_param(host.first_seen, None)
            assert Host.__table__.c.last_seen.type.process_bind_param(host.last_seen, None)
        assert len(session.added) == 2

    asyncio.run(check())
