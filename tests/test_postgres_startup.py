"""PostgreSQL startup regressions that do not require a server."""

import subprocess

from cygor.webapp.db_adapters import PostgreSQLAdapter


def _result(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def test_setup_uses_template0_when_template1_collation_is_stale(monkeypatch):
    adapter = PostgreSQLAdapter(port=5432)

    def run_psql(args, use_postgres_user=True):
        if "pg_roles" in args[-1]:
            return _result(stdout="1\n")
        if args[-1].startswith("ALTER ROLE"):
            return _result()
        if "pg_database" in args[-1]:
            return _result()
        raise AssertionError(f"Unexpected SQL: {args}")

    commands = []

    def run_createdb(cmd, **kwargs):
        commands.append(cmd)
        if "template0" in cmd:
            return _result()
        return _result(1, stderr='ERROR: template database "template1" has a collation version mismatch')

    monkeypatch.setattr(adapter, "_run_psql", run_psql)
    monkeypatch.setattr("cygor.webapp.db_adapters.os.geteuid", lambda: 1000)
    monkeypatch.setattr("cygor.webapp.db_adapters.shutil.which", lambda name: "/usr/bin/sudo")
    monkeypatch.setattr("cygor.webapp.db_adapters.subprocess.run", run_createdb)

    assert adapter.setup()
    assert len(commands) == 2
    assert commands[0][:5] == ["sudo", "-n", "-u", "postgres", "createdb"]
    assert commands[1][-3:] == ["-T", "template0", "cygor"]


def test_setup_stops_when_role_check_cannot_connect(monkeypatch):
    adapter = PostgreSQLAdapter(port=5432)
    calls = []

    def run_psql(args, use_postgres_user=True):
        calls.append((args, use_postgres_user))
        return _result(2, stderr="connection refused")

    monkeypatch.setattr(adapter, "_run_psql", run_psql)
    assert not adapter.setup()
    assert len(calls) == 2
    assert all("pg_roles" in args[-1] for args, _ in calls)


def test_admin_psql_uses_maintenance_database(monkeypatch):
    adapter = PostgreSQLAdapter(port=5432)
    commands = []

    def run(cmd, **kwargs):
        commands.append(cmd)
        return _result()

    monkeypatch.setattr("cygor.webapp.db_adapters.os.geteuid", lambda: 1000)
    monkeypatch.setattr("cygor.webapp.db_adapters.shutil.which", lambda name: "/usr/bin/sudo")
    monkeypatch.setattr("cygor.webapp.db_adapters.subprocess.run", run)

    adapter._run_psql(["-tAc", "SELECT 1"], use_postgres_user=False)
    assert commands[0][:7] == ["psql", "-X", "-w", "-v", "ON_ERROR_STOP=1", "-d", "postgres"]
