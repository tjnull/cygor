"""
Tests for the /api/enrich pre-flight validation.

The endpoint must refuse to start a task when no API keys are configured
for the requested sources, returning 400 with an actionable message that
names what's missing.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


def _stub_request():
    """Minimal request object with state.current_user set so user-tracking
    branches don't blow up."""
    req = MagicMock()
    req.state = MagicMock()
    req.state.current_user = None
    return req


@pytest.mark.asyncio
async def test_no_keys_configured_returns_400(monkeypatch, tmp_path):
    """
    With an empty config and a typical 'all' request, the endpoint should
    raise HTTP 400 telling the user how to configure keys — and must NOT
    create a task.
    """
    from fastapi import HTTPException
    from cygor.webapp.routes.tasks import create_enrich_task

    # Force EnrichmentConfig to load from an empty file so no env keys leak in.
    empty_cfg = tmp_path / "empty.json"
    empty_cfg.write_text("{}")

    # Strip every env var that could populate the config out from under us.
    for var in (
        "SHODAN_API_KEY", "VIRUSTOTAL_API_KEY", "VT_API_KEY",
        "OTX_API_KEY", "ABUSEIPDB_API_KEY", "URLSCAN_API_KEY",
        "CENSYS_API_ID", "DEHASHED_API_KEY", "GREYNOISE_API_KEY",
        "SPUR_API_KEY", "BAZAAR_API_KEY", "PROSPEO_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)

    # Repoint the default config path inside EnrichmentConfig.__init__
    import cygor.enrich
    real_init = cygor.enrich.EnrichmentConfig.__init__

    def _fake_init(self, config_path=None):
        real_init(self, empty_cfg)
    monkeypatch.setattr(cygor.enrich.EnrichmentConfig, "__init__", _fake_init)

    # Sources that DON'T need keys (crt_sh, wayback, commoncrawl) would
    # always be usable. We pass an explicit list of key-required sources
    # here to force the "no usable sources" branch.
    req = {"iocs": ["1.2.3.4"], "sources": ["shodan", "virustotal"]}
    with pytest.raises(HTTPException) as ei:
        await create_enrich_task(req, _stub_request())
    assert ei.value.status_code == 400
    assert "no usable enrichment sources" in str(ei.value.detail).lower()
    # The error names the expected fix
    assert "config-manager set" in str(ei.value.detail)


@pytest.mark.asyncio
async def test_unconfigured_sources_dropped_when_at_least_one_works(monkeypatch, tmp_path):
    """
    When the user requests a mix of configured + unconfigured sources, the
    endpoint should drop the unconfigured ones and proceed with the rest.

    We patch the task-manager so no subprocess actually launches.
    """
    from cygor.webapp.routes.tasks import create_enrich_task

    cfg_file = tmp_path / "partial.json"
    cfg_file.write_text('{"shodan": "fake-key"}')

    for var in (
        "SHODAN_API_KEY", "VIRUSTOTAL_API_KEY", "VT_API_KEY",
        "OTX_API_KEY", "ABUSEIPDB_API_KEY", "URLSCAN_API_KEY",
        "CENSYS_API_ID", "DEHASHED_API_KEY", "GREYNOISE_API_KEY",
        "SPUR_API_KEY", "BAZAAR_API_KEY", "PROSPEO_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)

    import cygor.enrich
    real_init = cygor.enrich.EnrichmentConfig.__init__

    def _fake_init(self, config_path=None):
        real_init(self, cfg_file)
    monkeypatch.setattr(cygor.enrich.EnrichmentConfig, "__init__", _fake_init)

    # Patch the task manager so no real task runs
    captured = {}
    async def _fake_create_generic_task(**kwargs):
        captured["cmd"] = kwargs.get("command")
        return "fake-task-id"

    monkeypatch.setattr(
        "cygor.webapp.routes.tasks.task_manager.create_generic_task",
        _fake_create_generic_task,
    )

    req = {
        "iocs": ["1.2.3.4"],
        "sources": ["shodan", "virustotal"],   # only shodan is configured
    }
    resp = await create_enrich_task(req, _stub_request())
    body = resp.body.decode() if hasattr(resp, "body") else ""
    # The task should have been created and the cmd should only mention
    # shodan as a source — virustotal got dropped silently.
    assert "fake-task-id" in body
    cmd = captured["cmd"]
    assert "--sources" in cmd
    # The next arg(s) after --sources should include shodan, NOT virustotal
    sources_idx = cmd.index("--sources")
    sources_in_cmd = []
    for a in cmd[sources_idx + 1:]:
        if a.startswith("--"):
            break
        sources_in_cmd.append(a)
    assert "shodan" in sources_in_cmd
    assert "virustotal" not in sources_in_cmd


@pytest.mark.asyncio
async def test_keyless_source_alone_is_accepted(monkeypatch, tmp_path):
    """
    crt_sh has no API key requirement. Even with a totally empty config,
    requesting only crt_sh should be accepted.
    """
    from cygor.webapp.routes.tasks import create_enrich_task

    empty_cfg = tmp_path / "empty.json"
    empty_cfg.write_text("{}")
    for var in (
        "SHODAN_API_KEY", "VIRUSTOTAL_API_KEY", "VT_API_KEY",
        "OTX_API_KEY", "ABUSEIPDB_API_KEY", "URLSCAN_API_KEY",
        "CENSYS_API_ID", "DEHASHED_API_KEY", "GREYNOISE_API_KEY",
        "SPUR_API_KEY", "BAZAAR_API_KEY", "PROSPEO_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)

    import cygor.enrich
    real_init = cygor.enrich.EnrichmentConfig.__init__

    def _fake_init(self, config_path=None):
        real_init(self, empty_cfg)
    monkeypatch.setattr(cygor.enrich.EnrichmentConfig, "__init__", _fake_init)

    async def _fake_create_generic_task(**kwargs):
        return "task-123"
    monkeypatch.setattr(
        "cygor.webapp.routes.tasks.task_manager.create_generic_task",
        _fake_create_generic_task,
    )

    req = {"iocs": ["example.com"], "sources": ["crt_sh"]}
    resp = await create_enrich_task(req, _stub_request())
    body = resp.body.decode() if hasattr(resp, "body") else ""
    assert "task-123" in body
