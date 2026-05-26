"""Tests for SQLModel models in cygor/webapp/models.py.

These tests verify model instantiation and field defaults only --
no running database is required.
"""

import pytest
from datetime import datetime


class TestHostModel:
    """Test Host model instantiation and defaults."""

    def test_instantiation_with_required_fields(self):
        from cygor.webapp.models import Host

        host = Host(id=1, address="192.168.1.1")
        assert host.id == 1
        assert host.address == "192.168.1.1"

    def test_hostname_defaults_to_none(self):
        from cygor.webapp.models import Host

        host = Host(id=1, address="10.0.0.1")
        assert host.hostname is None

    def test_scan_count_defaults_to_zero(self):
        from cygor.webapp.models import Host

        host = Host(id=1, address="10.0.0.1")
        assert host.scan_count == 0

    def test_first_seen_defaults_to_none(self):
        from cygor.webapp.models import Host

        host = Host(id=1, address="10.0.0.1")
        assert host.first_seen is None

    def test_last_seen_defaults_to_none(self):
        from cygor.webapp.models import Host

        host = Host(id=1, address="10.0.0.1")
        assert host.last_seen is None


class TestPortModel:
    """Test Port model instantiation and foreign key fields."""

    def test_instantiation(self):
        from cygor.webapp.models import Port

        port = Port(id=1, host_id=10, port=80)
        assert port.id == 1
        assert port.host_id == 10
        assert port.port == 80

    def test_foreign_key_host_id(self):
        from cygor.webapp.models import Port

        port = Port(id=1, host_id=42, port=443)
        assert port.host_id == 42

    def test_optional_fields_default_none(self):
        from cygor.webapp.models import Port

        port = Port(id=1, host_id=1, port=22)
        assert port.protocol is None
        assert port.service is None
        assert port.banner is None
        assert port.product is None
        assert port.version is None
        assert port.extrainfo is None
        assert port.cpe is None
        assert port.state is None
        assert port.reason is None
        assert port.confidence is None


class TestOSGuessModel:
    """Test OSGuess model instantiation."""

    def test_instantiation(self):
        from cygor.webapp.models import OSGuess

        og = OSGuess(id=1, host_id=5, name="Linux 5.x")
        assert og.id == 1
        assert og.host_id == 5
        assert og.name == "Linux 5.x"

    def test_accuracy_defaults_to_zero(self):
        from cygor.webapp.models import OSGuess

        og = OSGuess(id=1, host_id=1, name="Windows 10")
        assert og.accuracy == 0

    def test_optional_fields_default_none(self):
        from cygor.webapp.models import OSGuess

        og = OSGuess(id=1, host_id=1, name="Ubuntu")
        assert og.type is None
        assert og.vendor is None
        assert og.family is None
        assert og.generation is None
        assert og.cpe is None


