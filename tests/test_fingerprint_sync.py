"""
Tests for cygor.fingerprinting.sync — processor methods of JSONSyncEngine.

Each test creates a temporary cache directory, instantiates the sync engine,
points its cache to the temp dir, feeds sample data into a processor, and
asserts the return count plus the existence of the cache file.
"""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from cygor.fingerprinting.sync import JSONSyncEngine
from cygor.fingerprinting.cache import FingerprintCache


@pytest.fixture
def sync_engine(tmp_path):
    """Create a JSONSyncEngine whose cache points at a temporary directory."""
    engine = JSONSyncEngine()
    engine.cache = FingerprintCache(cache_dir=tmp_path)
    return engine


# =========================================================================
# _process_satori_json
# =========================================================================

class TestProcessSatoriJson:
    """Tests for _process_satori_json with each satori source type."""

    SATORI_SOURCES = [
        "satori_ssh",
        "satori_smb",
        "satori_http",
        "satori_useragent",
        "satori_dhcp",
        "satori_sip",
    ]

    @pytest.fixture(params=SATORI_SOURCES)
    def satori_source(self, request):
        return request.param

    def _sample_array(self):
        """Return a small JSON array suitable for any satori source."""
        return [
            {"name": "OpenSSH", "pattern": "openssh", "os": "Linux"},
            {"name": "Dropbear", "pattern": "dropbear", "os": "Linux"},
            {"name": "WinSSHD", "pattern": "winsshd", "os": "Windows"},
        ]

    def test_process_satori_json_returns_count(self, sync_engine, satori_source):
        """Processor should return the number of entries in the array."""
        sample = self._sample_array()
        content = json.dumps(sample)
        count = sync_engine._process_satori_json(satori_source, content)
        assert count == len(sample)

    def test_process_satori_json_creates_file(self, sync_engine, satori_source, tmp_path):
        """Processor should write a JSON file in the cache directory."""
        sample = self._sample_array()
        content = json.dumps(sample)
        sync_engine._process_satori_json(satori_source, content)

        expected_file = tmp_path / sync_engine.cache.CACHE_FILES[satori_source]
        assert expected_file.exists(), f"Cache file {expected_file} was not created"

        written_data = json.loads(expected_file.read_text())
        assert isinstance(written_data, list)
        assert len(written_data) == len(sample)

    def test_process_satori_json_handles_dict_input(self, sync_engine):
        """When given a dict instead of a list, values should be extracted."""
        data = {"a": {"pattern": "openssh"}, "b": {"pattern": "dropbear"}}
        content = json.dumps(data)
        count = sync_engine._process_satori_json("satori_ssh", content)
        assert count == 2

    def test_process_satori_json_empty_array(self, sync_engine):
        """Empty array should return 0 and still write a file."""
        content = json.dumps([])
        count = sync_engine._process_satori_json("satori_ssh", content)
        assert count == 0

    def test_process_satori_json_invalid_json(self, sync_engine):
        """Invalid JSON should return 0 without raising."""
        count = sync_engine._process_satori_json("satori_ssh", "NOT VALID JSON{{{")
        assert count == 0

    def test_process_satori_json_clears_memory_cache(self, sync_engine):
        """After processing, the in-memory cache attribute should be None."""
        sample = self._sample_array()
        content = json.dumps(sample)
        # Prime the memory cache
        sync_engine.cache._satori_ssh_cache = [{"old": True}]
        sync_engine._process_satori_json("satori_ssh", content)
        assert sync_engine.cache._satori_ssh_cache is None


# =========================================================================
# _process_huginn_combinations
# =========================================================================

class TestProcessHuginnCombinations:
    """Tests for _process_huginn_combinations."""

    def test_dict_input(self, sync_engine, tmp_path):
        """Dict content should be saved directly and count should match."""
        data = {
            "combo_1": {"dhcp_fingerprint": "1,15,3,6", "dhcp_vendor": "MSFT 5.0", "device": "Windows"},
            "combo_2": {"dhcp_fingerprint": "1,3,6,15,28", "dhcp_vendor": "dhcpcd", "device": "Linux"},
        }
        content = json.dumps(data)
        count = sync_engine._process_huginn_combinations(content)
        assert count == 2

        filepath = tmp_path / sync_engine.cache.CACHE_FILES["huginn_combinations"]
        assert filepath.exists()
        written = json.loads(filepath.read_text())
        assert "combo_1" in written

    def test_array_input(self, sync_engine, tmp_path):
        """Array content should be converted to dict keyed by index."""
        data = [
            {"dhcp_fingerprint": "1,15,3,6", "device": "Windows"},
            {"dhcp_fingerprint": "1,3,6,15,28", "device": "Linux"},
            {"dhcp_fingerprint": "1,3,6,12,15", "device": "macOS"},
        ]
        content = json.dumps(data)
        count = sync_engine._process_huginn_combinations(content)
        assert count == 3

        filepath = tmp_path / sync_engine.cache.CACHE_FILES["huginn_combinations"]
        written = json.loads(filepath.read_text())
        assert "0" in written
        assert "1" in written
        assert "2" in written

    def test_empty_dict(self, sync_engine):
        """Empty dict should return 0."""
        count = sync_engine._process_huginn_combinations(json.dumps({}))
        assert count == 0

    def test_invalid_json(self, sync_engine):
        """Invalid JSON should return 0."""
        count = sync_engine._process_huginn_combinations("BROKEN{{")
        assert count == 0

    def test_clears_memory_cache(self, sync_engine):
        """After processing, in-memory combination cache should be cleared."""
        sync_engine.cache._huginn_combinations_cache = {"old": True}
        sync_engine._process_huginn_combinations(json.dumps({"a": {"device": "test"}}))
        assert sync_engine.cache._huginn_combinations_cache is None


# =========================================================================
# _process_oui
# =========================================================================

class TestProcessOui:
    """Tests for _process_oui with both CSV and IEEE text formats."""

    def _csv_content(self):
        """Small OUI-Master CSV sample."""
        return (
            "oui,manufacturer,registry,short_name,device_type,registered_date,address,sources\n"
            "00:00:0C,Cisco Systems Inc,MA-L,Cisco,Networking,,San Jose CA,ieee+wireshark\n"
            "28:6F:B9,Nokia Corporation,MA-L,Nokia,Phone,,Espoo Finland,ieee\n"
            "DC:A6:32,Raspberry Pi Trading Ltd,MA-L,RPi,IoT,,Cambridge UK,ieee+nmap\n"
        )

    def _ieee_txt_content(self):
        """Small IEEE OUI text sample."""
        return (
            "\n"
            "OUI/MA-L\n"
            "00-00-0C   (hex)   Cisco Systems, Inc\n"
            "28-6F-B9   (hex)   Nokia Corporation\n"
            "DC-A6-32   (hex)   Raspberry Pi Trading Ltd\n"
        )

    def test_csv_format_count(self, sync_engine):
        """OUI-Master CSV format should parse all entries."""
        count = sync_engine._process_oui(self._csv_content())
        assert count == 3

    def test_csv_format_creates_file(self, sync_engine, tmp_path):
        """OUI cache file should be created after processing CSV."""
        sync_engine._process_oui(self._csv_content())
        assert (tmp_path / "oui.json").exists()

    def test_csv_format_entries_content(self, sync_engine, tmp_path):
        """Parsed CSV entries should have vendor and device_type fields."""
        sync_engine._process_oui(self._csv_content())
        data = json.loads((tmp_path / "oui.json").read_text())
        entries = data["entries"]
        assert "00:00:0C" in entries
        assert entries["00:00:0C"]["vendor"] == "Cisco Systems Inc"
        assert entries["00:00:0C"]["device_type"] == "Networking"

    def test_ieee_txt_format_count(self, sync_engine):
        """IEEE OUI text format should parse all entries."""
        count = sync_engine._process_oui(self._ieee_txt_content())
        assert count == 3

    def test_ieee_txt_format_creates_file(self, sync_engine, tmp_path):
        """OUI cache file should be created after processing IEEE text."""
        sync_engine._process_oui(self._ieee_txt_content())
        assert (tmp_path / "oui.json").exists()

    def test_ieee_txt_entries_content(self, sync_engine, tmp_path):
        """Parsed IEEE entries should have vendor field."""
        sync_engine._process_oui(self._ieee_txt_content())
        data = json.loads((tmp_path / "oui.json").read_text())
        entries = data["entries"]
        assert "00:00:0C" in entries
        assert entries["00:00:0C"]["vendor"] == "Cisco Systems, Inc"


# =========================================================================
# _process_p0f
# =========================================================================

class TestProcessP0f:
    """Tests for _process_p0f with sample p0f fingerprint data."""

    def _sample_p0f_content(self):
        """Small p0f fingerprint file sample."""
        return (
            "; p0f - passive OS fingerprinting\n"
            "\n"
            "[syn]\n"
            "\n"
            "label = s:Linux:3.x\n"
            "sig   = *:64:0:*:mss*20,7:mss,sok,ts,nop,ws:df,id+:0\n"
            "sig   = *:64:0:*:mss*10,5:mss,sok,ts,nop,ws:df:0\n"
            "\n"
            "label = s:Windows:7 or 8\n"
            "sig   = *:128:0:*:8192,8:mss,nop,ws,nop,nop,sok:df,id+:0\n"
            "\n"
            "[syn+ack]\n"
            "\n"
            "label = s:Linux:3.x\n"
            "sig   = *:64:0:*:mss*20,7:mss,sok,ts,nop,ws:df:0\n"
        )

    def test_count(self, sync_engine):
        """Should parse all signature lines."""
        count = sync_engine._process_p0f(self._sample_p0f_content())
        assert count == 4

    def test_creates_tcpip_file(self, sync_engine, tmp_path):
        """Should write tcpip.json to cache."""
        sync_engine._process_p0f(self._sample_p0f_content())
        assert (tmp_path / "tcpip.json").exists()

    def test_entries_have_expected_fields(self, sync_engine, tmp_path):
        """Each entry should have signature, class, label, and os_family."""
        sync_engine._process_p0f(self._sample_p0f_content())
        data = json.loads((tmp_path / "tcpip.json").read_text())
        entries = data["entries"]
        assert len(entries) == 4

        linux_entry = entries[0]
        assert linux_entry["class"] == "syn"
        assert linux_entry["os_family"] == "s"
        assert "Linux" in linux_entry["label"]
        assert linux_entry["signature"] is not None

    def test_class_assignment(self, sync_engine, tmp_path):
        """Entries should be assigned the correct class from section headers."""
        sync_engine._process_p0f(self._sample_p0f_content())
        data = json.loads((tmp_path / "tcpip.json").read_text())
        entries = data["entries"]

        # First two sigs are [syn], third is [syn], fourth is [syn+ack]
        assert entries[0]["class"] == "syn"
        assert entries[1]["class"] == "syn"
        assert entries[2]["class"] == "syn"
        assert entries[3]["class"] == "syn+ack"

    def test_empty_content(self, sync_engine):
        """Empty content should produce 0 entries."""
        count = sync_engine._process_p0f("")
        assert count == 0

    def test_comments_only(self, sync_engine):
        """Content with only comments should produce 0 entries."""
        count = sync_engine._process_p0f("; just a comment\n; another comment\n")
        assert count == 0


# =========================================================================
# _process_huginn_devices
# =========================================================================

class TestProcessHuginnDevices:
    """Tests for _process_huginn_devices with sample device JSON."""

    def _sample_devices(self):
        """Small JSON array of Huginn-Muninn device objects."""
        return [
            {"id": 1, "name": "Desktop", "parent_id": None, "mobile": 0, "tablet": 0},
            {"id": 2, "name": "Windows Desktop", "parent_id": 1, "mobile": 0, "tablet": 0},
            {"id": 3, "name": "Windows 10", "parent_id": 2, "mobile": 0, "tablet": 0,
             "simplified_name": "Win10"},
            {"id": 10, "name": "Smartphone", "parent_id": None, "mobile": 1, "tablet": 0},
            {"id": 11, "name": "iPhone", "parent_id": 10, "mobile": 1, "tablet": 0},
        ]

    def test_count(self, sync_engine):
        """Should return correct number of device entries."""
        content = json.dumps(self._sample_devices())
        count = sync_engine._process_huginn_devices(content)
        assert count == 5

    def test_creates_cache_file(self, sync_engine, tmp_path):
        """Should write huginn_devices.json to cache."""
        content = json.dumps(self._sample_devices())
        sync_engine._process_huginn_devices(content)
        assert (tmp_path / "huginn_devices.json").exists()

    def test_hierarchy_building(self, sync_engine, tmp_path):
        """Devices should have hierarchy paths built from parent chain."""
        content = json.dumps(self._sample_devices())
        sync_engine._process_huginn_devices(content)
        data = json.loads((tmp_path / "huginn_devices.json").read_text())
        entries = data["entries"]

        # "Windows 10" (id=3) should have hierarchy: Desktop > Windows Desktop > Windows 10
        win10 = entries["3"]
        assert win10["hierarchy"] == ["Desktop", "Windows Desktop", "Windows 10"]
        assert win10["hierarchy_str"] == "Desktop > Windows Desktop > Windows 10"

    def test_mobile_tablet_flags(self, sync_engine, tmp_path):
        """Mobile and tablet flags should be boolean."""
        content = json.dumps(self._sample_devices())
        sync_engine._process_huginn_devices(content)
        data = json.loads((tmp_path / "huginn_devices.json").read_text())
        entries = data["entries"]

        assert entries["1"]["mobile"] is False
        assert entries["10"]["mobile"] is True
        assert entries["11"]["mobile"] is True
        assert entries["1"]["tablet"] is False

    def test_simplified_name(self, sync_engine, tmp_path):
        """simplified_name should be stored when present."""
        content = json.dumps(self._sample_devices())
        sync_engine._process_huginn_devices(content)
        data = json.loads((tmp_path / "huginn_devices.json").read_text())
        entries = data["entries"]

        assert entries["3"].get("simplified_name") == "Win10"
        assert "simplified_name" not in entries["1"]

    def test_root_device_hierarchy(self, sync_engine, tmp_path):
        """Root devices (no parent) should have single-element hierarchy."""
        content = json.dumps(self._sample_devices())
        sync_engine._process_huginn_devices(content)
        data = json.loads((tmp_path / "huginn_devices.json").read_text())
        entries = data["entries"]

        assert entries["1"]["hierarchy"] == ["Desktop"]
        assert entries["1"]["parent_id"] is None

    def test_empty_array(self, sync_engine):
        """Empty array should return 0."""
        count = sync_engine._process_huginn_devices(json.dumps([]))
        assert count == 0

    def test_invalid_json(self, sync_engine):
        """Invalid JSON should return 0."""
        count = sync_engine._process_huginn_devices("NOT JSON")
        assert count == 0
