"""
Tests for cygor.fingerprinting.cache — FingerprintCache load/lookup/clear methods.

All tests use tmp_path fixtures so no real cache directory is touched.
"""

import json
from pathlib import Path

import pytest

from cygor.fingerprinting.cache import FingerprintCache


@pytest.fixture
def cache(tmp_path):
    """Create a FingerprintCache pointing at a temporary directory."""
    return FingerprintCache(cache_dir=tmp_path)


# =========================================================================
# Initialization
# =========================================================================

class TestCacheInit:
    """Verify FingerprintCache initialization behaviour."""

    def test_creates_cache_directory(self, tmp_path):
        """Cache dir should be created if it does not exist."""
        new_dir = tmp_path / "sub" / "fingerprints"
        assert not new_dir.exists()
        cache = FingerprintCache(cache_dir=new_dir)
        assert new_dir.exists()
        assert new_dir.is_dir()

    def test_cache_dir_attribute(self, cache, tmp_path):
        """cache_dir attribute should match the provided directory."""
        assert cache.cache_dir == tmp_path

    def test_memory_caches_start_none(self, cache):
        """All in-memory caches should be None before any loading."""
        assert cache._satori_ssh_cache is None
        assert cache._satori_smb_cache is None
        assert cache._satori_http_cache is None
        assert cache._huginn_combinations_cache is None


# =========================================================================
# Satori SSH
# =========================================================================

class TestSatoriSsh:
    """Tests for load_satori_ssh / lookup_satori_ssh."""

    def test_load_returns_empty_when_no_file(self, cache):
        """With no file on disk, load should return an empty list."""
        result = cache.load_satori_ssh()
        assert result == []

    def test_load_returns_data_when_file_exists(self, cache, tmp_path):
        """When the JSON file exists, load should return its contents."""
        entries = [
            {"name": "OpenSSH", "pattern": "openssh", "os": "Linux"},
            {"name": "Dropbear", "pattern": "dropbear", "os": "Linux"},
        ]
        filepath = tmp_path / cache.CACHE_FILES["satori_ssh"]
        filepath.write_text(json.dumps(entries))

        result = cache.load_satori_ssh()
        assert len(result) == 2
        assert result[0]["name"] == "OpenSSH"

    def test_load_caches_in_memory(self, cache, tmp_path):
        """Second call should return cached data without re-reading file."""
        entries = [{"name": "OpenSSH", "pattern": "openssh"}]
        filepath = tmp_path / cache.CACHE_FILES["satori_ssh"]
        filepath.write_text(json.dumps(entries))

        first = cache.load_satori_ssh()
        # Modify file on disk -- should NOT affect cached result
        filepath.write_text(json.dumps([]))
        second = cache.load_satori_ssh()
        assert second is first  # same object reference

    def test_lookup_finds_match_by_banner_pattern(self, cache, tmp_path):
        """lookup_satori_ssh should find a match when banner contains the pattern."""
        entries = [
            {"name": "OpenSSH", "pattern": "openssh", "os": "Linux"},
            {"name": "Dropbear", "pattern": "dropbear", "os": "Linux"},
        ]
        filepath = tmp_path / cache.CACHE_FILES["satori_ssh"]
        filepath.write_text(json.dumps(entries))

        result = cache.lookup_satori_ssh("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")
        assert result is not None
        assert result["name"] == "OpenSSH"

    def test_lookup_case_insensitive(self, cache, tmp_path):
        """Lookup should be case-insensitive."""
        entries = [{"name": "OpenSSH", "pattern": "openssh"}]
        filepath = tmp_path / cache.CACHE_FILES["satori_ssh"]
        filepath.write_text(json.dumps(entries))

        result = cache.lookup_satori_ssh("SSH-2.0-OPENSSH_9.0")
        assert result is not None

    def test_lookup_returns_none_for_no_match(self, cache, tmp_path):
        """lookup_satori_ssh should return None when nothing matches."""
        entries = [
            {"name": "OpenSSH", "pattern": "openssh"},
        ]
        filepath = tmp_path / cache.CACHE_FILES["satori_ssh"]
        filepath.write_text(json.dumps(entries))

        result = cache.lookup_satori_ssh("SSH-2.0-libssh-0.9.6")
        assert result is None

    def test_lookup_returns_none_for_empty_banner(self, cache):
        """Empty or None banner should return None."""
        assert cache.lookup_satori_ssh("") is None
        assert cache.lookup_satori_ssh(None) is None


# =========================================================================
# Satori SMB
# =========================================================================

class TestSatoriSmb:
    """Tests for load_satori_smb / lookup_satori_smb."""

    def test_load_returns_empty_when_no_file(self, cache):
        result = cache.load_satori_smb()
        assert result == []

    def test_load_returns_data_when_file_exists(self, cache, tmp_path):
        entries = [
            {"os": "Windows 10", "native_os": "Windows 10 Enterprise"},
            {"os": "Samba", "native_os": "Samba 4.15"},
        ]
        filepath = tmp_path / cache.CACHE_FILES["satori_smb"]
        filepath.write_text(json.dumps(entries))

        result = cache.load_satori_smb()
        assert len(result) == 2

    def test_lookup_finds_match(self, cache, tmp_path):
        entries = [
            {"os": "Windows 10", "native_os": "Windows 10 Enterprise"},
            {"os": "Samba", "native_os": "Samba 4.15"},
        ]
        filepath = tmp_path / cache.CACHE_FILES["satori_smb"]
        filepath.write_text(json.dumps(entries))

        result = cache.lookup_satori_smb("Windows 10 Enterprise 19041")
        assert result is not None
        assert result["os"] == "Windows 10"

    def test_lookup_returns_none_for_no_match(self, cache, tmp_path):
        entries = [{"os": "Windows 10", "native_os": "Windows 10 Enterprise"}]
        filepath = tmp_path / cache.CACHE_FILES["satori_smb"]
        filepath.write_text(json.dumps(entries))

        result = cache.lookup_satori_smb("FreeBSD 13.0")
        assert result is None

    def test_lookup_returns_none_for_empty(self, cache):
        assert cache.lookup_satori_smb("") is None
        assert cache.lookup_satori_smb(None) is None


# =========================================================================
# Satori HTTP
# =========================================================================

class TestSatoriHttp:
    """Tests for load_satori_http / lookup_satori_http."""

    def test_load_returns_empty_when_no_file(self, cache):
        result = cache.load_satori_http()
        assert result == []

    def test_load_returns_data_when_file_exists(self, cache, tmp_path):
        entries = [
            {"name": "Apache", "pattern": "apache"},
            {"name": "nginx", "pattern": "nginx"},
        ]
        filepath = tmp_path / cache.CACHE_FILES["satori_http"]
        filepath.write_text(json.dumps(entries))

        result = cache.load_satori_http()
        assert len(result) == 2

    def test_lookup_finds_match(self, cache, tmp_path):
        entries = [
            {"name": "Apache", "pattern": "apache"},
            {"name": "nginx", "pattern": "nginx"},
        ]
        filepath = tmp_path / cache.CACHE_FILES["satori_http"]
        filepath.write_text(json.dumps(entries))

        result = cache.lookup_satori_http("Apache/2.4.52 (Ubuntu)")
        assert result is not None
        assert result["name"] == "Apache"

    def test_lookup_returns_none_for_no_match(self, cache, tmp_path):
        entries = [{"name": "Apache", "pattern": "apache"}]
        filepath = tmp_path / cache.CACHE_FILES["satori_http"]
        filepath.write_text(json.dumps(entries))

        result = cache.lookup_satori_http("Microsoft-IIS/10.0")
        assert result is None

    def test_lookup_returns_none_for_empty(self, cache):
        assert cache.lookup_satori_http("") is None
        assert cache.lookup_satori_http(None) is None


# =========================================================================
# Huginn Combinations
# =========================================================================

class TestHuginnCombinations:
    """Tests for load_huginn_combinations / lookup_huginn_combination."""

    def test_load_returns_empty_dict_when_no_file(self, cache):
        result = cache.load_huginn_combinations()
        assert result == {}

    def test_load_returns_dict_from_file(self, cache, tmp_path):
        data = {
            "combo_1": {"dhcp_fingerprint": "1,15,3,6", "dhcp_vendor": "MSFT 5.0", "device": "Windows"},
            "combo_2": {"dhcp_fingerprint": "1,3,6,15,28", "dhcp_vendor": "dhcpcd", "device": "Linux"},
        }
        filepath = tmp_path / cache.CACHE_FILES["huginn_combinations"]
        filepath.write_text(json.dumps(data))

        result = cache.load_huginn_combinations()
        assert len(result) == 2
        assert "combo_1" in result

    def test_load_converts_list_to_dict(self, cache, tmp_path):
        """When the file contains a list, load should convert to index-keyed dict."""
        data = [
            {"dhcp_fingerprint": "1,15,3,6", "device": "Windows"},
            {"dhcp_fingerprint": "1,3,6,15,28", "device": "Linux"},
        ]
        filepath = tmp_path / cache.CACHE_FILES["huginn_combinations"]
        filepath.write_text(json.dumps(data))

        result = cache.load_huginn_combinations()
        assert isinstance(result, dict)
        assert "0" in result
        assert "1" in result

    def test_load_caches_in_memory(self, cache, tmp_path):
        data = {"a": {"dhcp_fingerprint": "1,15,3,6"}}
        filepath = tmp_path / cache.CACHE_FILES["huginn_combinations"]
        filepath.write_text(json.dumps(data))

        first = cache.load_huginn_combinations()
        second = cache.load_huginn_combinations()
        assert second is first

    def test_lookup_finds_match_by_fingerprint(self, cache, tmp_path):
        data = {
            "combo_1": {"dhcp_fingerprint": "1,15,3,6", "dhcp_vendor": "MSFT 5.0", "device": "Windows"},
            "combo_2": {"dhcp_fingerprint": "1,3,6,15,28", "dhcp_vendor": "dhcpcd", "device": "Linux"},
        }
        filepath = tmp_path / cache.CACHE_FILES["huginn_combinations"]
        filepath.write_text(json.dumps(data))

        result = cache.lookup_huginn_combination("1,15,3,6")
        assert result is not None
        assert result["device"] == "Windows"

    def test_lookup_matches_with_vendor(self, cache, tmp_path):
        data = {
            "combo_1": {"dhcp_fingerprint": "1,15,3,6", "dhcp_vendor": "MSFT 5.0", "device": "Windows 10"},
            "combo_2": {"dhcp_fingerprint": "1,15,3,6", "dhcp_vendor": "dhcpcd", "device": "Linux"},
        }
        filepath = tmp_path / cache.CACHE_FILES["huginn_combinations"]
        filepath.write_text(json.dumps(data))

        # With matching vendor, should get the first match (MSFT 5.0)
        result = cache.lookup_huginn_combination("1,15,3,6", "MSFT 5.0")
        assert result is not None
        assert result["device"] == "Windows 10"

    def test_lookup_returns_none_for_no_match(self, cache, tmp_path):
        data = {
            "combo_1": {"dhcp_fingerprint": "1,15,3,6", "dhcp_vendor": "MSFT 5.0"},
        }
        filepath = tmp_path / cache.CACHE_FILES["huginn_combinations"]
        filepath.write_text(json.dumps(data))

        result = cache.lookup_huginn_combination("99,99,99")
        assert result is None

    def test_lookup_on_empty_cache(self, cache):
        result = cache.lookup_huginn_combination("1,15,3,6")
        assert result is None


# =========================================================================
# clear_memory_cache
# =========================================================================

class TestClearMemoryCache:
    """Tests for clear_memory_cache."""

    def test_clears_all_caches(self, cache, tmp_path):
        """After populating several caches, clear_memory_cache should reset all to None."""
        # Write and load satori_ssh
        ssh_entries = [{"name": "OpenSSH", "pattern": "openssh"}]
        (tmp_path / cache.CACHE_FILES["satori_ssh"]).write_text(json.dumps(ssh_entries))
        cache.load_satori_ssh()
        assert cache._satori_ssh_cache is not None

        # Write and load satori_smb
        smb_entries = [{"os": "Windows 10"}]
        (tmp_path / cache.CACHE_FILES["satori_smb"]).write_text(json.dumps(smb_entries))
        cache.load_satori_smb()
        assert cache._satori_smb_cache is not None

        # Write and load satori_http
        http_entries = [{"name": "Apache", "pattern": "apache"}]
        (tmp_path / cache.CACHE_FILES["satori_http"]).write_text(json.dumps(http_entries))
        cache.load_satori_http()
        assert cache._satori_http_cache is not None

        # Write and load huginn_combinations
        combo_data = {"a": {"dhcp_fingerprint": "1,15,3,6"}}
        (tmp_path / cache.CACHE_FILES["huginn_combinations"]).write_text(json.dumps(combo_data))
        cache.load_huginn_combinations()
        assert cache._huginn_combinations_cache is not None

        # Now clear
        cache.clear_memory_cache()

        assert cache._satori_ssh_cache is None
        assert cache._satori_smb_cache is None
        assert cache._satori_http_cache is None
        assert cache._satori_useragent_cache is None
        assert cache._satori_dhcp_cache is None
        assert cache._satori_sip_cache is None
        assert cache._huginn_combinations_cache is None
        assert cache._oui_cache is None
        assert cache._tcpip_cache is None
        assert cache._banners_cache is None
        assert cache._huginn_devices_cache is None
        assert cache._huginn_dhcp_cache is None
        assert cache._huginn_dhcp_vendor_cache is None

    def test_clear_then_reload(self, cache, tmp_path):
        """After clearing, loading should re-read from disk."""
        entries = [{"name": "OpenSSH", "pattern": "openssh"}]
        filepath = tmp_path / cache.CACHE_FILES["satori_ssh"]
        filepath.write_text(json.dumps(entries))

        # Load to populate memory cache
        cache.load_satori_ssh()
        assert cache._satori_ssh_cache is not None

        # Update file on disk
        new_entries = [{"name": "Dropbear", "pattern": "dropbear"}]
        filepath.write_text(json.dumps(new_entries))

        # Clear and reload
        cache.clear_memory_cache()
        result = cache.load_satori_ssh()
        assert len(result) == 1
        assert result[0]["name"] == "Dropbear"
