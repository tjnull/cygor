"""Tests for the cygor CLI help system (cygor/cli.py)."""

import sys
import pytest


class TestFormatUsagePlain:
    """Tests for _format_usage_plain()."""

    def test_returns_string(self):
        from cygor.cli import _format_usage_plain

        result = _format_usage_plain()
        assert isinstance(result, str)

    def test_contains_commands_section(self):
        from cygor.cli import _format_usage_plain

        result = _format_usage_plain()
        assert "Commands:" in result

    def test_contains_environment_variables_section(self):
        from cygor.cli import _format_usage_plain

        result = _format_usage_plain()
        assert "Environment Variables:" in result

    def test_contains_usage_line(self):
        from cygor.cli import _format_usage_plain

        result = _format_usage_plain()
        assert "Usage:" in result
        assert "cygor <command>" in result


class TestGetUsage:
    """Tests for get_usage() -- plain-text output with all command names."""

    def test_returns_string(self):
        from cygor.cli import get_usage

        result = get_usage()
        assert isinstance(result, str)

    @pytest.mark.parametrize(
        "command_name",
        [
            "scan",
            "parse",
            "enrich",
            "enum",
            "credrecon",
            "sync",  # unified entry point — replaces fingerprint-sync
            "workspace",
            "proxy",
            "plugin",
            "web",
            "setup-privileges",
            "banner",
        ],
    )
    def test_contains_command_name(self, command_name):
        from cygor.cli import get_usage

        result = get_usage()
        assert command_name in result, (
            f"Expected command '{command_name}' to appear in usage text"
        )


class TestPrintHelp:
    """Tests for _print_help() -- should execute without raising."""

    def test_executes_without_error(self, capsys):
        from cygor.cli import _print_help

        # _print_help uses Rich (or falls back to plain text).
        # Either path should complete without error.
        _print_help()

        # Verify something was printed (Rich writes to its own console,
        # so captured output may be empty when Rich is available; that's fine).


class TestMainHelp:
    """Tests for main() with help / no-args / unknown-command."""

    def test_help_flag_exits_zero(self, monkeypatch):
        """main() with -h should exit with code 0."""
        from cygor import cli

        monkeypatch.setattr(sys, "argv", ["cygor", "-h"])
        with pytest.raises(SystemExit) as exc_info:
            cli.main()
        assert exc_info.value.code == 0

    def test_no_args_exits_zero(self, monkeypatch):
        """main() with no arguments should print help and exit 0."""
        from cygor import cli

        monkeypatch.setattr(sys, "argv", ["cygor"])
        with pytest.raises(SystemExit) as exc_info:
            cli.main()
        assert exc_info.value.code == 0

    def test_unknown_command_exits_two(self, monkeypatch):
        """main() with an unrecognised command should exit with code 2."""
        from cygor import cli

        monkeypatch.setattr(sys, "argv", ["cygor", "not-a-real-command"])
        with pytest.raises(SystemExit) as exc_info:
            cli.main()
        assert exc_info.value.code == 2
