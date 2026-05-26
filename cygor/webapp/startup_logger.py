"""
Centralized startup logging for Cygor Web UI.
Provides consistent formatting and timestamps for all startup messages.
"""
from datetime import datetime
from enum import Enum
from typing import Optional
from colorama import Fore, Style, init as colorama_init

# Initialize colorama
colorama_init(autoreset=True, strip=False)


class StartupPhase(Enum):
    """Phases of the startup process for better organization."""
    INIT = "Initialization"
    DATABASE = "Database"
    SECURITY = "Security"
    MODULES = "Modules"
    DATA = "Data Loading"
    SERVER = "Server"
    READY = "Ready"


class StartupLogger:
    """
    Centralized logger for startup messages with consistent formatting.
    Provides timestamps and phase-based organization.
    """

    def __init__(self, verbose: int = 0):
        """
        Initialize startup logger.

        Args:
            verbose: Verbosity level (0=normal, 1=verbose, 2=debug)
        """
        self.verbosity_level = verbose
        self.current_phase = None
        self.start_time = datetime.now()

    def _timestamp(self) -> str:
        """Generate timestamp for log messages."""
        return datetime.now().strftime("%H:%M:%S")

    def _datetime_stamp(self) -> str:
        """Generate day+timestamp for phase messages."""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _elapsed(self) -> str:
        """Calculate elapsed time since start."""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        return f"+{elapsed:.1f}s"

    def phase(self, phase: StartupPhase):
        """Start a new phase of the startup process."""
        self.current_phase = phase
        print(f"\n{'─' * 80}")
        print(f"{phase.value}")
        print(f"{'─' * 80}")

    def success(self, message: str, detail: Optional[str] = None):
        """Log a success message."""
        timestamp = self._datetime_stamp()
        print(f"[{Fore.CYAN}{timestamp}{Style.RESET_ALL}] {Fore.GREEN}✓{Style.RESET_ALL} {message}")
        if detail and self.verbosity_level > 0:
            print(f"                        {Fore.GREEN}└─{Style.RESET_ALL} {detail}")

    def info(self, message: str, detail: Optional[str] = None):
        """Log an informational message."""
        timestamp = self._datetime_stamp()
        print(f"[{Fore.CYAN}{timestamp}{Style.RESET_ALL}] {Fore.BLUE}•{Style.RESET_ALL} {message}")
        if detail and self.verbosity_level > 0:
            print(f"                        {Fore.BLUE}└─{Style.RESET_ALL} {detail}")

    def warning(self, message: str, detail: Optional[str] = None):
        """Log a warning message."""
        timestamp = self._datetime_stamp()
        print(f"[{Fore.CYAN}{timestamp}{Style.RESET_ALL}] {Fore.YELLOW}⚠{Style.RESET_ALL} {message}")
        if detail and self.verbosity_level > 0:
            print(f"                        {Fore.YELLOW}└─{Style.RESET_ALL} {detail}")

    def error(self, message: str, detail: Optional[str] = None):
        """Log an error message."""
        timestamp = self._datetime_stamp()
        print(f"[{Fore.CYAN}{timestamp}{Style.RESET_ALL}] {Fore.RED}✗{Style.RESET_ALL} {message}")
        if detail:
            print(f"                        {Fore.RED}└─{Style.RESET_ALL} {detail}")

    def debug(self, message: str, detail: Optional[str] = None):
        """Log a debug message (only shown in verbose mode)."""
        if self.verbosity_level >= 2:
            timestamp = self._datetime_stamp()
            print(f"[{Fore.CYAN}{timestamp}{Style.RESET_ALL}] {Fore.MAGENTA}[DEBUG]{Style.RESET_ALL} {message}")
            if detail:
                print(f"                                 {Fore.MAGENTA}└─{Style.RESET_ALL} {detail}")

    def verbose(self, message: str, detail: Optional[str] = None):
        """Log a verbose message (shown in verbose mode)."""
        if self.verbosity_level >= 1:
            timestamp = self._datetime_stamp()
            print(f"[{Fore.CYAN}{timestamp}{Style.RESET_ALL}]   {message}")
            if detail:
                print(f"                        {Fore.CYAN}└─{Style.RESET_ALL} {detail}")

    def divider(self):
        """Print a divider line."""
        print(f"{'─' * 80}")

    def banner(self, title: str, items: dict):
        """
        Print a formatted banner with key-value pairs.

        Args:
            title: Banner title
            items: Dictionary of key-value pairs to display
        """
        print(f"\n{'═' * 80}")
        print(f"{title.center(80)}")
        print(f"{'═' * 80}")
        for key, value in items.items():
            print(f"  {key:20s}: {value}")
        print(f"{'═' * 80}\n")

    def summary(self, metrics: dict):
        """
        Print a startup summary with metrics.

        Args:
            metrics: Dictionary of metrics to display
        """
        elapsed = self._elapsed()
        timestamp = self._timestamp()

        print(f"\n{'═' * 80}")
        print(f"[{timestamp}] {elapsed} Cygor Web UI Ready".center(80))
        print(f"{'═' * 80}")

        for key, value in metrics.items():
            print(f"  {key:25s}: {value}")

        print(f"{'═' * 80}\n")


# Global instance (will be initialized by webctl.py)
_logger: Optional[StartupLogger] = None


def init_logger(verbose: int = 0):
    """Initialize the global startup logger."""
    global _logger
    _logger = StartupLogger(verbose)
    return _logger


def get_logger() -> StartupLogger:
    """Get the global startup logger instance."""
    global _logger
    if _logger is None:
        _logger = StartupLogger()
    return _logger
