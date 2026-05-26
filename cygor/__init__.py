"""
Cygor Red Teaming Toolkit

Subcommands:
- scan  : Run network scans (masscan, naabu, nmap)
- parse : Parse Nmap XML results into categorized service files
- enum  : Enumeration modules (e.g., smbexplorer, nfsexplorer, lockon, etc.)
"""

from pathlib import Path
import sys

__version__ = "1.0.0"

_pkg_root = Path(__file__).resolve().parent
if str(_pkg_root) not in sys.path:
    sys.path.insert(0, str(_pkg_root))

__all__ = ["scan", "parse", "enum", "module_loader", "webapp"]

