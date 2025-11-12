"""
Credential Scanner Module

Tests default and weak credentials across multiple protocols including:
HTTP/HTTPS, SSH, FTP, MySQL, PostgreSQL, MSSQL, MongoDB, Redis, SNMP, RDP, and VNC.
"""

from .scanner import *

__all__ = ['module_info', 'run']
