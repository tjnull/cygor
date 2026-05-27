"""
Database adapters for PostgreSQL and SQLite with version detection and fallback.

This module provides a unified interface for database connections with automatic
fallback from PostgreSQL to SQLite if needed. PostgreSQL version detection ensures
compatibility with the latest available version.
"""
import json
import logging
import os
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, Tuple

logger = logging.getLogger(__name__)


@dataclass
class DatabaseInfo:
    """Information about a database connection."""
    url: str
    backend: str  # 'postgresql' or 'sqlite'
    version: Optional[str] = None
    port: Optional[int] = None
    host: Optional[str] = None
    database: Optional[str] = None
    user: Optional[str] = None


class DatabaseAdapter(ABC):
    """Base class for database adapters."""

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this database backend is available."""
        pass

    @abstractmethod
    def get_connection_url(self) -> Optional[str]:
        """Get the database connection URL."""
        pass

    @abstractmethod
    def test_connection(self) -> bool:
        """Test if the connection works."""
        pass

    @abstractmethod
    def get_info(self) -> Optional[DatabaseInfo]:
        """Get information about the database connection."""
        pass

    @abstractmethod
    def setup(self) -> bool:
        """Set up the database (create user, database, etc.)."""
        pass


class PostgreSQLAdapter(DatabaseAdapter):
    """PostgreSQL database adapter with version detection and automatic setup."""

    def __init__(
        self,
        user: Optional[str] = None,
        password: Optional[str] = None,
        database: Optional[str] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        auto_detect_port: bool = True,
        preferred_version: Optional[int] = None,
    ):
        self.user = user or os.getenv("CYGOR_DB_USER", "cygor")
        self.password = password or os.getenv("CYGOR_DB_PASSWORD")
        self.database = database or os.getenv("CYGOR_DB_NAME", "cygor")
        self.host = host or os.getenv("CYGOR_DB_HOST", "localhost")
        self.port = port or (int(os.getenv("CYGOR_DB_PORT")) if os.getenv("CYGOR_DB_PORT") else None)
        self.auto_detect_port = auto_detect_port
        self.preferred_version = preferred_version or (int(os.getenv("CYGOR_DB_PREFERRED_VERSION")) if os.getenv("CYGOR_DB_PREFERRED_VERSION") else None)
        self._version = None
        self._detected_ports: List[Tuple[int, str]] = []
        self._connection_url: Optional[str] = None

        # Use a well-known default password so test_connection works without
        # needing sudo to ALTER ROLE on every restart.
        if not self.password:
            self.password = "cygor"

        # Validate user/database names against Postgres identifier rules
        # BEFORE any SQL string-interpolation later. CYGOR_DB_USER and
        # CYGOR_DB_NAME come from env vars; a name containing `;` or `'`
        # would otherwise be executed as superuser SQL when setup() runs.
        # The valid Postgres unquoted-identifier grammar is letter|_ then
        # letter|digit|_|$ -- reject anything outside that strict shape.
        # We never need quoted identifiers here; if someone insists on
        # special characters in role/db names they can use a custom
        # CYGOR_DB_URL that bypasses setup() entirely.
        self._validate_identifier("CYGOR_DB_USER", self.user)
        self._validate_identifier("CYGOR_DB_NAME", self.database)

    @staticmethod
    def _validate_identifier(field_name: str, value: str) -> None:
        """Raise ValueError if `value` isn't a safe Postgres identifier.

        Restricts to ASCII letter/digit/underscore (Postgres unquoted-
        identifier grammar). Keeps the SQL string-interpolation in setup()
        from being an injection vector via env-supplied role/db names.
        """
        import re
        if not isinstance(value, str) or not value:
            raise ValueError(f"{field_name} must be a non-empty string")
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$", value):
            raise ValueError(
                f"{field_name}={value!r} is not a valid Postgres identifier. "
                f"Allowed: ASCII letter/underscore start, then "
                f"letter/digit/underscore (max 63 chars). For special "
                f"characters use CYGOR_DB_URL directly."
            )

    @staticmethod
    def _quote_sql_literal(value: str) -> str:
        """Quote a string for use inside a single-quoted SQL literal.

        Doubles every embedded single quote and rejects null bytes.
        Returns the value with surrounding quotes -- caller embeds the
        result directly (no extra quoting). Used for password fields
        where Postgres doesn't allow parameterised binding.
        """
        if value is None:
            return "''"
        if "\x00" in str(value):
            raise ValueError("SQL literal must not contain null bytes")
        return "'" + str(value).replace("'", "''") + "'"

    def is_available(self) -> bool:
        """Check if PostgreSQL client is installed."""
        try:
            result = subprocess.run(
                ["psql", "--version"],
                capture_output=True,
                text=True,
                timeout=2
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def detect_running_instances(self) -> List[Tuple[int, str]]:
        """
        Detect running PostgreSQL instances and their versions.
        Returns a list of (port, version) tuples, sorted by version (latest first).
        """
        if self._detected_ports:
            return self._detected_ports

        ports = []

        # Method 1: Try pg_lsclusters (Debian/Ubuntu)
        try:
            result = subprocess.run(
                ["pg_lsclusters", "-h"],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().split('\n'):
                    if not line.strip():
                        continue
                    parts = line.split()
                    if len(parts) >= 4 and parts[3] == "online":
                        # Format: Ver Cluster Port Status
                        version = parts[0]
                        port = int(parts[2])
                        ports.append((port, version))
        except (FileNotFoundError, subprocess.TimeoutExpired, ValueError):
            pass

        # Method 2: Check listening ports using lsof
        if not ports:
            try:
                result = subprocess.run(
                    ["lsof", "-i", "-n", "-P"],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'postgres' in line.lower() and 'LISTEN' in line:
                            parts = line.split()
                            for part in parts:
                                if ':' in part and part.split(':')[-1].isdigit():
                                    port = int(part.split(':')[-1])
                                    if 5430 <= port <= 5440:
                                        ports.append((port, "detected"))
            except (FileNotFoundError, subprocess.TimeoutExpired, ValueError):
                pass

        # Method 3: Try ss command if lsof not available
        if not ports:
            try:
                result = subprocess.run(
                    ["ss", "-tlnp"],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'postgres' in line.lower():
                            parts = line.split()
                            for part in parts:
                                if ':' in part:
                                    port_str = part.split(':')[-1]
                                    if port_str.isdigit():
                                        port = int(port_str)
                                        if 5430 <= port <= 5440:
                                            ports.append((port, "detected"))
            except (FileNotFoundError, subprocess.TimeoutExpired, ValueError):
                pass

        # Remove duplicates and sort by version (latest first)
        if ports:
            unique_ports = []
            seen_ports = set()
            for port, version in ports:
                if port not in seen_ports:
                    unique_ports.append((port, version))
                    seen_ports.add(port)

            # Sort by version number (descending) - latest PostgreSQL version first
            # If user has a preferred version, prioritize that version
            def version_key(item):
                port, version = item
                try:
                    if version.isdigit():
                        version_num = int(version)

                        # If user specified a preferred version, prioritize it
                        if self.preferred_version:
                            if version_num == self.preferred_version:
                                # Preferred version gets highest priority (0)
                                return (0, 0)
                            else:
                                # Non-preferred versions: sort by distance from preferred, then by version desc
                                distance = abs(version_num - self.preferred_version)
                                return (1, distance, -version_num)
                        else:
                            # No preference: sort by version (descending), then prefer port 5432
                            if port == 5432:
                                port_priority = 0
                            else:
                                port_priority = abs(port - 5432)
                            return (-version_num, port_priority)
                    else:
                        # Non-numeric versions go last
                        return (9999, 9999)
                except (ValueError, TypeError):
                    return (9999, 9999)

            unique_ports.sort(key=version_key)
            self._detected_ports = unique_ports

        return self._detected_ports

    def start_cluster(self, verbose: int = 0) -> bool:
        """
        Start a PostgreSQL cluster if none are running.
        Prefers the latest PostgreSQL version available.
        """
        # Check if any clusters are already running
        running_ports = self.detect_running_instances()
        if running_ports:
            if verbose > 0:
                logger.debug(f"PostgreSQL already running on port {running_ports[0][0]}")
            return True

        # Get list of all PostgreSQL clusters
        try:
            result = subprocess.run(
                ["pg_lsclusters", "-h"],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode != 0 or not result.stdout.strip():
                logger.warning("No PostgreSQL clusters found")
                return False

            # Parse cluster information
            clusters = []
            for line in result.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    version = parts[0]
                    cluster_name = parts[1]
                    port = parts[2]
                    status = parts[3]
                    clusters.append((version, cluster_name, port, status))

            if not clusters:
                logger.warning("No PostgreSQL clusters found")
                return False

            # Prefer the latest version (highest version number)
            down_clusters = [(ver, name, port) for ver, name, port, status in clusters if status == "down"]

            if not down_clusters:
                # All clusters are already running
                return True

            # Sort by version (descending) to get latest version first
            down_clusters.sort(key=lambda x: int(x[0]), reverse=True)
            cluster_to_start = down_clusters[0]

            version, cluster_name, port = cluster_to_start
            logger.info(f"Starting PostgreSQL {version}/{cluster_name} on port {port}...")

            # Start the cluster using sudo
            result = subprocess.run(
                ["sudo", "-n", "pg_ctlcluster", version, cluster_name, "start"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                logger.info(f"PostgreSQL {version}/{cluster_name} started successfully")
                # Wait for the cluster to be ready
                import time
                time.sleep(2)
                # Clear cached detected ports
                self._detected_ports = []
                return True
            else:
                logger.error(f"Failed to start PostgreSQL {version}/{cluster_name}")
                if verbose > 0 and result.stderr:
                    logger.debug(result.stderr.strip())
                return False

        except FileNotFoundError:
            logger.warning("pg_lsclusters not found (not a Debian/Ubuntu system)")
            return False
        except subprocess.TimeoutExpired:
            logger.error("Timeout starting PostgreSQL cluster")
            return False
        except Exception as e:
            logger.error(f"Error starting PostgreSQL: {e}")
            return False

    def _run_psql(self, args: List[str], use_postgres_user: bool = True) -> subprocess.CompletedProcess:
        """Run psql command with appropriate user privileges and correct port."""
        need_sudo = os.geteuid() != 0 and shutil.which("sudo")

        # Add port specification if we have one
        port_args = []
        if self.port:
            port_args = ["-p", str(self.port)]

        if use_postgres_user:
            if need_sudo:
                cmd = ["sudo", "-n", "-u", "postgres", "psql"] + port_args + args
            else:
                cmd = ["psql", "-U", "postgres"] + port_args + args
        else:
            cmd = ["psql"] + port_args + args

        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd="/",
            env=os.environ.copy(),
            timeout=10
        )

    def setup(self, verbose: int = 0) -> bool:
        """Create PostgreSQL role and database if not present."""
        try:
            if verbose > 0:
                logger.info(f"Setting up PostgreSQL database '{self.database}' for user '{self.user}'")

            # Check if user exists
            if verbose > 1:
                logger.debug(f"Checking if PostgreSQL user '{self.user}' exists")

            check_user = self._run_psql(["-tAc", f"SELECT 1 FROM pg_roles WHERE rolname='{self.user}'"])

            if check_user.returncode != 0:
                if verbose > 1:
                    logger.debug("Retrying user check without postgres user")
                check_user = self._run_psql(
                    ["-tAc", f"SELECT 1 FROM pg_roles WHERE rolname='{self.user}'"],
                    use_postgres_user=False
                )

            # Create user if doesn't exist, or update password if exists
            if check_user.returncode == 0 and not check_user.stdout.strip():
                # User doesn't exist, create it
                if verbose > 0:
                    logger.info(f"Creating PostgreSQL user '{self.user}'")

                # self.user was validated in __init__; password is quoted
                # via _quote_sql_literal so embedded quotes can't break out.
                _pw_lit = self._quote_sql_literal(self.password)
                _create_sql = f"CREATE ROLE {self.user} LOGIN PASSWORD {_pw_lit};"
                create_user = self._run_psql(["-c", _create_sql])
                if create_user.returncode != 0:
                    if verbose > 1:
                        logger.debug("Retrying user creation without postgres user")
                    create_user = self._run_psql(
                        ["-c", _create_sql],
                        use_postgres_user=False
                    )
                    if create_user.returncode != 0:
                        logger.error(f"Failed to create PostgreSQL user '{self.user}'")
                        if verbose > 1 and create_user.stderr:
                            logger.debug(f"Error details: {create_user.stderr.strip()[:200]}")
                        return False

                if verbose > 0:
                    logger.info(f"PostgreSQL user '{self.user}' created successfully")
            else:
                # User exists, update the password to ensure it matches
                if verbose > 1:
                    logger.debug(f"PostgreSQL user '{self.user}' already exists, updating password")

                _pw_lit = self._quote_sql_literal(self.password)
                _alter_sql = f"ALTER ROLE {self.user} PASSWORD {_pw_lit};"
                update_password = self._run_psql(["-c", _alter_sql])
                if update_password.returncode != 0:
                    if verbose > 1:
                        logger.debug("Retrying password update without postgres user")
                    update_password = self._run_psql(
                        ["-c", _alter_sql],
                        use_postgres_user=False
                    )
                    if update_password.returncode != 0 and verbose > 1:
                        logger.debug(f"Failed to update password: {update_password.stderr.strip()[:200] if update_password.stderr else 'Unknown error'}")

                if verbose > 1:
                    logger.debug(f"PostgreSQL user '{self.user}' password updated")

            # Check if database exists
            if verbose > 1:
                logger.debug(f"Checking if PostgreSQL database '{self.database}' exists")

            # self.database was validated in __init__, but use the literal
            # quoter anyway -- defense-in-depth, and a clearer signal to
            # future maintainers that this string ends up in raw SQL.
            _db_lit = self._quote_sql_literal(self.database)
            _check_sql = f"SELECT 1 FROM pg_database WHERE datname={_db_lit}"
            check_db = self._run_psql(["-tAc", _check_sql])

            if check_db.returncode != 0:
                if verbose > 1:
                    logger.debug("Retrying database check without postgres user")
                check_db = self._run_psql(
                    ["-tAc", _check_sql],
                    use_postgres_user=False
                )

            # Create database if doesn't exist
            if check_db.returncode == 0 and not check_db.stdout.strip():
                if verbose > 0:
                    logger.info(f"Creating PostgreSQL database '{self.database}'")

                # Try createdb command
                need_sudo = os.geteuid() != 0 and shutil.which("sudo")
                port_args = ["-p", str(self.port)] if self.port else []
                if need_sudo:
                    create_db_cmd = ["sudo", "-u", "postgres", "createdb"] + port_args + ["-O", self.user, self.database]
                else:
                    create_db_cmd = ["createdb", "-U", "postgres"] + port_args + ["-O", self.user, self.database]

                if verbose > 1:
                    logger.debug(f"Using createdb command: {' '.join(create_db_cmd[:5])} ...")

                create_db = subprocess.run(create_db_cmd, capture_output=True, text=True, timeout=10)

                if create_db.returncode != 0:
                    if verbose > 1:
                        logger.debug("createdb failed, trying psql CREATE DATABASE")

                    # Fallback to psql CREATE DATABASE. Both identifiers
                    # were validated in __init__ (only [A-Za-z_][A-Za-z0-9_]*
                    # allowed) so the f-string interpolation here is safe.
                    create_db_sql = f"CREATE DATABASE {self.database} OWNER {self.user};"
                    create_db = self._run_psql(["-c", create_db_sql])
                    if create_db.returncode != 0:
                        if verbose > 1:
                            logger.debug("Retrying database creation without postgres user")
                        create_db = self._run_psql(["-c", create_db_sql], use_postgres_user=False)
                        if create_db.returncode != 0:
                            logger.error(f"Failed to create PostgreSQL database '{self.database}'")
                            if verbose > 1 and create_db.stderr:
                                logger.debug(f"Error details: {create_db.stderr.strip()[:200]}")
                            return False

                if verbose > 0:
                    logger.info(f"PostgreSQL database '{self.database}' created successfully")
            else:
                if verbose > 1:
                    logger.debug(f"PostgreSQL database '{self.database}' already exists")

            if verbose > 0:
                logger.info("PostgreSQL setup completed successfully")

            return True

        except subprocess.TimeoutExpired:
            logger.error("Timeout during PostgreSQL setup (max 10 seconds)")
            return False
        except Exception as e:
            logger.error(f"Error setting up PostgreSQL: {e}")
            if verbose > 1:
                import traceback
                logger.debug(f"Traceback: {traceback.format_exc()}")
            return False

    def get_version(self, port: int) -> Optional[str]:
        """Get PostgreSQL version for a specific port."""
        try:
            url = f"postgresql://{self.user}:{self.password}@{self.host}:{port}/{self.database}"
            result = subprocess.run(
                ["psql", url, "-tAc", "SELECT version();"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                # Extract version number from output like "PostgreSQL 18.1 (Debian 18.1-1) on ..."
                version_line = result.stdout.strip()
                if "PostgreSQL" in version_line:
                    parts = version_line.split()
                    for i, part in enumerate(parts):
                        if part == "PostgreSQL" and i + 1 < len(parts):
                            return parts[i + 1]
        except (subprocess.TimeoutExpired, Exception):
            pass
        return None

    def get_connection_url(self) -> Optional[str]:
        """Get the database connection URL, trying detected ports if needed."""
        if self._connection_url:
            return self._connection_url

        # If port is explicitly set, use it
        if self.port:
            self._connection_url = f"postgresql+psycopg_async://{self.user}:{self.password}@{self.host}:{self.port}/{self.database}"
            return self._connection_url

        # Auto-detect running PostgreSQL instances
        if self.auto_detect_port:
            detected = self.detect_running_instances()
            if detected:
                # Try each detected port
                for port, version in detected:
                    url = f"postgresql+psycopg_async://{self.user}:{self.password}@{self.host}:{port}/{self.database}"
                    # We'll test this connection later
                    self.port = port
                    self._version = version
                    self._connection_url = url
                    return url

        # Default to standard PostgreSQL port
        self.port = 5432
        self._connection_url = f"postgresql+psycopg_async://{self.user}:{self.password}@{self.host}:{self.port}/{self.database}"
        return self._connection_url

    def test_connection(self) -> bool:
        """Test if the connection works using Python's psycopg."""
        try:
            # Try using psycopg (synchronous) for testing
            try:
                import psycopg
                conn_string = f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.database}"
                with psycopg.connect(conn_string, connect_timeout=5) as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT 1")
                        return True
            except ImportError:
                # Fallback to environment variable method with psql
                import os
                env = os.environ.copy()
                env['PGPASSWORD'] = self.password
                result = subprocess.run(
                    ["psql", "-U", self.user, "-h", self.host, "-p", str(self.port), "-d", self.database, "-c", "SELECT 1;"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    env=env
                )
                return result.returncode == 0
        except (subprocess.TimeoutExpired, Exception) as e:
            logger.debug(f"Connection test failed: {e}")
            return False

    def get_info(self) -> Optional[DatabaseInfo]:
        """Get information about the database connection."""
        url = self.get_connection_url()
        if not url:
            return None

        return DatabaseInfo(
            url=url,
            backend="postgresql",
            version=self._version,
            port=self.port,
            host=self.host,
            database=self.database,
            user=self.user
        )


class SQLiteAdapter(DatabaseAdapter):
    """SQLite database adapter."""

    def __init__(self, db_path: Optional[Path] = None):
        # Default to the app data dir (~/.cygor), never a throwaway cygor.db in
        # the current working directory.
        if db_path is None:
            from cygor.workspace import app_data_dir
            db_path = app_data_dir() / "cygor.db"
        self.db_path = Path(db_path)
        self._connection_url: Optional[str] = None

    def is_available(self) -> bool:
        """SQLite is always available (bundled with Python)."""
        return True

    def setup(self) -> bool:
        """No setup needed for SQLite."""
        return True

    def get_connection_url(self) -> Optional[str]:
        """Get the database connection URL."""
        if self._connection_url:
            return self._connection_url

        # Ensure parent directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._connection_url = f"sqlite+aiosqlite:///{self.db_path.absolute()}"
        return self._connection_url

    def test_connection(self) -> bool:
        """Test if the connection works."""
        try:
            import sqlite3
            conn = sqlite3.connect(str(self.db_path))
            conn.execute("SELECT 1")
            conn.close()
            return True
        except Exception:
            return False

    def get_info(self) -> Optional[DatabaseInfo]:
        """Get information about the database connection."""
        url = self.get_connection_url()
        if not url:
            return None

        return DatabaseInfo(
            url=url,
            backend="sqlite",
            version=None,
            database=str(self.db_path)
        )


class MSSQLAdapter(DatabaseAdapter):
    """Microsoft SQL Server adapter using aioodbc."""

    def __init__(
        self,
        user: Optional[str] = None,
        password: Optional[str] = None,
        database: Optional[str] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        ssl_mode: Optional[str] = None,
        ssl_ca: Optional[str] = None,
        odbc_driver: Optional[str] = None,
    ):
        self.user = user or os.getenv("CYGOR_DB_USER", "sa")
        self.password = password or os.getenv("CYGOR_DB_PASSWORD", "")
        self.database = database or os.getenv("CYGOR_DB_NAME", "cygor")
        self.host = host or os.getenv("CYGOR_DB_HOST", "localhost")
        self.port = port or int(os.getenv("CYGOR_DB_PORT", "1433"))
        self.ssl_mode = ssl_mode
        self.ssl_ca = ssl_ca
        self.odbc_driver = odbc_driver
        self._connection_url: Optional[str] = None

    def _detect_odbc_driver(self) -> Optional[str]:
        """Find an installed MSSQL ODBC driver."""
        if self.odbc_driver:
            return self.odbc_driver
        try:
            import pyodbc
            drivers = [d for d in pyodbc.drivers() if "SQL Server" in d]
            for preferred in ["ODBC Driver 18 for SQL Server", "ODBC Driver 17 for SQL Server"]:
                if preferred in drivers:
                    return preferred
            return drivers[0] if drivers else None
        except Exception:
            return None

    def is_available(self) -> bool:
        try:
            import pyodbc  # noqa: F401
            return self._detect_odbc_driver() is not None
        except ImportError:
            return False

    def get_connection_url(self) -> Optional[str]:
        if self._connection_url:
            return self._connection_url
        driver = self._detect_odbc_driver()
        if not driver:
            driver = "ODBC Driver 18 for SQL Server"
        driver_encoded = driver.replace(" ", "+")
        url = (
            f"mssql+aioodbc://{self.user}:{self.password}"
            f"@{self.host}:{self.port}/{self.database}"
            f"?driver={driver_encoded}"
        )
        if self.ssl_mode and self.ssl_mode != "disable":
            url += "&Encrypt=yes"
            if self.ssl_mode == "require":
                url += "&TrustServerCertificate=yes"
            else:
                url += "&TrustServerCertificate=no"
        else:
            url += "&Encrypt=no"
        self._connection_url = url
        return url

    def test_connection(self) -> bool:
        try:
            import pyodbc
            driver = self._detect_odbc_driver()
            if not driver:
                return False
            conn_str = (
                f"DRIVER={{{driver}}};"
                f"SERVER={self.host},{self.port};"
                f"DATABASE={self.database};"
                f"UID={self.user};PWD={self.password}"
            )
            if self.ssl_mode and self.ssl_mode != "disable":
                conn_str += ";Encrypt=yes"
                if self.ssl_mode == "require":
                    conn_str += ";TrustServerCertificate=yes"
            conn = pyodbc.connect(conn_str, timeout=5)
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.close()
            conn.close()
            return True
        except Exception as e:
            logger.debug(f"MSSQL connection test failed: {e}")
            return False

    def setup(self) -> bool:
        """Create cygor database on the MSSQL server if it does not exist."""
        try:
            import pyodbc
            driver = self._detect_odbc_driver()
            if not driver:
                logger.warning("No MSSQL ODBC driver found")
                return False
            conn_str = (
                f"DRIVER={{{driver}}};"
                f"SERVER={self.host},{self.port};"
                f"DATABASE=master;"
                f"UID={self.user};PWD={self.password}"
            )
            conn = pyodbc.connect(conn_str, timeout=10, autocommit=True)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT name FROM sys.databases WHERE name = ?",
                (self.database,),
            )
            if not cursor.fetchone():
                logger.info(f"Creating MSSQL database: {self.database}")
                cursor.execute(f"CREATE DATABASE [{self.database}]")
            cursor.close()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"MSSQL setup failed: {e}")
            return False

    def get_info(self) -> Optional[DatabaseInfo]:
        return DatabaseInfo(
            url=self.get_connection_url() or "",
            backend="mssql",
            host=self.host,
            port=self.port,
            database=self.database,
            user=self.user,
        )


class MySQLAdapter(DatabaseAdapter):
    """MySQL / MariaDB adapter using asyncmy."""

    def __init__(
        self,
        user: Optional[str] = None,
        password: Optional[str] = None,
        database: Optional[str] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        ssl_mode: Optional[str] = None,
        ssl_ca: Optional[str] = None,
    ):
        self.user = user or os.getenv("CYGOR_DB_USER", "cygor")
        self.password = password or os.getenv("CYGOR_DB_PASSWORD", "")
        self.database = database or os.getenv("CYGOR_DB_NAME", "cygor")
        self.host = host or os.getenv("CYGOR_DB_HOST", "localhost")
        self.port = port or int(os.getenv("CYGOR_DB_PORT", "3306"))
        self.ssl_mode = ssl_mode
        self.ssl_ca = ssl_ca
        self._connection_url: Optional[str] = None

    def is_available(self) -> bool:
        try:
            import asyncmy  # noqa: F401
            return True
        except ImportError:
            return False

    def get_connection_url(self) -> Optional[str]:
        if self._connection_url:
            return self._connection_url
        url = (
            f"mysql+asyncmy://{self.user}:{self.password}"
            f"@{self.host}:{self.port}/{self.database}"
            f"?charset=utf8mb4"
        )
        if self.ssl_mode and self.ssl_mode != "disable" and self.ssl_ca:
            url += f"&ssl_ca={self.ssl_ca}&ssl_verify_cert=true"
        self._connection_url = url
        return url

    def test_connection(self) -> bool:
        try:
            import pymysql
            conn = pymysql.connect(
                host=self.host, port=self.port, user=self.user,
                password=self.password, database=self.database,
                connect_timeout=5,
            )
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.close()
            conn.close()
            return True
        except Exception as e:
            logger.debug(f"MySQL connection test failed: {e}")
            return False

    def setup(self) -> bool:
        """Create cygor database on MySQL server if it does not exist."""
        try:
            import pymysql
            conn = pymysql.connect(
                host=self.host, port=self.port, user=self.user,
                password=self.password, connect_timeout=10,
            )
            cursor = conn.cursor()
            cursor.execute(
                f"CREATE DATABASE IF NOT EXISTS `{self.database}` "
                f"CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            )
            conn.commit()
            cursor.close()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"MySQL setup failed: {e}")
            return False

    def get_info(self) -> Optional[DatabaseInfo]:
        return DatabaseInfo(
            url=self.get_connection_url() or "",
            backend="mysql",
            host=self.host,
            port=self.port,
            database=self.database,
            user=self.user,
        )


class OracleAdapter(DatabaseAdapter):
    """Oracle Database adapter using oracledb thin mode."""

    def __init__(
        self,
        user: Optional[str] = None,
        password: Optional[str] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        service_name: Optional[str] = None,
        ssl_mode: Optional[str] = None,
        wallet_location: Optional[str] = None,
    ):
        self.user = user or os.getenv("CYGOR_DB_USER", "cygor")
        self.password = password or os.getenv("CYGOR_DB_PASSWORD", "")
        self.host = host or os.getenv("CYGOR_DB_HOST", "localhost")
        self.port = port or int(os.getenv("CYGOR_DB_PORT", "1521"))
        self.service_name = service_name or os.getenv("CYGOR_DB_SERVICE_NAME", "CYGOR")
        self.ssl_mode = ssl_mode
        self.wallet_location = wallet_location
        self._connection_url: Optional[str] = None

    def is_available(self) -> bool:
        try:
            import oracledb  # noqa: F401
            return True
        except ImportError:
            return False

    def get_connection_url(self) -> Optional[str]:
        if self._connection_url:
            return self._connection_url
        url = (
            f"oracle+oracledb://{self.user}:{self.password}"
            f"@{self.host}:{self.port}/?service_name={self.service_name}"
        )
        self._connection_url = url
        return url

    def test_connection(self) -> bool:
        try:
            import oracledb
            conn = oracledb.connect(
                user=self.user, password=self.password,
                dsn=f"{self.host}:{self.port}/{self.service_name}",
            )
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM DUAL")
            cursor.close()
            conn.close()
            return True
        except Exception as e:
            logger.debug(f"Oracle connection test failed: {e}")
            return False

    def setup(self) -> bool:
        """Verify Oracle connection. Schema creation requires DBA privileges."""
        try:
            return self.test_connection()
        except Exception as e:
            logger.error(f"Oracle setup failed: {e}")
            return False

    def get_info(self) -> Optional[DatabaseInfo]:
        return DatabaseInfo(
            url=self.get_connection_url() or "",
            backend="oracle",
            host=self.host,
            port=self.port,
            database=self.service_name,
            user=self.user,
        )


class DatabaseManager:
    """
    Manages database connections with automatic fallback from PostgreSQL to SQLite.

    This class attempts to connect to PostgreSQL (trying multiple versions if available),
    and falls back to SQLite if PostgreSQL is not available or fails to connect.
    """

    DB_CONFIG_PATH = Path.home() / ".config" / "cygor" / "db.json"

    def __init__(self, workspace: Optional[Path] = None, verbose: int = 0):
        # The SQLite DB is cygor's own state, so default it to the app data
        # dir (~/.cygor) rather than an implicit ./results directory.
        from cygor.workspace import app_data_dir
        self.workspace = workspace or app_data_dir()
        self.verbose = verbose
        self.adapter: Optional[DatabaseAdapter] = None
        self.info: Optional[DatabaseInfo] = None

    def _load_db_config(self, config_path: Path = None) -> Optional[dict]:
        """Load database configuration from JSON file."""
        path = config_path or self.DB_CONFIG_PATH
        try:
            if path.exists():
                return json.loads(path.read_text())
        except Exception as e:
            logger.warning(f"Failed to load db config from {path}: {e}")
        return None

    def _save_db_config(self, config_path: Path = None, config: dict = None) -> None:
        """Save database configuration (excluding password) to JSON file."""
        path = config_path or self.DB_CONFIG_PATH
        safe_config = {k: v for k, v in config.items() if k != "password"}
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(safe_config, indent=2))
            logger.info(f"Database config saved to {path}")
        except Exception as e:
            logger.warning(f"Failed to save db config: {e}")

    def _select_adapter(
        self,
        backend: str,
        host: Optional[str] = None,
        port: Optional[int] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        database: Optional[str] = None,
        ssl_mode: Optional[str] = None,
        ssl_ca: Optional[str] = None,
        service_name: Optional[str] = None,
    ) -> Optional[DatabaseAdapter]:
        """Create the appropriate adapter for the given backend."""
        kwargs = {}
        if host: kwargs["host"] = host
        if port: kwargs["port"] = port
        if user: kwargs["user"] = user
        if password: kwargs["password"] = password
        if database: kwargs["database"] = database
        if ssl_mode: kwargs["ssl_mode"] = ssl_mode
        if ssl_ca: kwargs["ssl_ca"] = ssl_ca

        if backend == "postgresql":
            pg_kwargs = {k: v for k, v in kwargs.items() if k not in ("ssl_mode", "ssl_ca")}
            return PostgreSQLAdapter(**pg_kwargs)
        elif backend == "sqlite":
            db_path = Path(database) if database else self.workspace / "cygor.db"
            return SQLiteAdapter(db_path=db_path)
        elif backend == "mssql":
            return MSSQLAdapter(**kwargs)
        elif backend == "mysql":
            mysql_kwargs = {k: v for k, v in kwargs.items() if k != "service_name"}
            return MySQLAdapter(**mysql_kwargs)
        elif backend == "oracle":
            if service_name:
                kwargs["service_name"] = service_name
            return OracleAdapter(**kwargs)
        else:
            logger.error(f"Unknown backend: {backend}")
            return None

    def initialize(
        self,
        prefer_postgres: bool = True,
        auto_start_postgres: bool = False,
        backend: Optional[str] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        database: Optional[str] = None,
        ssl_mode: Optional[str] = None,
        ssl_ca: Optional[str] = None,
        service_name: Optional[str] = None,
    ) -> DatabaseInfo:
        """
        Initialize database connection with fallback logic.

        Priority:
        1. CYGOR_DB_URL env var (explicit override)
        2. Explicit backend parameter (from CLI flags)
        3. Saved config from ~/.config/cygor/db.json
        4. Auto-detect local PostgreSQL
        5. SQLite fallback (last resort)
        """
        # 1. Explicit URL overrides everything
        env_url = os.getenv("CYGOR_DB_URL")
        if env_url:
            return self._initialize_from_url(env_url)

        # 2. Explicit backend from CLI flags
        if backend:
            adapter = self._select_adapter(
                backend=backend, host=host, port=port, user=user,
                password=password, database=database, ssl_mode=ssl_mode,
                ssl_ca=ssl_ca, service_name=service_name,
            )
            if adapter:
                if not adapter.is_available():
                    logger.warning(f"Driver for {backend} is not installed")
                elif adapter.setup():
                    info = adapter.get_info()
                    if info:
                        self._save_db_config(config={
                            "backend": backend, "host": host, "port": port,
                            "user": user, "database": database, "ssl_mode": ssl_mode,
                            "ssl_ca": ssl_ca, "service_name": service_name,
                        })
                        return info
                logger.warning(f"Configured {backend} backend failed, falling through")

        # 3. Saved config from db.json
        saved = self._load_db_config()
        if saved and saved.get("backend"):
            saved_password = password or os.getenv("CYGOR_DB_PASSWORD", "")
            adapter = self._select_adapter(
                backend=saved["backend"],
                host=saved.get("host"),
                port=saved.get("port"),
                user=saved.get("user"),
                password=saved_password,
                database=saved.get("database"),
                ssl_mode=saved.get("ssl_mode"),
                ssl_ca=saved.get("ssl_ca"),
                service_name=saved.get("service_name"),
            )
            if adapter and adapter.is_available():
                if adapter.setup():
                    info = adapter.get_info()
                    if info:
                        return info
                logger.warning(f"Saved {saved['backend']} config failed, falling through")

        # 4. Auto-detect local PostgreSQL
        if prefer_postgres:
            pg_info = self._try_postgresql(auto_start=auto_start_postgres)
            if pg_info:
                return pg_info

        # 5. SQLite fallback (last resort)
        return self._initialize_sqlite()

    def _initialize_from_url(self, url: str) -> DatabaseInfo:
        """Initialize database from explicit URL."""
        if "postgresql" in url.lower():
            # Extract connection details from URL
            # Format: postgresql+psycopg_async://user:password@host:port/database
            adapter = PostgreSQLAdapter(auto_detect_port=False)
            adapter._connection_url = url
            self.adapter = adapter
            self.info = DatabaseInfo(url=url, backend="postgresql")
            logger.info(f"Using PostgreSQL from CYGOR_DB_URL")
            return self.info
        elif "sqlite" in url.lower():
            # Extract path from URL
            # Format: sqlite+aiosqlite:///path/to/db
            db_path = url.split("///")[-1]
            adapter = SQLiteAdapter(db_path=Path(db_path))
            self.adapter = adapter
            self.info = adapter.get_info()
            logger.info(f"Using SQLite from CYGOR_DB_URL: {db_path}")
            return self.info
        else:
            raise ValueError(f"Unsupported database URL: {url}")

    def _try_postgresql(self, auto_start: bool = False) -> Optional[DatabaseInfo]:
        """Try to initialize PostgreSQL connection with automatic fallback."""
        if self.verbose > 0:
            logger.info("Attempting PostgreSQL connection")

        # Check for preferred version from environment
        preferred_version = None
        if os.getenv("CYGOR_DB_PREFERRED_VERSION"):
            try:
                preferred_version = int(os.getenv("CYGOR_DB_PREFERRED_VERSION"))
                if self.verbose > 0:
                    logger.info(f"User preference: PostgreSQL {preferred_version}")
            except ValueError:
                logger.warning(f"Invalid CYGOR_DB_PREFERRED_VERSION: {os.getenv('CYGOR_DB_PREFERRED_VERSION')}")

        adapter = PostgreSQLAdapter(preferred_version=preferred_version)

        if not adapter.is_available():
            if self.verbose > 0:
                logger.debug("PostgreSQL client not available (psql not found)")
            logger.warning("PostgreSQL client not installed")
            return None

        # Try to start PostgreSQL cluster if requested
        if auto_start:
            if self.verbose > 0:
                logger.info("Auto-starting PostgreSQL cluster")
            adapter.start_cluster(verbose=self.verbose)

        # Detect running instances
        if self.verbose > 1:
            logger.debug("Detecting running PostgreSQL instances")

        detected = adapter.detect_running_instances()
        if not detected:
            if self.verbose > 0:
                logger.debug("No running PostgreSQL instances detected")
            logger.warning("No running PostgreSQL instances found")
            logger.info("Start PostgreSQL with: sudo pg_ctlcluster <version> main start")
            logger.info("Or use: cygor web start --start-postgres")
            return None

        if self.verbose > 0:
            logger.info(f"Detected {len(detected)} PostgreSQL instance(s)")
            for idx, (port, version) in enumerate(detected, 1):
                version_str = f"v{version}" if version and version.isdigit() else version
                priority_marker = " (preferred)" if preferred_version and version.isdigit() and int(version) == preferred_version else ""
                priority_marker = priority_marker or (" (latest)" if idx == 1 and not preferred_version else "")
                logger.info(f"  {idx}. Port {port}: PostgreSQL {version_str}{priority_marker}")

        # Try each detected port in order (already sorted by preference)
        if self.verbose > 0:
            logger.info("Testing PostgreSQL connections (trying in order of preference)")

        failed_attempts = []
        setup_attempted = False

        for idx, (port, version) in enumerate(detected, 1):
            adapter.port = port
            adapter._version = version

            version_str = f"v{version}" if version and version.isdigit() else version
            if self.verbose > 0:
                logger.info(f"Attempt {idx}/{len(detected)}: {adapter.host}:{port} (PostgreSQL {version_str})")

            if self.verbose > 1:
                logger.debug(f"Connection string: postgresql://{adapter.user}@{adapter.host}:{port}/{adapter.database}")

            # Test connection first - if it fails, try setting up user/database
            if not adapter.test_connection():
                # Connection failed - try to set up user and database on this specific instance
                if not setup_attempted:
                    if self.verbose > 0:
                        logger.info("Setting up PostgreSQL user and database")
                    setup_attempted = True

                if self.verbose > 1:
                    logger.debug(f"Setting up PostgreSQL on port {port}")

                if not adapter.setup(verbose=self.verbose):
                    if self.verbose > 1:
                        logger.debug(f"Setup failed on port {port}")
                    # Setup failed, try connection again anyway (maybe credentials were wrong)

                # Test connection again after setup
                if not adapter.test_connection():
                    version_label = f"PostgreSQL {version}" if version and version.isdigit() else f"port {port}"
                    failed_attempts.append(version_label)
                    if self.verbose > 0:
                        logger.warning(f"✗ Connection failed: {version_label}")
                    continue

            # Connection successful!
            self.adapter = adapter
            self.info = adapter.get_info()
            if version and version.isdigit():
                logger.info(f"✓ Connected to PostgreSQL {version} on port {port}")
                if failed_attempts:
                    logger.info(f"Note: {len(failed_attempts)} other version(s) were unavailable: {', '.join(failed_attempts)}")
            else:
                logger.info(f"✓ Connected to PostgreSQL on port {port}")
            return self.info

        logger.warning("All PostgreSQL connection attempts failed")
        logger.info(f"Tried versions: {', '.join(failed_attempts)}")
        logger.info("Check PostgreSQL logs: tail -f /var/log/postgresql/postgresql-*-main.log")
        logger.info("Or try setting CYGOR_DB_PORT to a specific port number")
        return None

    def _initialize_sqlite(self) -> DatabaseInfo:
        """Initialize SQLite connection as fallback."""
        sqlite_path = self.workspace / "cygor.db"
        adapter = SQLiteAdapter(db_path=sqlite_path)
        self.adapter = adapter
        self.info = adapter.get_info()
        logger.info(f"Using SQLite: {sqlite_path.name}")
        return self.info

    def get_connection_url(self) -> str:
        """Get the current database connection URL."""
        if not self.adapter:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        url = self.adapter.get_connection_url()
        if not url:
            raise RuntimeError("Failed to get database connection URL")
        return url

    def get_info(self) -> DatabaseInfo:
        """Get information about the current database connection."""
        if not self.info:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        return self.info
