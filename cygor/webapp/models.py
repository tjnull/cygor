from typing import List, Optional, Dict, Any
from datetime import datetime, date
from sqlmodel import SQLModel, Field, Relationship, Column
from sqlalchemy import JSON, Text, Index
from sqlalchemy.dialects.postgresql import JSONB


class Host(SQLModel, table=True):
    __tablename__ = "host"

    id: int = Field(primary_key=True, index=True)
    address: str = Field(index=True)
    hostname: Optional[str] = Field(default=None, index=True)

    # Timestamp fields for historical tracking
    first_seen: Optional[datetime] = Field(default=None, index=True)  # First time host was scanned
    last_seen: Optional[datetime] = Field(default=None, index=True)  # Most recent scan
    scan_count: int = Field(default=0)  # Number of times scanned

    ports: List["Port"] = Relationship(back_populates="host")
    scripts: List["Script"] = Relationship(back_populates="host")
    os_guesses: List["OSGuess"] = Relationship(back_populates="host")
    device_info: Optional["DeviceInfo"] = Relationship(back_populates="host")
    tags: List["HostTag"] = Relationship(back_populates="host")


class HostTag(SQLModel, table=True):
    """Free-form tags assigned to hosts by users."""
    __tablename__ = "host_tag"
    __table_args__ = (
        Index("ix_host_tag_unique", "host_id", "tag_name", unique=True),
        Index("ix_host_tag_name", "tag_name"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    host_id: int = Field(foreign_key="host.id", index=True)
    tag_name: str = Field(max_length=100, index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[int] = Field(default=None, index=True)

    host: "Host" = Relationship(back_populates="tags")


class Port(SQLModel, table=True):
    __tablename__ = "port"

    id: int = Field(primary_key=True, index=True)
    host_id: int = Field(foreign_key="host.id", index=True)
    port: int = Field(index=True)
    protocol: Optional[str] = Field(default=None)
    service: Optional[str] = Field(default=None)
    banner: Optional[str] = Field(default=None)

    # Service version detection fields
    product: Optional[str] = Field(default=None, index=True)  # e.g., "Apache httpd"
    version: Optional[str] = Field(default=None, index=True)  # e.g., "2.4.41"
    extrainfo: Optional[str] = Field(default=None)  # e.g., "Ubuntu Linux"
    cpe: Optional[str] = Field(default=None)  # CPE identifier
    state: Optional[str] = Field(default=None)  # open, filtered, closed
    reason: Optional[str] = Field(default=None)  # Why nmap thinks port is in this state
    confidence: Optional[int] = Field(default=None)  # Service detection confidence (0-10)

    host: "Host" = Relationship(back_populates="ports")
    scripts: List["Script"] = Relationship(back_populates="port")


class Script(SQLModel, table=True):
    __tablename__ = "script"

    id: int = Field(primary_key=True, index=True)
    host_id: int = Field(foreign_key="host.id", index=True)
    port_id: Optional[int] = Field(default=None, foreign_key="port.id", index=True)
    name: str = Field(index=True)
    output: str

    # --- New fields for Lockon ---
    url: Optional[str] = Field(default=None, index=True)
    status_code: Optional[int] = Field(default=None, index=True)
    screenshot_file: Optional[str] = Field(default=None)
    screenshot_failed: Optional[bool] = Field(default=None)

    host: "Host" = Relationship(back_populates="scripts")
    port: Optional["Port"] = Relationship(back_populates="scripts")


class OSGuess(SQLModel, table=True):
    __tablename__ = "os_guess"
    id: int = Field(primary_key=True, index=True)
    host_id: int = Field(foreign_key="host.id", index=True)

    name: str = Field(index=True)
    accuracy: int = Field(default=0, index=True)

    type: Optional[str] = Field(default=None, index=True)
    vendor: Optional[str] = Field(default=None, index=True)
    family: Optional[str] = Field(default=None, index=True)
    generation: Optional[str] = Field(default=None, index=True)
    cpe: Optional[str] = Field(default=None, index=True)

    host: "Host" = Relationship(back_populates="os_guesses")


class CredReconScan(SQLModel, table=True):
    """Credential reconnaissance scan session."""
    __tablename__ = "credrecon_scan"

    id: int = Field(primary_key=True, index=True)
    scan_id: str = Field(unique=True, index=True)  # UUID from task manager
    created_at: str = Field(index=True)  # ISO timestamp
    started_at: Optional[str] = Field(default=None)  # ISO timestamp
    completed_at: Optional[str] = Field(default=None)  # ISO timestamp
    status: str = Field(index=True)  # pending, running, completed, failed
    command: str  # Full command executed
    num_targets: int = Field(default=0)
    # Note: output_dir field removed - column doesn't exist in database
    # The output directory path can be reconstructed from created_at timestamp
    # or extracted from the command string if needed

    # Relationships
    results: List["CredReconResult"] = Relationship(back_populates="scan")


class CredReconResult(SQLModel, table=True):
    """Individual credential test result."""
    __tablename__ = "credrecon_result"
    __table_args__ = (
        Index("ix_credrecon_result_scan_status", "scan_id", "status"),
        Index("ix_credrecon_result_scan_target", "scan_id", "target", "port", "protocol"),
    )

    id: int = Field(primary_key=True, index=True)
    scan_id: int = Field(foreign_key="credrecon_scan.id", index=True)

    # Target information
    target: str = Field(index=True)  # IP or URL
    port: int = Field(index=True)
    protocol: str = Field(index=True)  # http, ssh, ftp, etc.
    service: Optional[str] = Field(default=None)  # http-basic, ssh, etc.

    # Credential information
    username: str = Field(index=True)
    password: Optional[str] = Field(default=None)

    # Result information
    status: str = Field(index=True)  # success, failed, error, skipped
    reason: Optional[str] = Field(default=None)  # Details about the result
    tested_at: Optional[str] = Field(default=None)  # ISO timestamp when test was performed

    # Service fingerprinting fields
    fingerprint_product: Optional[str] = Field(default=None)  # e.g., "OpenSSH", "MariaDB"
    fingerprint_version: Optional[str] = Field(default=None)  # e.g., "10.5.15"
    fingerprint_confidence: Optional[float] = Field(default=None)  # 0.0-1.0
    fingerprint_raw: Optional[str] = Field(default=None)  # JSON blob with full details
    credential_selection: Optional[str] = Field(default=None)  # Rationale for cred selection
    source_ip: Optional[str] = Field(default=None)  # Source IP used for this attempt (IP rotation)

    # Relationships
    scan: "CredReconScan" = Relationship(back_populates="results")


class SavedSearch(SQLModel, table=True):
    """Saved search queries for quick access."""
    __tablename__ = "saved_searches"

    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: Optional[int] = Field(default=None, index=True, nullable=True)

    # Search details
    name: str = Field(max_length=100, index=True)
    description: Optional[str] = Field(default=None, max_length=500)
    query: str = Field(max_length=1000)

    # Filters stored as JSON
    filters: Optional[str] = Field(default=None, sa_column=Column(JSON))

    # Sharing and visibility
    is_shared: bool = Field(default=False, index=True)
    is_global: bool = Field(default=False, index=True)  # Available to all users

    # Usage tracking
    use_count: int = Field(default=0)
    last_used: Optional[datetime] = Field(default=None)

    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class Finding(SQLModel, table=True):
    """A high-signal observation distilled from an enumeration module result.

    These are the evidence-backed facts the Next-Steps engine derives from module
    output (unauthenticated database, anonymous SMB share, DNS AXFR, ...). The
    per-module cygor-result.json files remain the source of truth; this table is
    the queryable index that powers cross-host triage. One row per
    (host, finding_type, port) is kept; re-ingestion replaces a host's findings.
    """
    __tablename__ = "finding"

    id: int = Field(primary_key=True, index=True)
    host_id: Optional[int] = Field(default=None, foreign_key="host.id", index=True)
    target_host: str = Field(index=True)          # IP/hostname (matches even if host_id unresolved)
    port: Optional[int] = Field(default=None, index=True)
    service: Optional[str] = Field(default=None, index=True)
    module: Optional[str] = Field(default=None, index=True)   # producing module slug

    finding_type: str = Field(index=True)         # stable key, e.g. unauth_database
    severity: str = Field(default="info", index=True)  # critical|high|medium|low|info
    title: str = Field(default="")
    evidence: Optional[str] = Field(default=None, sa_column=Column(Text))
    command: Optional[str] = Field(default=None, sa_column=Column(Text))

    detected_at: datetime = Field(default_factory=datetime.utcnow, index=True)


class ScheduledTask(SQLModel, table=True):
    """Scheduled task configuration for recurring scans."""
    __tablename__ = "scheduled_task"

    # Primary Key
    id: int = Field(primary_key=True, index=True)

    # Ownership
    user_id: Optional[int] = Field(default=None, index=True, nullable=True)

    # Task Identification
    name: str = Field(max_length=200, index=True)
    description: Optional[str] = Field(default=None, max_length=1000)

    # Task Type: 'port_scan', 'module_scan', 'credrecon'
    task_type: str = Field(index=True)

    # Task Configuration (JSON) - stores parameters for execution
    # Examples:
    # port_scan: {"targets": ["192.168.1.0/24"], "ports": "1-1000", "arguments": "-sV"}
    # credrecon: {"targets": ["192.168.1.1"], "protocols": ["ssh", "http"]}
    config: str = Field(sa_column=Column(JSON))

    # Schedule Configuration
    schedule_type: str = Field(index=True)  # 'cron', 'interval', 'date'
    schedule_config: str = Field(sa_column=Column(JSON))
    # Examples:
    # cron: {"hour": "2", "minute": "0", "day_of_week": "mon-fri"}
    # interval: {"hours": 24, "minutes": 0}
    # date: {"run_date": "2025-12-15 14:00:00"}

    # User timezone for schedule
    timezone: str = Field(default="UTC", max_length=50)

    # Status & Control
    is_active: bool = Field(default=True, index=True)
    is_paused: bool = Field(default=False, index=True)

    # Execution Tracking
    next_run: Optional[datetime] = Field(default=None, index=True)
    last_run: Optional[datetime] = Field(default=None, index=True)
    last_run_status: Optional[str] = Field(default=None, index=True)  # 'success', 'failed', 'running', 'queued'
    last_task_id: Optional[str] = Field(default=None)  # Reference to last executed task
    run_count: int = Field(default=0)

    # Limits & Constraints (optional)
    max_runs: Optional[int] = Field(default=None)  # Null = unlimited
    start_date: Optional[datetime] = Field(default=None)
    end_date: Optional[datetime] = Field(default=None)

    # Concurrency Control
    allow_concurrent: bool = Field(default=False)  # Allow overlap with previous runs
    max_concurrent_runs: int = Field(default=1)  # Max parallel instances

    # Resource Monitoring
    check_resources: bool = Field(default=True)  # Check system resources before running
    max_cpu_percent: Optional[float] = Field(default=80.0)  # Max CPU usage threshold
    max_memory_percent: Optional[float] = Field(default=80.0)  # Max memory usage threshold

    # Retry Configuration
    max_retries: int = Field(default=3)  # Max retry attempts per fire (0 = disabled)
    retry_delay_seconds: int = Field(default=300)  # Base delay between retries (5 min)
    retry_backoff: bool = Field(default=True)  # Double delay each retry

    # Misfire Grace
    misfire_grace_time: Optional[int] = Field(default=None)  # Per-task override (seconds), None = use global

    # Health Watchdog
    stall_timeout_seconds: Optional[int] = Field(default=None)  # Kill if no output for this long, None = disabled

    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    # APScheduler job ID (internal tracking)
    apscheduler_job_id: Optional[str] = Field(default=None, unique=True, index=True)

    # Relationships
    history: List["ScheduledTaskHistory"] = Relationship(
        back_populates="scheduled_task",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )


class ScheduledTaskHistory(SQLModel, table=True):
    """Execution history for scheduled tasks."""
    __tablename__ = "scheduled_task_history"
    __table_args__ = (
        Index("ix_sched_history_task_status", "scheduled_task_id", "status"),
    )

    # Primary Key
    id: int = Field(primary_key=True, index=True)

    # Foreign Key
    scheduled_task_id: int = Field(foreign_key="scheduled_task.id", index=True)

    # Execution Details
    task_id: Optional[str] = Field(default=None, index=True)  # ID from task manager
    status: str = Field(index=True)  # 'success', 'failed', 'running', 'queued', 'skipped'

    # Timing
    scheduled_time: datetime = Field(index=True)  # When it was supposed to run
    started_at: Optional[datetime] = Field(default=None)  # When it actually started
    completed_at: Optional[datetime] = Field(default=None)  # When it finished
    duration_seconds: Optional[float] = Field(default=None)  # Execution duration

    # Result Information
    message: Optional[str] = Field(default=None, max_length=1000)  # Status message
    error: Optional[str] = Field(default=None)  # Error details if failed

    # Resource Usage (captured at execution time)
    cpu_percent: Optional[float] = Field(default=None)
    memory_percent: Optional[float] = Field(default=None)
    resources_ok: bool = Field(default=True)  # Were resources within limits

    # Output reference
    output_path: Optional[str] = Field(default=None)  # Path to scan output

    # Retry tracking
    retry_attempt: int = Field(default=0)  # 0 = original, 1+ = retry
    retry_of_history_id: Optional[int] = Field(default=None)  # Links to original execution

    # Relationships
    scheduled_task: "ScheduledTask" = Relationship(back_populates="history")


class RunningTaskRecord(SQLModel, table=True):
    """Persistent record of currently running tasks.

    Survives server restarts so the scheduler can recover orphaned tasks.
    Rows are inserted when a task starts and deleted when it completes.
    """
    __tablename__ = "running_task_record"
    __table_args__ = (
        Index("ix_running_task_sched_id", "scheduled_task_id"),
    )

    id: int = Field(primary_key=True, index=True)
    task_id: str = Field(index=True)  # ID from TaskManager
    scheduled_task_id: Optional[int] = Field(default=None, foreign_key="scheduled_task.id")
    task_type: str = Field(default="scan")  # scan, module, credrecon, etc.
    pid: Optional[int] = Field(default=None)  # OS process ID for cleanup
    started_at: datetime = Field(default_factory=datetime.utcnow)
    hostname: Optional[str] = Field(default=None)  # Machine hostname for multi-node
    metadata_json: Optional[str] = Field(default=None, sa_column=Column(JSON))  # Extra context
    last_output_at: Optional[datetime] = Field(default=None)  # For watchdog: last time output was produced


# =============================================================================
# Enrichment Models (Threat Intelligence Enrichment)
# =============================================================================

class EnrichmentRun(SQLModel, table=True):
    """
    A single execution of `cygor enrich` (or one of its scoped variants).

    Created when an enrich task starts, finalized when it completes. The
    output JSON file on disk remains the source of truth; this table is
    the searchable index over what cygor has gathered from external
    sources for the assets in scope.
    """
    __tablename__ = "enrichment_run"

    id: Optional[int] = Field(default=None, primary_key=True)
    task_id: Optional[str] = Field(default=None, index=True, max_length=100)

    # When the run started / finished. completed_at == NULL means in-progress.
    started_at: datetime = Field(default_factory=datetime.utcnow, index=True)
    completed_at: Optional[datetime] = Field(default=None, index=True)

    # Source of truth on disk (results/enrichment/enrichment-<ts>.json).
    output_path: str = Field(max_length=500)

    # Sources requested for this run (e.g. ["shodan","virustotal","crt_sh"]).
    sources: List[str] = Field(default_factory=list, sa_column=Column(JSON))

    # Roll-up counts populated at completion.
    ioc_count: int = Field(default=0)
    finding_count: int = Field(default=0)

    # User-facing notes — currently unused but reserved for "this run was for
    # the AI scope sweep on 10.10.0.0/16" style breadcrumbs.
    notes: Optional[str] = Field(default=None, sa_column=Column(Text))

    findings: List["EnrichmentFinding"] = Relationship(back_populates="run")


class EnrichmentFinding(SQLModel, table=True):
    """
    One observation about one IOC from one external source.

    Replaces the "severity" model with a neutral signals tag list — we record
    what the source reported, not whether we think it's dangerous. Severity
    rollups (if any consumer wants them) are derived at render time from
    the signals list.
    """
    __tablename__ = "enrichment_finding"
    __table_args__ = (
        Index("ix_enrichment_finding_ioc_source", "ioc_value", "source"),
        Index("ix_enrichment_finding_run_source", "run_id", "source"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    run_id: int = Field(foreign_key="enrichment_run.id", index=True)

    # The IOC this finding describes.
    ioc_value: str = Field(index=True, max_length=500)
    ioc_type: str = Field(index=True, max_length=20)  # ip | domain | hash | url

    # Which external service contributed this row.
    source: str = Field(index=True, max_length=40)
    # What sort of finding it is (parallel to ioc_type but describes the
    # finding rather than the IOC). e.g. observation | cert | ai_indicator |
    # mcp_indicator. Lets us filter without parsing summary strings.
    finding_kind: str = Field(default="observation", index=True, max_length=40)

    # Neutral one-line takeaway, suitable for tables. No severity language.
    summary: str = Field(default="", sa_column=Column(Text))

    # Searchable tags. Any consumer (UI filters, search, reports) reads from
    # this list rather than parsing summary strings.
    signals: List[str] = Field(default_factory=list, sa_column=Column(JSON))

    # The source's own response for this IOC. Untouched.
    raw: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))

    # Linkage back to a known asset when ioc_type=="ip" matches a host record.
    # Null for IOCs cygor hasn't seen in its scan database.
    host_id: Optional[int] = Field(default=None, foreign_key="host.id", index=True)

    enriched_at: datetime = Field(default_factory=datetime.utcnow, index=True)

    run: "EnrichmentRun" = Relationship(back_populates="findings")


class AppSettings(SQLModel, table=True):
    """
    Application settings stored in database.
    Uses key-value pairs for flexibility.
    """
    __tablename__ = "app_settings"

    key: str = Field(primary_key=True, max_length=100)
    value: Optional[str] = Field(default=None, sa_column=Column(Text))
    description: Optional[str] = Field(default=None, max_length=500)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

# =============================================================================
# Device Fingerprinting Models
# =============================================================================

class DeviceInfo(SQLModel, table=True):
    """
    Device identification from fingerprinting.

    Stores aggregated device information from multiple fingerprint sources:
    - MAC OUI (manufacturer)
    - Service banners (OS, product - SSH, HTTP, SMB, FTP)
    - Nmap OS detection
    - SSL/TLS certificate CommonName
    - SMB/NetBIOS discovery
    - DHCP fingerprints
    """
    __tablename__ = "device_info"

    id: Optional[int] = Field(default=None, primary_key=True)
    host_id: int = Field(foreign_key="host.id", unique=True, index=True)

    # Device classification
    device_type: str = Field(default="Unknown", index=True)  # workstation, server, router, printer, iot, etc.
    device_category: str = Field(default="Unknown", index=True)  # Computing, Network Device, IoT, etc.
    manufacturer: Optional[str] = Field(default=None, index=True)  # Apple, Cisco, HP, etc.
    model: Optional[str] = Field(default=None)

    # OS information (aggregated from multiple sources)
    os_family: Optional[str] = Field(default=None, index=True)  # Windows, Linux, macOS, iOS, Android
    os_name: Optional[str] = Field(default=None, index=True)  # Ubuntu, Debian, Windows 10, etc.
    os_version: Optional[str] = Field(default=None)  # 8.04, 22.04, 10, etc.
    os_kernel: Optional[str] = Field(default=None)  # 2.6.9 - 2.6.33, 5.15, etc.
    os_full: Optional[str] = Field(default=None)  # Ubuntu 8.04 (Linux 2.6.x) - combined display string

    # Host identification
    netbios_name: Optional[str] = Field(default=None, index=True)  # NetBIOS/SMB computer name

    # MAC address info
    mac_address: Optional[str] = Field(default=None, index=True)
    mac_vendor: Optional[str] = Field(default=None)

    # Validation status (multi-source agreement)
    validated: bool = Field(default=False)  # True if 2+ sources agree
    validation_sources: int = Field(default=0)  # Number of agreeing sources

    # Enhanced OS detection (raw vs inferred)
    nmap_os_raw: Optional[str] = Field(default=None)  # Raw Nmap detection: "Linux 3.2 - 4.14"
    inferred_os: Optional[str] = Field(default=None)  # Inferred OS: "Debian 7 / Ubuntu 12.04"
    inferred_firmware: Optional[str] = Field(default=None)  # For IoT: "UniFi OS 3.x"

    # Enhanced validation
    validation_status: Optional[str] = Field(default=None, index=True)  # VALIDATED/PLAUSIBLE/SUSPECT/UNKNOWN
    validation_reason: Optional[str] = Field(default=None)  # Human-readable validation reason
    plausibility_score: float = Field(default=0.0)  # 0.0 - 1.0 plausibility rating

    # Confidence and evidence
    confidence: float = Field(default=0.0)  # 0.0 - 1.0
    device_type_certainty: float = Field(default=0.0)  # Per-field certainty for device type
    manufacturer_certainty: float = Field(default=0.0)  # Per-field certainty for manufacturer
    os_family_certainty: float = Field(default=0.0)  # Per-field certainty for OS family
    evidence: Optional[str] = Field(default=None, sa_column=Column(JSON))  # JSON array of fingerprint matches
    sources: Optional[str] = Field(default=None)  # Comma-separated list of sources that contributed

    # SSL certificate info (from ssl-cert script)
    ssl_common_name: Optional[str] = Field(default=None)  # CN from SSL cert

    # SMB/NetBIOS info
    smb_os: Optional[str] = Field(default=None)  # OS string from smb-os-discovery
    samba_version: Optional[str] = Field(default=None)  # Samba version if Linux

    # Timestamps
    first_fingerprinted: datetime = Field(default_factory=datetime.utcnow, index=True)
    last_fingerprinted: datetime = Field(default_factory=datetime.utcnow, index=True)
    fingerprint_count: int = Field(default=1)  # Number of times fingerprinted

    # Relationship
    host: "Host" = Relationship(back_populates="device_info")


