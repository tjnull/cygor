from typing import List, Optional
from sqlmodel import SQLModel, Field, Relationship


class Host(SQLModel, table=True):
    __tablename__ = "host"

    id: int = Field(primary_key=True, index=True)
    address: str = Field(index=True)
    hostname: Optional[str] = Field(default=None, index=True)

    ports: List["Port"] = Relationship(back_populates="host")
    scripts: List["Script"] = Relationship(back_populates="host")
    os_guesses: List["OSGuess"] = Relationship(back_populates="host")


class Port(SQLModel, table=True):
    __tablename__ = "port"

    id: int = Field(primary_key=True, index=True)
    host_id: int = Field(foreign_key="host.id", index=True)
    port: int = Field(index=True)
    protocol: Optional[str] = Field(default=None)
    service: Optional[str] = Field(default=None)
    banner: Optional[str] = Field(default=None)

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

    # Relationships
    scan: "CredReconScan" = Relationship(back_populates="results")

