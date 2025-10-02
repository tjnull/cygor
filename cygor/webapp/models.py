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

