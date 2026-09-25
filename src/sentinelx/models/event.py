import hashlib
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class NormalizedEvent(BaseModel):
    event_id: str = Field(description="Deterministic event ID")
    event_time: datetime = Field(
        description="When the event occurred at the source (UTC)"
    )
    collected_at: datetime = Field(
        description="When SentinelX collected the event (UTC)"
    )
    source: str = Field(description="Source of the event (e.g. auth.log, syslog)")
    hostname: str | None = None
    event_type: str | None = None
    username: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    process: str | None = None
    command: str | None = None
    file_path: str | None = None
    severity: str | None = None
    message: str | None = None
    raw_log: str = Field(description="Original unparsed log string")
    indicators: dict[str, Any] | None = None


def generate_event_id(source_id: str, position_identity: str, raw_event: str) -> str:
    """
    Generates a deterministic event ID based on:
    hash(source_id, position_identity, raw_event_identity)

    position_identity could be:
    - offset string (e.g., '12345') for files
    - journalctl cursor for journald
    """
    hasher = hashlib.sha256()
    hasher.update(source_id.encode("utf-8"))
    hasher.update(b"|")
    hasher.update(position_identity.encode("utf-8"))
    hasher.update(b"|")
    hasher.update(raw_event.encode("utf-8"))
    return hasher.hexdigest()
