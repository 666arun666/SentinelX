from sqlalchemy import JSON, BigInteger, Column, DateTime, Index, String, Text

from sentinelx.models.base import Base


class LogSource(Base):
    __tablename__ = "log_sources"

    source = Column(String, primary_key=True)
    format = Column(String, nullable=False)
    file_inode = Column(BigInteger, nullable=True)
    offset = Column(BigInteger, nullable=True)
    journal_cursor = Column(String, nullable=True)
    status = Column(String, nullable=False, default="active")
    last_read_at = Column(DateTime(timezone=True), nullable=True)
    metadata_json = Column(JSON, nullable=True)


class Event(Base):
    __tablename__ = "events"

    event_id = Column(String, primary_key=True)
    event_time = Column(DateTime(timezone=True), nullable=False)
    collected_at = Column(DateTime(timezone=True), nullable=False)
    hostname = Column(String, nullable=True)
    source = Column(String, nullable=False)
    event_type = Column(String, nullable=True)
    username = Column(String, nullable=True)
    source_ip = Column(String, nullable=True)
    destination_ip = Column(String, nullable=True)
    process = Column(String, nullable=True)
    command = Column(String, nullable=True)
    file_path = Column(String, nullable=True)
    severity = Column(String, nullable=True)
    message = Column(Text, nullable=True)
    raw_log = Column(Text, nullable=False)
    indicators = Column(JSON, nullable=True)
    log_source = Column(String, nullable=True)  # reference


# Composite Index: event_time + source_ip + username
Index("idx_events_time_ip_user", Event.event_time, Event.source_ip, Event.username)

# Supporting indexes
Index("idx_events_source", Event.source)
Index("idx_events_hostname", Event.hostname)
Index("idx_events_event_type", Event.event_type)
Index("idx_events_severity", Event.severity)


class Finding(Base):
    __tablename__ = "findings"

    finding_id = Column(String, primary_key=True)
    rule_id = Column(String, nullable=False)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    event_id = Column(
        String, nullable=False
    )  # logical FK, or use ForeignKey("events.event_id")
    status = Column(String, nullable=False, default="open")
    created_at = Column(DateTime(timezone=True), nullable=False)
    evidence = Column(JSON, nullable=False)
    enrichments = Column(JSON, nullable=True)
    correlations = Column(JSON, nullable=True)
    mitre_tags = Column(JSON, nullable=True)


# Finding indexes
Index("idx_findings_rule_id", Finding.rule_id)
Index("idx_findings_severity", Finding.severity)
Index("idx_findings_status", Finding.status)
Index("idx_findings_created_at", Finding.created_at)
