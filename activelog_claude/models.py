"""Log entry data structures."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LogCategory(str, Enum):
    SYSTEM = "system"
    NETWORK = "network"
    AUTH = "auth"
    DATABASE = "database"
    APPLICATION = "application"
    INFRASTRUCTURE = "infrastructure"
    SECURITY = "security"
    UNKNOWN = "unknown"


@dataclass
class LogEntry:
    """A single parsed log line."""

    raw: str
    timestamp: Optional[datetime] = None
    severity: Severity = Severity.INFO
    category: LogCategory = LogCategory.UNKNOWN
    source: str = ""
    message: str = ""
    line_number: int = 0
    anomaly_score: float = 0.0
    tags: list = field(default_factory=list)


@dataclass
class AnomalyReport:
    """Result of anomaly analysis on a log entry."""

    entry: LogEntry
    score: float
    reasons: list = field(default_factory=list)
    is_anomaly: bool = False


@dataclass
class LogSummary:
    """Condensed representation of a log stream."""

    total_entries: int = 0
    severity_counts: dict = field(default_factory=dict)
    category_counts: dict = field(default_factory=dict)
    time_range: tuple = (None, None)  # (earliest, latest) timestamps
    top_messages: list = field(default_factory=list)
    anomaly_count: int = 0
    burst_events: list = field(default_factory=list)
    key_findings: list = field(default_factory=list)


@dataclass
class Insight:
    """An extracted insight or correlation."""

    kind: str  # "correlation", "root_cause", "pattern", "burst"
    confidence: float
    description: str
    related_entries: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
