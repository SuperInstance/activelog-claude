"""Configuration for ActiveLog Claude analyzers."""

from dataclasses import dataclass, field
from typing import Dict, List, Tuple


@dataclass
class AnalyzerConfig:
    """Customizable rules and thresholds for log analysis."""

    # Severity thresholds (0.0 – 1.0)
    anomaly_threshold: float = 0.6
    """Score above which a log entry is flagged anomalous."""

    correlation_threshold: float = 0.5
    """Minimum similarity for two events to be considered correlated."""

    # Pattern detection
    error_keywords: Tuple[str, ...] = (
        "error", "exception", "fail", "fatal", "panic", "crash",
        "timeout", "refused", "denied", "unauthorized", "segfault",
    )
    """Keywords that elevate severity toward ERROR/CRITICAL."""

    warning_keywords: Tuple[str, ...] = (
        "warn", "warning", "slow", "retry", "degraded", "deprecated",
        "retryable", "throttle", "backpressure",
    )
    """Keywords that elevate severity toward WARNING."""

    info_keywords: Tuple[str, ...] = (
        "info", "started", "stopped", "connected", "registered",
        "completed", "success", "ok", "ready",
    )
    """Keywords that indicate normal operation."""

    debug_keywords: Tuple[str, ...] = (
        "debug", "trace", "verbose", "detail",
    )
    """Keywords that indicate debug-level output."""

    # Time window for burst detection (seconds)
    burst_window_seconds: int = 10
    """Window within which *burst_count* occurrences trigger a burst alert."""

    burst_count: int = 5
    """Number of similar messages within *burst_window_seconds* to flag a burst."""

    # Summarization
    summary_max_items: int = 20
    """Maximum distinct items kept in a summary before condensation."""

    # Custom patterns: name → regex (stored as plain strings)
    custom_patterns: Dict[str, str] = field(default_factory=dict)
    """User-defined pattern name → regex string pairs."""

    # Category labels
    severity_levels: Tuple[str, ...] = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
    """Ordered severity levels from least to most severe."""

    def validate(self) -> None:
        """Raise ValueError if configuration is inconsistent."""
        if not 0.0 <= self.anomaly_threshold <= 1.0:
            raise ValueError("anomaly_threshold must be between 0.0 and 1.0")
        if not 0.0 <= self.correlation_threshold <= 1.0:
            raise ValueError("correlation_threshold must be between 0.0 and 1.0")
        if self.burst_window_seconds < 1:
            raise ValueError("burst_window_seconds must be >= 1")
        if self.burst_count < 2:
            raise ValueError("burst_count must be >= 2")
        if self.summary_max_items < 1:
            raise ValueError("summary_max_items must be >= 1")
