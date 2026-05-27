"""LogAnalyzer — pattern detection and anomaly scoring for log streams."""

import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import List, Optional

from .config import AnalyzerConfig
from .models import LogEntry, AnomalyReport, Severity


_TIMESTAMP_PATTERNS = [
    # ISO 8601
    r"(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)",
    # Syslog-style
    r"(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})",
    # Common log format
    r"(?P<ts>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})",
    # Simple time
    r"(?P<ts>\d{2}:\d{2}:\d{2}\.\d+)",
]


class LogAnalyzer:
    """Rule-based log analysis with pattern detection and anomaly scoring."""

    def __init__(self, config: Optional[AnalyzerConfig] = None):
        self.config = config or AnalyzerConfig()
        self.config.validate()
        self._compiled_custom = {
            name: re.compile(pattern, re.IGNORECASE)
            for name, pattern in self.config.custom_patterns.items()
        }

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def parse_line(self, raw: str, line_number: int = 0) -> LogEntry:
        """Parse a raw log line into a LogEntry."""
        entry = LogEntry(raw=raw, line_number=line_number)
        lower = raw.lower()

        # Extract timestamp
        entry.timestamp = self._extract_timestamp(raw)

        # Extract severity
        entry.severity = self._detect_severity(lower)

        # Extract message (strip timestamp prefix if present)
        entry.message = self._strip_timestamp(raw).strip()

        return entry

    def parse_lines(self, lines: List[str]) -> List[LogEntry]:
        """Parse multiple raw log lines."""
        return [self.parse_line(line, idx + 1) for idx, line in enumerate(lines) if line.strip()]

    # ------------------------------------------------------------------
    # Anomaly scoring
    # ------------------------------------------------------------------

    def score_entry(self, entry: LogEntry) -> AnomalyReport:
        """Compute an anomaly score for a single entry."""
        reasons: List[str] = []
        score = 0.0
        lower = entry.raw.lower()

        # Severity-based contribution
        sev_weights = {
            Severity.DEBUG: 0.0,
            Severity.INFO: 0.05,
            Severity.WARNING: 0.25,
            Severity.ERROR: 0.5,
            Severity.CRITICAL: 0.7,
        }
        score += sev_weights.get(entry.severity, 0.0)

        # Keyword hits
        for kw in self.config.error_keywords:
            if kw in lower:
                score += 0.15
                reasons.append(f"error_keyword:{kw}")
                break

        for kw in self.config.warning_keywords:
            if kw in lower:
                score += 0.08
                reasons.append(f"warning_keyword:{kw}")
                break

        # Stack trace indicators
        if "traceback" in lower or "at " in lower and ".py" in lower:
            score += 0.2
            reasons.append("stack_trace")

        # Custom patterns
        for name, pat in self._compiled_custom.items():
            if pat.search(entry.raw):
                score += 0.3
                reasons.append(f"custom_pattern:{name}")

        # Unexpected length (very long or very short)
        if len(entry.raw) > 2000:
            score += 0.1
            reasons.append("unusually_long_line")
        elif len(entry.raw.strip()) < 5 and entry.raw.strip():
            score += 0.05
            reasons.append("suspiciously_short_line")

        score = min(score, 1.0)
        return AnomalyReport(
            entry=entry,
            score=score,
            reasons=reasons,
            is_anomaly=score >= self.config.anomaly_threshold,
        )

    def analyze(self, entries: List[LogEntry]) -> List[AnomalyReport]:
        """Score all entries and return anomaly reports."""
        return [self.score_entry(e) for e in entries]

    # ------------------------------------------------------------------
    # Burst detection
    # ------------------------------------------------------------------

    def detect_bursts(self, entries: List[LogEntry]) -> List[List[LogEntry]]:
        """Find groups of similar messages within a short time window."""
        if not entries:
            return []

        # Group by normalized message
        groups: dict = defaultdict(list)
        for entry in entries:
            key = self._normalize_for_burst(entry.message)
            groups[key].append(entry)

        bursts: List[List[LogEntry]] = []
        window = timedelta(seconds=self.config.burst_window_seconds)

        for group in groups.values():
            if len(group) < self.config.burst_count:
                continue
            # Sort by timestamp (None treated as epoch)
            group.sort(key=lambda e: e.timestamp or datetime.min)
            # Sliding window
            start = 0
            for end in range(len(group)):
                while (
                    start < end
                    and group[end].timestamp
                    and group[start].timestamp
                    and (group[end].timestamp - group[start].timestamp) > window
                ):
                    start += 1
                window_size = end - start + 1
                if window_size >= self.config.burst_count:
                    bursts.append(group[start : end + 1])

        return bursts

    # ------------------------------------------------------------------
    # Pattern frequency
    # ------------------------------------------------------------------

    def pattern_frequencies(self, entries: List[LogEntry]) -> Counter:
        """Return a counter of normalized message patterns."""
        return Counter(self._normalize_for_burst(e.message) for e in entries)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_timestamp(raw: str) -> Optional[datetime]:
        for pat in _TIMESTAMP_PATTERNS:
            m = re.search(pat, raw)
            if m:
                ts_str = m.group("ts")
                for fmt in (
                    "%Y-%m-%dT%H:%M:%S.%fZ",
                    "%Y-%m-%dT%H:%M:%S.%f%z",
                    "%Y-%m-%dT%H:%M:%S%z",
                    "%Y-%m-%dT%H:%M:%SZ",
                    "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%d %H:%M:%S.%f",
                    "%Y-%m-%d %H:%M:%S",
                    "%d/%b/%Y:%H:%M:%S %z",
                ):
                    try:
                        return datetime.strptime(ts_str, fmt)
                    except ValueError:
                        continue
        return None

    def _detect_severity(self, lower: str) -> Severity:
        for kw in self.config.error_keywords:
            if kw in lower:
                if kw == "fatal" or kw == "panic":
                    return Severity.CRITICAL
                return Severity.ERROR
        for kw in self.config.warning_keywords:
            if kw in lower:
                return Severity.WARNING
        for kw in self.config.debug_keywords:
            if kw in lower:
                return Severity.DEBUG
        for kw in self.config.info_keywords:
            if kw in lower:
                return Severity.INFO
        # Check for explicit severity labels
        for sev in self.config.severity_levels:
            if sev.lower() in lower:
                return Severity(sev)
        return Severity.INFO

    @staticmethod
    def _strip_timestamp(raw: str) -> str:
        # Remove bracketed or ISO timestamp prefix
        stripped = re.sub(r"^\[?[^\]]*?\]\s*", "", raw, count=1)
        stripped = re.sub(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s*", "", stripped, count=1)
        return stripped if stripped else raw

    @staticmethod
    def _normalize_for_burst(message: str) -> str:
        """Normalize a message for burst comparison (strip numbers, hex, uuids)."""
        s = message.lower().strip()
        s = re.sub(r"0x[0-9a-f]+", "0xN", s)
        s = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "<UUID>", s)
        s = re.sub(r"\b\d+\b", "N", s)
        return s[:120]
