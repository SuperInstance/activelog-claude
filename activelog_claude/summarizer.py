"""LogSummarizer — condense log streams into structured summaries."""

from collections import Counter
from datetime import datetime
from typing import List, Optional

from .config import AnalyzerConfig
from .models import LogEntry, LogSummary, Severity, LogCategory
from .analyzer import LogAnalyzer


class LogSummarizer:
    """Produces structured summaries from log entry streams."""

    def __init__(self, config: Optional[AnalyzerConfig] = None):
        self.config = config or AnalyzerConfig()
        self.analyzer = LogAnalyzer(self.config)

    def summarize(self, entries: List[LogEntry]) -> LogSummary:
        """Build a summary from a list of parsed log entries."""
        if not entries:
            return LogSummary()

        severity_counts: Counter = Counter()
        category_counts: Counter = Counter()
        message_counter: Counter = Counter()
        anomaly_count = 0
        timestamps: List[datetime] = []

        anomaly_reports = self.analyzer.analyze(entries)

        for entry, report in zip(entries, anomaly_reports):
            severity_counts[entry.severity.value] += 1
            category_counts[entry.category.value] += 1
            normalized = self.analyzer._normalize_for_burst(entry.message)
            message_counter[normalized] += 1
            if report.is_anomaly:
                anomaly_count += 1
            if entry.timestamp:
                timestamps.append(entry.timestamp)

        # Time range
        if timestamps:
            time_range = (min(timestamps), max(timestamps))
        else:
            time_range = (None, None)

        # Top messages
        top_messages = [
            msg for msg, _ in message_counter.most_common(self.config.summary_max_items)
        ]

        # Burst detection
        bursts = self.analyzer.detect_bursts(entries)
        burst_events = [
            {"pattern": self.analyzer._normalize_for_burst(b[0].message), "count": len(b)}
            for b in bursts
        ]

        # Key findings
        key_findings = self._generate_findings(
            entries, severity_counts, anomaly_count, burst_events, time_range
        )

        return LogSummary(
            total_entries=len(entries),
            severity_counts=dict(severity_counts),
            category_counts=dict(category_counts),
            time_range=time_range,
            top_messages=top_messages,
            anomaly_count=anomaly_count,
            burst_events=burst_events,
            key_findings=key_findings,
        )

    def summarize_raw(self, lines: List[str]) -> LogSummary:
        """Parse raw log lines and summarize them."""
        entries = self.analyzer.parse_lines(lines)
        return self.summarize(entries)

    @staticmethod
    def _generate_findings(
        entries: List[LogEntry],
        severity_counts: Counter,
        anomaly_count: int,
        burst_events: list,
        time_range: tuple,
    ) -> List[str]:
        """Generate human-readable key findings."""
        findings: List[str] = []
        total = len(entries)

        if total == 0:
            return findings

        # High error rate
        error_count = severity_counts.get("ERROR", 0) + severity_counts.get("CRITICAL", 0)
        error_rate = error_count / total
        if error_rate > 0.5:
            findings.append(f"Very high error rate: {error_rate:.0%} of entries are ERROR/CRITICAL")
        elif error_rate > 0.2:
            findings.append(f"Elevated error rate: {error_rate:.0%} of entries are ERROR/CRITICAL")

        # Anomalies
        if anomaly_count > 0:
            findings.append(f"{anomaly_count} anomalous entries detected")

        # Bursts
        if burst_events:
            biggest = max(burst_events, key=lambda b: b["count"])
            findings.append(
                f"Burst detected: '{biggest['pattern'][:60]}' repeated {biggest['count']} times"
            )

        # Time gaps
        earliest, latest = time_range
        if earliest and latest:
            span = latest - earliest
            if span.total_seconds() < 1 and total > 10:
                findings.append("All entries within 1 second — possible dump or bulk log")

        # Warnings
        warn_count = severity_counts.get("WARNING", 0)
        if warn_count > total * 0.3:
            findings.append(f"High warning count: {warn_count} ({warn_count / total:.0%})")

        if not findings:
            findings.append("Log stream appears healthy — no significant issues detected")

        return findings
