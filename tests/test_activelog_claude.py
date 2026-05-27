"""Tests for activelog_claude."""

import pytest
from datetime import datetime, timedelta

from activelog_claude.config import AnalyzerConfig
from activelog_claude.models import LogEntry, Severity, LogCategory, AnomalyReport, Insight, LogSummary
from activelog_claude.analyzer import LogAnalyzer
from activelog_claude.summarizer import LogSummarizer
from activelog_claude.classifier import LogClassifier
from activelog_claude.insight import InsightExtractor


# ── Config ──────────────────────────────────────────────────────────

class TestConfig:
    def test_defaults_valid(self):
        cfg = AnalyzerConfig()
        cfg.validate()  # should not raise

    def test_invalid_threshold(self):
        cfg = AnalyzerConfig(anomaly_threshold=1.5)
        with pytest.raises(ValueError):
            cfg.validate()

    def test_invalid_burst_count(self):
        cfg = AnalyzerConfig(burst_count=1)
        with pytest.raises(ValueError):
            cfg.validate()

    def test_custom_patterns(self):
        cfg = AnalyzerConfig(custom_patterns={"my_ip": r"\d+\.\d+\.\d+\.\d+"})
        assert "my_ip" in cfg.custom_patterns


# ── Analyzer ────────────────────────────────────────────────────────

SAMPLE_LINES = [
    "2026-05-26 10:00:00 INFO Application started on port 8080",
    "2026-05-26 10:00:01 WARNING Connection timeout to db-host",
    "2026-05-26 10:00:02 ERROR Failed to authenticate user admin",
    "2026-05-26 10:00:03 CRITICAL Out of memory: killed process 1234",
    "just a random line without timestamp",
    "Traceback (most recent call last):",
    "  File \"app.py\", line 42, in handler",
    "TimeoutError: connection refused after 30s",
]


class TestAnalyzer:
    def setup_method(self):
        self.analyzer = LogAnalyzer()

    def test_parse_line_basic(self):
        entry = self.analyzer.parse_line(SAMPLE_LINES[0], 1)
        assert entry.line_number == 1
        assert entry.severity == Severity.INFO
        assert entry.timestamp is not None
        assert entry.timestamp.year == 2026

    def test_parse_line_error(self):
        entry = self.analyzer.parse_line(SAMPLE_LINES[2], 3)
        assert entry.severity == Severity.ERROR

    def test_parse_line_critical(self):
        entry = self.analyzer.parse_line(SAMPLE_LINES[3], 4)
        assert entry.severity == Severity.CRITICAL

    def test_parse_line_no_timestamp(self):
        entry = self.analyzer.parse_line(SAMPLE_LINES[4], 5)
        assert entry.timestamp is None
        assert entry.severity == Severity.INFO  # default

    def test_parse_lines(self):
        entries = self.analyzer.parse_lines(SAMPLE_LINES)
        assert len(entries) == len(SAMPLE_LINES)

    def test_score_entry_normal(self):
        entry = self.analyzer.parse_line(SAMPLE_LINES[0], 1)
        report = self.analyzer.score_entry(entry)
        assert report.score < 0.3
        assert not report.is_anomaly

    def test_score_entry_error(self):
        entry = self.analyzer.parse_line(SAMPLE_LINES[2], 3)
        report = self.analyzer.score_entry(entry)
        assert report.score >= 0.3
        assert len(report.reasons) > 0

    def test_score_entry_critical_anomaly(self):
        entry = self.analyzer.parse_line(SAMPLE_LINES[3], 4)
        report = self.analyzer.score_entry(entry)
        assert report.is_anomaly

    def test_analyze_all(self):
        entries = self.analyzer.parse_lines(SAMPLE_LINES)
        reports = self.analyzer.analyze(entries)
        assert len(reports) == len(entries)
        anomalies = [r for r in reports if r.is_anomaly]
        assert len(anomalies) >= 1

    def test_burst_detection(self):
        now = datetime(2026, 1, 1, 12, 0, 0)
        entries = [
            LogEntry(
                raw=f"ERROR Connection refused to db host",
                timestamp=now + timedelta(seconds=i),
                message="Connection refused to db host",
                severity=Severity.ERROR,
                line_number=i + 1,
            )
            for i in range(10)
        ]
        bursts = self.analyzer.detect_bursts(entries)
        assert len(bursts) >= 1
        assert bursts[0][0].message == "Connection refused to db host"

    def test_burst_no_burst(self):
        entries = [
            LogEntry(raw=f"msg {i}", message=f"msg {i}", line_number=i + 1)
            for i in range(3)
        ]
        bursts = self.analyzer.detect_bursts(entries)
        assert len(bursts) == 0

    def test_pattern_frequencies(self):
        entries = self.analyzer.parse_lines(SAMPLE_LINES)
        freqs = self.analyzer.pattern_frequencies(entries)
        assert len(freqs) > 0

    def test_custom_pattern_match(self):
        cfg = AnalyzerConfig(custom_patterns={"ip_addr": r"\d+\.\d+\.\d+\.\d+"})
        analyzer = LogAnalyzer(cfg)
        entry = LogEntry(raw="ERROR failed to connect to 10.0.0.1", message="ERROR failed to connect to 10.0.0.1")
        report = analyzer.score_entry(entry)
        assert any("custom_pattern:ip_addr" in r for r in report.reasons)

    def test_parse_empty_lines_skipped(self):
        entries = self.analyzer.parse_lines(["", "  ", "INFO ok"])
        assert len(entries) == 1


# ── Summarizer ──────────────────────────────────────────────────────

class TestSummarizer:
    def setup_method(self):
        self.summarizer = LogSummarizer()

    def test_summarize_empty(self):
        summary = self.summarizer.summarize([])
        assert summary.total_entries == 0

    def test_summarize_basic(self):
        entries = LogAnalyzer().parse_lines(SAMPLE_LINES)
        summary = self.summarizer.summarize(entries)
        assert summary.total_entries == len(SAMPLE_LINES)
        assert "ERROR" in summary.severity_counts or "CRITICAL" in summary.severity_counts
        assert len(summary.key_findings) > 0

    def test_summarize_raw(self):
        summary = self.summarizer.summarize_raw(SAMPLE_LINES)
        assert summary.total_entries == len(SAMPLE_LINES)

    def test_summarize_time_range(self):
        entries = LogAnalyzer().parse_lines(SAMPLE_LINES[:4])
        summary = self.summarizer.summarize(entries)
        assert summary.time_range[0] is not None
        assert summary.time_range[1] is not None

    def test_summarize_healthy_logs(self):
        lines = [
            "INFO Service started",
            "INFO Connected to database",
            "INFO Ready to accept requests",
        ]
        summary = self.summarizer.summarize_raw(lines)
        assert any("healthy" in f.lower() for f in summary.key_findings)

    def test_summarize_high_error_rate(self):
        lines = ["ERROR Something broke"] * 10 + ["INFO ok"] * 2
        summary = self.summarizer.summarize_raw(lines)
        assert any("error rate" in f.lower() for f in summary.key_findings)


# ── Classifier ──────────────────────────────────────────────────────

class TestClassifier:
    def setup_method(self):
        self.classifier = LogClassifier()

    def test_classify_auth(self):
        entry = LogEntry(raw="Failed login attempt for user admin", message="Failed login attempt for user admin")
        result = self.classifier.classify(entry)
        assert result.category == LogCategory.AUTH

    def test_classify_network(self):
        entry = LogEntry(raw="Connection refused to 10.0.0.1:5432", message="Connection refused to 10.0.0.1:5432")
        result = self.classifier.classify(entry)
        assert result.category == LogCategory.NETWORK

    def test_classify_database(self):
        entry = LogEntry(raw="SELECT * FROM users timed out", message="SELECT * FROM users timed out")
        result = self.classifier.classify(entry)
        assert result.category == LogCategory.DATABASE

    def test_classify_security(self):
        entry = LogEntry(raw="Firewall blocked intrusion attempt from 1.2.3.4", message="Firewall blocked intrusion attempt from 1.2.3.4")
        result = self.classifier.classify(entry)
        assert result.category == LogCategory.SECURITY

    def test_classify_infrastructure(self):
        entry = LogEntry(raw="CPU usage at 95%, scaling up pod", message="CPU usage at 95%, scaling up pod")
        result = self.classifier.classify(entry)
        assert result.category == LogCategory.INFRASTRUCTURE

    def test_classify_system(self):
        entry = LogEntry(raw="systemd[1]: Started cron.service", message="systemd[1]: Started cron.service")
        result = self.classifier.classify(entry)
        assert result.category == LogCategory.SYSTEM

    def test_classify_application_default(self):
        entry = LogEntry(raw="Something happened in the app", message="Something happened in the app")
        result = self.classifier.classify(entry)
        assert result.category == LogCategory.APPLICATION

    def test_classify_all(self):
        entries = [
            LogEntry(raw="login ok", message="login ok"),
            LogEntry(raw="GET /api/users", message="GET /api/users"),
        ]
        results = self.classifier.classify_all(entries)
        assert len(results) == 2
        assert results[0].category == LogCategory.AUTH
        assert results[1].category == LogCategory.NETWORK

    def test_security_severity_elevation(self):
        entry = LogEntry(
            raw="Attack detected from 1.2.3.4",
            message="Attack detected from 1.2.3.4",
            severity=Severity.INFO,
        )
        result = self.classifier.classify(entry)
        assert result.severity == Severity.CRITICAL

    def test_auth_failure_elevation(self):
        entry = LogEntry(
            raw="login failed for user admin",
            message="login failed for user admin",
            severity=Severity.INFO,
        )
        result = self.classifier.classify(entry)
        assert result.severity == Severity.WARNING


# ── InsightExtractor ────────────────────────────────────────────────

class TestInsightExtractor:
    def setup_method(self):
        self.extractor = InsightExtractor()

    def test_extract_empty(self):
        insights = self.extractor.extract([])
        assert len(insights) == 0

    def test_extract_error_cascade(self):
        entries = [
            LogEntry(
                raw=f"ERROR db connection failed #{i}",
                message=f"db connection failed #{i}",
                severity=Severity.ERROR,
                category=LogCategory.DATABASE,
                line_number=i + 1,
            )
            for i in range(5)
        ]
        insights = self.extractor.extract(entries)
        cascade = [i for i in insights if i.kind == "pattern"]
        assert len(cascade) >= 1

    def test_extract_root_cause(self):
        now = datetime(2026, 1, 1, 12, 0, 0)
        entries = [
            LogEntry(
                raw="WARNING Database latency high",
                message="Database latency high",
                severity=Severity.WARNING,
                category=LogCategory.DATABASE,
                timestamp=now,
                line_number=1,
            ),
            LogEntry(
                raw="ERROR Database connection lost",
                message="Database connection lost",
                severity=Severity.ERROR,
                category=LogCategory.DATABASE,
                timestamp=now + timedelta(seconds=1),
                line_number=2,
            ),
        ]
        # Make anomaly report for the error
        reports = [
            AnomalyReport(entry=entries[0], score=0.3, reasons=[], is_anomaly=False),
            AnomalyReport(entry=entries[1], score=0.8, reasons=["error_keyword:error"], is_anomaly=True),
        ]
        insights = self.extractor.extract(entries, reports)
        root_causes = [i for i in insights if i.kind == "root_cause"]
        assert len(root_causes) >= 1
        assert "line 2" in root_causes[0].description

    def test_extract_correlation(self):
        entries = [
            LogEntry(
                raw="ERROR Network timeout",
                message="Network timeout",
                severity=Severity.ERROR,
                category=LogCategory.NETWORK,
                line_number=i + 1,
            )
            for i in range(5)
        ]
        insights = self.extractor.extract(entries)
        corrs = [i for i in insights if i.kind == "correlation"]
        assert len(corrs) >= 1
        assert corrs[0].confidence >= 0.5

    def test_insights_sorted_by_confidence(self):
        entries = [
            LogEntry(raw=f"ERROR something {i}", message=f"something {i}",
                     severity=Severity.ERROR, line_number=i + 1)
            for i in range(5)
        ]
        insights = self.extractor.extract(entries)
        confidences = [i.confidence for i in insights]
        assert confidences == sorted(confidences, reverse=True)


# ── Integration ─────────────────────────────────────────────────────

class TestIntegration:
    """End-to-end pipeline test."""

    def test_full_pipeline(self):
        lines = [
            "2026-05-26 10:00:00 INFO Application started",
            "2026-05-26 10:00:01 WARNING Slow query detected: SELECT * FROM users",
            "2026-05-26 10:00:02 ERROR Database connection refused to 10.0.0.1:5432",
            "2026-05-26 10:00:03 ERROR Failed to reconnect to database",
            "2026-05-26 10:00:04 CRITICAL Service unavailable - all retries exhausted",
            "2026-05-26 10:00:05 ERROR Database connection refused to 10.0.0.1:5432",
            "2026-05-26 10:00:06 ERROR Database connection refused to 10.0.0.1:5432",
        ]

        analyzer = LogAnalyzer()
        classifier = LogClassifier()
        summarizer = LogSummarizer()
        extractor = InsightExtractor()

        # Parse
        entries = analyzer.parse_lines(lines)
        assert len(entries) == 7

        # Classify
        entries = classifier.classify_all(entries)
        db_entries = [e for e in entries if e.category == LogCategory.DATABASE]
        assert len(db_entries) >= 2

        # Anomaly detection
        reports = analyzer.analyze(entries)
        anomalies = [r for r in reports if r.is_anomaly]
        assert len(anomalies) >= 1

        # Summary
        summary = summarizer.summarize(entries)
        assert summary.total_entries == 7
        assert summary.anomaly_count >= 1

        # Insights
        insights = extractor.extract(entries, reports)
        assert len(insights) >= 1

    def test_import_all(self):
        """Verify all public exports are importable."""
        from activelog_claude import (
            AnalyzerConfig, LogAnalyzer, LogSummarizer,
            LogClassifier, InsightExtractor,
        )
        assert AnalyzerConfig is not None
        assert LogAnalyzer is not None
