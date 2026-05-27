"""LogClassifier — categorize log entries by severity and type."""

import re
from typing import List, Optional

from .config import AnalyzerConfig
from .models import LogEntry, LogCategory, Severity


# Category detection patterns (compiled once)
_CATEGORY_RULES: list = [
    # (category, keywords, regex_patterns)
    (LogCategory.AUTH, (
        "login", "logout", "auth", "credential", "token", "session",
        "password", "oauth", "saml", "ldap", "sso", "mfa",
    ), (r"user\s+\w+\s+(logged|signed|auth)",)),

    (LogCategory.NETWORK, (
        "connection", "socket", "tcp", "udp", "dns", "http",
        "request", "response", "latency", "bandwidth", "packet",
        "refused", "reset", "timeout", "listen", "bind",
    ), (r"(GET|POST|PUT|DELETE|PATCH)\s+/", r"\d{1,3}(\.\d{1,3}){3}:\d+")),

    (LogCategory.DATABASE, (
        "query", "sql", "database", "db", "transaction", "rollback",
        "commit", "deadlock", "migration", "connection pool",
        "postgres", "mysql", "sqlite", "mongo", "redis",
    ), (r"SELECT\s+", r"INSERT\s+", r"UPDATE\s+", r"DELETE\s+")),

    (LogCategory.SECURITY, (
        "firewall", "intrusion", "attack", "exploit", "vulnerability",
        "breach", "malware", "suspicious", "blocklist", "waf",
    ), (r"CVE-\d{4}-\d+",)),

    (LogCategory.INFRASTRUCTURE, (
        "cpu", "memory", "disk", "load", "container", "pod", "node",
        "kubernetes", "docker", "vm", "hypervisor", "provision",
        "deploy", "scaling", "replica", "healthcheck", "heartbeat",
    ), ()),

    (LogCategory.SYSTEM, (
        "kernel", "systemd", "init", "boot", "mount", "fsck",
        "cron", "syslog", "udev", "selinux", "apparmor", "oom",
    ), (r"OUT OF MEMORY", r"oom-killer")),
]


class LogClassifier:
    """Classify log entries by severity and category."""

    def __init__(self, config: Optional[AnalyzerConfig] = None):
        self.config = config or AnalyzerConfig()
        self._compiled_regexes: dict = {}
        for category, _, patterns in _CATEGORY_RULES:
            self._compiled_regexes[category] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

    def classify(self, entry: LogEntry) -> LogEntry:
        """Classify a single entry, mutating and returning it."""
        entry.category = self._detect_category(entry)
        if entry.severity == Severity.INFO:
            entry.severity = self._refine_severity(entry)
        return entry

    def classify_all(self, entries: List[LogEntry]) -> List[LogEntry]:
        """Classify all entries."""
        return [self.classify(e) for e in entries]

    def _detect_category(self, entry: LogEntry) -> LogCategory:
        lower = entry.raw.lower()

        for category, keywords, _ in _CATEGORY_RULES:
            # Check regex patterns first (higher confidence)
            for pat in self._compiled_regexes[category]:
                if pat.search(entry.raw):
                    return category
            # Check keywords
            for kw in keywords:
                if kw in lower:
                    return category

        return LogCategory.APPLICATION

    def _refine_severity(self, entry: LogEntry) -> Severity:
        """Refine severity based on category-specific rules."""
        lower = entry.raw.lower()

        # Security entries default higher
        if entry.category == LogCategory.SECURITY:
            if any(kw in lower for kw in ("attack", "breach", "exploit")):
                return Severity.CRITICAL
            return Severity.WARNING

        # Auth failures
        if entry.category == LogCategory.AUTH:
            if "fail" in lower or "denied" in lower or "invalid" in lower:
                return Severity.WARNING

        return entry.severity
