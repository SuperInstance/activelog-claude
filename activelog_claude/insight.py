"""InsightExtractor — find correlations, root causes, and patterns in logs."""

from collections import defaultdict
from typing import Dict, List, Optional, Set

from .config import AnalyzerConfig
from .models import LogEntry, AnomalyReport, Insight, Severity, LogCategory
from .analyzer import LogAnalyzer


class InsightExtractor:
    """Extract correlations, root causes, and patterns from log data."""

    def __init__(self, config: Optional[AnalyzerConfig] = None):
        self.config = config or AnalyzerConfig()
        self.analyzer = LogAnalyzer(self.config)

    def extract(
        self,
        entries: List[LogEntry],
        anomaly_reports: Optional[List[AnomalyReport]] = None,
    ) -> List[Insight]:
        """Extract all insights from a set of log entries."""
        insights: List[Insight] = []

        if not entries:
            return insights

        if anomaly_reports is None:
            anomaly_reports = self.analyzer.analyze(entries)

        anomalies = [r for r in anomaly_reports if r.is_anomaly]

        insights.extend(self._find_error_cascades(entries, anomalies))
        insights.extend(self._find_category_correlations(entries))
        insights.extend(self._find_temporal_patterns(entries, anomalies))
        insights.extend(self._find_root_causes(entries, anomalies))

        # Sort by confidence descending
        insights.sort(key=lambda i: i.confidence, reverse=True)
        return insights

    def _find_error_cascades(
        self, entries: List[LogEntry], anomalies: List[AnomalyReport]
    ) -> List[Insight]:
        """Detect cascading errors — when one error is followed by others."""
        insights: List[Insight] = []
        error_indices = [
            i for i, e in enumerate(entries)
            if e.severity in (Severity.ERROR, Severity.CRITICAL)
        ]

        if len(error_indices) < 2:
            return insights

        # Find clusters of errors within 10 lines of each other
        clusters: List[List[int]] = []
        current_cluster = [error_indices[0]]

        for idx in error_indices[1:]:
            if idx - current_cluster[-1] <= 10:
                current_cluster.append(idx)
            else:
                if len(current_cluster) >= 2:
                    clusters.append(current_cluster)
                current_cluster = [idx]
        if len(current_cluster) >= 2:
            clusters.append(current_cluster)

        for cluster in clusters:
            related = [entries[i] for i in cluster]
            categories: Set[LogCategory] = {e.category for e in related}
            desc = (
                f"Cascade of {len(cluster)} errors across "
                f"{len(categories)} categories in lines {cluster[0]+1}–{cluster[-1]+1}"
            )
            insights.append(Insight(
                kind="pattern",
                confidence=0.7 + min(len(cluster) * 0.05, 0.25),
                description=desc,
                related_entries=related,
                metadata={"indices": cluster},
            ))

        return insights

    def _find_category_correlations(
        self, entries: List[LogEntry]
    ) -> List[Insight]:
        """Find categories that frequently co-occur with errors."""
        insights: List[Insight] = []

        # Count errors per category
        error_cats: Dict[LogCategory, int] = defaultdict(int)
        total_cats: Dict[LogCategory, int] = defaultdict(int)

        for entry in entries:
            total_cats[entry.category] += 1
            if entry.severity in (Severity.ERROR, Severity.CRITICAL):
                error_cats[entry.category] += 1

        for cat in total_cats:
            if cat == LogCategory.UNKNOWN:
                continue
            total = total_cats[cat]
            errors = error_cats.get(cat, 0)
            ratio = errors / total if total > 2 else 0.0

            if ratio >= self.config.correlation_threshold and total >= 3:
                insights.append(Insight(
                    kind="correlation",
                    confidence=min(ratio, 0.95),
                    description=(
                        f"Category '{cat.value}' has {ratio:.0%} error rate "
                        f"({errors}/{total} entries)"
                    ),
                    metadata={"category": cat.value, "error_ratio": ratio},
                ))

        return insights

    def _find_temporal_patterns(
        self, entries: List[LogEntry], anomalies: List[AnomalyReport]
    ) -> List[Insight]:
        """Detect bursts and temporal clustering of anomalies."""
        insights: List[Insight] = []

        bursts = self.analyzer.detect_bursts(entries)
        for burst in bursts:
            insights.append(Insight(
                kind="burst",
                confidence=0.6 + min(len(burst) * 0.05, 0.35),
                description=(
                    f"Burst of {len(burst)} similar messages around "
                    f"{burst[0].timestamp or 'unknown time'}"
                ),
                related_entries=burst,
            ))

        return insights

    def _find_root_causes(
        self, entries: List[LogEntry], anomalies: List[AnomalyReport]
    ) -> List[Insight]:
        """Heuristic root-cause detection: first error in a cascade."""
        insights: List[Insight] = []

        if not anomalies:
            return insights

        # Sort anomalies by line number
        sorted_anomalies = sorted(anomalies, key=lambda a: a.entry.line_number)

        # The first anomaly with high score is a candidate root cause
        for report in sorted_anomalies:
            if report.score >= 0.5 and report.entry.severity in (
                Severity.ERROR, Severity.CRITICAL
            ):
                # Check for earlier WARNING entries in same category
                earlier_warnings = [
                    e for e in entries
                    if e.line_number < report.entry.line_number
                    and e.category == report.entry.category
                    and e.severity == Severity.WARNING
                ]
                cause_desc = f"Potential root cause at line {report.entry.line_number}"
                if earlier_warnings:
                    cause_desc += (
                        f" — preceded by {len(earlier_warnings)} warning(s) "
                        f"in '{report.entry.category.value}'"
                    )

                insights.append(Insight(
                    kind="root_cause",
                    confidence=report.score * 0.8,
                    description=cause_desc,
                    related_entries=[report.entry] + earlier_warnings[:3],
                    metadata={"score": report.score},
                ))
                break  # Only report the first root cause candidate

        return insights
