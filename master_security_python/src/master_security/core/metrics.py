"""
Master Security Framework - Prometheus Metrics Engine
=====================================================

Native Prometheus metrics for all security operations.
Provides counters, histograms, and gauges for observability.

Metrics exposed:
    - msf_requests_total: Total requests processed
    - msf_threats_detected_total: Threats detected by category
    - msf_auth_attempts_total: Authentication attempts
    - msf_auth_failures_total: Authentication failures
    - msf_validation_duration_seconds: Validation latency
    - msf_crypto_operations_total: Cryptographic operations
    - msf_rate_limit_hits_total: Rate limit triggers
    - msf_active_sessions: Current active sessions
    - msf_policy_violations_total: Policy violations
    - msf_alerts_triggered_total: Security alerts

Usage:
    >>> from master_security.core import get_metrics
    >>> metrics = get_metrics()
    >>> metrics.inc_counter("auth_attempts", user_type="premium")
"""

from __future__ import annotations

import threading
from typing import Any, Optional

from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry

from master_security.core.logger import get_logger

logger = get_logger("msf.metrics")


class MetricsRegistry:
    """
    Prometheus metrics registry for MSF.

    Thread-safe metrics collection with automatic labeling.

    Attributes:
        registry: Prometheus CollectorRegistry
        prefix: Metric name prefix

    Example:
        >>> registry = MetricsRegistry()
        >>> registry.inc_counter("requests", method="GET")
    """

    def __init__(
        self,
        prefix: str = "msf",
        registry: Optional[CollectorRegistry] = None,
    ) -> None:
        self.prefix = prefix
        self.registry = registry or CollectorRegistry()
        self._counters: dict[str, Counter] = {}
        self._histograms: dict[str, Histogram] = {}
        self._gauges: dict[str, Gauge] = {}
        self._lock = threading.Lock()

    def _counter_name(self, name: str) -> str:
        return f"{self.prefix}_{name}_total"

    def inc_counter(
        self,
        name: str,
        value: float = 1.0,
        labels: Optional[dict[str, str]] = None,
    ) -> None:
        """
        Increment a counter metric.

        Args:
            name: Metric name (without prefix)
            value: Amount to increment
            labels: Optional label key-value pairs
        """
        full_name = self._counter_name(name)
        if full_name not in self._counters:
            with self._lock:
                if full_name not in self._counters:
                    self._counters[full_name] = Counter(
                        full_name,
                        f"MSF {name} total",
                        labelnames=sorted(labels.keys()) if labels else [],
                        registry=self.registry,
                    )
        if labels:
            self._counters[full_name].labels(**labels).inc(value)
        else:
            self._counters[full_name].inc(value)

    def observe_histogram(
        self,
        name: str,
        value: float,
        labels: Optional[dict[str, str]] = None,
    ) -> None:
        """
        Record a histogram observation.

        Args:
            name: Metric name
            value: Observed value
            labels: Optional labels
        """
        full_name = f"{self.prefix}_{name}_seconds"
        if full_name not in self._histograms:
            with self._lock:
                if full_name not in self._histograms:
                    self._histograms[full_name] = Histogram(
                        full_name,
                        f"MSF {name} duration",
                        labelnames=sorted(labels.keys()) if labels else [],
                        buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
                        registry=self.registry,
                    )
        if labels:
            self._histograms[full_name].labels(**labels).observe(value)
        else:
            self._histograms[full_name].observe(value)

    def set_gauge(
        self,
        name: str,
        value: float,
        labels: Optional[dict[str, str]] = None,
    ) -> None:
        """
        Set a gauge metric.

        Args:
            name: Metric name
            value: Gauge value
            labels: Optional labels
        """
        full_name = f"{self.prefix}_{name}"
        if full_name not in self._gauges:
            with self._lock:
                if full_name not in self._gauges:
                    self._gauges[full_name] = Gauge(
                        full_name,
                        f"MSF {name}",
                        labelnames=sorted(labels.keys()) if labels else [],
                        registry=self.registry,
                    )
        if labels:
            self._gauges[full_name].labels(**labels).set(value)
        else:
            self._gauges[full_name].set(value)

    def inc_gauge(
        self,
        name: str,
        value: float = 1.0,
        labels: Optional[dict[str, str]] = None,
    ) -> None:
        """Increment a gauge metric."""
        full_name = f"{self.prefix}_{name}"
        if full_name not in self._gauges:
            self.set_gauge(name, 0, labels)
        if labels:
            self._gauges[full_name].labels(**labels).inc(value)
        else:
            self._gauges[full_name].inc(value)

    def dec_gauge(
        self,
        name: str,
        value: float = 1.0,
        labels: Optional[dict[str, str]] = None,
    ) -> None:
        """Decrement a gauge metric."""
        full_name = f"{self.prefix}_{name}"
        if full_name in self._gauges:
            if labels:
                self._gauges[full_name].labels(**labels).dec(value)
            else:
                self._gauges[full_name].dec(value)

    def get_metrics_text(self) -> str:
        """Get all metrics as Prometheus text format."""
        from prometheus_client import generate_latest
        return generate_latest(self.registry).decode("utf-8")


_global_metrics: MetricsRegistry | None = None
_metrics_lock = threading.Lock()


def get_metrics() -> MetricsRegistry:
    """
    Get the global metrics registry.

    Returns:
        Global MetricsRegistry instance.
    """
    global _global_metrics
    if _global_metrics is None:
        with _metrics_lock:
            if _global_metrics is None:
                _global_metrics = MetricsRegistry()
                logger.info("msf.metrics.initialized")
    return _global_metrics
