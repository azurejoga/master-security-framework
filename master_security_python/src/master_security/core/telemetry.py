"""
Master Security Framework - OpenTelemetry Tracing Engine
=========================================================

Native OpenTelemetry integration for distributed tracing
of all security operations.

Features:
    - Automatic span creation for security operations
    - Security context propagation
    - Error recording with security attributes
    - Correlation with structured logs
    - MITRE ATT&CK technique tagging

Usage:
    >>> from master_security.core import get_telemetry, create_span
    >>> telemetry = get_telemetry()
    >>> with create_span("validate_jwt") as span:
    ...     result = validate_jwt(token)
"""

from __future__ import annotations

import os

import secrets
from contextlib import contextmanager
from typing import Any, Generator, Optional

from opentelemetry import trace, context
from opentelemetry.trace import Span, Status, StatusCode, TracerProvider
from opentelemetry.sdk.trace import TracerProvider as SDKTracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    SpanExporter,
    ConsoleSpanExporter,
)
from opentelemetry.sdk.resources import Resource

from master_security.core.logger import get_logger

logger = get_logger("msf.telemetry")

MSF_SERVICE_NAME = "master-security-framework"
MSF_SERVICE_VERSION = "1.0.0"


class TelemetryManager:
    """
    OpenTelemetry manager for MSF.

    Provides tracer instances and span utilities for
    all security operations.

    Attributes:
        service_name: Service name for telemetry
        endpoint: OTLP exporter endpoint
        enabled: Whether telemetry is enabled

    Example:
        >>> tm = TelemetryManager()
        >>> with tm.start_span("auth.validate_jwt") as span:
        ...     span.set_attribute("user.id", "u123")
    """

    def __init__(
        self,
        service_name: str = MSF_SERVICE_NAME,
        endpoint: str = "http://localhost:4318",
        enabled: bool = None,
    ) -> None:
        self.service_name = service_name
        self.endpoint = endpoint
        self.enabled = enabled if enabled is not None else os.getenv("MSF_OTEL_ENABLED", "true").lower() != "false"
        self._tracer = trace.get_tracer(service_name, MSF_SERVICE_VERSION)

        if enabled:
            resource = Resource.create({
                "service.name": service_name,
                "service.version": MSF_SERVICE_VERSION,
                "telemetry.sdk.name": "msf",
                "telemetry.sdk.language": "python",
            })
            provider = SDKTracerProvider(resource=resource)
            provider.add_span_processor(
                BatchSpanProcessor(ConsoleSpanExporter())
            )
            trace.set_tracer_provider(provider)
            self._tracer = trace.get_tracer(service_name, MSF_SERVICE_VERSION)
            logger.info("msf.telemetry.initialized", endpoint=endpoint)

    @contextmanager
    def start_span(
        self,
        name: str,
        attributes: Optional[dict[str, Any]] = None,
    ) -> Generator[Span, None, None]:
        """
        Start a new security operation span.

        Args:
            name: Span name (e.g., "auth.validate_jwt")
            attributes: Optional span attributes

        Yields:
            Active Span object.
        """
        if not self.enabled:
            class _DummySpan:
                def set_attribute(self, *a, **kw): pass
                def set_status(self, *a, **kw): pass
                def record_exception(self, *a, **kw): pass
                def is_recording(self): return False
                def add_event(self, *a, **kw): pass
                def end(self): pass
            yield _DummySpan()
            return

        with self._tracer.start_as_current_span(name) as span:
            span.set_attribute("msf.operation", name)
            span.set_attribute("msf.version", MSF_SERVICE_VERSION)
            if attributes:
                for key, value in attributes.items():
                    span.set_attribute(key, value)
            try:
                yield span
                span.set_status(Status(StatusCode.OK))
            except Exception as exc:
                span.set_status(Status(StatusCode.ERROR, str(exc)))
                span.record_exception(exc)
                raise

    def create_security_span(
        self,
        operation: str,
        severity: str = "info",
        mitre_technique: str = "",
        threat_type: str = "",
        **kwargs: Any,
    ) -> Span:
        """
        Create a security-specific span with MITRE ATT&CK context.

        Args:
            operation: Security operation name
            severity: Event severity
            mitre_technique: MITRE ATT&CK technique ID
            threat_type: Detected threat type
            **kwargs: Additional attributes

        Returns:
            Created Span object.
        """
        span = self._tracer.start_span(f"msf.security.{operation}")
        span.set_attribute("msf.operation", operation)
        span.set_attribute("msf.severity", severity)
        if mitre_technique:
            span.set_attribute("mitre.technique", mitre_technique)
        if threat_type:
            span.set_attribute("msf.threat_type", threat_type)
        for key, value in kwargs.items():
            span.set_attribute(f"msf.{key}", str(value))
        return span

    def get_trace_id(self) -> str:
        """Get current trace ID or generate new one."""
        current = trace.get_current_span()
        if current and current.get_span_context().trace_id:
            return format(current.get_span_context().trace_id, "032x")
        return secrets.token_hex(16)


_global_telemetry: TelemetryManager | None = None
_telemetry_lock = __import__("threading").Lock()


def get_telemetry() -> TelemetryManager:
    """
    Get the global telemetry manager.

    Returns:
        Global TelemetryManager instance.
    """
    global _global_telemetry
    if _global_telemetry is None:
        with _telemetry_lock:
            if _global_telemetry is None:
                _global_telemetry = TelemetryManager()
    return _global_telemetry


@contextmanager
def create_span(
    name: str,
    attributes: Optional[dict[str, Any]] = None,
) -> Generator[Span, None, None]:
    """
    Convenience context manager for creating spans.

    Args:
        name: Span name
        attributes: Optional attributes

    Yields:
        Active Span.

    Example:
        >>> with create_span("auth.login") as span:
        ...     span.set_attribute("user.id", "u123")
    """
    telemetry = get_telemetry()
    with telemetry.start_span(name, attributes) as span:
        yield span
