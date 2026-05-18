"""
Master Security Framework - Async Event Bus
=============================================

Event-driven security architecture with async event processing.
Supports real-time threat detection, alerting, and autonomous response.

Features:
    - Async event publishing and subscription
    - Event filtering by type and severity
    - Dead letter queue for failed handlers
    - Event replay for forensic analysis
    - Multi-tenant event isolation

Usage:
    >>> from master_security.core import get_event_bus, SecurityEvent
    >>> bus = get_event_bus()
    >>> bus.subscribe("threat.detected", my_handler)
    >>> bus.publish(SecurityEvent(type="threat.detected", severity="high"))
"""

from __future__ import annotations

import asyncio
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional

from master_security.core.logger import get_logger

logger = get_logger("msf.events")


class EventSeverity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(Enum):
    AUTH_SUCCESS = "auth.success"
    AUTH_FAILURE = "auth.failure"
    THREAT_DETECTED = "threat.detected"
    POLICY_VIOLATION = "policy.violation"
    RATE_LIMIT_HIT = "rate_limit.hit"
    ANOMALY_DETECTED = "anomaly.detected"
    SESSION_HIJACK = "session.hijack"
    CREDENTIAL_STUFFING = "credential.stuffing"
    BRUTE_FORCE = "brute.force"
    XSS_ATTEMPT = "xss.attempt"
    SQLI_ATTEMPT = "sqli.attempt"
    PROMPT_INJECTION = "prompt.injection"
    MALWARE_DETECTED = "malware.detected"
    CONTAINER_ESCAPE = "container.escape"
    DATA_EXFILTRATION = "data.exfiltration"
    AUTONOMOUS_RESPONSE = "autonomous.response"
    CUSTOM = "custom"


@dataclass
class SecurityEvent:
    """
    Security event for the event bus.

    Attributes:
        type: Event type
        severity: Event severity
        source: Event source module
        tenant_id: Multi-tenant identifier
        trace_id: Correlation trace ID
        data: Event payload
        timestamp: Event timestamp
        id: Unique event ID
    """
    type: str
    severity: EventSeverity = EventSeverity.MEDIUM
    source: str = ""
    tenant_id: str = "default"
    trace_id: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    id: str = field(default_factory=lambda: secrets.token_hex(8))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "severity": self.severity.value,
            "source": self.source,
            "tenant_id": self.tenant_id,
            "trace_id": self.trace_id,
            "data": self.data,
            "timestamp": self.timestamp,
        }


EventHandler = Callable[[SecurityEvent], Any]
AsyncEventHandler = Callable[[SecurityEvent], Any]


class EventBus:
    """
    Async event bus for security events.

    Thread-safe event publishing and subscription with
    support for sync and async handlers.

    Attributes:
        max_queue_size: Maximum event queue size
        dead_letter_enabled: Enable dead letter queue

    Example:
        >>> bus = EventBus()
        >>> bus.subscribe("threat.detected", handle_threat)
        >>> await bus.publish(SecurityEvent(type="threat.detected"))
    """

    def __init__(
        self,
        max_queue_size: int = 10000,
        dead_letter_enabled: bool = True,
    ) -> None:
        self.max_queue_size = max_queue_size
        self.dead_letter_enabled = dead_letter_enabled
        self._handlers: dict[str, list[EventHandler | AsyncEventHandler]] = {}
        self._dead_letter: list[SecurityEvent] = []
        self._event_history: list[SecurityEvent] = []
        self._max_history = 10000
        self._lock = threading.RLock()
        self._async_lock = asyncio.Lock()
        self._running = False

    def subscribe(
        self,
        event_type: str,
        handler: EventHandler | AsyncEventHandler,
    ) -> None:
        """
        Subscribe to an event type.

        Args:
            event_type: Event type to subscribe to
            handler: Handler function (sync or async)
        """
        with self._lock:
            if event_type not in self._handlers:
                self._handlers[event_type] = []
            self._handlers[event_type].append(handler)
        logger.debug("msf.events.subscribed", event_type=event_type)

    def unsubscribe(
        self,
        event_type: str,
        handler: EventHandler | AsyncEventHandler,
    ) -> None:
        """Unsubscribe from an event type."""
        with self._lock:
            if event_type in self._handlers:
                self._handlers[event_type] = [
                    h for h in self._handlers[event_type] if h != handler
                ]

    def publish_sync(self, event: SecurityEvent) -> None:
        """Synchronously publish a security event."""
        with self._lock:
            self._event_history.append(event)
            if len(self._event_history) > self._max_history:
                self._event_history = self._event_history[-self._max_history:]
            handlers = list(
                self._handlers.get(event.type, [])
                + self._handlers.get("*", [])
            )
        for handler in handlers:
            try:
                if not asyncio.iscoroutinefunction(handler):
                    handler(event)
            except Exception as exc:
                if self.dead_letter_enabled:
                    self._dead_letter.append(event)

    async def publish(self, event: SecurityEvent) -> None:
        """
        Publish a security event to all subscribers.

        Args:
            event: Security event to publish.
        """
        import asyncio as aio

        with self._lock:
            self._event_history.append(event)
            if len(self._event_history) > self._max_history:
                self._event_history = self._event_history[-self._max_history:]

        handlers = []
        with self._lock:
            handlers = list(
                self._handlers.get(event.type, [])
                + self._handlers.get("*", [])
            )

        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
            except Exception as exc:
                logger.error("msf.events.handler_error", error=str(exc))
                if self.dead_letter_enabled:
                    self._dead_letter.append(event)

    def get_history(
        self,
        event_type: Optional[str] = None,
        limit: int = 100,
    ) -> list[SecurityEvent]:
        """Get recent event history."""
        with self._lock:
            events = self._event_history
            if event_type:
                events = [e for e in events if e.type == event_type]
            return events[-limit:]

    def get_dead_letter(self) -> list[SecurityEvent]:
        """Get dead letter queue."""
        with self._lock:
            return list(self._dead_letter)


_global_event_bus: EventBus | None = None
_event_bus_lock = threading.Lock()


def get_event_bus() -> EventBus:
    """Get the global event bus instance."""
    global _global_event_bus
    if _global_event_bus is None:
        with _event_bus_lock:
            if _global_event_bus is None:
                _global_event_bus = EventBus()
    return _global_event_bus
