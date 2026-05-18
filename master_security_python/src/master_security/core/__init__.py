"""
Master Security Framework - Core Infrastructure
=================================================

Foundation modules: config, logging, metrics, telemetry, events, policy, cache.
"""

from master_security.core.config import MSFConfig, get_config, set_config, reload_config
from master_security.core.logger import get_logger, MSFLogger, TamperProofChain
from master_security.core.metrics import MetricsRegistry, get_metrics
from master_security.core.telemetry import TelemetryManager, get_telemetry, create_span
from master_security.core.events import EventBus, SecurityEvent, EventSeverity, EventType, get_event_bus
from master_security.core.policy import PolicyEngine, PolicyRule, PolicyEvaluation, get_policy_engine
from master_security.core.cache import CacheManager, LRUCache, get_cache
from master_security.core.exceptions import (
    MSFError,
    SecurityError,
    AuthenticationError,
    AuthorizationError,
    ValidationError,
    CryptographyError,
    RateLimitError,
    TimeoutError,
    PolicyViolationError,
    ThreatDetectedError,
    ConfigurationError,
    PluginError,
    SeverityLevel,
)

__all__ = [
    "MSFConfig",
    "get_config",
    "set_config",
    "reload_config",
    "get_logger",
    "MSFLogger",
    "TamperProofChain",
    "MetricsRegistry",
    "get_metrics",
    "TelemetryManager",
    "get_telemetry",
    "create_span",
    "EventBus",
    "SecurityEvent",
    "EventSeverity",
    "EventType",
    "get_event_bus",
    "PolicyEngine",
    "PolicyRule",
    "PolicyEvaluation",
    "get_policy_engine",
    "CacheManager",
    "LRUCache",
    "get_cache",
    "MSFError",
    "SecurityError",
    "AuthenticationError",
    "AuthorizationError",
    "ValidationError",
    "CryptographyError",
    "RateLimitError",
    "TimeoutError",
    "PolicyViolationError",
    "ThreatDetectedError",
    "ConfigurationError",
    "PluginError",
    "SeverityLevel",
]
