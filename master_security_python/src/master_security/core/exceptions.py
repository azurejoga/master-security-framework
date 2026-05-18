"""
Master Security Framework - Exception Hierarchy
================================================

Typed exception hierarchy for all security operations.
Each exception includes security context for tracing and alerting.

Exception Hierarchy:
    MSFError
    +-- SecurityError
    |   +-- AuthenticationError
    |   +-- AuthorizationError
    |   +-- ValidationError
    |   +-- CryptographyError
    |   +-- RateLimitError
    |   +-- TimeoutError
    |   +-- PolicyViolationError
    |   +-- ThreatDetectedError
    +-- ConfigurationError
    +-- PluginError

Usage:
    >>> from master_security.core import AuthenticationError
    >>> raise AuthenticationError("Invalid JWT", user_id="u123", severity="high")
"""

from __future__ import annotations

from typing import Any, Optional
from enum import Enum


class SeverityLevel(Enum):
    """Security event severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MSFError(Exception):
    """
    Base exception for all Master Security Framework errors.

    Attributes:
        message: Human-readable error message
        code: Machine-readable error code
        severity: Security severity level
        context: Additional context dictionary
        trace_id: Unique trace identifier
    """

    def __init__(
        self,
        message: str,
        code: str = "MSF_ERROR",
        severity: SeverityLevel = SeverityLevel.MEDIUM,
        context: Optional[dict[str, Any]] = None,
        trace_id: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.severity = severity
        self.context = context or {}
        self.trace_id = trace_id or ""
        self.context["error_code"] = code
        self.context["severity"] = severity.value

    def to_dict(self) -> dict[str, Any]:
        """Convert exception to dictionary for logging."""
        return {
            "error": self.__class__.__name__,
            "message": self.message,
            "code": self.code,
            "severity": self.severity.value,
            "context": self.context,
            "trace_id": self.trace_id,
        }


class SecurityError(MSFError):
    """Base exception for security-related errors."""

    def __init__(
        self,
        message: str,
        code: str = "SECURITY_ERROR",
        severity: SeverityLevel = SeverityLevel.HIGH,
        context: Optional[dict[str, Any]] = None,
        trace_id: Optional[str] = None,
    ) -> None:
        super().__init__(message, code, severity, context, trace_id)


class AuthenticationError(SecurityError):
    """Authentication failure - invalid credentials, expired tokens, etc."""

    def __init__(
        self,
        message: str,
        code: str = "AUTH_ERROR",
        severity: SeverityLevel = SeverityLevel.HIGH,
        context: Optional[dict[str, Any]] = None,
        trace_id: Optional[str] = None,
    ) -> None:
        super().__init__(message, code, severity, context, trace_id)


class AuthorizationError(SecurityError):
    """Authorization failure - insufficient permissions, access denied."""

    def __init__(
        self,
        message: str,
        code: str = "AUTHZ_ERROR",
        severity: SeverityLevel = SeverityLevel.HIGH,
        context: Optional[dict[str, Any]] = None,
        trace_id: Optional[str] = None,
    ) -> None:
        super().__init__(message, code, severity, context, trace_id)


class ValidationError(SecurityError):
    """Input validation failure - malformed data, schema violations."""

    def __init__(
        self,
        message: str,
        code: str = "VALIDATION_ERROR",
        severity: SeverityLevel = SeverityLevel.MEDIUM,
        context: Optional[dict[str, Any]] = None,
        trace_id: Optional[str] = None,
    ) -> None:
        super().__init__(message, code, severity, context, trace_id)


class CryptographyError(SecurityError):
    """Cryptographic operation failure - encryption, decryption, signing."""

    def __init__(
        self,
        message: str,
        code: str = "CRYPTO_ERROR",
        severity: SeverityLevel = SeverityLevel.CRITICAL,
        context: Optional[dict[str, Any]] = None,
        trace_id: Optional[str] = None,
    ) -> None:
        super().__init__(message, code, severity, context, trace_id)


class RateLimitError(SecurityError):
    """Rate limit exceeded."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        code: str = "RATE_LIMIT",
        severity: SeverityLevel = SeverityLevel.MEDIUM,
        context: Optional[dict[str, Any]] = None,
        trace_id: Optional[str] = None,
        retry_after: int = 60,
    ) -> None:
        super().__init__(message, code, severity, context, trace_id)
        self.retry_after = retry_after
        self.context["retry_after"] = retry_after


class TimeoutError(SecurityError):
    """Operation timeout - security operation took too long."""

    def __init__(
        self,
        message: str = "Security operation timeout",
        code: str = "TIMEOUT",
        severity: SeverityLevel = SeverityLevel.MEDIUM,
        context: Optional[dict[str, Any]] = None,
        trace_id: Optional[str] = None,
        timeout_ms: int = 5000,
    ) -> None:
        super().__init__(message, code, severity, context, trace_id)
        self.timeout_ms = timeout_ms
        self.context["timeout_ms"] = timeout_ms


class PolicyViolationError(SecurityError):
    """Security policy violation detected."""

    def __init__(
        self,
        message: str,
        code: str = "POLICY_VIOLATION",
        severity: SeverityLevel = SeverityLevel.HIGH,
        context: Optional[dict[str, Any]] = None,
        trace_id: Optional[str] = None,
        policy_name: str = "",
    ) -> None:
        super().__init__(message, code, severity, context, trace_id)
        self.policy_name = policy_name
        self.context["policy_name"] = policy_name


class ThreatDetectedError(SecurityError):
    """Active threat detected - requires immediate action."""

    def __init__(
        self,
        message: str,
        code: str = "THREAT_DETECTED",
        severity: SeverityLevel = SeverityLevel.CRITICAL,
        context: Optional[dict[str, Any]] = None,
        trace_id: Optional[str] = None,
        threat_type: str = "unknown",
        mitre_technique: str = "",
    ) -> None:
        super().__init__(message, code, severity, context, trace_id)
        self.threat_type = threat_type
        self.mitre_technique = mitre_technique
        self.context["threat_type"] = threat_type
        self.context["mitre_technique"] = mitre_technique


class ConfigurationError(MSFError):
    """Configuration error - invalid or missing configuration."""

    def __init__(
        self,
        message: str,
        code: str = "CONFIG_ERROR",
        context: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code, SeverityLevel.HIGH, context)


class PluginError(MSFError):
    """Plugin error - plugin load, execution, or compatibility failure."""

    def __init__(
        self,
        message: str,
        code: str = "PLUGIN_ERROR",
        context: Optional[dict[str, Any]] = None,
        plugin_name: str = "",
    ) -> None:
        super().__init__(message, code, SeverityLevel.HIGH, context)
        self.plugin_name = plugin_name
        self.context["plugin_name"] = plugin_name
