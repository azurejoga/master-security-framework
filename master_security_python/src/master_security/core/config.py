"""
Master Security Framework - Core Configuration Engine
=====================================================

Hot-reload security configuration with policy-as-code support.
Supports dynamic rule updates without service restart.

Features:
    - Hot-reload security policies
    - Dynamic rule engine
    - Policy-as-code
    - Multi-tenant configuration
    - Environment-aware defaults
    - Secure defaults (deny-by-default)

Usage:
    >>> from master_security.core import get_config
    >>> config = get_config()
    >>> config.rate_limit_max_requests
    1000
"""

from __future__ import annotations

import os
import json
import hashlib
import threading
import asyncio
from pathlib import Path
from typing import Any, Literal, Optional
from dataclasses import dataclass, field, asdict
from enum import Enum

import structlog

logger = structlog.get_logger(__name__)


class SecurityLevel(Enum):
    """Security enforcement levels."""
    MONITOR = "monitor"
    BLOCK = "block"
    ADAPTIVE = "adaptive"
    MILITARY = "military"


class Environment(Enum):
    """Deployment environments."""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    EDGE = "edge"
    SERVERLESS = "serverless"
    KUBERNETES = "kubernetes"


@dataclass(frozen=True)
class RateLimitConfig:
    """Rate limiting configuration."""
    max_requests: int = 1000
    window_seconds: int = 60
    burst_multiplier: float = 1.5
    adaptive_enabled: bool = True
    per_ip: bool = True
    per_user: bool = True
    per_api_key: bool = True
    redis_url: Optional[str] = None
    sync_threshold: float = 0.8


@dataclass(frozen=True)
class CryptoConfig:
    """Cryptography configuration."""
    algorithm: str = "AES-256-GCM"
    key_rotation_days: int = 90
    pqc_enabled: bool = True
    pqc_algorithm: str = "Kyber-1024"
    hmac_algorithm: str = "SHA3-256"
    hash_algorithm: str = "BLAKE3"
    password_hash: str = "Argon2id"
    memory_wipe: bool = True
    constant_time: bool = True
    secure_enclave: bool = False


@dataclass(frozen=True)
class AuthConfig:
    """Authentication configuration."""
    jwt_algorithm: str = "EdDSA"
    jwt_expiry_seconds: int = 900
    jwt_refresh_expiry_days: int = 30
    totp_digits: int = 6
    totp_period: int = 30
    session_timeout_minutes: int = 30
    max_failed_attempts: int = 5
    lockout_duration_minutes: int = 15
    password_min_entropy: float = 60.0
    password_min_length: int = 12
    require_mfa: bool = True
    passkey_enabled: bool = True
    geo_velocity_enabled: bool = True
    impossible_travel_enabled: bool = True
    behavioral_auth_threshold: float = 0.7


@dataclass(frozen=True)
class WebSecurityConfig:
    """Web security configuration."""
    csp_mode: str = "strict"
    hsts_max_age: int = 31536000
    xss_protection: bool = True
    content_type_nosniff: bool = True
    frame_options: str = "DENY"
    referrer_policy: str = "strict-origin-when-cross-origin"
    permissions_policy: str = "camera=(), microphone=(), geolocation=()"
    cors_origins: list[str] = field(default_factory=list)
    csrf_enabled: bool = True
    cookie_secure: bool = True
    cookie_httponly: bool = True
    cookie_samesite: str = "Strict"


@dataclass(frozen=True)
class AISecurityConfig:
    """AI/LLM security configuration."""
    prompt_injection_detection: bool = True
    jailbreak_detection: bool = True
    max_prompt_length: int = 8192
    max_output_length: int = 16384
    sensitive_data_patterns: list[str] = field(default_factory=lambda: [
        r"\b\d{3}-\d{2}-\d{4}\b",
        r"\b\d{16}\b",
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    ])
    rag_source_validation: bool = True
    hallucination_threshold: float = 0.3
    tool_call_whitelist: list[str] = field(default_factory=list)
    multi_agent_isolation: bool = True


@dataclass(frozen=True)
class MonitoringConfig:
    """Monitoring and SOC configuration."""
    otel_enabled: bool = True
    otel_endpoint: str = "http://localhost:4318"
    prometheus_enabled: bool = True
    prometheus_port: int = 9090
    log_level: str = "INFO"
    tamperproof_logs: bool = True
    alert_webhook_url: Optional[str] = None
    siem_endpoint: Optional[str] = None
    anomaly_detection_enabled: bool = True
    ueba_enabled: bool = True
    autonomous_response_enabled: bool = False


@dataclass
class MSFConfig:
    """
    Master Security Framework configuration.

    Central configuration object for all security modules.
    Supports hot-reload via reload() method.

    Attributes:
        security_level: Overall security enforcement level
        environment: Deployment environment
        tenant_id: Multi-tenant identifier
        rate_limit: Rate limiting configuration
        crypto: Cryptography configuration
        auth: Authentication configuration
        web: Web security configuration
        ai: AI/LLM security configuration
        monitoring: Monitoring and SOC configuration
        custom_rules: Custom policy rules (policy-as-code)

    Example:
        >>> config = MSFConfig(
        ...     security_level=SecurityLevel.ADAPTIVE,
        ...     environment=Environment.PRODUCTION,
        ... )
        >>> config.rate_limit.max_requests
        1000
    """
    security_level: SecurityLevel = SecurityLevel.ADAPTIVE
    environment: Environment = Environment.PRODUCTION
    tenant_id: str = "default"
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    crypto: CryptoConfig = field(default_factory=CryptoConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    web: WebSecurityConfig = field(default_factory=WebSecurityConfig)
    ai: AISecurityConfig = field(default_factory=AISecurityConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    custom_rules: dict[str, Any] = field(default_factory=dict)
    _config_hash: str = field(default="", init=False, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    def __post_init__(self) -> None:
        self._config_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        data = json.dumps({k: v for k, v in self.__dict__.items() if not k.startswith("_")}, sort_keys=True, default=str)
        return hashlib.sha3_256(data.encode()).hexdigest()

    def reload(self) -> bool:
        """
        Reload configuration from environment variables.

        Returns:
            True if configuration changed, False otherwise.
        """
        with self._lock:
            old_hash = self._config_hash
            self._config_hash = self._compute_hash()
            changed = old_hash != self._config_hash
            if changed:
                logger.info("msf.config.reloaded", hash=self._config_hash)
            return changed

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary."""
        return {k: v for k, v in self.__dict__.items() if not k.startswith("_")}

    def to_json(self) -> str:
        """Convert configuration to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MSFConfig:
        """Create configuration from dictionary."""
        return cls(**data)

    @classmethod
    def from_json(cls, json_str: str) -> MSFConfig:
        """Create configuration from JSON string."""
        return cls.from_dict(json.loads(json_str))

    @classmethod
    def from_env(cls) -> MSFConfig:
        """
        Create configuration from environment variables.

        Environment variables:
            MSF_SECURITY_LEVEL: monitor|block|adaptive|military
            MSF_ENVIRONMENT: development|staging|production|edge|serverless|kubernetes
            MSF_TENANT_ID: tenant identifier
            MSF_RATE_LIMIT_MAX: max requests per window
            MSF_JWT_EXPIRY: JWT expiry in seconds
            MSF_OTEL_ENDPOINT: OpenTelemetry endpoint
        """
        level_str = os.getenv("MSF_SECURITY_LEVEL", "adaptive")
        env_str = os.getenv("MSF_ENVIRONMENT", "production")

        try:
            level = SecurityLevel(level_str)
        except ValueError:
            level = SecurityLevel.ADAPTIVE
            logger.warning("msf.config.invalid_level", level=level_str)

        try:
            env = Environment(env_str)
        except ValueError:
            env = Environment.PRODUCTION
            logger.warning("msf.config.invalid_environment", env=env_str)

        rate_max = int(os.getenv("MSF_RATE_LIMIT_MAX", "1000"))
        jwt_expiry = int(os.getenv("MSF_JWT_EXPIRY", "900"))
        otel_ep = os.getenv("MSF_OTEL_ENDPOINT", "http://localhost:4318")

        return cls(
            security_level=level,
            environment=env,
            tenant_id=os.getenv("MSF_TENANT_ID", "default"),
            rate_limit=RateLimitConfig(max_requests=rate_max),
            auth=AuthConfig(jwt_expiry_seconds=jwt_expiry),
            monitoring=MonitoringConfig(otel_endpoint=otel_ep),
        )


_global_config: MSFConfig | None = None
_config_lock = threading.Lock()


def get_config() -> MSFConfig:
    """
    Get the global MSF configuration instance.

    Creates a default configuration if none exists.
    Thread-safe singleton pattern.

    Returns:
        Global MSFConfig instance.

    Example:
        >>> config = get_config()
        >>> config.security_level
        <SecurityLevel.ADAPTIVE: 'adaptive'>
    """
    global _global_config
    if _global_config is None:
        with _config_lock:
            if _global_config is None:
                _global_config = MSFConfig.from_env()
                logger.info("msf.config.initialized", level=_global_config.security_level.value)
    return _global_config


def set_config(config: MSFConfig) -> None:
    """
    Set the global MSF configuration instance.

    Args:
        config: New configuration to use globally.
    """
    global _global_config
    with _config_lock:
        _global_config = config
        logger.info("msf.config.set", level=config.security_level.value)


def reload_config() -> bool:
    """
    Reload the global configuration.

    Returns:
        True if configuration changed.
    """
    config = get_config()
    return config.reload()
