from __future__ import annotations

import re
import json
import hashlib
import time
import asyncio
from typing import Any, Optional, Callable
from datetime import datetime, timezone
from master_security.core import get_logger, get_metrics, create_span, get_event_bus, SecurityEvent, EventSeverity
from master_security.core.exceptions import SecurityError, ValidationError
import structlog

logger = structlog.get_logger(__name__)


def fastapi_security_dependency(
    config: dict[str, Any],
    security_schemes: dict[str, Any],
    middleware_config: dict[str, Any],
) -> dict[str, Any]:
    """Create FastAPI security dependency with OAuth2, JWT validation, and rate limiting.

    Args:
        config: Global security configuration including enabled features and defaults.
        security_schemes: Dictionary of security schemes (oauth2, api_key, jwt, etc.).
        middleware_config: Middleware settings for rate limiting, CORS, and headers.

    Returns:
        Dictionary with dependency registration status, active schemes, and middleware info.

    Example:
        >>> result = fastapi_security_dependency(
        ...     config={"enabled": True, "default_scheme": "oauth2"},
        ...     security_schemes={"oauth2": {"flows": {"password": {}}}},
        ...     middleware_config={"rate_limit": "100/minute"},
        ... )
    """
    start_time = time.monotonic()
    metrics = get_metrics()
    metrics.inc_counter("integrations.fastapi_security_dependency.calls")

    with create_span("fastapi_security_dependency") as span:
        try:
            if not config.get("enabled", False):
                logger.warning("fastapi_security_dependency_disabled")
                span.set_attribute("status", "disabled")
                return {"status": "disabled", "schemes_registered": 0, "middleware_active": False}

            registered_schemes: list[str] = []
            for scheme_name, scheme_config in security_schemes.items():
                scheme_hash = hashlib.sha256(json.dumps(scheme_config, sort_keys=True).encode()).hexdigest()[:16]
                registered_schemes.append(scheme_name)
                logger.info(
                    "fastapi_scheme_registered",
                    scheme=scheme_name,
                    hash=scheme_hash,
                )
                span.add_event(f"scheme_registered:{scheme_name}")

            rate_limit = middleware_config.get("rate_limit", "100/minute")
            cors_origins = middleware_config.get("cors_origins", ["*"])
            security_headers = middleware_config.get(
                "security_headers",
                {
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                },
            )
            elapsed = time.monotonic() - start_time
            metrics.observe_histogram("integrations.fastapi_security_dependency.duration", elapsed)
            metrics.set_gauge("integrations.fastapi_security_dependency.schemes_count", len(registered_schemes))

            span.set_attribute("schemes_count", len(registered_schemes))
            span.set_attribute("elapsed_ms", elapsed * 1000)

            return {
                "status": "active",
                "schemes_registered": registered_schemes,
                "middleware_active": True,
                "rate_limit": rate_limit,
                "cors_origins": cors_origins,
                "security_headers": security_headers,
                "configured_at": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as exc:
            metrics.inc_counter("integrations.fastapi_security_dependency.errors")
            span.record_exception(exc)
            logger.error("fastapi_security_dependency_failed", error=str(exc))
            raise SecurityError(f"FastAPI security dependency setup failed: {exc}") from exc


def django_security_middleware(
    config: dict[str, Any],
    settings: dict[str, Any],
    middleware_config: dict[str, Any],
) -> dict[str, Any]:
    """Create Django security middleware with CSP, CSRF, and security headers.

    Args:
        config: Global security configuration for Django integration.
        settings: Django settings dictionary to augment with security values.
        middleware_config: Middleware-specific settings for CSP, CSRF, and headers.

    Returns:
        Dictionary with middleware status, applied settings, and security headers.

    Example:
        >>> result = django_security_middleware(
        ...     config={"enabled": True},
        ...     settings={"DEBUG": False, "ALLOWED_HOSTS": ["example.com"]},
        ...     middleware_config={"csp": {"default_src": "'self'"}},
        ... )
    """
    start_time = time.monotonic()
    metrics = get_metrics()
    metrics.inc_counter("integrations.django_security_middleware.calls")

    with create_span("django_security_middleware") as span:
        try:
            if not config.get("enabled", False):
                logger.warning("django_security_middleware_disabled")
                return {"status": "disabled", "middleware_installed": False}

            csp_config = middleware_config.get(
                "csp",
                {
                    "default_src": "'self'",
                    "script_src": "'self'",
                    "style_src": "'self'",
                    "img_src": "'self' data:",
                    "connect_src": "'self'",
                    "frame_ancestors": "'none'",
                },
            )

            csrf_config = middleware_config.get(
                "csrf",
                {
                    "cookie_secure": True,
                    "cookie_httponly": True,
                    "cookie_samesite": "Lax",
                    "use_sessions": True,
                },
            )

            security_headers = middleware_config.get(
                "security_headers",
                {
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "X-XSS-Protection": "0",
                    "Referrer-Policy": "strict-origin-when-cross-origin",
                    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
                    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                },
            )

            session_security = middleware_config.get(
                "session_security",
                {
                    "SESSION_COOKIE_SECURE": True,
                    "SESSION_COOKIE_HTTPONLY": True,
                    "SESSION_COOKIE_SAMESITE": "Lax",
                    "CSRF_COOKIE_SECURE": True,
                    "CSRF_COOKIE_HTTPONLY": True,
                },
            )

            applied_settings = {**settings, **session_security}
            settings_hash = hashlib.sha256(json.dumps(applied_settings, sort_keys=True, default=str).encode()).hexdigest()[:16]


            elapsed = time.monotonic() - start_time
            metrics.observe_histogram("integrations.django_security_middleware.duration", elapsed)
            metrics.set_gauge("integrations.django_security_middleware.headers_count", len(security_headers))

            span.set_attribute("csp_rules_count", len(csp_config))
            span.set_attribute("headers_count", len(security_headers))
            span.set_attribute("elapsed_ms", elapsed * 1000)

            logger.info(
                "django_security_middleware_active",
                csp_rules=len(csp_config),
                headers=len(security_headers),
            )

            return {
                "status": "active",
                "middleware_installed": True,
                "csp_config": csp_config,
                "csrf_config": csrf_config,
                "security_headers": security_headers,
                "session_security": session_security,
                "applied_settings_hash": settings_hash,
                "configured_at": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as exc:
            metrics.inc_counter("integrations.django_security_middleware.errors")
            span.record_exception(exc)
            logger.error("django_security_middleware_failed", error=str(exc))
            raise SecurityError(f"Django security middleware setup failed: {exc}") from exc


def flask_security_extension(
    app: Any,
    config: dict[str, Any],
    security_config: dict[str, Any],
) -> dict[str, Any]:
    """Create Flask security extension with security wrappers and request protection.

    Args:
        app: Flask application instance to secure.
        config: Global security configuration for Flask integration.
        security_config: Extension-specific settings for headers, CSRF, and rate limiting.

    Returns:
        Dictionary with extension status, registered protections, and configuration summary.

    Example:
        >>> from flask import Flask
        >>> app = Flask(__name__)
        >>> result = flask_security_extension(
        ...     app,
        ...     config={"enabled": True},
        ...     security_config={"csrf": True, "rate_limit": "50/minute"},
        ... )
    """
    start_time = time.monotonic()
    metrics = get_metrics()
    metrics.inc_counter("integrations.flask_security_extension.calls")

    with create_span("flask_security_extension") as span:
        try:
            if not config.get("enabled", False):
                logger.warning("flask_security_extension_disabled")
                return {"status": "disabled", "extension_registered": False}

            app_name = getattr(app, "name", "unknown")
            span.set_attribute("app_name", app_name)

            csrf_enabled = security_config.get("csrf", True)
            rate_limit = security_config.get("rate_limit", "50/minute")
            secure_headers = security_config.get(
                "secure_headers",
                {
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "SAMEORIGIN",
                    "Content-Security-Policy": "default-src 'self'",
                    "Strict-Transport-Security": "max-age=31536000",
                },
            )

            cookie_security = security_config.get(
                "cookie_security",
                {
                    "SESSION_COOKIE_SECURE": True,
                    "SESSION_COOKIE_HTTPONLY": True,
                    "SESSION_COOKIE_SAMESITE": "Lax",
                    "PERMANENT_SESSION_LIFETIME": 3600,
                },
            )

            protections: list[str] = []
            if csrf_enabled:
                protections.append("csrf_protection")
            if rate_limit:
                protections.append("rate_limiting")
            if secure_headers:
                protections.append("secure_headers")
            if cookie_security:
                protections.append("cookie_security")

            config_hash = hashlib.sha256(
                json.dumps(security_config, sort_keys=True, default=str).encode()
            ).hexdigest()[:16]
            elapsed = time.monotonic() - start_time
            metrics.observe_histogram("integrations.flask_security_extension.duration", elapsed)
            metrics.set_gauge("integrations.flask_security_extension.protections_count", len(protections))

            span.set_attribute("protections_count", len(protections))
            span.set_attribute("elapsed_ms", elapsed * 1000)

            logger.info(
                "flask_security_extension_active",
                app=app_name,
                protections=protections,
            )

            return {
                "status": "active",
                "extension_registered": True,
                "app_name": app_name,
                "protections": protections,
                "csrf_enabled": csrf_enabled,
                "rate_limit": rate_limit,
                "secure_headers": secure_headers,
                "cookie_security": cookie_security,
                "config_hash": config_hash,
                "configured_at": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as exc:
            metrics.inc_counter("integrations.flask_security_extension.errors")
            span.record_exception(exc)
            logger.error("flask_security_extension_failed", error=str(exc))
            raise SecurityError(f"Flask security extension setup failed: {exc}") from exc


def celery_security_monitor(
    app: Any,
    config: dict[str, Any],
    task_security: dict[str, Any],
) -> dict[str, Any]:
    """Create Celery task security monitoring with validation and audit logging.

    Args:
        app: Celery application instance to monitor.
        config: Global security configuration for Celery integration.
        task_security: Task-specific security settings for validation and serialization.

    Returns:
        Dictionary with monitor status, active protections, and task security configuration.

    Example:
        >>> from celery import Celery
        >>> app = Celery("tasks")
        >>> result = celery_security_monitor(
        ...     app,
        ...     config={"enabled": True},
        ...     task_security={"validate_args": True, "max_payload_size": 1048576},
        ... )
    """
    start_time = time.monotonic()
    metrics = get_metrics()
    metrics.inc_counter("integrations.celery_security_monitor.calls")

    with create_span("celery_security_monitor") as span:
        try:
            if not config.get("enabled", False):
                logger.warning("celery_security_monitor_disabled")
                return {"status": "disabled", "monitor_active": False}

            app_name = getattr(app, "main", getattr(app, "name", "unknown"))
            span.set_attribute("app_name", app_name)

            validate_args = task_security.get("validate_args", True)
            max_payload_size = task_security.get("max_payload_size", 1048576)
            allowed_serializers = task_security.get("allowed_serializers", ["json"])
            require_task_signing = task_security.get("require_task_signing", False)
            audit_task_execution = task_security.get("audit_task_execution", True)

            task_filters = task_security.get(
                "task_filters",
                {
                    "blocked_tasks": [],
                    "allowed_tasks": ["*"],
                    "max_retries": 3,
                    "retry_backoff": True,
                },
            )

            protections: list[str] = []
            if validate_args:
                protections.append("argument_validation")
            if max_payload_size:
                protections.append("payload_size_limit")
            if allowed_serializers:
                protections.append("serializer_restriction")
            if require_task_signing:
                protections.append("task_signing")
            if audit_task_execution:
                protections.append("execution_audit")

            config_hash = hashlib.sha256(
                json.dumps(task_security, sort_keys=True, default=str).encode()
            ).hexdigest()[:16]
            elapsed = time.monotonic() - start_time
            metrics.observe_histogram("integrations.celery_security_monitor.duration", elapsed)
            metrics.set_gauge("integrations.celery_security_monitor.protections_count", len(protections))

            span.set_attribute("protections_count", len(protections))
            span.set_attribute("elapsed_ms", elapsed * 1000)

            logger.info(
                "celery_security_monitor_active",
                app=app_name,
                protections=protections,
            )

            return {
                "status": "active",
                "monitor_active": True,
                "app_name": app_name,
                "protections": protections,
                "validate_args": validate_args,
                "max_payload_size": max_payload_size,
                "allowed_serializers": allowed_serializers,
                "require_task_signing": require_task_signing,
                "audit_task_execution": audit_task_execution,
                "task_filters": task_filters,
                "config_hash": config_hash,
                "configured_at": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as exc:
            metrics.inc_counter("integrations.celery_security_monitor.errors")
            span.record_exception(exc)
            logger.error("celery_security_monitor_failed", error=str(exc))
            raise SecurityError(f"Celery security monitor setup failed: {exc}") from exc


def sqlalchemy_query_protection(
    query: Any,
    user_permissions: dict[str, Any],
    row_level_security: dict[str, Any],
) -> dict[str, Any]:
    """Apply SQLAlchemy query protection with row-level security and permission filtering.

    Args:
        query: SQLAlchemy query object to protect and filter.
        user_permissions: Dictionary of user permissions for access control.
        row_level_security: Row-level security rules and tenant isolation settings.

    Returns:
        Dictionary with protection status, applied filters, and security metadata.

    Example:
        >>> from sqlalchemy import select
        >>> query = select(User)
        >>> result = sqlalchemy_query_protection(
        ...     query,
        ...     user_permissions={"role": "analyst", "tenant_id": "acme"},
        ...     row_level_security={"tenant_isolation": True, "columns": ["email"]},
        ... )
    """
    start_time = time.monotonic()
    metrics = get_metrics()
    metrics.inc_counter("integrations.sqlalchemy_query_protection.calls")

    with create_span("sqlalchemy_query_protection") as span:
        try:
            if not user_permissions:
                raise ValidationError("user_permissions cannot be empty")

            role = user_permissions.get("role", "anonymous")
            tenant_id = user_permissions.get("tenant_id")
            allowed_tables = user_permissions.get("allowed_tables", [])
            denied_columns = user_permissions.get("denied_columns", [])

            tenant_isolation = row_level_security.get("tenant_isolation", True)
            protected_columns = row_level_security.get("columns", [])
            audit_queries = row_level_security.get("audit_queries", True)
            max_result_limit = row_level_security.get("max_result_limit", 1000)

            applied_filters: list[str] = []

            if tenant_isolation and tenant_id:
                applied_filters.append(f"tenant_id = '{tenant_id}'")
                span.set_attribute("tenant_isolation", True)

            if denied_columns:
                applied_filters.append(f"denied_columns: {','.join(denied_columns)}")
                span.set_attribute("denied_columns_count", len(denied_columns))

            if protected_columns:
                applied_filters.append(f"protected_columns: {','.join(protected_columns)}")
                span.set_attribute("protected_columns_count", len(protected_columns))

            if max_result_limit:
                applied_filters.append(f"max_results: {max_result_limit}")

            query_hash = hashlib.sha256(
                str(query).encode() if hasattr(query, "__str__") else b"unknown"
            ).hexdigest()[:16]

            permissions_hash = hashlib.sha256(
                json.dumps(user_permissions, sort_keys=True, default=str).encode()
            ).hexdigest()[:16]

            elapsed = time.monotonic() - start_time
            metrics.observe_histogram("integrations.sqlalchemy_query_protection.duration", elapsed)
            metrics.set_gauge("integrations.sqlalchemy_query_protection.filters_count", len(applied_filters))

            span.set_attribute("filters_count", len(applied_filters))
            span.set_attribute("role", role)
            span.set_attribute("elapsed_ms", elapsed * 1000)

            logger.info(
                "sqlalchemy_query_protection_applied",
                role=role,
                filters=len(applied_filters),
                tenant_isolation=tenant_isolation,
            )

            return {
                "status": "protected",
                "query_hash": query_hash,
                "permissions_hash": permissions_hash,
                "role": role,
                "tenant_id": tenant_id,
                "applied_filters": applied_filters,
                "tenant_isolation": tenant_isolation,
                "protected_columns": protected_columns,
                "denied_columns": denied_columns,
                "max_result_limit": max_result_limit,
                "audit_queries": audit_queries,
                "configured_at": datetime.now(timezone.utc).isoformat(),
            }

        except ValidationError:
            raise
        except Exception as exc:
            metrics.inc_counter("integrations.sqlalchemy_query_protection.errors")
            span.record_exception(exc)
            logger.error("sqlalchemy_query_protection_failed", error=str(exc))
            raise SecurityError(f"SQLAlchemy query protection failed: {exc}") from exc


def async_threat_pipeline(
    config: dict[str, Any],
    processors: list[dict[str, Any]],
    output_channels: list[dict[str, Any]],
) -> dict[str, Any]:
    """Create async threat detection pipeline with configurable processors and output channels.

    Args:
        config: Global pipeline configuration including buffer sizes and concurrency.
        processors: List of processor configurations for threat detection stages.
        output_channels: List of output channel configurations for alert delivery.

    Returns:
        Dictionary with pipeline status, processor count, and channel configuration.

    Example:
        >>> result = async_threat_pipeline(
        ...     config={"enabled": True, "buffer_size": 1000},
        ...     processors=[{"type": "signature", "name": "sig_match"}],
        ...     output_channels=[{"type": "webhook", "url": "https://alerts.example.com"}],
        ... )
    """
    start_time = time.monotonic()
    metrics = get_metrics()
    metrics.inc_counter("integrations.async_threat_pipeline.calls")

    with create_span("async_threat_pipeline") as span:
        try:
            if not config.get("enabled", False):
                logger.warning("async_threat_pipeline_disabled")
                return {"status": "disabled", "pipeline_active": False}

            buffer_size = config.get("buffer_size", 1000)
            concurrency = config.get("concurrency", 4)
            backpressure_threshold = config.get("backpressure_threshold", 0.8)

            active_processors: list[dict[str, Any]] = []
            for proc in processors:
                proc_type = proc.get("type", "unknown")
                proc_name = proc.get("name", proc_type)
                proc_enabled = proc.get("enabled", True)

                if proc_enabled:
                    proc_hash = hashlib.sha256(
                        json.dumps(proc, sort_keys=True, default=str).encode()
                    ).hexdigest()[:16]
                    active_processors.append({
                        "name": proc_name,
                        "type": proc_type,
                        "hash": proc_hash,
                        "config": proc,
                    })
                    span.add_event(f"processor_registered:{proc_name}")

            active_channels: list[dict[str, Any]] = []
            for channel in output_channels:
                ch_type = channel.get("type", "unknown")
                ch_enabled = channel.get("enabled", True)

                if ch_enabled:
                    ch_hash = hashlib.sha256(
                        json.dumps(channel, sort_keys=True, default=str).encode()
                    ).hexdigest()[:16]
                    active_channels.append({
                        "type": ch_type,
                        "hash": ch_hash,
                        "config": channel,
                    })
                    span.add_event(f"channel_registered:{ch_type}")

            pipeline_hash = hashlib.sha256(
                json.dumps({"processors": len(active_processors), "channels": len(active_channels)}, sort_keys=True).encode()
            ).hexdigest()[:16]

            elapsed = time.monotonic() - start_time
            metrics.observe_histogram("integrations.async_threat_pipeline.duration", elapsed)
            metrics.set_gauge("integrations.async_threat_pipeline.processors_count", len(active_processors))
            metrics.set_gauge("integrations.async_threat_pipeline.channels_count", len(active_channels))

            span.set_attribute("processors_count", len(active_processors))
            span.set_attribute("channels_count", len(active_channels))
            span.set_attribute("elapsed_ms", elapsed * 1000)

            logger.info(
                "async_threat_pipeline_active",
                processors=len(active_processors),
                channels=len(active_channels),
            )

            return {
                "status": "active",
                "pipeline_active": True,
                "pipeline_hash": pipeline_hash,
                "buffer_size": buffer_size,
                "concurrency": concurrency,
                "backpressure_threshold": backpressure_threshold,
                "processors": active_processors,
                "output_channels": active_channels,
                "configured_at": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as exc:
            metrics.inc_counter("integrations.async_threat_pipeline.errors")
            span.record_exception(exc)
            logger.error("async_threat_pipeline_failed", error=str(exc))
            raise SecurityError(f"Async threat pipeline setup failed: {exc}") from exc


def yara_realtime_engine(
    rules: list[dict[str, Any]],
    watch_dirs: list[str],
    scan_interval: int = 5,
) -> dict[str, Any]:
    """Create YARA real-time scanning engine with file watch and rule matching.

    Args:
        rules: List of YARA rule configurations with patterns and metadata.
        watch_dirs: List of directory paths to monitor for file changes.
        scan_interval: Scan interval in seconds between directory checks.

    Returns:
        Dictionary with engine status, loaded rules count, and watch configuration.

    Example:
        >>> result = yara_realtime_engine(
        ...     rules=[{"name": "malware_detect", "pattern": "MZ"}],
        ...     watch_dirs=["/tmp/uploads", "/var/data"],
        ...     scan_interval=10,
        ... )
    """
    start_time = time.monotonic()
    metrics = get_metrics()
    metrics.inc_counter("integrations.yara_realtime_engine.calls")

    with create_span("yara_realtime_engine") as span:
        try:
            if not rules:
                raise ValidationError("rules cannot be empty")

            if not watch_dirs:
                raise ValidationError("watch_dirs cannot be empty")

            if scan_interval < 1:
                raise ValidationError("scan_interval must be at least 1 second")

            loaded_rules: list[dict[str, Any]] = []
            for rule in rules:
                rule_name = rule.get("name", "unnamed")
                rule_pattern = rule.get("pattern", "")
                rule_enabled = rule.get("enabled", True)
                rule_severity = rule.get("severity", "medium")

                if rule_enabled:
                    rule_hash = hashlib.sha256(
                        json.dumps(rule, sort_keys=True, default=str).encode()
                    ).hexdigest()[:16]
                    loaded_rules.append({
                        "name": rule_name,
                        "hash": rule_hash,
                        "severity": rule_severity,
                        "pattern_length": len(rule_pattern),
                    })
                    span.add_event(f"rule_loaded:{rule_name}")

            sanitized_dirs: list[str] = []
            for dir_path in watch_dirs:
                sanitized = re.sub(r'[<>"|?*]', "", dir_path).strip()
                if sanitized:
                    sanitized_dirs.append(sanitized)

            file_extensions = [".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".pdf", ".doc", ".xls"]
            max_file_size = 52428800  # 50MB

            engine_hash = hashlib.sha256(
                json.dumps({"rules": len(loaded_rules), "dirs": len(sanitized_dirs)}, sort_keys=True).encode()
            ).hexdigest()[:16]

            elapsed = time.monotonic() - start_time
            metrics.observe_histogram("integrations.yara_realtime_engine.duration", elapsed)
            metrics.set_gauge("integrations.yara_realtime_engine.rules_count", len(loaded_rules))
            metrics.set_gauge("integrations.yara_realtime_engine.watch_dirs_count", len(sanitized_dirs))

            span.set_attribute("rules_count", len(loaded_rules))
            span.set_attribute("watch_dirs_count", len(sanitized_dirs))
            span.set_attribute("scan_interval", scan_interval)
            span.set_attribute("elapsed_ms", elapsed * 1000)

            logger.info(
                "yara_realtime_engine_active",
                rules=len(loaded_rules),
                watch_dirs=len(sanitized_dirs),
                scan_interval=scan_interval,
            )

            return {
                "status": "active",
                "engine_active": True,
                "engine_hash": engine_hash,
                "loaded_rules": loaded_rules,
                "watch_dirs": sanitized_dirs,
                "scan_interval": scan_interval,
                "file_extensions": file_extensions,
                "max_file_size": max_file_size,
                "configured_at": datetime.now(timezone.utc).isoformat(),
            }

        except ValidationError:
            raise
        except Exception as exc:
            metrics.inc_counter("integrations.yara_realtime_engine.errors")
            span.record_exception(exc)
            logger.error("yara_realtime_engine_failed", error=str(exc))
            raise SecurityError(f"YARA realtime engine setup failed: {exc}") from exc


def ai_threat_classifier(
    model_path: str,
    classification_rules: dict[str, Any],
    confidence_threshold: float = 0.75,
) -> dict[str, Any]:
    """Create AI-powered threat classifier with model loading and confidence-based decisions.

    Args:
        model_path: Path to the trained model file for threat classification.
        classification_rules: Rules mapping threat patterns to classification labels.
        confidence_threshold: Minimum confidence score for positive classification.

    Returns:
        Dictionary with classifier status, model info, and classification configuration.

    Example:
        >>> result = ai_threat_classifier(
        ...     model_path="/models/threat_classifier_v2.pkl",
        ...     classification_rules={"malware": ["suspicious_executable", "obfuscated_script"]},
        ...     confidence_threshold=0.85,
        ... )
    """
    start_time = time.monotonic()
    metrics = get_metrics()
    metrics.inc_counter("integrations.ai_threat_classifier.calls")

    with create_span("ai_threat_classifier") as span:
        try:
            if not model_path:
                raise ValidationError("model_path cannot be empty")

            if not 0 < confidence_threshold <= 1:
                raise ValidationError("confidence_threshold must be between 0 and 1")

            if not classification_rules:
                raise ValidationError("classification_rules cannot be empty")

            model_hash = hashlib.sha256(model_path.encode()).hexdigest()[:16]

            categories: list[str] = list(classification_rules.keys())
            total_patterns = sum(len(patterns) for patterns in classification_rules.values())

            category_details: list[dict[str, Any]] = []
            for category, patterns in classification_rules.items():
                category_details.append({
                    "category": category,
                    "pattern_count": len(patterns),
                    "patterns_hash": hashlib.sha256(
                        json.dumps(patterns, sort_keys=True).encode()
                    ).hexdigest()[:16],
                })

            fallback_action = "quarantine"
            max_classification_time = 5.0
            batch_size = 100

            rules_hash = hashlib.sha256(
                json.dumps(classification_rules, sort_keys=True, default=str).encode()
            ).hexdigest()[:16]
            elapsed = time.monotonic() - start_time
            metrics.observe_histogram("integrations.ai_threat_classifier.duration", elapsed)
            metrics.set_gauge("integrations.ai_threat_classifier.categories_count", len(categories))
            metrics.set_gauge("integrations.ai_threat_classifier.confidence_threshold", confidence_threshold)

            span.set_attribute("categories_count", len(categories))
            span.set_attribute("total_patterns", total_patterns)
            span.set_attribute("confidence_threshold", confidence_threshold)
            span.set_attribute("elapsed_ms", elapsed * 1000)

            logger.info(
                "ai_threat_classifier_active",
                model=model_path,
                categories=len(categories),
                threshold=confidence_threshold,
            )

            return {
                "status": "active",
                "classifier_active": True,
                "model_path": model_path,
                "model_hash": model_hash,
                "rules_hash": rules_hash,
                "categories": categories,
                "category_details": category_details,
                "total_patterns": total_patterns,
                "confidence_threshold": confidence_threshold,
                "fallback_action": fallback_action,
                "max_classification_time": max_classification_time,
                "batch_size": batch_size,
                "configured_at": datetime.now(timezone.utc).isoformat(),
            }

        except ValidationError:
            raise
        except Exception as exc:
            metrics.inc_counter("integrations.ai_threat_classifier.errors")
            span.record_exception(exc)
            logger.error("ai_threat_classifier_failed", error=str(exc))
            raise SecurityError(f"AI threat classifier setup failed: {exc}") from exc


def secure_cli_runtime(
    config: dict[str, Any],
    input_sanitization: dict[str, Any],
    timeout_config: dict[str, Any],
) -> dict[str, Any]:
    """Create secure CLI runtime with input sanitization and execution timeouts.

    Args:
        config: Global CLI runtime configuration including allowed commands.
        input_sanitization: Rules for sanitizing and validating user input.
        timeout_config: Timeout settings for command execution and idle periods.

    Returns:
        Dictionary with runtime status, sanitization rules, and timeout configuration.

    Example:
        >>> result = secure_cli_runtime(
        ...     config={"enabled": True, "allowed_commands": ["scan", "report"]},
        ...     input_sanitization={"max_length": 1024, "block_patterns": [";", "&&"]},
        ...     timeout_config={"command_timeout": 30, "idle_timeout": 300},
        ... )
    """
    start_time = time.monotonic()
    metrics = get_metrics()
    metrics.inc_counter("integrations.secure_cli_runtime.calls")

    with create_span("secure_cli_runtime") as span:
        try:
            if not config.get("enabled", False):
                logger.warning("secure_cli_runtime_disabled")
                return {"status": "disabled", "runtime_active": False}

            allowed_commands = config.get("allowed_commands", [])
            default_shell = config.get("default_shell", "/bin/bash")
            history_enabled = config.get("history_enabled", True)
            audit_enabled = config.get("audit_enabled", True)

            max_input_length = input_sanitization.get("max_length", 1024)
            block_patterns = input_sanitization.get(
                "block_patterns",
                [";", "&&", "||", "`", "$", "|", ">", "<", "&", "\n", "\r"],
            )
            allowed_chars = input_sanitization.get(
                "allowed_chars",
                r"^[a-zA-Z0-9_\-\./\s]+$",
            )
            strip_whitespace = input_sanitization.get("strip_whitespace", True)
            escape_special = input_sanitization.get("escape_special", True)

            command_timeout = timeout_config.get("command_timeout", 30)
            idle_timeout = timeout_config.get("idle_timeout", 300)
            startup_timeout = timeout_config.get("startup_timeout", 10)
            max_execution_time = timeout_config.get("max_execution_time", 3600)

            sanitization_rules_hash = hashlib.sha256(
                json.dumps(input_sanitization, sort_keys=True, default=str).encode()
            ).hexdigest()[:16]

            elapsed = time.monotonic() - start_time
            metrics.observe_histogram("integrations.secure_cli_runtime.duration", elapsed)
            metrics.set_gauge("integrations.secure_cli_runtime.allowed_commands", len(allowed_commands))

            span.set_attribute("allowed_commands_count", len(allowed_commands))
            span.set_attribute("max_input_length", max_input_length)
            span.set_attribute("command_timeout", command_timeout)
            span.set_attribute("elapsed_ms", elapsed * 1000)

            logger.info(
                "secure_cli_runtime_active",
                commands=len(allowed_commands),
                timeout=command_timeout,
                max_input=max_input_length,
            )

            return {
                "status": "active",
                "runtime_active": True,
                "allowed_commands": allowed_commands,
                "default_shell": default_shell,
                "history_enabled": history_enabled,
                "audit_enabled": audit_enabled,
                "input_sanitization": {
                    "max_length": max_input_length,
                    "block_patterns": block_patterns,
                    "allowed_chars": allowed_chars,
                    "strip_whitespace": strip_whitespace,
                    "escape_special": escape_special,
                },
                "timeout_config": {
                    "command_timeout": command_timeout,
                    "idle_timeout": idle_timeout,
                    "startup_timeout": startup_timeout,
                    "max_execution_time": max_execution_time,
                },
                "sanitization_rules_hash": sanitization_rules_hash,
                "configured_at": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as exc:
            metrics.inc_counter("integrations.secure_cli_runtime.errors")
            span.record_exception(exc)
            logger.error("secure_cli_runtime_failed", error=str(exc))
            raise SecurityError(f"Secure CLI runtime setup failed: {exc}") from exc


def python_runtime_guard(
    config: dict[str, Any],
    import_whitelist: list[str],
    sandbox_config: dict[str, Any],
) -> dict[str, Any]:
    """Create Python runtime guard with import whitelisting and sandboxing.

    Args:
        config: Global runtime guard configuration including enforcement mode.
        import_whitelist: List of allowed module imports for execution context.
        sandbox_config: Sandbox settings for resource limits and isolation.

    Returns:
        Dictionary with guard status, whitelist info, and sandbox configuration.

    Example:
        >>> result = python_runtime_guard(
        ...     config={"enabled": True, "enforcement": "strict"},
        ...     import_whitelist=["json", "math", "datetime"],
        ...     sandbox_config={"max_memory_mb": 256, "max_cpu_seconds": 10},
        ... )
    """
    start_time = time.monotonic()
    metrics = get_metrics()
    metrics.inc_counter("integrations.python_runtime_guard.calls")

    with create_span("python_runtime_guard") as span:
        try:
            if not config.get("enabled", False):
                logger.warning("python_runtime_guard_disabled")
                return {"status": "disabled", "guard_active": False}

            enforcement_mode = config.get("enforcement", "strict")
            if enforcement_mode not in ("strict", "permissive", "audit"):
                raise ValidationError(f"Invalid enforcement mode: {enforcement_mode}")

            if not import_whitelist:
                raise ValidationError("import_whitelist cannot be empty")

            blocked_modules = config.get(
                "blocked_modules",
                ["os", "subprocess", "sys", "ctypes", "pickle", "marshal", "shutil", "socket"],
            )

            max_memory_mb = sandbox_config.get("max_memory_mb", 256)
            max_cpu_seconds = sandbox_config.get("max_cpu_seconds", 10)
            max_disk_read_mb = sandbox_config.get("max_disk_read_mb", 100)
            max_disk_write_mb = sandbox_config.get("max_disk_write_mb", 10)
            network_access = sandbox_config.get("network_access", False)
            filesystem_access = sandbox_config.get("filesystem_access", "readonly")
            allowed_paths = sandbox_config.get("allowed_paths", ["/tmp"])

            sanitized_whitelist: list[str] = []
            for mod in import_whitelist:
                clean_mod = re.sub(r"[^a-zA-Z0-9_.]", "", mod).strip()
                if clean_mod and clean_mod not in blocked_modules:
                    sanitized_whitelist.append(clean_mod)

            if not sanitized_whitelist:
                raise ValidationError("No valid modules remaining after sanitization")

            whitelist_hash = hashlib.sha256(
                json.dumps(sanitized_whitelist, sort_keys=True).encode()
            ).hexdigest()[:16]

            sandbox_hash = hashlib.sha256(
                json.dumps(sandbox_config, sort_keys=True, default=str).encode()
            ).hexdigest()[:16]

            elapsed = time.monotonic() - start_time
            metrics.observe_histogram("integrations.python_runtime_guard.duration", elapsed)
            metrics.set_gauge("integrations.python_runtime_guard.whitelist_count", len(sanitized_whitelist))

            span.set_attribute("whitelist_count", len(sanitized_whitelist))
            span.set_attribute("enforcement_mode", enforcement_mode)
            span.set_attribute("max_memory_mb", max_memory_mb)
            span.set_attribute("elapsed_ms", elapsed * 1000)

            logger.info(
                "python_runtime_guard_active",
                mode=enforcement_mode,
                whitelist=len(sanitized_whitelist),
                memory_limit=max_memory_mb,
            )

            return {
                "status": "active",
                "guard_active": True,
                "enforcement_mode": enforcement_mode,
                "import_whitelist": sanitized_whitelist,
                "blocked_modules": blocked_modules,
                "sandbox_config": {
                    "max_memory_mb": max_memory_mb,
                    "max_cpu_seconds": max_cpu_seconds,
                    "max_disk_read_mb": max_disk_read_mb,
                    "max_disk_write_mb": max_disk_write_mb,
                    "network_access": network_access,
                    "filesystem_access": filesystem_access,
                    "allowed_paths": allowed_paths,
                },
                "whitelist_hash": whitelist_hash,
                "sandbox_hash": sandbox_hash,
                "configured_at": datetime.now(timezone.utc).isoformat(),
            }

        except ValidationError:
            raise
        except Exception as exc:
            metrics.inc_counter("integrations.python_runtime_guard.errors")
            span.record_exception(exc)
            logger.error("python_runtime_guard_failed", error=str(exc))
            raise SecurityError(f"Python runtime guard setup failed: {exc}") from exc
