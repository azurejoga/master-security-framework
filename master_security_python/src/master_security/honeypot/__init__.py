"""
Master Security Framework - Honeypot & Deception Module
========================================================

Advanced honeypot deployment, deception infrastructure, attacker behavior tracking,
honeytoken generation, and moving target defense capabilities.
"""

from __future__ import annotations

import json
import secrets
import time
import hashlib
import random
from typing import Any, Optional
from datetime import datetime, timezone
from master_security.core import get_logger, get_metrics, create_span, get_event_bus, SecurityEvent, EventSeverity
from master_security.core.exceptions import SecurityError
import structlog

logger = structlog.get_logger(__name__)


def _generate_session_id() -> str:
    """Generate a unique honeypot session identifier."""
    return f"hp_sess_{secrets.token_hex(16)}"


def _hash_value(value: str) -> str:
    """Create a SHA-256 hash of a value for tracking."""
    return hashlib.sha256(value.encode()).hexdigest()


def _emit_honeypot_event(event_type: str, severity: EventSeverity, details: dict[str, Any]) -> None:
    """Emit a structured honeypot security event."""
    event_bus = get_event_bus()
    event = SecurityEvent(type=event_type,
        severity=severity,
        source="honeypot",
        data=details,
    )
    event_bus.publish_sync(event)


def _record_metric(metric_name: str, value: float, tags: dict[str, str] | None = None) -> None:
    """Record a honeypot metric."""
    metrics = get_metrics()
    metrics.inc_counter(metric_name, labels=tags or {})
    metrics.set_gauge(f"{metric_name}_value", value, labels=tags or {})


# ---------------------------------------------------------------------------
# 1. Adaptive Honeypot
# ---------------------------------------------------------------------------

def adaptive_honeypot(
    config: dict[str, Any],
    traffic_analysis: dict[str, Any],
    threat_level: str = "medium",
) -> dict[str, Any]:
    """Dynamically adjust honeypot configuration based on observed traffic and threat level.

    Analyzes incoming traffic patterns and current threat intelligence to automatically
    scale honeypot resources, adjust deception depth, and modify engagement strategies.

    Args:
        config: Base honeypot configuration including services, ports, and response templates.
        traffic_analysis: Dict with keys like request_rate, unique_ips, attack_signatures,
            geographic_distribution, and protocol_breakdown.
        threat_level: Current threat level assessment. One of low, medium, high, critical.

    Returns:
        Dict with adjusted honeypot configuration including services, engagement_depth,
            alert_thresholds, resource_allocation, and deception_strategy.

    Example:
        >>> config = {"services": ["ssh", "http"], "max_sessions": 100}
        >>> traffic = {"request_rate": 500, "unique_ips": 45, "attack_signatures": ["sql_injection"]}
        >>> result = adaptive_honeypot(config, traffic, "high")
        >>> result["engagement_depth"]
        'deep'
    """
    with create_span("adaptive_honeypot") as span:
        start = time.monotonic()

        threat_multipliers = {"low": 0.5, "medium": 1.0, "high": 2.0, "critical": 4.0}
        multiplier = threat_multipliers.get(threat_level, 1.0)

        request_rate = traffic_analysis.get("request_rate", 0)
        unique_ips = traffic_analysis.get("unique_ips", 0)
        attack_sigs = traffic_analysis.get("attack_signatures", [])

        engagement_depth = "shallow"
        if multiplier >= 2.0 or request_rate > 200:
            engagement_depth = "deep"
        elif multiplier >= 1.0 or request_rate > 50:
            engagement_depth = "moderate"

        max_sessions = int(config.get("max_sessions", 100) * multiplier)
        active_services = config.get("services", [])
        if threat_level in ("high", "critical"):
            extra_services = ["rdp", "smb", "ftp", "telnet"]
            active_services = list(set(active_services + extra_services))

        alert_threshold = max(10, int(50 / multiplier))
        resource_allocation = {
            "cpu_percent": min(95, int(30 * multiplier)),
            "memory_mb": int(512 * multiplier),
            "bandwidth_mbps": int(100 * multiplier),
        }

        deception_strategy = {
            "response_delay_ms": random.randint(50, 500) if threat_level == "high" else random.randint(10, 100),
            "fake_data_depth": "comprehensive" if threat_level == "critical" else "moderate",
            "interaction_logging": True,
            "auto_escalate": threat_level in ("high", "critical"),
        }

        result = {
            "session_id": _generate_session_id(),
            "threat_level": threat_level,
            "engagement_depth": engagement_depth,
            "max_sessions": max_sessions,
            "active_services": active_services,
            "alert_threshold": alert_threshold,
            "resource_allocation": resource_allocation,
            "deception_strategy": deception_strategy,
            "traffic_summary": {
                "request_rate": request_rate,
                "unique_sources": unique_ips,
                "detected_signatures": len(attack_sigs),
            },
            "adjusted_at": datetime.now(timezone.utc).isoformat(),
        }

        _emit_honeypot_event(
            "honeypot.adaptive_adjustment",
            EventSeverity.INFO,
            {"threat_level": threat_level, "engagement_depth": engagement_depth, "services_count": len(active_services)},
        )
        _record_metric("honeypot.adaptive_adjustments", 1, {"threat_level": threat_level})
        _record_metric("honeypot.adjustment_latency", time.monotonic() - start)

        span.set_attribute("threat_level", threat_level)
        span.set_attribute("engagement_depth", engagement_depth)

        logger.info(
            "adaptive_honeypot.adjusted",
            threat_level=threat_level,
            engagement_depth=engagement_depth,
            services=len(active_services),
        )
        return result


# ---------------------------------------------------------------------------
# 2. Fake Admin Panel
# ---------------------------------------------------------------------------

def fake_admin_panel(
    template: str = "default",
    routes: list[str] | None = None,
    responses: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Deploy a realistic fake admin panel to attract and track unauthorized access attempts.

    Creates a convincing administrative interface with plausible routes, login forms,
    dashboard widgets, and administrative functionality that logs all interactions.

    Args:
        template: UI template to use. Options: default, modern, legacy, enterprise.
        routes: List of admin route paths to expose (e.g., [/admin/users, /admin/settings]).
        responses: Custom response payloads for specific routes.

    Returns:
        Dict with panel_id, url, routes, login_endpoint, session_tracking,
            intercepted_actions, and deployment_status.

    Example:
        >>> result = fake_admin_panel("enterprise", ["/admin/dashboard", "/admin/users"])
        >>> result["login_endpoint"]
        '/admin/login'
    """
    with create_span("fake_admin_panel") as span:
        start = time.monotonic()

        default_routes = [
            "/admin/login",
            "/admin/dashboard",
            "/admin/users",
            "/admin/settings",
            "/admin/logs",
            "/admin/backup",
            "/admin/database",
            "/admin/api-keys",
            "/admin/audit",
            "/admin/reports",
        ]
        active_routes = routes or default_routes
        if "/admin/login" not in active_routes:
            active_routes.insert(0, "/admin/login")

        panel_id = f"admin_{secrets.token_hex(8)}"
        base_url = f"/admin-{secrets.token_hex(4)}"

        fake_users = [
            {"id": 1, "username": "admin", "role": "superadmin", "last_login": "2026-05-16T08:30:00Z"},
            {"id": 2, "username": "jdoe", "role": "admin", "last_login": "2026-05-15T14:22:00Z"},
            {"id": 3, "username": "msmith", "role": "moderator", "last_login": "2026-05-14T09:15:00Z"},
        ]

        default_responses: dict[str, Any] = {
            "/admin/login": {"status": "ok", "csrf_token": secrets.token_hex(32), "session_timeout": 3600},
            "/admin/dashboard": {"users_online": random.randint(5, 50), "active_sessions": random.randint(10, 200)},
            "/admin/users": {"total": 1247, "active": 892, "data": fake_users},
            "/admin/settings": {"version": "4.2.1", "environment": "production", "debug": False},
        }
        merged_responses = {**default_responses, **(responses or {})}

        result = {
            "panel_id": panel_id,
            "url": base_url,
            "template": template,
            "routes": active_routes,
            "login_endpoint": "/admin/login",
            "session_tracking": {
                "enabled": True,
                "cookie_name": f"admin_sess_{secrets.token_hex(8)}",
                "ttl_seconds": 3600,
            },
            "intercepted_actions": [],
            "fake_credentials": {
                "username": "admin",
                "password_hash": _hash_value("P@ssw0rd!2026"),
            },
            "responses": merged_responses,
            "deployment_status": "active",
            "deployed_at": datetime.now(timezone.utc).isoformat(),
        }

        _emit_honeypot_event(
            "honeypot.admin_panel_deployed",
            EventSeverity.INFO,
            {"panel_id": panel_id, "routes_count": len(active_routes), "template": template},
        )
        _record_metric("honeypot.admin_panels_deployed", 1, {"template": template})
        _record_metric("honeypot.deployment_latency", time.monotonic() - start)

        span.set_attribute("panel_id", panel_id)
        span.set_attribute("routes_count", len(active_routes))

        logger.info(
            "fake_admin_panel.deployed",
            panel_id=panel_id,
            routes_count=len(active_routes),
            template=template,
        )
        return result


# ---------------------------------------------------------------------------
# 3. Fake Database
# ---------------------------------------------------------------------------

def fake_database(
    schema: dict[str, Any] | None = None,
    records: dict[str, list[dict[str, Any]]] | None = None,
    connection_string: str = "postgresql://honeypot:honeypot@127.0.0.1:5432/production_db",
) -> dict[str, Any]:
    """Create a convincing fake database with realistic schema and sample records.

    Simulates a production database with plausible table structures, data types,
    relationships, and realistic record counts to engage database-focused attackers.

    Args:
        schema: Dict mapping table names to column definitions with types and constraints.
        records: Dict mapping table names to lists of record dicts.
        connection_string: Fake connection string to expose for attacker discovery.

    Returns:
        Dict with db_id, connection_string, schema, record_counts,
            query_log, injection_attempts, and status.

    Example:
        >>> schema = {"users": {"id": "integer", "name": "varchar(255)"}}
        >>> result = fake_database(schema)
        >>> "users" in result["schema"]
        True
    """
    with create_span("fake_database") as span:
        start = time.monotonic()

        default_schema = {
            "users": {
                "columns": {
                    "id": {"type": "SERIAL", "primary_key": True},
                    "username": {"type": "VARCHAR(255)", "unique": True},
                    "email": {"type": "VARCHAR(255)", "unique": True},
                    "password_hash": {"type": "VARCHAR(512)"},
                    "role": {"type": "VARCHAR(50)", "default": "user"},
                    "created_at": {"type": "TIMESTAMP", "default": "NOW()"},
                    "last_login": {"type": "TIMESTAMP"},
                    "is_active": {"type": "BOOLEAN", "default": True},
                },
                "indexes": ["username", "email", "role"],
            },
            "sessions": {
                "columns": {
                    "id": {"type": "SERIAL", "primary_key": True},
                    "user_id": {"type": "INTEGER", "foreign_key": "users.id"},
                    "token": {"type": "VARCHAR(512)", "unique": True},
                    "ip_address": {"type": "INET"},
                    "user_agent": {"type": "TEXT"},
                    "created_at": {"type": "TIMESTAMP", "default": "NOW()"},
                    "expires_at": {"type": "TIMESTAMP"},
                },
                "indexes": ["token", "user_id", "expires_at"],
            },
            "api_keys": {
                "columns": {
                    "id": {"type": "SERIAL", "primary_key": True},
                    "user_id": {"type": "INTEGER", "foreign_key": "users.id"},
                    "key": {"type": "VARCHAR(256)", "unique": True},
                    "permissions": {"type": "JSONB"},
                    "created_at": {"type": "TIMESTAMP", "default": "NOW()"},
                    "revoked": {"type": "BOOLEAN", "default": False},
                },
                "indexes": ["key", "user_id"],
            },
            "audit_log": {
                "columns": {
                    "id": {"type": "SERIAL", "primary_key": True},
                    "user_id": {"type": "INTEGER"},
                    "action": {"type": "VARCHAR(100)"},
                    "resource": {"type": "VARCHAR(255)"},
                    "details": {"type": "JSONB"},
                    "ip_address": {"type": "INET"},
                    "timestamp": {"type": "TIMESTAMP", "default": "NOW()"},
                },
                "indexes": ["user_id", "action", "timestamp"],
            },
        }
        active_schema = schema or default_schema

        default_records: dict[str, list[dict[str, Any]]] = {
            "users": [
                {"id": 1, "username": "admin", "email": "admin@company.com", "role": "superadmin", "is_active": True},
                {"id": 2, "username": "developer1", "email": "dev1@company.com", "role": "developer", "is_active": True},
                {"id": 3, "username": "analyst", "email": "analyst@company.com", "role": "analyst", "is_active": True},
            ],
            "api_keys": [
                {"id": 1, "user_id": 1, "key": f"sk_live_{secrets.token_hex(24)}", "permissions": {"read": True, "write": True}, "revoked": False},
                {"id": 2, "user_id": 2, "key": f"sk_live_{secrets.token_hex(24)}", "permissions": {"read": True, "write": False}, "revoked": False},
            ],
            "audit_log": [
                {"id": 1, "user_id": 1, "action": "login", "resource": "/admin", "timestamp": "2026-05-16T08:30:00Z"},
                {"id": 2, "user_id": 2, "action": "api_call", "resource": "/api/v1/data", "timestamp": "2026-05-16T09:15:00Z"},
            ],
        }
        active_records = records or default_records
        record_counts = {table: len(recs) for table, recs in active_records.items()}
        db_id = f"db_{secrets.token_hex(8)}"

        result = {
            "db_id": db_id,
            "connection_string": connection_string,
            "engine": "postgresql",
            "version": "15.4",
            "schema": active_schema,
            "record_counts": record_counts,
            "records": active_records,
            "query_log": [],
            "injection_attempts": [],
            "slow_queries": [],
            "status": "online",
            "uptime_seconds": random.randint(86400, 2592000),
            "deployed_at": datetime.now(timezone.utc).isoformat(),
        }

        _emit_honeypot_event(
            "honeypot.database_deployed",
            EventSeverity.INFO,
            {"db_id": db_id, "tables": len(active_schema), "connection_string_hash": _hash_value(connection_string)[:16]},
        )
        _record_metric("honeypot.databases_deployed", 1, {"engine": "postgresql"})
        _record_metric("honeypot.deployment_latency", time.monotonic() - start)

        span.set_attribute("db_id", db_id)
        span.set_attribute("tables_count", len(active_schema))

        logger.info(
            "fake_database.deployed",
            db_id=db_id,
            tables=len(active_schema),
            total_records=sum(record_counts.values()),
        )
        return result


# ---------------------------------------------------------------------------
# 4. Fake API
# ---------------------------------------------------------------------------

def fake_api(
    endpoints: list[str] | None = None,
    responses: dict[str, Any] | None = None,
    rate_limit: int = 1000,
) -> dict[str, Any]:
    """Deploy a fake REST API with realistic endpoints and response payloads.

    Creates a convincing API surface that mimics production endpoints, returns
    plausible JSON responses, and tracks all request patterns for analysis.

    Args:
        endpoints: List of API endpoint paths (e.g., [/api/v1/users, /api/v1/data]).
        responses: Dict mapping endpoint paths to response payload templates.
        rate_limit: Maximum requests per minute before rate limiting triggers.

    Returns:
        Dict with api_id, base_url, endpoints, rate_limit_config,
            request_log, detected_abuse, and status.

    Example:
        >>> endpoints = ["/api/v1/users", "/api/v1/orders"]
        >>> result = fake_api(endpoints, rate_limit=500)
        >>> result["rate_limit_config"]["max_requests_per_minute"]
        500
    """
    with create_span("fake_api") as span:
        start = time.monotonic()

        default_endpoints = [
            "/api/v1/users",
            "/api/v1/users/<id>",
            "/api/v1/orders",
            "/api/v1/orders/<id>",
            "/api/v1/products",
            "/api/v1/products/<id>",
            "/api/v1/auth/login",
            "/api/v1/auth/token",
            "/api/v1/admin/config",
            "/api/v1/health",
        ]
        active_endpoints = endpoints or default_endpoints

        default_responses: dict[str, Any] = {
            "/api/v1/users": {
                "status": "success",
                "data": [{"id": 1, "name": "John Doe", "email": "john@example.com"}],
                "pagination": {"page": 1, "per_page": 20, "total": 1247},
            },
            "/api/v1/orders": {
                "status": "success",
                "data": [{"id": 1001, "user_id": 1, "total": 99.99, "status": "completed"}],
                "pagination": {"page": 1, "per_page": 20, "total": 5832},
            },
            "/api/v1/auth/login": {
                "status": "success",
                "token": f"eyJhbGci.{secrets.token_hex(32)}.{secrets.token_hex(16)}",
                "expires_in": 3600,
            },
            "/api/v1/health": {"status": "healthy", "version": "2.1.0", "uptime": 86400},
        }
        merged_responses = {**default_responses, **(responses or {})}

        api_id = f"api_{secrets.token_hex(8)}"
        base_url = f"/api-{secrets.token_hex(4)}"

        result = {
            "api_id": api_id,
            "base_url": base_url,
            "version": "v1",
            "endpoints": active_endpoints,
            "responses": merged_responses,
            "rate_limit_config": {
                "max_requests_per_minute": rate_limit,
                "burst_limit": rate_limit * 2,
                "current_usage": 0,
                "blocked_ips": [],
            },
            "request_log": [],
            "detected_abuse": [],
            "auth_tokens_issued": 0,
            "status": "active",
            "deployed_at": datetime.now(timezone.utc).isoformat(),
        }

        _emit_honeypot_event(
            "honeypot.api_deployed",
            EventSeverity.INFO,
            {"api_id": api_id, "endpoints_count": len(active_endpoints), "rate_limit": rate_limit},
        )
        _record_metric("honeypot.apis_deployed", 1)
        _record_metric("honeypot.deployment_latency", time.monotonic() - start)

        span.set_attribute("api_id", api_id)
        span.set_attribute("endpoints_count", len(active_endpoints))

        logger.info(
            "fake_api.deployed",
            api_id=api_id,
            endpoints_count=len(active_endpoints),
            rate_limit=rate_limit,
        )
        return result


# ---------------------------------------------------------------------------
# 5. Fake Filesystem
# ---------------------------------------------------------------------------

def _count_dirs(structure: dict[str, Any]) -> int:
    """Recursively count directories in a filesystem structure."""
    count = 0
    for key, value in structure.items():
        if isinstance(value, dict):
            count += 1
            count += _count_dirs(value)
    return count


def fake_filesystem(
    structure: dict[str, Any] | None = None,
    files: dict[str, str] | None = None,
    permissions: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Create a realistic fake filesystem with plausible directory structures and files.

    Generates a convincing filesystem tree with realistic file contents, proper
    permissions, and sensitive-looking paths to attract filesystem enumeration attacks.

    Args:
        structure: Dict representing directory tree (e.g., {/etc: {config.yml: None}}).
        files: Dict mapping file paths to their fake contents.
        permissions: Dict mapping paths to permission strings (e.g., {/etc/shadow: 600}).

    Returns:
        Dict with fs_id, root, structure, file_contents, permissions,
            access_log, and status.

    Example:
        >>> structure = {"/etc": {"passwd": None, "shadow": None}}
        >>> result = fake_filesystem(structure)
        >>> "/etc" in result["structure"]
        True
    """
    with create_span("fake_filesystem") as span:
        start = time.monotonic()

        default_structure = {
            "/etc": {
                "passwd": None,
                "shadow": None,
                "hosts": None,
                "nginx": {"nginx.conf": None, "sites-enabled": {"default": None}},
            },
            "/var": {
                "log": {"syslog": None, "auth.log": None, "nginx": {"access.log": None, "error.log": None}},
                "www": {"html": {"index.html": None}},
            },
            "/home": {
                "admin": {".bashrc": None, ".ssh": {"authorized_keys": None, "id_rsa": None}},
                "deploy": {".bashrc": None, "app": {"config.py": None, ".env": None}},
            },
            "/opt": {
                "app": {"src": {"main.py": None, "config.py": None}, "requirements.txt": None},
            },
            "/tmp": {".hidden": {"backdoor.sh": None, "payload.bin": None}},
        }
        active_structure = structure or default_structure

        default_files = {
            "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Admin:/home/admin:/bin/bash\ndeploy:x:1001:1001:Deploy:/home/deploy:/bin/bash\n",
            "/etc/shadow": f"root:{_hash_value(chr(39)+chr(39))}:19000:0:99999:7:::\nadmin:{_hash_value(chr(39)+chr(39))}:19000:0:99999:7:::\n",
            "/etc/hosts": "127.0.0.1 localhost\n10.0.0.1 db-primary\n10.0.0.2 db-replica\n10.0.0.3 cache-redis\n",
            "/home/admin/.ssh/authorized_keys": f"ssh-rsa AAAAB3NzaC1yc2EAAA... admin@production\nssh-ed25519 AAAAC3NzaC1lZDI1... deploy@ci-server\n",
            "/home/deploy/app/.env": f"DATABASE_URL=postgresql://app:{secrets.token_hex(16)}@db-primary:5432/production\nSECRET_KEY={secrets.token_hex(32)}\nREDIS_URL=redis://cache-redis:6379/0\n",
            "/opt/app/requirements.txt": "flask==2.3.2\nsqlalchemy==2.0.19\nredis==4.6.0\ncelery==5.3.1\ngunicorn==21.2.0\n",
        }
        merged_files = {**default_files, **(files or {})}

        default_permissions = {
            "/etc/passwd": "644",
            "/etc/shadow": "640",
            "/etc/hosts": "644",
            "/home/admin/.ssh/authorized_keys": "600",
            "/home/admin/.ssh/id_rsa": "600",
            "/home/deploy/app/.env": "600",
            "/tmp/.hidden/backdoor.sh": "755",
        }
        merged_permissions = {**default_permissions, **(permissions or {})}

        fs_id = f"fs_{secrets.token_hex(8)}"

        result = {
            "fs_id": fs_id,
            "root": "/",
            "structure": active_structure,
            "file_contents": merged_files,
            "permissions": merged_permissions,
            "access_log": [],
            "file_access_attempts": [],
            "privilege_escalation_attempts": [],
            "total_files": len(merged_files),
            "total_directories": _count_dirs(active_structure),
            "status": "active",
            "deployed_at": datetime.now(timezone.utc).isoformat(),
        }

        _emit_honeypot_event(
            "honeypot.filesystem_deployed",
            EventSeverity.INFO,
            {"fs_id": fs_id, "files": len(merged_files), "permissions_count": len(merged_permissions)},
        )
        _record_metric("honeypot.filesystems_deployed", 1)
        _record_metric("honeypot.deployment_latency", time.monotonic() - start)

        span.set_attribute("fs_id", fs_id)
        span.set_attribute("files_count", len(merged_files))

        logger.info(
            "fake_filesystem.deployed",
            fs_id=fs_id,
            files=len(merged_files),
            directories=result["total_directories"],
        )
        return result


# ---------------------------------------------------------------------------
# 6. Fake SSH Service
# ---------------------------------------------------------------------------

def fake_ssh_service(
    banner: str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
    host_key: str | None = None,
    port: int = 22,
) -> dict[str, Any]:
    """Deploy a fake SSH service that accepts connections and logs all interaction attempts.

    Simulates a realistic SSH server with configurable banner, host key fingerprint,
    and authentication behavior. Tracks brute force attempts and credential stuffing.

    Args:
        banner: SSH protocol version string to present to connecting clients.
        host_key: Optional host key fingerprint to use (generated if not provided).
        port: Port number to listen on (default 22).

    Returns:
        Dict with service_id, port, banner, host_key_fingerprint,
            connection_log, auth_attempts, brute_force_detected, and status.

    Example:
        >>> result = fake_ssh_service(port=2222)
        >>> result["port"]
        2222
    """
    with create_span("fake_ssh_service") as span:
        start = time.monotonic()

        generated_key = secrets.token_hex(16)
        host_key_fp = host_key or f"SHA256:{secrets.token_urlsafe(43)[:43]}"
        service_id = f"ssh_{secrets.token_hex(8)}"

        supported_methods = ["publickey", "password", "keyboard-interactive"]
        allowed_users = ["root", "admin", "ubuntu", "deploy", "jenkins", "git"]

        result = {
            "service_id": service_id,
            "port": port,
            "protocol": "SSH-2.0",
            "banner": banner,
            "host_key_fingerprint": host_key_fp,
            "host_key_type": "ssh-ed25519",
            "supported_auth_methods": supported_methods,
            "allowed_users": allowed_users,
            "connection_log": [],
            "auth_attempts": [],
            "brute_force_detected": False,
            "brute_force_threshold": 10,
            "current_failed_attempts": 0,
            "successful_logins": 0,
            "commands_executed": [],
            "status": "listening",
            "uptime_seconds": random.randint(86400, 7776000),
            "deployed_at": datetime.now(timezone.utc).isoformat(),
        }

        _emit_honeypot_event(
            "honeypot.ssh_deployed",
            EventSeverity.INFO,
            {"service_id": service_id, "port": port, "banner": banner},
        )
        _record_metric("honeypot.ssh_services_deployed", 1, {"port": str(port)})
        _record_metric("honeypot.deployment_latency", time.monotonic() - start)

        span.set_attribute("service_id", service_id)
        span.set_attribute("port", port)

        logger.info(
            "fake_ssh_service.deployed",
            service_id=service_id,
            port=port,
            banner=banner,
        )
        return result


# ---------------------------------------------------------------------------
# 7. Fake RDP Service
# ---------------------------------------------------------------------------

def fake_rdp_service(
    banner: str = "RDP-10.0.19041",
    port: int = 3389,
    authentication: str = "nla",
) -> dict[str, Any]:
    """Deploy a fake RDP service to detect and track remote desktop attacks.

    Simulates a Windows RDP endpoint with configurable authentication mode,
    capturing connection attempts, credential submissions, and NLA negotiations.

    Args:
        banner: RDP version banner to present (e.g., RDP-10.0.19041).
        port: Port number to listen on (default 3389).
        authentication: Authentication mode. One of nla, tls, rdp.

    Returns:
        Dict with service_id, port, banner, auth_mode, connection_log,
            credential_attempts, network_level_auth, and status.

    Example:
        >>> result = fake_rdp_service(port=3390, authentication="tls")
        >>> result["auth_mode"]
        'tls'
    """
    with create_span("fake_rdp_service") as span:
        start = time.monotonic()

        service_id = f"rdp_{secrets.token_hex(8)}"

        fake_os_info = {
            "product_name": "Windows Server 2022 Standard",
            "build_number": 20348,
            "service_pack": "",
            "domain": "CORP.LOCAL",
        }

        result = {
            "service_id": service_id,
            "port": port,
            "protocol": "RDP",
            "banner": banner,
            "auth_mode": authentication,
            "network_level_auth": authentication == "nla",
            "os_info": fake_os_info,
            "encryption_level": "high",
            "supported_protocols": ["rdp", "ssl", "hybrid"],
            "connection_log": [],
            "credential_attempts": [],
            "clipboard_events": [],
            "drive_redirects": [],
            "failed_attempts": 0,
            "successful_connections": 0,
            "status": "listening",
            "uptime_seconds": random.randint(86400, 7776000),
            "deployed_at": datetime.now(timezone.utc).isoformat(),
        }

        _emit_honeypot_event(
            "honeypot.rdp_deployed",
            EventSeverity.INFO,
            {"service_id": service_id, "port": port, "auth_mode": authentication},
        )
        _record_metric("honeypot.rdp_services_deployed", 1, {"port": str(port)})
        _record_metric("honeypot.deployment_latency", time.monotonic() - start)

        span.set_attribute("service_id", service_id)
        span.set_attribute("port", port)

        logger.info(
            "fake_rdp_service.deployed",
            service_id=service_id,
            port=port,
            auth_mode=authentication,
        )
        return result


# ---------------------------------------------------------------------------
# 8. Fake Kubernetes Cluster
# ---------------------------------------------------------------------------

def fake_kubernetes_cluster(
    api_server: str = "https://k8s-api.corp.local:6443",
    nodes: list[dict[str, Any]] | None = None,
    namespaces: list[str] | None = None,
) -> dict[str, Any]:
    """Deploy a fake Kubernetes cluster API to attract container-focused attackers.

    Simulates a production K8s environment with realistic node configurations,
    namespace structures, pod definitions, and service accounts.

    Args:
        api_server: URL of the fake API server endpoint.
        nodes: List of node definitions with name, role, capacity, and status.
        namespaces: List of namespace names to expose.

    Returns:
        Dict with cluster_id, api_server, nodes, namespaces, pods,
            service_accounts, access_log, and status.

    Example:
        >>> nodes = [{"name": "worker-1", "role": "worker"}]
        >>> result = fake_kubernetes_cluster(nodes=nodes)
        >>> len(result["nodes"]) > 0
        True
    """
    with create_span("fake_kubernetes_cluster") as span:
        start = time.monotonic()

        cluster_id = f"k8s_{secrets.token_hex(8)}"

        default_nodes = [
            {"name": "master-01", "role": "control-plane", "status": "Ready", "cpu": "4", "memory": "8Gi", "pods": 42, "version": "v1.28.2"},
            {"name": "worker-01", "role": "worker", "status": "Ready", "cpu": "8", "memory": "32Gi", "pods": 87, "version": "v1.28.2"},
            {"name": "worker-02", "role": "worker", "status": "Ready", "cpu": "8", "memory": "32Gi", "pods": 65, "version": "v1.28.2"},
            {"name": "worker-03", "role": "worker", "status": "Ready", "cpu": "16", "memory": "64Gi", "pods": 112, "version": "v1.28.2"},
        ]
        active_nodes = nodes or default_nodes

        default_namespaces = ["default", "kube-system", "kube-public", "monitoring", "production", "staging", "ingress-nginx", "cert-manager"]
        active_namespaces = namespaces or default_namespaces

        fake_pods = [
            {"name": "api-server-7d4b8c6f9-x2k4m", "namespace": "production", "status": "Running", "restarts": 0, "age": "15d"},
            {"name": "worker-5f8a9b2c1-j7n3p", "namespace": "production", "status": "Running", "restarts": 2, "age": "8d"},
            {"name": "redis-master-0", "namespace": "production", "status": "Running", "restarts": 0, "age": "30d"},
            {"name": "prometheus-server-6c8d4e2a1-q9w5r", "namespace": "monitoring", "status": "Running", "restarts": 1, "age": "22d"},
            {"name": "nginx-ingress-controller-8b7f3d1c-m4t6y", "namespace": "ingress-nginx", "status": "Running", "restarts": 0, "age": "45d"},
        ]

        fake_service_accounts = [
            {"name": "default", "namespace": "default", "secrets": 1},
            {"name": "kube-proxy", "namespace": "kube-system", "secrets": 1},
            {"name": "monitoring-sa", "namespace": "monitoring", "secrets": 2},
            {"name": "deploy-bot", "namespace": "production", "secrets": 3},
        ]

        fake_tokens = [
            {"name": "deploy-bot-token", "namespace": "production", "token": f"eyJhbGci.{secrets.token_hex(32)}.{secrets.token_hex(16)}"},
            {"name": "monitoring-sa-token", "namespace": "monitoring", "token": f"eyJhbGci.{secrets.token_hex(32)}.{secrets.token_hex(16)}"},
        ]

        result = {
            "cluster_id": cluster_id,
            "api_server": api_server,
            "kubernetes_version": "v1.28.2",
            "nodes": active_nodes,
            "namespaces": active_namespaces,
            "pods": fake_pods,
            "service_accounts": fake_service_accounts,
            "tokens": fake_tokens,
            "cluster_roles": ["cluster-admin", "edit", "view", "system:node"],
            "access_log": [],
            "privilege_escalation_attempts": [],
            "container_escape_attempts": [],
            "status": "active",
            "deployed_at": datetime.now(timezone.utc).isoformat(),
        }

        _emit_honeypot_event(
            "honeypot.k8s_deployed",
            EventSeverity.INFO,
            {"cluster_id": cluster_id, "nodes_count": len(active_nodes), "namespaces_count": len(active_namespaces)},
        )
        _record_metric("honeypot.k8s_clusters_deployed", 1)
        _record_metric("honeypot.deployment_latency", time.monotonic() - start)

        span.set_attribute("cluster_id", cluster_id)
        span.set_attribute("nodes_count", len(active_nodes))

        logger.info(
            "fake_kubernetes_cluster.deployed",
            cluster_id=cluster_id,
            nodes=len(active_nodes),
            namespaces=len(active_namespaces),
        )
        return result


# ---------------------------------------------------------------------------
# 9. Fake S3 Bucket
# ---------------------------------------------------------------------------

def fake_s3_bucket(
    bucket_name: str = "company-production-data",
    objects: list[dict[str, Any]] | None = None,
    permissions: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Create a fake S3 bucket with realistic objects and access policies.

    Simulates an AWS S3 bucket containing plausible objects, versioning,
    lifecycle policies, and bucket policies to attract cloud enumeration attacks.

    Args:
        bucket_name: Name of the fake S3 bucket.
        objects: List of object definitions with key, size, content_type, and last_modified.
        permissions: Dict mapping object keys or prefixes to ACL permissions.

    Returns:
        Dict with bucket_id, name, region, objects, policies,
            access_log, unauthorized_access_attempts, and status.

    Example:
        >>> result = fake_s3_bucket("my-company-backups")
        >>> result["name"]
        'my-company-backups'
    """
    with create_span("fake_s3_bucket") as span:
        start = time.monotonic()

        bucket_id = f"s3_{secrets.token_hex(8)}"
        region = "us-east-1"

        default_objects = [
            {"key": "backups/db-dump-2026-05-16.sql.gz", "size": 524288000, "content_type": "application/gzip", "last_modified": "2026-05-16T03:00:00Z", "storage_class": "STANDARD_IA"},
            {"key": "backups/db-dump-2026-05-15.sql.gz", "size": 518901760, "content_type": "application/gzip", "last_modified": "2026-05-15T03:00:00Z", "storage_class": "STANDARD_IA"},
            {"key": "exports/customer-data-2026-q1.csv", "size": 15728640, "content_type": "text/csv", "last_modified": "2026-04-01T12:00:00Z", "storage_class": "STANDARD"},
            {"key": "exports/financial-report-2025.pdf", "size": 2097152, "content_type": "application/pdf", "last_modified": "2026-01-15T09:00:00Z", "storage_class": "STANDARD"},
            {"key": "config/application.yml", "size": 4096, "content_type": "application/x-yaml", "last_modified": "2026-05-10T14:30:00Z", "storage_class": "STANDARD"},
            {"key": "config/.env.production", "size": 1024, "content_type": "text/plain", "last_modified": "2026-05-10T14:30:00Z", "storage_class": "STANDARD"},
            {"key": "logs/application-2026-05-16.log", "size": 10485760, "content_type": "text/plain", "last_modified": "2026-05-16T23:59:00Z", "storage_class": "STANDARD"},
            {"key": "certs/wildcard-corp-local.pem", "size": 8192, "content_type": "application/x-pem-file", "last_modified": "2026-03-01T10:00:00Z", "storage_class": "STANDARD"},
        ]
        active_objects = objects or default_objects

        default_permissions = {
            "backups/*": "private",
            "exports/*": "authenticated-read",
            "config/*": "private",
            "logs/*": "private",
            "certs/*": "private",
        }
        merged_permissions = {**default_permissions, **(permissions or {})}

        bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowInternalAccess",
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:role/InternalServiceRole"},
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
                },
            ],
        }

        result = {
            "bucket_id": bucket_id,
            "name": bucket_name,
            "region": region,
            "arn": f"arn:aws:s3:::{bucket_name}",
            "creation_date": "2024-01-15T08:00:00Z",
            "versioning": "enabled",
            "encryption": "AES256",
            "objects": active_objects,
            "total_objects": len(active_objects),
            "total_size_bytes": sum(obj.get("size", 0) for obj in active_objects),
            "permissions": merged_permissions,
            "bucket_policy": bucket_policy,
            "cors_rules": [],
            "lifecycle_rules": [{"id": "expire-old-logs", "prefix": "logs/", "expiration_days": 90}],
            "access_log": [],
            "unauthorized_access_attempts": [],
            "presigned_urls_issued": [],
            "status": "active",
            "deployed_at": datetime.now(timezone.utc).isoformat(),
        }

        _emit_honeypot_event(
            "honeypot.s3_bucket_deployed",
            EventSeverity.INFO,
            {"bucket_id": bucket_id, "name": bucket_name, "objects_count": len(active_objects)},
        )
        _record_metric("honeypot.s3_buckets_deployed", 1)
        _record_metric("honeypot.deployment_latency", time.monotonic() - start)

        span.set_attribute("bucket_id", bucket_id)
        span.set_attribute("bucket_name", bucket_name)

        logger.info(
            "fake_s3_bucket.deployed",
            bucket_id=bucket_id,
            name=bucket_name,
            objects=len(active_objects),
        )
        return result


# ---------------------------------------------------------------------------
# 10. Fake Secrets
# ---------------------------------------------------------------------------

def fake_secrets(
    secrets_list: list[dict[str, Any]] | None = None,
    rotation_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate and manage fake secrets to detect credential harvesting attempts.

    Creates realistic-looking API keys, tokens, passwords, and certificates that
    are tracked when used, enabling detection of credential exfiltration.

    Args:
        secrets_list: List of secret definitions with type, name, and optional value.
        rotation_policy: Dict with interval_days, auto_rotate, and notify_on_use settings.

    Returns:
        Dict with secrets_id, secrets, rotation_policy, usage_tracking,
            compromised_secrets, and status.

    Example:
        >>> secrets = [{"type": "api_key", "name": "stripe_key"}]
        >>> result = fake_secrets(secrets)
        >>> len(result["secrets"]) > 0
        True
    """
    with create_span("fake_secrets") as span:
        start = time.monotonic()

        secrets_id = f"secrets_{secrets.token_hex(8)}"

        default_secrets = [
            {"type": "api_key", "name": "stripe_secret_key", "value": f"sk_live_{secrets.token_hex(24)}", "service": "stripe", "created": "2026-01-15T10:00:00Z"},
            {"type": "api_key", "name": "aws_access_key", "value": f"AKIA{secrets.token_hex(16).upper()}", "service": "aws", "created": "2026-02-20T14:30:00Z"},
            {"type": "api_key", "name": "aws_secret_key", "value": secrets.token_hex(20), "service": "aws", "created": "2026-02-20T14:30:00Z"},
            {"type": "token", "name": "github_pat", "value": f"ghp_{secrets.token_hex(18)}", "service": "github", "created": "2026-03-10T09:00:00Z"},
            {"type": "token", "name": "slack_bot_token", "value": f"xoxb-{secrets.token_hex(10)}-{secrets.token_hex(10)}-{secrets.token_hex(20)}", "service": "slack", "created": "2026-03-15T11:00:00Z"},
            {"type": "password", "name": "db_master_password", "value": f"DbM@st3r!{secrets.token_hex(4)}#2026", "service": "postgresql", "created": "2026-01-01T00:00:00Z"},
            {"type": "certificate", "name": "tls_private_key", "value": f"-----BEGIN RSA PRIVATE KEY-----\n{secrets.token_hex(64)}\n-----END RSA PRIVATE KEY-----", "service": "nginx", "created": "2026-04-01T08:00:00Z"},
            {"type": "api_key", "name": "sendgrid_key", "value": f"SG.{secrets.token_hex(22)}.{secrets.token_hex(22)}", "service": "sendgrid", "created": "2026-04-15T16:00:00Z"},
        ]

        if secrets_list:
            for req in secrets_list:
                secret_type = req.get("type", "api_key")
                name = req.get("name", f"custom_{secrets.token_hex(4)}")
                value = req.get("value")
                if not value:
                    if secret_type == "api_key":
                        value = f"sk_{secrets.token_hex(24)}"
                    elif secret_type == "token":
                        value = f"tok_{secrets.token_hex(32)}"
                    elif secret_type == "password":
                        value = f"P@ss{secrets.token_hex(8)}!2026"
                    elif secret_type == "certificate":
                        value = f"-----BEGIN CERTIFICATE-----\n{secrets.token_hex(64)}\n-----END CERTIFICATE-----"
                    else:
                        value = secrets.token_hex(32)
                default_secrets.append({
                    "type": secret_type,
                    "name": name,
                    "value": value,
                    "service": req.get("service", "unknown"),
                    "created": datetime.now(timezone.utc).isoformat(),
                })

        active_secrets = []
        for s in default_secrets:
            active_secrets.append({
                "type": s["type"],
                "name": s["name"],
                "value": s["value"],
                "value_hash": _hash_value(s["value"]),
                "service": s["service"],
                "created": s["created"],
                "last_used": None,
                "use_count": 0,
                "compromised": False,
            })

        default_rotation = {
            "interval_days": 90,
            "auto_rotate": True,
            "notify_on_use": True,
            "max_age_days": 180,
            "grace_period_days": 7,
        }
        active_rotation = {**default_rotation, **(rotation_policy or {})}

        result = {
            "secrets_id": secrets_id,
            "secrets": active_secrets,
            "total_secrets": len(active_secrets),
            "rotation_policy": active_rotation,
            "usage_tracking": {},
            "compromised_secrets": [],
            "alerts_triggered": [],
            "last_rotation": "2026-04-15T00:00:00Z",
            "next_rotation": "2026-07-15T00:00:00Z",
            "status": "active",
            "deployed_at": datetime.now(timezone.utc).isoformat(),
        }

        _emit_honeypot_event(
            "honeypot.secrets_deployed",
            EventSeverity.INFO,
            {"secrets_id": secrets_id, "count": len(active_secrets), "types": list(set(s["type"] for s in active_secrets))},
        )
        _record_metric("honeypot.secrets_deployed", len(active_secrets))
        _record_metric("honeypot.deployment_latency", time.monotonic() - start)

        span.set_attribute("secrets_id", secrets_id)
        span.set_attribute("secrets_count", len(active_secrets))

        logger.info(
            "fake_secrets.deployed",
            secrets_id=secrets_id,
            count=len(active_secrets),
        )
        return result


# ---------------------------------------------------------------------------
# 11. Deceptive Routes
# ---------------------------------------------------------------------------

def deceptive_routes(
    route_patterns: list[str] | None = None,
    handlers: dict[str, Any] | None = None,
    detection_callback: str | None = None,
) -> dict[str, Any]:
    """Register deceptive routes that appear legitimate but trigger alerts when accessed.

    Creates routes that mimic common admin, debug, and sensitive endpoints. Any
    access to these routes is logged and can trigger custom detection callbacks.

    Args:
        route_patterns: List of route path patterns to register as deceptive.
        handlers: Dict mapping route patterns to handler configurations.
        detection_callback: Name of callback function to invoke on route access.

    Returns:
        Dict with routes_id, registered_routes, handlers, access_log,
            detections, and status.

    Example:
        >>> patterns = ["/admin/config.json", "/.env", "/debug/vars"]
        >>> result = deceptive_routes(patterns)
        >>> len(result["registered_routes"]) > 0
        True
    """
    with create_span("deceptive_routes") as span:
        start = time.monotonic()

        routes_id = f"routes_{secrets.token_hex(8)}"

        default_patterns = [
            "/admin/config.json",
            "/admin/backup.sql",
            "/.env",
            "/.env.production",
            "/.git/config",
            "/.git/HEAD",
            "/debug/vars",
            "/debug/pprof",
            "/server-status",
            "/server-info",
            "/phpinfo.php",
            "/wp-admin/",
            "/wp-login.php",
            "/.htaccess",
            "/api/internal/keys",
            "/api/internal/tokens",
            "/console",
            "/actuator/env",
            "/actuator/beans",
            "/swagger.json",
        ]
        active_patterns = route_patterns or default_patterns

        default_handlers: dict[str, Any] = {}
        for pattern in active_patterns:
            default_handlers[pattern] = {
                "method": ["GET", "POST", "HEAD"],
                "response_code": 200,
                "response_delay_ms": random.randint(50, 300),
                "log_access": True,
                "alert_on_access": True,
                "track_source": True,
            }
        merged_handlers = {**default_handlers, **(handlers or {})}

        result = {
            "routes_id": routes_id,
            "registered_routes": active_patterns,
            "handlers": merged_handlers,
            "detection_callback": detection_callback,
            "access_log": [],
            "detections": [],
            "total_accesses": 0,
            "unique_sources": [],
            "most_targeted_route": None,
            "status": "active",
            "deployed_at": datetime.now(timezone.utc).isoformat(),
        }

        _emit_honeypot_event(
            "honeypot.routes_deployed",
            EventSeverity.INFO,
            {"routes_id": routes_id, "patterns_count": len(active_patterns), "callback": detection_callback},
        )
        _record_metric("honeypot.deceptive_routes_deployed", len(active_patterns))
        _record_metric("honeypot.deployment_latency", time.monotonic() - start)

        span.set_attribute("routes_id", routes_id)
        span.set_attribute("routes_count", len(active_patterns))

        logger.info(
            "deceptive_routes.deployed",
            routes_id=routes_id,
            routes_count=len(active_patterns),
            callback=detection_callback,
        )
        return result


# ---------------------------------------------------------------------------
# 12. Attacker Behavior Tracking
# ---------------------------------------------------------------------------

def _determine_attack_phase(action_types: list[str]) -> str:
    """Determine the current attack phase based on observed action types."""
    recon_actions = {"reconnaissance", "scanning", "enumeration"}
    exploit_actions = {"injection_attempt", "brute_force", "login_attempt"}
    post_actions = {"privilege_escalation", "lateral_movement", "persistence", "data_exfiltration"}

    recon_count = sum(1 for a in action_types if a in recon_actions)
    exploit_count = sum(1 for a in action_types if a in exploit_actions)
    post_count = sum(1 for a in action_types if a in post_actions)

    if post_count > 0:
        return "post_exploitation"
    elif exploit_count > recon_count:
        return "exploitation"
    elif recon_count > 0:
        return "reconnaissance"
    return "unknown"


def attacker_behavior_tracking(
    session_id: str,
    actions: list[dict[str, Any]],
    timeline: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Track and analyze attacker behavior patterns within a honeypot session.

    Records all actions taken by an attacker, builds a behavioral profile,
    identifies attack patterns, and calculates threat scores.

    Args:
        session_id: Unique identifier for the honeypot session.
        actions: List of action dicts with type, target, timestamp, and details.
        timeline: Optional list of timeline entries with event, timestamp, and context.

    Returns:
        Dict with tracking_id, session_id, behavior_profile, attack_patterns,
            threat_score, recommendations, and timeline.

    Example:
        >>> actions = [{"type": "login_attempt", "target": "/admin", "details": {"username": "admin"}}]
        >>> result = attacker_behavior_tracking("sess_123", actions)
        >>> result["threat_score"] > 0
        True
    """
    with create_span("attacker_behavior_tracking") as span:
        start = time.monotonic()

        tracking_id = f"track_{secrets.token_hex(8)}"

        action_types = [a.get("type", "unknown") for a in actions]
        targets = [a.get("target", "unknown") for a in actions]

        severity_weights = {
            "reconnaissance": 1,
            "scanning": 2,
            "enumeration": 3,
            "login_attempt": 4,
            "brute_force": 5,
            "injection_attempt": 7,
            "privilege_escalation": 8,
            "data_exfiltration": 9,
            "lateral_movement": 9,
            "persistence": 10,
        }

        threat_score = 0
        attack_patterns: list[dict[str, Any]] = []
        pattern_counts: dict[str, int] = {}

        for action in actions:
            action_type = action.get("type", "unknown")
            weight = severity_weights.get(action_type, 1)
            threat_score += weight
            pattern_counts[action_type] = pattern_counts.get(action_type, 0) + 1

        for pattern, count in pattern_counts.items():
            attack_patterns.append({
                "pattern": pattern,
                "count": count,
                "severity": severity_weights.get(pattern, 1),
                "first_seen": actions[0].get("timestamp", "") if pattern_counts[pattern] > 0 else "",
            })

        threat_score = min(100, threat_score)

        behavior_profile = {
            "session_id": session_id,
            "total_actions": len(actions),
            "unique_targets": len(set(targets)),
            "action_distribution": pattern_counts,
            "attack_sophistication": "advanced" if threat_score > 70 else "intermediate" if threat_score > 40 else "basic",
            "attack_phase": _determine_attack_phase(action_types),
            "persistence_level": "high" if pattern_counts.get("persistence", 0) > 2 else "medium" if pattern_counts.get("persistence", 0) > 0 else "low",
        }

        recommendations = []
        if threat_score > 70:
            recommendations.append("Immediately isolate and block source IP")
            recommendations.append("Escalate to incident response team")
        if pattern_counts.get("brute_force", 0) > 5:
            recommendations.append("Implement rate limiting on authentication endpoints")
        if pattern_counts.get("injection_attempt", 0) > 0:
            recommendations.append("Review input validation on targeted endpoints")
        if pattern_counts.get("data_exfiltration", 0) > 0:
            recommendations.append("Audit data access controls and DLP policies")
        if not recommendations:
            recommendations.append("Continue monitoring and log analysis")

        active_timeline = timeline or [
            {"event": a.get("type", "unknown"), "timestamp": a.get("timestamp", datetime.now(timezone.utc).isoformat()), "context": a.get("details", {})}
            for a in actions
        ]

        result = {
            "tracking_id": tracking_id,
            "session_id": session_id,
            "behavior_profile": behavior_profile,
            "attack_patterns": attack_patterns,
            "threat_score": threat_score,
            "threat_level": "critical" if threat_score > 80 else "high" if threat_score > 60 else "medium" if threat_score > 30 else "low",
            "recommendations": recommendations,
            "timeline": active_timeline,
            "first_action": actions[0].get("timestamp", "") if actions else "",
            "last_action": actions[-1].get("timestamp", "") if actions else "",
            "analysis_completed_at": datetime.now(timezone.utc).isoformat(),
        }

        _emit_honeypot_event(
            "honeypot.attacker_tracked",
            EventSeverity.HIGH if threat_score > 60 else EventSeverity.MEDIUM,
            {"tracking_id": tracking_id, "session_id": session_id, "threat_score": threat_score, "actions_count": len(actions)},
        )
        _record_metric("honeypot.attacker_sessions_tracked", 1, {"threat_level": result["threat_level"]})
        _record_metric("honeypot.threat_score", threat_score)
        _record_metric("honeypot.deployment_latency", time.monotonic() - start)

        span.set_attribute("tracking_id", tracking_id)
        span.set_attribute("threat_score", threat_score)

        logger.info(
            "attacker_behavior_tracking.completed",
            tracking_id=tracking_id,
            session_id=session_id,
            threat_score=threat_score,
            actions=len(actions),
        )
        return result


# ---------------------------------------------------------------------------
# 13. Adaptive Deception
# ---------------------------------------------------------------------------

def _generate_engagement_hooks(goals: list[str]) -> list[str]:
    """Generate engagement hooks tailored to attacker goals."""
    hooks = []
    goal_hooks = {
        "data_exfiltration": ["large_fake_dataset", "export_endpoint", "bulk_download_api"],
        "credential_harvesting": ["password_reset_flow", "admin_login_portal", "sso_integration"],
        "lateral_movement": ["internal_api_endpoints", "service_discovery", "network_topology_map"],
        "privilege_escalation": ["sudo_config", "admin_panel", "role_management_api"],
        "reconnaissance": ["sitemap.xml", "robots.txt", "api_documentation"],
        "persistence": ["cron_jobs", "scheduled_tasks", "startup_scripts"],
    }
    for goal in goals:
        hooks.extend(goal_hooks.get(goal, ["generic_engagement_point"]))
    return list(set(hooks))


def adaptive_deception(
    current_deception: dict[str, Any],
    attacker_profile: dict[str, Any],
    effectiveness: dict[str, float],
) -> dict[str, Any]:
    """Dynamically adjust deception tactics based on attacker profile and effectiveness metrics.

    Analyzes how well current deception measures are working against a specific
    attacker and adapts the deception strategy in real-time.

    Args:
        current_deception: Dict describing current deception setup with type, depth, and engagement.
        attacker_profile: Dict with attacker characteristics like skill_level, goals, patience, and tools.
        effectiveness: Dict with metrics like engagement_time, belief_score, interaction_depth.

    Returns:
        Dict with adaptation_id, new_strategy, adjusted_parameters,
            predicted_effectiveness, and recommendations.

    Example:
        >>> deception = {"type": "fake_api", "depth": "moderate"}
        >>> profile = {"skill_level": "advanced", "goals": ["data_exfiltration"]}
        >>> eff = {"engagement_time": 0.7, "belief_score": 0.5}
        >>> result = adaptive_deception(deception, profile, eff)
        >>> result["new_strategy"]["depth"] in ["shallow", "moderate", "deep"]
        True
    """
    with create_span("adaptive_deception") as span:
        start = time.monotonic()

        adaptation_id = f"adapt_{secrets.token_hex(8)}"

        skill_level = attacker_profile.get("skill_level", "unknown")
        attacker_goals = attacker_profile.get("goals", [])
        patience = attacker_profile.get("patience", "medium")

        engagement_time = effectiveness.get("engagement_time", 0.5)
        belief_score = effectiveness.get("belief_score", 0.5)
        interaction_depth = effectiveness.get("interaction_depth", 0.3)

        current_depth = current_deception.get("depth", "moderate")
        deception_type = current_deception.get("type", "generic")

        depth_levels = ["shallow", "moderate", "deep", "comprehensive"]
        current_idx = depth_levels.index(current_depth) if current_depth in depth_levels else 1

        if belief_score < 0.3 and engagement_time < 0.2:
            new_depth_idx = min(len(depth_levels) - 1, current_idx + 1)
            strategy_change = "increase_depth"
        elif belief_score > 0.8 and engagement_time > 0.7:
            new_depth_idx = max(0, current_idx - 1)
            strategy_change = "maintain_and_collect"
        elif interaction_depth < 0.2:
            new_depth_idx = min(len(depth_levels) - 1, current_idx + 2)
            strategy_change = "aggressive_escalation"
        else:
            new_depth_idx = current_idx
            strategy_change = "maintain"

        new_depth = depth_levels[new_depth_idx]

        adjusted_params = {
            "response_delay_ms": random.randint(100, 1000) if skill_level == "advanced" else random.randint(10, 200),
            "data_realism": "high" if belief_score < 0.5 else "moderate",
            "error_injection": skill_level == "advanced" and belief_score > 0.6,
            "breadcrumb_trail": len(attacker_goals) > 1,
            "engagement_hooks": _generate_engagement_hooks(attacker_goals),
        }

        predicted_effectiveness = min(1.0, belief_score + (0.1 if new_depth_idx > current_idx else 0))

        recommendations = []
        if skill_level == "advanced":
            recommendations.append("Add subtle inconsistencies to maintain believability")
            recommendations.append("Include realistic error responses")
        if "data_exfiltration" in attacker_goals:
            recommendations.append("Plant fake sensitive data with honeytokens")
        if "lateral_movement" in attacker_goals:
            recommendations.append("Create fake internal network topology")
        if patience == "low":
            recommendations.append("Provide quick wins to maintain engagement")

        result = {
            "adaptation_id": adaptation_id,
            "deception_type": deception_type,
            "previous_depth": current_depth,
            "new_strategy": {
                "depth": new_depth,
                "strategy_change": strategy_change,
                "rationale": f"belief_score={belief_score}, engagement={engagement_time}, skill={skill_level}",
            },
            "adjusted_parameters": adjusted_params,
            "predicted_effectiveness": predicted_effectiveness,
            "attacker_profile_summary": {
                "skill_level": skill_level,
                "goals": attacker_goals,
                "patience": patience,
            },
            "recommendations": recommendations,
            "adapted_at": datetime.now(timezone.utc).isoformat(),
        }

        _emit_honeypot_event(
            "honeypot.deception_adapted",
            EventSeverity.INFO,
            {"adaptation_id": adaptation_id, "depth_change": f"{current_depth} -> {new_depth}", "predicted_effectiveness": predicted_effectiveness},
        )
        _record_metric("honeypot.deception_adaptations", 1, {"strategy_change": strategy_change})
        _record_metric("honeypot.predicted_effectiveness", predicted_effectiveness)
        _record_metric("honeypot.deployment_latency", time.monotonic() - start)

        span.set_attribute("adaptation_id", adaptation_id)
        span.set_attribute("depth_change", f"{current_depth} -> {new_depth}")

        logger.info(
            "adaptive_deception.adapted",
            adaptation_id=adaptation_id,
            depth_change=f"{current_depth} -> {new_depth}",
            predicted_effectiveness=predicted_effectiveness,
        )
        return result


# ---------------------------------------------------------------------------
# 14. Moving Target Defense
# ---------------------------------------------------------------------------

def moving_target_defense(
    services: list[dict[str, Any]],
    rotation_interval: int = 3600,
    randomization: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Implement moving target defense by rotating service configurations.

    Dynamically changes ports, banners, endpoints, and other service fingerprints
    at configurable intervals to frustrate attacker reconnaissance.

    Args:
        services: List of service definitions with name, type, port, and config.
        rotation_interval: Seconds between configuration rotations (default 3600).
        randomization: Dict with port_range, banner_pool, and endpoint_suffixes.

    Returns:
        Dict with mti_id, current_config, rotation_schedule, rotation_history,
            active_ports, and status.

    Example:
        >>> services = [{"name": "web", "type": "http", "port": 8080}]
        >>> result = moving_target_defense(services, rotation_interval=1800)
        >>> result["rotation_schedule"]["interval_seconds"]
        1800
    """
    with create_span("moving_target_defense") as span:
        start = time.monotonic()

        mti_id = f"mti_{secrets.token_hex(8)}"

        default_randomization = {
            "port_range": {"min": 8000, "max": 9999},
            "banner_pool": [
                "Apache/2.4.52 (Ubuntu)",
                "nginx/1.24.0",
                "Caddy/2.7.4",
                "OpenResty/1.21.4.3",
                "LiteSpeed/6.2",
            ],
            "endpoint_suffixes": [secrets.token_hex(4) for _ in range(5)],
        }
        active_randomization = {**default_randomization, **(randomization or {})}

        port_range = active_randomization["port_range"]
        banner_pool = active_randomization["banner_pool"]

        current_config = []
        for svc in services:
            new_port = random.randint(port_range["min"], port_range["max"])
            new_banner = random.choice(banner_pool)
            current_config.append({
                "name": svc.get("name", "unknown"),
                "type": svc.get("type", "unknown"),
                "original_port": svc.get("port", 0),
                "current_port": new_port,
                "current_banner": new_banner,
                "endpoint_suffix": random.choice(active_randomization["endpoint_suffixes"]),
                "rotation_count": 0,
            })

        rotation_schedule = {
            "interval_seconds": rotation_interval,
            "next_rotation": datetime.now(timezone.utc).timestamp() + rotation_interval,
            "rotation_strategy": "staggered",
            "max_rotations": 1000,
            "current_rotation": 0,
        }

        result = {
            "mti_id": mti_id,
            "services_count": len(services),
            "current_config": current_config,
            "rotation_schedule": rotation_schedule,
            "rotation_history": [],
            "active_ports": [c["current_port"] for c in current_config],
            "port_range": port_range,
            "randomization_config": active_randomization,
            "total_rotations": 0,
            "status": "active",
            "deployed_at": datetime.now(timezone.utc).isoformat(),
        }

        _emit_honeypot_event(
            "honeypot.moving_target_deployed",
            EventSeverity.INFO,
            {"mti_id": mti_id, "services_count": len(services), "rotation_interval": rotation_interval},
        )
        _record_metric("honeypot.moving_target_defenses", 1)
        _record_metric("honeypot.rotation_interval", rotation_interval)
        _record_metric("honeypot.deployment_latency", time.monotonic() - start)

        span.set_attribute("mti_id", mti_id)
        span.set_attribute("services_count", len(services))

        logger.info(
            "moving_target_defense.deployed",
            mti_id=mti_id,
            services=len(services),
            rotation_interval=rotation_interval,
        )
        return result


# ---------------------------------------------------------------------------
# 15. Honeytoken Generation
# ---------------------------------------------------------------------------

def honeytoken_generation(
    token_type: str = "api_key",
    metadata: dict[str, Any] | None = None,
    tracking: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate trackable honeytokens that alert when used outside authorized contexts.

    Creates various types of tokens (API keys, URLs, credentials, documents) that
    are indistinguishable from real tokens but trigger alerts upon any use.

    Args:
        token_type: Type of honeytoken. One of api_key, url, credential, document, aws_key, jwt.
        metadata: Dict with contextual metadata like service, environment, owner.
        tracking: Dict with alert_channel, webhook_url, and tracking_id settings.

    Returns:
        Dict with token_id, token_type, token_value, metadata, tracking_config,
            usage_log, and status.

    Example:
        >>> result = honeytoken_generation("aws_key", {"service": "s3"})
        >>> result["token_type"]
        'aws_key'
    """
    with create_span("honeytoken_generation") as span:
        start = time.monotonic()

        token_id = f"ht_{secrets.token_hex(8)}"
        tracking_id = f"htrack_{secrets.token_hex(6)}"

        token_generators = {
            "api_key": lambda: f"hny_sk_{secrets.token_hex(24)}",
            "url": lambda: f"https://honey.internal.corp/track/{secrets.token_hex(16)}",
            "credential": lambda: {"username": f"honeyuser_{secrets.token_hex(4)}", "password": f"H0n3y!{secrets.token_hex(8)}#2026"},
            "document": lambda: f"hny_doc_{secrets.token_hex(12)}.pdf",
            "aws_key": lambda: {"access_key_id": f"AKIAHNY{secrets.token_hex(12).upper()}", "secret_access_key": secrets.token_hex(20)},
            "jwt": lambda: f"eyJhbGciOiJIUzI1NiJ9.{secrets.token_urlsafe(48)}.{secrets.token_hex(16)}",
        }

        generator = token_generators.get(token_type, token_generators["api_key"])
        token_value = generator()

        default_metadata = {
            "service": "unknown",
            "environment": "production",
            "owner": "security_team",
            "purpose": "honeytoken",
            "created_by": "master_security",
        }
        active_metadata = {**default_metadata, **(metadata or {})}

        default_tracking = {
            "alert_channel": "security_alerts",
            "webhook_url": f"https://alerts.internal.corp/honeytoken/{tracking_id}",
            "tracking_id": tracking_id,
            "alert_on_first_use": True,
            "alert_on_every_use": True,
            "collect_source_ip": True,
            "collect_user_agent": True,
            "collect_timestamp": True,
        }
        active_tracking = {**default_tracking, **(tracking or {})}

        token_str = json.dumps(token_value, default=str) if isinstance(token_value, dict) else str(token_value)

        result = {
            "token_id": token_id,
            "token_type": token_type,
            "token_value": token_value,
            "token_hash": _hash_value(token_str),
            "metadata": active_metadata,
            "tracking_config": active_tracking,
            "usage_log": [],
            "use_count": 0,
            "first_used": None,
            "last_used": None,
            "compromised": False,
            "status": "active",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": None,
        }

        _emit_honeypot_event(
            "honeypot.honeytoken_generated",
            EventSeverity.INFO,
            {"token_id": token_id, "token_type": token_type, "tracking_id": tracking_id},
        )
        _record_metric("honeypot.honeytokens_generated", 1, {"token_type": token_type})
        _record_metric("honeypot.deployment_latency", time.monotonic() - start)

        span.set_attribute("token_id", token_id)
        span.set_attribute("token_type", token_type)

        logger.info(
            "honeytoken_generation.created",
            token_id=token_id,
            token_type=token_type,
            tracking_id=tracking_id,
        )
        return result


# ---------------------------------------------------------------------------
# 16. Honeycredential Detection
# ---------------------------------------------------------------------------

def honeycredential_detection(
    credentials: list[dict[str, Any]],
    honeytoken_db: dict[str, Any],
) -> dict[str, Any]:
    """Check submitted credentials against known honeytoken database.

    Compares provided credentials against a database of planted honeytokens
    to detect credential stuffing, brute force, or credential harvesting attacks.

    Args:
        credentials: List of credential dicts with username, password, source, and timestamp.
        honeytoken_db: Dict mapping credential identifiers to honeytoken records.

    Returns:
        Dict with detection_id, matches, non_matches, alert_triggered,
            matched_tokens, and recommendations.

    Example:
        >>> creds = [{"username": "honeyuser", "password": "test123"}]
        >>> db = {"honeyuser": {"is_honeytoken": True, "token_id": "ht_123"}}
        >>> result = honeycredential_detection(creds, db)
        >>> "matches" in result
        True
    """
    with create_span("honeycredential_detection") as span:
        start = time.monotonic()

        detection_id = f"hcd_{secrets.token_hex(8)}"

        matches = []
        non_matches = []
        matched_tokens = []

        for cred in credentials:
            username = cred.get("username", "")
            password = cred.get("password", "")
            source = cred.get("source", "unknown")

            is_match = False
            matched_token = None

            for token_key, token_record in honeytoken_db.items():
                if isinstance(token_record, dict):
                    if token_record.get("is_honeytoken") and (
                        token_key == username
                        or token_record.get("username") == username
                        or token_record.get("password_hash") == _hash_value(password)
                    ):
                        is_match = True
                        matched_token = {
                            "token_id": token_record.get("token_id", token_key),
                            "username": username,
                            "source": source,
                            "matched_at": datetime.now(timezone.utc).isoformat(),
                        }
                        matched_tokens.append(matched_token)
                        break

            if is_match:
                matches.append({"credential": cred, "matched_token": matched_token})
            else:
                non_matches.append(cred)

        alert_triggered = len(matches) > 0

        recommendations = []
        if alert_triggered:
            recommendations.append("Block source IP immediately")
            recommendations.append("Alert security operations center")
            recommendations.append("Investigate credential source for broader compromise")
            if len(matches) > 3:
                recommendations.append("Initiate incident response procedure")
        else:
            recommendations.append("Continue monitoring - no honeytoken matches")

        result = {
            "detection_id": detection_id,
            "total_checked": len(credentials),
            "matches": matches,
            "non_matches": non_matches,
            "match_count": len(matches),
            "non_match_count": len(non_matches),
            "alert_triggered": alert_triggered,
            "matched_tokens": matched_tokens,
            "recommendations": recommendations,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

        severity = EventSeverity.HIGH if alert_triggered else EventSeverity.INFO
        _emit_honeypot_event(
            "honeypot.honeycredential_checked",
            severity,
            {"detection_id": detection_id, "matches": len(matches), "alert": alert_triggered},
        )
        _record_metric("honeypot.honeycredential_checks", 1)
        _record_metric("honeypot.honeycredential_matches", len(matches))
        _record_metric("honeypot.deployment_latency", time.monotonic() - start)

        span.set_attribute("detection_id", detection_id)
        span.set_attribute("match_count", len(matches))

        logger.info(
            "honeycredential_detection.completed",
            detection_id=detection_id,
            checked=len(credentials),
            matches=len(matches),
            alert=alert_triggered,
        )
        return result


# ---------------------------------------------------------------------------
# 17. Decoy Endpoints
# ---------------------------------------------------------------------------

def decoy_endpoints(
    base_path: str = "/api",
    count: int = 10,
    patterns: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Generate a list of decoy API endpoints that mimic real service endpoints.

    Creates realistic-looking endpoint paths that appear to be legitimate API
    routes but are monitored for unauthorized access attempts.

    Args:
        base_path: Base path prefix for all decoy endpoints.
        count: Number of decoy endpoints to generate.
        patterns: List of pattern templates to use (e.g., ["{base}/v1/{resource}"]).

    Returns:
        List of dicts, each with path, method, description, monitoring,
            and alert_config.

    Example:
        >>> endpoints = decoy_endpoints("/api", count=5)
        >>> len(endpoints)
        5
    """
    with create_span("decoy_endpoints") as span:
        start = time.monotonic()

        default_patterns = [
            "{base}/v1/{resource}",
            "{base}/v2/{resource}",
            "{base}/internal/{resource}",
            "{base}/admin/{resource}",
            "{base}/debug/{resource}",
            "{base}/management/{resource}",
            "{base}/config/{resource}",
            "{base}/metrics/{resource}",
        ]
        active_patterns = patterns or default_patterns

        resources = [
            "users", "sessions", "tokens", "keys", "secrets",
            "config", "settings", "logs", "backup", "database",
            "credentials", "certificates", "deployments", "clusters",
            "nodes", "pods", "services", "ingress", "storage",
        ]

        methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]

        endpoints = []
        used_paths: set[str] = set()

        for i in range(count):
            pattern = random.choice(active_patterns)
            resource = random.choice(resources)
            path = pattern.format(base=base_path, resource=resource)

            while path in used_paths:
                resource = random.choice(resources)
                path = pattern.format(base=base_path, resource=resource)
            used_paths.add(path)

            endpoints.append({
                "path": path,
                "method": random.choice(methods),
                "description": f"Decoy endpoint for {resource} monitoring",
                "monitoring": {
                    "enabled": True,
                    "log_requests": True,
                    "log_headers": True,
                    "log_body": True,
                    "alert_on_access": True,
                },
                "alert_config": {
                    "severity": "high",
                    "channels": ["security_alerts", "siem"],
                    "include_source_ip": True,
                    "include_user_agent": True,
                },
                "response_template": {
                    "status_code": random.choice([200, 401, 403, 404, 500]),
                    "delay_ms": random.randint(50, 500),
                },
                "created_at": datetime.now(timezone.utc).isoformat(),
            })

        _emit_honeypot_event(
            "honeypot.decoy_endpoints_generated",
            EventSeverity.INFO,
            {"base_path": base_path, "count": count, "patterns_used": len(active_patterns)},
        )
        _record_metric("honeypot.decoy_endpoints_generated", count)
        _record_metric("honeypot.deployment_latency", time.monotonic() - start)

        span.set_attribute("base_path", base_path)
        span.set_attribute("count", count)

        logger.info(
            "decoy_endpoints.generated",
            base_path=base_path,
            count=count,
            patterns=len(active_patterns),
        )
        return endpoints


# ---------------------------------------------------------------------------
# 18. Deceptive Responses
# ---------------------------------------------------------------------------

def _generate_error_response(status_code: int, path: str) -> dict[str, Any]:
    """Generate a realistic error response body."""
    error_messages = {
        400: {"error": "Bad Request", "message": "The request could not be understood by the server", "path": path},
        401: {"error": "Unauthorized", "message": "Authentication credentials were missing or invalid", "path": path, "www_authenticate": "Bearer"},
        403: {"error": "Forbidden", "message": "You do not have permission to access this resource", "path": path},
        500: {"error": "Internal Server Error", "message": "An unexpected error occurred", "path": path, "request_id": f"req_{secrets.token_hex(8)}"},
        502: {"error": "Bad Gateway", "message": "The server received an invalid response from upstream", "path": path},
        503: {"error": "Service Unavailable", "message": "The service is temporarily unavailable", "path": path, "retry_after": 30},
    }
    return error_messages.get(status_code, {"error": "Unknown Error", "path": path})


def _generate_success_response(path: str, method: str, config: dict[str, Any]) -> dict[str, Any]:
    """Generate a realistic success response body."""
    if "/users" in path:
        return {
            "status": "success",
            "data": [{"id": 1, "name": "John Doe", "email": "john@company.com", "role": "admin"}],
            "pagination": {"page": 1, "per_page": 20, "total": 1247},
        }
    elif "/config" in path or "/settings" in path:
        return {
            "status": "success",
            "data": {"version": "4.2.1", "environment": "production", "debug": False, "maintenance_mode": False},
        }
    elif "/login" in path or "/auth" in path:
        return {
            "status": "success",
            "token": f"eyJhbGci.{secrets.token_hex(32)}.{secrets.token_hex(16)}",
            "expires_in": 3600,
            "refresh_token": f"rt_{secrets.token_hex(32)}",
        }
    elif "/keys" in path or "/secrets" in path:
        return {
            "status": "success",
            "data": [{"id": 1, "name": "production-api-key", "prefix": f"sk_live_{secrets.token_hex(4)}", "created": "2026-01-15"}],
        }
    else:
        return {
            "status": "success",
            "data": {"message": "OK", "timestamp": datetime.now(timezone.utc).isoformat()},
        }


def deceptive_responses(
    request: dict[str, Any],
    deception_config: dict[str, Any] | None = None,
    attacker_profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate contextually appropriate deceptive responses based on request and attacker profile.

    Crafts realistic-looking responses tailored to the specific request and
    known attacker characteristics to maximize engagement and intelligence gathering.

    Args:
        request: Dict with method, path, headers, body, and source_ip.
        deception_config: Dict with response_style, data_realism, and error_rate.
        attacker_profile: Dict with skill_level, goals, and engagement_history.

    Returns:
        Dict with response_id, status_code, headers, body, delay_ms,
            tracking, and deception_metadata.

    Example:
        >>> req = {"method": "GET", "path": "/api/v1/users", "source_ip": "10.0.0.1"}
        >>> result = deceptive_responses(req)
        >>> result["status_code"] in [200, 401, 403, 404, 500]
        True
    """
    with create_span("deceptive_responses") as span:
        start = time.monotonic()

        response_id = f"resp_{secrets.token_hex(8)}"

        default_config = {
            "response_style": "realistic",
            "data_realism": "high",
            "error_rate": 0.1,
            "include_server_headers": True,
            "include_timing": True,
        }
        active_config = {**default_config, **(deception_config or {})}

        path = request.get("path", "/")
        method = request.get("method", "GET")
        source_ip = request.get("source_ip", "unknown")

        skill_level = (attacker_profile or {}).get("skill_level", "unknown")

        should_error = random.random() < active_config.get("error_rate", 0.1)

        if should_error:
            status_code = random.choice([400, 401, 403, 500, 502, 503])
            body = _generate_error_response(status_code, path)
        else:
            status_code = 200
            body = _generate_success_response(path, method, active_config)

        headers = {
            "Content-Type": "application/json",
            "X-Request-ID": response_id,
            "X-Response-Time": f"{random.randint(10, 500)}ms",
        }
        if active_config.get("include_server_headers"):
            headers["Server"] = random.choice(["nginx/1.24.0", "Apache/2.4.52", "Caddy/2.7.4"])
            headers["X-Powered-By"] = random.choice(["Express", "Fastify", "Flask", "Django"])
            headers["X-Frame-Options"] = "DENY"
            headers["X-Content-Type-Options"] = "nosniff"

        delay_ms = random.randint(50, 300) if skill_level == "advanced" else random.randint(10, 150)

        tracking = {
            "response_id": response_id,
            "source_ip": source_ip,
            "path": path,
            "method": method,
            "status_code": status_code,
            "delay_ms": delay_ms,
            "deception_applied": True,
        }

        result = {
            "response_id": response_id,
            "status_code": status_code,
            "headers": headers,
            "body": body,
            "delay_ms": delay_ms,
            "tracking": tracking,
            "deception_metadata": {
                "config_used": active_config,
                "attacker_profile": attacker_profile or {},
                "response_type": "error" if should_error else "success",
                "generated_at": datetime.now(timezone.utc).isoformat(),
            },
        }

        _record_metric("honeypot.deceptive_responses_generated", 1, {"status_code": str(status_code)})
        _record_metric("honeypot.deployment_latency", time.monotonic() - start)

        span.set_attribute("response_id", response_id)
        span.set_attribute("status_code", status_code)

        logger.info(
            "deceptive_responses.generated",
            response_id=response_id,
            path=path,
            status_code=status_code,
        )
        return result


# ---------------------------------------------------------------------------
# 19. Fake Login Page
# ---------------------------------------------------------------------------

def fake_login_page(
    template: str = "default",
    branding: dict[str, Any] | None = None,
    tracking_script: str | None = None,
) -> dict[str, Any]:
    """Deploy a convincing fake login page to capture credential submission attempts.

    Creates a realistic login interface with customizable branding, form fields,
    and embedded tracking to capture and analyze authentication attacks.

    Args:
        template: UI template to use. Options: default, corporate, saas, legacy.
        branding: Dict with company_name, logo_url, primary_color, and favicon_url.
        tracking_script: JavaScript snippet to embed for client-side tracking.

    Returns:
        Dict with page_id, url, template, html_content, form_fields,
            tracking_config, credential_log, and status.

    Example:
        >>> branding = {"company_name": "Acme Corp", "primary_color": "#1a73e8"}
        >>> result = fake_login_page("corporate", branding)
        >>> result["template"]
        'corporate'
    """
    with create_span("fake_login_page") as span:
        start = time.monotonic()

        page_id = f"login_{secrets.token_hex(8)}"
        url = f"/auth-{secrets.token_hex(4)}"

        default_branding = {
            "company_name": "Enterprise Portal",
            "logo_url": "/static/logo.svg",
            "primary_color": "#1a73e8",
            "favicon_url": "/static/favicon.ico",
            "tagline": "Secure Access Management",
        }
        active_branding = {**default_branding, **(branding or {})}

        form_fields = [
            {"name": "username", "type": "text", "label": "Email or Username", "required": True, "autocomplete": "username"},
            {"name": "password", "type": "password", "label": "Password", "required": True, "autocomplete": "current-password"},
            {"name": "remember_me", "type": "checkbox", "label": "Remember me", "required": False},
            {"name": "csrf_token", "type": "hidden", "value": secrets.token_hex(32)},
            {"name": "mfa_code", "type": "text", "label": "MFA Code (optional)", "required": False, "pattern": "[0-9]{6}"},
        ]

        default_tracking = (
            "(function() {"
            "var trackingId = '" + page_id + "';"
            "var endpoint = '/api/honeypot/track';"
            "document.querySelector('form').addEventListener('submit', function(e) {"
            "var data = {"
            "tracking_id: trackingId,"
            "timestamp: new Date().toISOString(),"
            "user_agent: navigator.userAgent,"
            "screen_resolution: screen.width + 'x' + screen.height,"
            "timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,"
            "language: navigator.language,"
            "};"
            "navigator.sendBeacon(endpoint, JSON.stringify(data));"
            "});"
            "})();"
        )
        active_tracking = tracking_script or default_tracking

        html_content = (
            "<!DOCTYPE html>"
            "<html lang=\"en\">"
            "<head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
            "<title>" + active_branding["company_name"] + " - Login</title>"
            "<style>"
            "body{font-family:-apple-system,sans-serif;background:#f5f5f5;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}"
            ".login-container{background:white;padding:40px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1);width:100%;max-width:400px}"
            ".logo{text-align:center;margin-bottom:30px}"
            ".logo h1{color:" + active_branding["primary_color"] + ";margin:0;font-size:24px}"
            ".logo p{color:#666;margin:5px 0 0;font-size:14px}"
            ".form-group{margin-bottom:20px}"
            ".form-group label{display:block;margin-bottom:5px;font-weight:500;color:#333}"
            ".form-group input{width:100%;padding:10px;border:1px solid #ddd;border-radius:4px;box-sizing:border-box}"
            ".btn{width:100%;padding:12px;background:" + active_branding["primary_color"] + ";color:white;border:none;border-radius:4px;cursor:pointer;font-size:16px}"
            ".btn:hover{opacity:0.9}"
            ".footer{text-align:center;margin-top:20px;font-size:12px;color:#999}"
            "</style></head>"
            "<body><div class=\"login-container\">"
            "<div class=\"logo\"><h1>" + active_branding["company_name"] + "</h1>"
            "<p>" + active_branding["tagline"] + "</p></div>"
            "<form method=\"POST\" action=\"/auth/submit\">"
            "<div class=\"form-group\"><label for=\"username\">Email or Username</label>"
            "<input type=\"text\" id=\"username\" name=\"username\" required autocomplete=\"username\"></div>"
            "<div class=\"form-group\"><label for=\"password\">Password</label>"
            "<input type=\"password\" id=\"password\" name=\"password\" required autocomplete=\"current-password\"></div>"
            "<div class=\"form-group\"><label for=\"mfa_code\">MFA Code (optional)</label>"
            "<input type=\"text\" id=\"mfa_code\" name=\"mfa_code\" pattern=\"[0-9]{6}\" placeholder=\"123456\"></div>"
            "<div class=\"form-group\"><label><input type=\"checkbox\" name=\"remember_me\"> Remember me</label></div>"
            "<input type=\"hidden\" name=\"csrf_token\" value=\"" + secrets.token_hex(32) + "\">"
            "<button type=\"submit\" class=\"btn\">Sign In</button>"
            "</form>"
            "<div class=\"footer\">&copy; 2026 " + active_branding["company_name"] + ". All rights reserved.</div>"
            "</div><script>" + active_tracking + "</script></body></html>"
        )

        result = {
            "page_id": page_id,
            "url": url,
            "template": template,
            "branding": active_branding,
            "html_content": html_content,
            "form_fields": form_fields,
            "tracking_config": {
                "tracking_id": page_id,
                "script_embedded": True,
                "collect_user_agent": True,
                "collect_screen_resolution": True,
                "collect_timezone": True,
                "collect_language": True,
            },
            "credential_log": [],
            "submission_attempts": 0,
            "unique_visitors": 0,
            "status": "active",
            "deployed_at": datetime.now(timezone.utc).isoformat(),
        }

        _emit_honeypot_event(
            "honeypot.login_page_deployed",
            EventSeverity.INFO,
            {"page_id": page_id, "template": template, "company": active_branding["company_name"]},
        )
        _record_metric("honeypot.login_pages_deployed", 1, {"template": template})
        _record_metric("honeypot.deployment_latency", time.monotonic() - start)

        span.set_attribute("page_id", page_id)
        span.set_attribute("template", template)

        logger.info(
            "fake_login_page.deployed",
            page_id=page_id,
            template=template,
            company=active_branding["company_name"],
        )
        return result


# ---------------------------------------------------------------------------
# 20. Fake Debug Panel
# ---------------------------------------------------------------------------

def fake_debug_panel(
    config: dict[str, Any] | None = None,
    endpoints: list[str] | None = None,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Deploy a fake debug/development panel that appears to expose internal system information.

    Creates a convincing debug interface with plausible system metrics, environment
    variables, database queries, and configuration data to attract curious attackers.

    Args:
        config: Dict with panel settings like title, theme, and access_level.
        endpoints: List of debug endpoint paths to expose.
        data: Dict with fake system data to display (env vars, queries, cache stats).

    Returns:
        Dict with panel_id, url, config, endpoints, data,
            access_log, information_disclosure_attempts, and status.

    Example:
        >>> config = {"title": "System Debug Console"}
        >>> result = fake_debug_panel(config)
        >>> result["config"]["title"]
        'System Debug Console'
    """
    with create_span("fake_debug_panel") as span:
        start = time.monotonic()

        panel_id = f"debug_{secrets.token_hex(8)}"
        url = f"/debug-{secrets.token_hex(4)}"

        default_config = {
            "title": "System Debug Console",
            "theme": "dark",
            "access_level": "internal",
            "version": "3.2.1-debug",
            "show_stack_traces": True,
            "show_sql_queries": True,
            "show_env_vars": True,
            "show_cache_stats": True,
        }
        active_config = {**default_config, **(config or {})}

        default_endpoints = [
            "/debug/health",
            "/debug/metrics",
            "/debug/env",
            "/debug/config",
            "/debug/queries",
            "/debug/cache",
            "/debug/sessions",
            "/debug/threads",
            "/debug/memory",
            "/debug/gc",
        ]
        active_endpoints = endpoints or default_endpoints

        fake_env_vars = {
            "NODE_ENV": "production",
            "DATABASE_URL": "postgresql://app:****@db-primary:5432/production",
            "REDIS_URL": "redis://cache-redis:6379/0",
            "SECRET_KEY": f"sk_{secrets.token_hex(16)}...",
            "AWS_REGION": "us-east-1",
            "AWS_ACCESS_KEY_ID": f"AKIA{secrets.token_hex(8).upper()}****",
            "SENDGRID_API_KEY": f"SG.{secrets.token_hex(8)}****",
            "STRIPE_SECRET_KEY": f"sk_live_{secrets.token_hex(8)}****",
            "JWT_SECRET": f"jwt_{secrets.token_hex(16)}****",
            "LOG_LEVEL": "debug",
        }

        fake_queries = [
            {"query": "SELECT * FROM users WHERE email = $1", "duration_ms": 12.4, "rows": 1, "timestamp": "2026-05-16T14:30:00Z"},
            {"query": "SELECT count(*) FROM sessions WHERE expires_at > NOW()", "duration_ms": 3.2, "rows": 1, "timestamp": "2026-05-16T14:30:01Z"},
            {"query": "UPDATE api_keys SET last_used = NOW() WHERE key = $1", "duration_ms": 8.1, "rows": 1, "timestamp": "2026-05-16T14:30:02Z"},
            {"query": "INSERT INTO audit_log (user_id, action, resource) VALUES ($1, $2, $3)", "duration_ms": 5.6, "rows": 1, "timestamp": "2026-05-16T14:30:03Z"},
        ]

        fake_cache_stats = {
            "hit_rate": 0.87,
            "total_keys": 15234,
            "memory_used_mb": 256,
            "evictions": 42,
            "connections": 12,
            "uptime_seconds": 2592000,
        }

        fake_system_info = {
            "hostname": "prod-web-01",
            "os": "Ubuntu 22.04.3 LTS",
            "kernel": "5.15.0-91-generic",
            "cpu_cores": 8,
            "cpu_usage_percent": 34.2,
            "memory_total_gb": 32,
            "memory_used_gb": 18.7,
            "memory_used_percent": 58.4,
            "disk_total_gb": 500,
            "disk_used_gb": 287,
            "disk_used_percent": 57.4,
            "uptime_days": 45,
            "load_average": [1.2, 0.8, 0.6],
        }

        default_data = {
            "environment": fake_env_vars,
            "queries": fake_queries,
            "cache": fake_cache_stats,
            "system": fake_system_info,
            "active_sessions": random.randint(50, 200),
            "request_rate": random.randint(100, 500),
            "error_rate": random.uniform(0.01, 0.05),
        }
        active_data = {**default_data, **(data or {})}

        result = {
            "panel_id": panel_id,
            "url": url,
            "config": active_config,
            "endpoints": active_endpoints,
            "data": active_data,
            "access_log": [],
            "information_disclosure_attempts": [],
            "total_accesses": 0,
            "unique_visitors": 0,
            "status": "active",
            "deployed_at": datetime.now(timezone.utc).isoformat(),
        }

        _emit_honeypot_event(
            "honeypot.debug_panel_deployed",
            EventSeverity.INFO,
            {"panel_id": panel_id, "endpoints_count": len(active_endpoints), "title": active_config["title"]},
        )
        _record_metric("honeypot.debug_panels_deployed", 1)
        _record_metric("honeypot.deployment_latency", time.monotonic() - start)

        span.set_attribute("panel_id", panel_id)
        span.set_attribute("endpoints_count", len(active_endpoints))

        logger.info(
            "fake_debug_panel.deployed",
            panel_id=panel_id,
            endpoints=len(active_endpoints),
            title=active_config["title"],
        )
        return result


__all__ = [
    "adaptive_honeypot",
    "fake_admin_panel",
    "fake_database",
    "fake_api",
    "fake_filesystem",
    "fake_ssh_service",
    "fake_rdp_service",
    "fake_kubernetes_cluster",
    "fake_s3_bucket",
    "fake_secrets",
    "deceptive_routes",
    "attacker_behavior_tracking",
    "adaptive_deception",
    "moving_target_defense",
    "honeytoken_generation",
    "honeycredential_detection",
    "decoy_endpoints",
    "deceptive_responses",
    "fake_login_page",
    "fake_debug_panel",
]
