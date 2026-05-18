from __future__ import annotations

import re
import json
import time
import hashlib
import secrets
from typing import Any, Optional
from master_security.core import get_logger, get_metrics, create_span, get_cache, get_event_bus, SecurityEvent, EventSeverity
from master_security.core.exceptions import ValidationError, SecurityError, RateLimitError
import structlog

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Default constants
# ---------------------------------------------------------------------------

DEFAULT_RATE_LIMIT_WINDOW = 60
DEFAULT_RATE_LIMIT_MAX_REQUESTS = 100
DEFAULT_MAX_JSON_DEPTH = 10
DEFAULT_MAX_STRING_LENGTH = 10000
DEFAULT_MAX_GRAPHQL_DEPTH = 10
DEFAULT_MAX_GRAPHQL_COST = 1000
DEFAULT_API_KEY_EXPIRY_DAYS = 90
DEFAULT_ABUSE_WINDOW = 300
DEFAULT_FLOOD_WINDOW = 60
DEFAULT_MAX_WEBSOCKET_CONNECTIONS = 10

ALLOWED_JSON_TYPES = {"str", "int", "float", "bool", "null", "list", "dict"}

ABUSE_PATTERNS = [
    "enumeration",
    "scraping",
    "brute_force",
    "credential_stuffing",
    "data_exfiltration",
    "fuzzing",
    "injection_probe",
]


def validate_json_schema(
    data: Any,
    schema: dict[str, Any],
    strict_mode: bool = False,
) -> dict[str, Any]:
    """Validate data against a JSON schema definition.

    Performs recursive schema validation supporting type checking,
    required fields, enum constraints, min/max bounds, and pattern
    matching for strings.

    Args:
        data: The data to validate (any JSON-serializable value).
        schema: JSON schema dictionary with type, properties, required, etc.
        strict_mode: When True, reject any keys not defined in the schema.

    Returns:
        dict with keys: valid (bool), errors (list[str]), warnings (list[str]),
        sanitized_data (Any), validation_time_ms (float).

    Example:
        >>> schema = {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}
        >>> result = validate_json_schema({"name": "Alice"}, schema)
        >>> result["valid"]
        True
    """
    start = time.monotonic()
    metrics = get_metrics()
    errors: list[str] = []
    warnings: list[str] = []

    def _validate(value: Any, sch: dict[str, Any], path: str) -> None:
        expected_type = sch.get("type")
        if expected_type == "object":
            if not isinstance(value, dict):
                errors.append(f"{path}: expected object, got {type(value).__name__}")
                return
            properties = sch.get("properties", {})
            required = sch.get("required", [])
            for field in required:
                if field not in value:
                    errors.append(f"{path}.{field}: required field missing")
            if strict_mode:
                for key in value:
                    if key not in properties:
                        errors.append(f"{path}.{key}: unexpected field in strict mode")
            for key, prop_schema in properties.items():
                if key in value:
                    _validate(value[key], prop_schema, f"{path}.{key}")
        elif expected_type == "array":
            if not isinstance(value, list):
                errors.append(f"{path}: expected array, got {type(value).__name__}")
                return
            items_schema = sch.get("items", {})
            for i, item in enumerate(value):
                _validate(item, items_schema, f"{path}[{i}]")
            min_items = sch.get("minItems")
            max_items = sch.get("maxItems")
            if min_items is not None and len(value) < min_items:
                errors.append(f"{path}: array length {len(value)} < minItems {min_items}")
            if max_items is not None and len(value) > max_items:
                errors.append(f"{path}: array length {len(value)} > maxItems {max_items}")
        elif expected_type == "string":
            if not isinstance(value, str):
                errors.append(f"{path}: expected string, got {type(value).__name__}")
                return
            pattern = sch.get("pattern")
            if pattern and not re.match(pattern, value):
                errors.append(f"{path}: string does not match pattern {pattern}")
            min_len = sch.get("minLength")
            max_len = sch.get("maxLength")
            if min_len is not None and len(value) < min_len:
                errors.append(f"{path}: string length {len(value)} < minLength {min_len}")
            if max_len is not None and len(value) > max_len:
                errors.append(f"{path}: string length {len(value)} > maxLength {max_len}")
        elif expected_type == "integer":
            if not isinstance(value, int) or isinstance(value, bool):
                errors.append(f"{path}: expected integer, got {type(value).__name__}")
                return
            minimum = sch.get("minimum")
            maximum = sch.get("maximum")
            if minimum is not None and value < minimum:
                errors.append(f"{path}: value {value} < minimum {minimum}")
            if maximum is not None and value > maximum:
                errors.append(f"{path}: value {value} > maximum {maximum}")
        elif expected_type == "number":
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                errors.append(f"{path}: expected number, got {type(value).__name__}")
                return
            minimum = sch.get("minimum")
            maximum = sch.get("maximum")
            if minimum is not None and value < minimum:
                errors.append(f"{path}: value {value} < minimum {minimum}")
            if maximum is not None and value > maximum:
                errors.append(f"{path}: value {value} > maximum {maximum}")
        elif expected_type == "boolean":
            if not isinstance(value, bool):
                errors.append(f"{path}: expected boolean, got {type(value).__name__}")
        elif expected_type == "null":
            if value is not None:
                errors.append(f"{path}: expected null, got {type(value).__name__}")
        enum_values = sch.get("enum")
        if enum_values is not None and value not in enum_values:
            errors.append(f"{path}: value not in enum {enum_values}")

    _validate(data, schema, "root")
    elapsed_ms = (time.monotonic() - start) * 1000

    valid = len(errors) == 0
    metrics.inc_counter("api.schema_validation.total")
    if valid:
        metrics.inc_counter("api.schema_validation.passed")
    else:
        metrics.inc_counter("api.schema_validation.failed")
    metrics.observe_histogram("api.schema_validation.duration_ms", elapsed_ms)

    logger.info(
        "json_schema_validation",
        valid=valid,
        error_count=len(errors),
        strict_mode=strict_mode,
        duration_ms=elapsed_ms,
    )

    return {
        "valid": valid,
        "errors": errors,
        "warnings": warnings,
        "sanitized_data": data if valid else None,
        "validation_time_ms": round(elapsed_ms, 3),
    }


def validate_input(
    data: Any,
    rules: dict[str, Any],
    max_depth: int = DEFAULT_MAX_JSON_DEPTH,
    max_size: int = 1_000_000,
) -> dict[str, Any]:
    """Validate API input data against a set of rules.

    Checks depth, size, type constraints, allowed characters, and
    custom validator functions defined in the rules dictionary.

    Args:
        data: Input data to validate.
        rules: Validation rules dict with keys like 'type', 'max_length',
            'pattern', 'allowed_values', 'custom_validator'.
        max_depth: Maximum nesting depth allowed (default 10).
        max_size: Maximum serialized size in bytes (default 1MB).

    Returns:
        dict with keys: valid (bool), errors (list[str]), sanitized (Any),
        depth (int), size_bytes (int), validation_time_ms (float).

    Example:
        >>> rules = {"type": "dict", "max_length": 100}
        >>> result = validate_input({"key": "value"}, rules)
        >>> result["valid"]
        True
    """
    start = time.monotonic()
    metrics = get_metrics()
    errors: list[str] = []

    def _check_depth(value: Any, current_depth: int) -> int:
        if current_depth > max_depth:
            errors.append(f"Nesting depth {current_depth} exceeds max {max_depth}")
            return current_depth
        if isinstance(value, dict):
            return max((_check_depth(v, current_depth + 1) for v in value.values()), default=current_depth)
        if isinstance(value, list):
            return max((_check_depth(v, current_depth + 1) for v in value), default=current_depth)
        return current_depth

    def _check_size(value: Any) -> int:
        try:
            serialized = json.dumps(value) if not isinstance(value, str) else value
            return len(serialized.encode("utf-8"))
        except (TypeError, ValueError):
            return 0

    depth = _check_depth(data, 0)
    size_bytes = _check_size(data)

    if size_bytes > max_size:
        errors.append(f"Input size {size_bytes} bytes exceeds max {max_size} bytes")

    expected_type = rules.get("type")
    type_map = {
        "str": str, "string": str,
        "int": int, "integer": int,
        "float": float, "number": (int, float),
        "bool": bool, "boolean": bool,
        "dict": dict, "object": dict,
        "list": list, "array": list,
        "null": type(None),
    }
    if expected_type:
        py_type = type_map.get(expected_type)
        if py_type and not isinstance(data, py_type):
            errors.append(f"Expected type {expected_type}, got {type(data).__name__}")

    max_length = rules.get("max_length")
    if max_length is not None and isinstance(data, (str, list, dict)):
        actual_len = len(data) if isinstance(data, str) else len(json.dumps(data))
        if actual_len > max_length:
            errors.append(f"Length {actual_len} exceeds max_length {max_length}")

    pattern = rules.get("pattern")
    if pattern and isinstance(data, str):
        if not re.match(pattern, data):
            errors.append(f"Value does not match pattern {pattern}")

    allowed_values = rules.get("allowed_values")
    if allowed_values is not None and data not in allowed_values:
        errors.append(f"Value not in allowed values: {allowed_values}")

    allowed_keys = rules.get("allowed_keys")
    if allowed_keys is not None and isinstance(data, dict):
        for key in data:
            if key not in allowed_keys:
                errors.append(f"Key '{key}' is not in allowed_keys")

    custom_validator = rules.get("custom_validator")
    if callable(custom_validator):
        try:
            custom_result = custom_validator(data)
            if not custom_result:
                errors.append("Custom validator returned False")
        except Exception as exc:
            errors.append(f"Custom validator raised: {exc}")

    min_value = rules.get("min")
    max_value = rules.get("max")
    if min_value is not None and isinstance(data, (int, float)):
        if data < min_value:
            errors.append(f"Value {data} < min {min_value}")
    if max_value is not None and isinstance(data, (int, float)):
        if data > max_value:
            errors.append(f"Value {data} > max {max_value}")

    elapsed_ms = (time.monotonic() - start) * 1000
    valid = len(errors) == 0

    metrics.inc_counter("api.input_validation.total")
    metrics.inc_counter("api.input_validation.passed" if valid else "api.input_validation.failed")
    metrics.observe_histogram("api.input_validation.duration_ms", elapsed_ms)

    logger.info(
        "input_validation",
        valid=valid,
        error_count=len(errors),
        depth=depth,
        size_bytes=size_bytes,
        duration_ms=elapsed_ms,
    )

    return {
        "valid": valid,
        "errors": errors,
        "sanitized": data if valid else None,
        "depth": depth,
        "size_bytes": size_bytes,
        "validation_time_ms": round(elapsed_ms, 3),
    }


def sanitize_json(
    data: Any,
    allowed_types: Optional[set[str]] = None,
    max_string_length: int = DEFAULT_MAX_STRING_LENGTH,
) -> dict[str, Any]:
    """Sanitize JSON data by removing disallowed types and truncating strings.

    Recursively walks the data structure, truncating oversized strings,
    removing keys with disallowed value types, and stripping dangerous
    content from string values.

    Args:
        data: JSON data to sanitize.
        allowed_types: Set of allowed type names. Defaults to all JSON types.
        max_string_length: Maximum allowed string length (default 10000).

    Returns:
        dict with keys: sanitized (Any), removed_count (int),
        truncated_count (int), warnings (list[str]).

    Example:
        >>> data = {"name": "a" * 20000, "secret": b"binary"}
        >>> result = sanitize_json(data, max_string_length=100)
        >>> len(result["sanitized"]["name"])
        100
    """
    metrics = get_metrics()
    allowed = allowed_types or ALLOWED_JSON_TYPES
    removed_count = 0
    truncated_count = 0
    warnings: list[str] = []
    dangerous_patterns = re.compile(
        r"(?:<script|javascript:|on\w+\s*=|expression\s*\(|eval\s*\()",
        re.IGNORECASE,
    )

    def _sanitize(value: Any, path: str) -> Any:
        nonlocal removed_count, truncated_count
        if isinstance(value, str):
            if len(value) > max_string_length:
                truncated_count += 1
                warnings.append(f"{path}: string truncated from {len(value)} to {max_string_length}")
                value = value[:max_string_length]
            if dangerous_patterns.search(value):
                warnings.append(f"{path}: potentially dangerous content detected and escaped")
                value = value.replace("<", "&lt;").replace(">", "&gt;")
            return value
        if isinstance(value, bool):
            type_name = "bool"
        elif isinstance(value, int):
            type_name = "int"
        elif isinstance(value, float):
            type_name = "float"
        elif value is None:
            type_name = "null"
        elif isinstance(value, list):
            type_name = "list"
        elif isinstance(value, dict):
            type_name = "dict"
        else:
            type_name = type(value).__name__

        if type_name not in allowed:
            removed_count += 1
            warnings.append(f"{path}: removed value of disallowed type '{type_name}'")
            return None

        if isinstance(value, list):
            return [_sanitize(item, f"{path}[{i}]") for i, item in enumerate(value)]
        if isinstance(value, dict):
            sanitized = {}
            for k, v in value.items():
                sanitized[k] = _sanitize(v, f"{path}.{k}")
            return sanitized
        return value

    sanitized = _sanitize(data, "root")

    metrics.inc_counter("api.json_sanitize.total")
    if removed_count > 0:
        metrics.inc_counter("api.json_sanitize.removed")
    if truncated_count > 0:
        metrics.inc_counter("api.json_sanitize.truncated")

    logger.info(
        "json_sanitization",
        removed_count=removed_count,
        truncated_count=truncated_count,
        warning_count=len(warnings),
    )

    return {
        "sanitized": sanitized,
        "removed_count": removed_count,
        "truncated_count": truncated_count,
        "warnings": warnings,
    }


def api_rate_limit(
    client_id: str,
    endpoint: str,
    config: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Enforce API rate limiting using a sliding window algorithm.

    Tracks request timestamps in a cache and rejects requests that
    exceed the configured limit within the sliding window period.

    Args:
        client_id: Unique identifier for the API client.
        endpoint: The API endpoint being accessed.
        config: Optional dict with keys: max_requests (int), window_seconds (int),
            burst_multiplier (float). Defaults to 100 requests per 60s.

    Returns:
        dict with keys: allowed (bool), remaining (int), limit (int),
        reset_at (float), retry_after (Optional[float]), current_count (int).

    Example:
        >>> result = api_rate_limit("client-123", "/api/v1/users")
        >>> result["allowed"]
        True
    """
    start = time.monotonic()
    metrics = get_metrics()
    cache = get_cache()
    max_requests = (config or {}).get("max_requests", DEFAULT_RATE_LIMIT_MAX_REQUESTS)
    window_seconds = (config or {}).get("window_seconds", DEFAULT_RATE_LIMIT_WINDOW)
    burst_multiplier = (config or {}).get("burst_multiplier", 1.0)
    effective_limit = int(max_requests * burst_multiplier)

    now = time.time()
    key = f"ratelimit:{client_id}:{endpoint}"

    cached = cache.get(key)
    if cached is None:
        timestamps: list[float] = []
    else:
        try:
            timestamps = json.loads(cached)
        except (json.JSONDecodeError, TypeError):
            timestamps = []

    window_start = now - window_seconds
    timestamps = [ts for ts in timestamps if ts > window_start]
    current_count = len(timestamps)
    remaining = max(0, effective_limit - current_count)
    reset_at = now + window_seconds

    if current_count >= effective_limit:
        oldest = min(timestamps) if timestamps else now
        retry_after = round(oldest + window_seconds - now, 2)
        elapsed_ms = (time.monotonic() - start) * 1000

        metrics.inc_counter("api.rate_limit.exceeded")
        logger.warning(
            "rate_limit_exceeded",
            client_id=client_id,
            endpoint=endpoint,
            current_count=current_count,
            limit=effective_limit,
            retry_after=retry_after,
        )

        return {
            "allowed": False,
            "remaining": 0,
            "limit": effective_limit,
            "reset_at": reset_at,
            "retry_after": retry_after,
            "current_count": current_count,
            "processing_time_ms": round(elapsed_ms, 3),
        }

    timestamps.append(now)
    cache.set(key, json.dumps(timestamps), ttl=window_seconds)
    remaining = max(0, effective_limit - current_count - 1)
    elapsed_ms = (time.monotonic() - start) * 1000

    metrics.inc_counter("api.rate_limit.allowed")
    metrics.set_gauge("api.rate_limit.remaining", remaining)

    return {
        "allowed": True,
        "remaining": remaining,
        "limit": effective_limit,
        "reset_at": reset_at,
        "retry_after": None,
        "current_count": current_count + 1,
        "processing_time_ms": round(elapsed_ms, 3),
    }


def adaptive_rate_limit(
    client_id: str,
    endpoint: str,
    behavior: dict[str, Any],
    config: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Apply adaptive rate limiting based on client behavior patterns.

    Dynamically adjusts rate limits up or down based on historical
    behavior signals including error rates, response times, and
    request patterns.

    Args:
        client_id: Unique identifier for the API client.
        endpoint: The API endpoint being accessed.
        behavior: Dict with keys: error_rate (float), avg_response_time_ms (float),
            requests_per_minute (float), trust_score (float 0-1), is_authenticated (bool).
        config: Optional config with base max_requests and window_seconds.

    Returns:
        dict with keys: allowed (bool), effective_limit (int),
        trust_adjustment (float), risk_level (str), remaining (int),
        reset_at (float).

    Example:
        >>> behavior = {"error_rate": 0.01, "trust_score": 0.9, "is_authenticated": True}
        >>> result = adaptive_rate_limit("client-123", "/api/data", behavior)
        >>> result["risk_level"]
        'low'
    """
    metrics = get_metrics()
    cache = get_cache()

    base_max = (config or {}).get("max_requests", DEFAULT_RATE_LIMIT_MAX_REQUESTS)
    window = (config or {}).get("window_seconds", DEFAULT_RATE_LIMIT_WINDOW)

    error_rate = behavior.get("error_rate", 0.0)
    trust_score = behavior.get("trust_score", 0.5)
    avg_response_time = behavior.get("avg_response_time_ms", 100.0)
    rpm = behavior.get("requests_per_minute", 0.0)
    is_authenticated = behavior.get("is_authenticated", False)
    is_bot = behavior.get("is_bot", False)

    adjustment = 1.0
    risk_factors: list[str] = []

    if error_rate > 0.5:
        adjustment *= 0.2
        risk_factors.append("high_error_rate")
    elif error_rate > 0.2:
        adjustment *= 0.5
        risk_factors.append("elevated_error_rate")

    adjustment *= max(0.1, trust_score)

    if avg_response_time > 5000:
        adjustment *= 0.7
        risk_factors.append("slow_responses")

    if rpm > base_max * 2:
        adjustment *= 0.5
        risk_factors.append("high_rpm")

    if is_authenticated:
        adjustment *= 1.5
    if is_bot:
        adjustment *= 0.3
        risk_factors.append("bot_detected")

    effective_limit = max(1, int(base_max * adjustment))

    if risk_factors:
        risk_level = "critical" if len(risk_factors) >= 3 else ("high" if len(risk_factors) >= 2 else "medium")
    else:
        risk_level = "low" if trust_score > 0.7 else "medium"

    now = time.time()
    key = f"adaptive_ratelimit:{client_id}:{endpoint}"
    cached = cache.get(key)
    timestamps: list[float] = []
    if cached:
        try:
            timestamps = json.loads(cached)
        except (json.JSONDecodeError, TypeError):
            pass

    window_start = now - window
    timestamps = [ts for ts in timestamps if ts > window_start]
    current_count = len(timestamps)
    remaining = max(0, effective_limit - current_count)

    allowed = current_count < effective_limit
    if allowed:
        timestamps.append(now)
        cache.set(key, json.dumps(timestamps), ttl=window)
        remaining = max(0, effective_limit - current_count - 1)

    metrics.inc_counter("api.adaptive_rate_limit.total")
    metrics.inc_counter(
        "api.adaptive_rate_limit.allowed" if allowed else "api.adaptive_rate_limit.denied"
    )
    metrics.set_gauge("api.adaptive_rate_limit.effective_limit", effective_limit)

    logger.info(
        "adaptive_rate_limit",
        client_id=client_id,
        endpoint=endpoint,
        effective_limit=effective_limit,
        risk_level=risk_level,
        allowed=allowed,
        risk_factors=risk_factors,
    )

    return {
        "allowed": allowed,
        "effective_limit": effective_limit,
        "trust_adjustment": round(adjustment, 3),
        "risk_level": risk_level,
        "remaining": remaining,
        "reset_at": now + window,
        "risk_factors": risk_factors,
        "current_count": current_count + (1 if allowed else 0),
    }


def detect_api_abuse(
    requests: list[dict[str, Any]],
    patterns: Optional[list[str]] = None,
    window: int = DEFAULT_ABUSE_WINDOW,
) -> dict[str, Any]:
    """Detect API abuse patterns from a list of request records.

    Analyzes request patterns to identify enumeration, scraping,
    brute force, credential stuffing, data exfiltration, fuzzing,
    and injection probing attacks.

    Args:
        requests: List of request dicts with keys: timestamp (float),
            client_id (str), endpoint (str), method (str), status_code (int),
            response_size (int), user_agent (str).
        patterns: List of abuse pattern names to check. Defaults to all.
        window: Time window in seconds to analyze (default 300).

    Returns:
        dict with keys: abuse_detected (bool), patterns_found (list[str]),
        risk_score (float 0-1), details (dict), flagged_clients (list[str]).

    Example:
        >>> requests = [{"timestamp": time.time(), "client_id": "x", "endpoint": "/api/1", "method": "GET", "status_code": 404, "response_size": 100}]
        >>> result = detect_api_abuse(requests)
        >>> "abuse_detected" in result
        True
    """
    metrics = get_metrics()
    check_patterns = patterns or ABUSE_PATTERNS
    now = time.time()
    window_start = now - window

    recent = [r for r in requests if r.get("timestamp", 0) > window_start]
    if not recent:
        return {
            "abuse_detected": False,
            "patterns_found": [],
            "risk_score": 0.0,
            "details": {},
            "flagged_clients": [],
        }

    patterns_found: list[str] = []
    details: dict[str, Any] = {}
    flagged_clients: set[str] = set()
    risk_score = 0.0

    client_requests: dict[str, list[dict[str, Any]]] = {}
    for req in recent:
        cid = req.get("client_id", "unknown")
        client_requests.setdefault(cid, []).append(req)

    for cid, reqs in client_requests.items():
        client_risk = 0.0

        if "enumeration" in check_patterns:
            unique_endpoints = len({r.get("endpoint", "") for r in reqs})
            not_found = sum(1 for r in reqs if r.get("status_code") == 404)
            if unique_endpoints > 20 and not_found / len(reqs) > 0.5:
                patterns_found.append("enumeration")
                flagged_clients.add(cid)
                client_risk += 0.3
                details["enumeration"] = {
                    "unique_endpoints": unique_endpoints,
                    "not_found_rate": round(not_found / len(reqs), 3),
                }

        if "scraping" in check_patterns:
            get_requests = sum(1 for r in reqs if r.get("method") == "GET")
            total_size = sum(r.get("response_size", 0) for r in reqs)
            if get_requests > 50 and total_size > 500_000:
                patterns_found.append("scraping")
                flagged_clients.add(cid)
                client_risk += 0.25
                details["scraping"] = {
                    "get_requests": get_requests,
                    "total_data_transferred": total_size,
                }

        if "brute_force" in check_patterns:
            auth_failures = sum(1 for r in reqs if r.get("status_code") in (401, 403))
            if auth_failures > 10:
                patterns_found.append("brute_force")
                flagged_clients.add(cid)
                client_risk += 0.35
                details["brute_force"] = {
                    "auth_failures": auth_failures,
                    "failure_rate": round(auth_failures / len(reqs), 3),
                }

        if "credential_stuffing" in check_patterns:
            auth_endpoints = [r for r in reqs if "login" in r.get("endpoint", "").lower() or "auth" in r.get("endpoint", "").lower()]
            if len(auth_endpoints) > 20:
                patterns_found.append("credential_stuffing")
                flagged_clients.add(cid)
                client_risk += 0.4
                details["credential_stuffing"] = {"auth_endpoint_hits": len(auth_endpoints)}

        if "data_exfiltration" in check_patterns:
            total_size = sum(r.get("response_size", 0) for r in reqs)
            if total_size > 5_000_000:
                patterns_found.append("data_exfiltration")
                flagged_clients.add(cid)
                client_risk += 0.45
                details["data_exfiltration"] = {"total_bytes": total_size}

        if "fuzzing" in check_patterns:
            error_rate = sum(1 for r in reqs if r.get("status_code", 200) >= 500) / max(len(reqs), 1)
            if error_rate > 0.3 and len(reqs) > 30:
                patterns_found.append("fuzzing")
                flagged_clients.add(cid)
                client_risk += 0.3
                details["fuzzing"] = {"error_rate": round(error_rate, 3)}

        if "injection_probe" in check_patterns:
            suspicious_endpoints = sum(
                1 for r in reqs
                if any(p in r.get("endpoint", "") for p in ["'", '"', "<", ">", "%27", "%3C"])
            )
            if suspicious_endpoints > 5:
                patterns_found.append("injection_probe")
                flagged_clients.add(cid)
                client_risk += 0.35
                details["injection_probe"] = {"suspicious_requests": suspicious_endpoints}

        risk_score = max(risk_score, min(client_risk, 1.0))

    patterns_found = list(set(patterns_found))
    abuse_detected = len(patterns_found) > 0

    metrics.inc_counter("api.abuse_detection.total")
    if abuse_detected:
        metrics.inc_counter("api.abuse_detection.detected")
        metrics.set_gauge("api.abuse_detection.risk_score", risk_score)

    logger.warning(
        "api_abuse_detection",
        abuse_detected=abuse_detected,
        patterns_found=patterns_found,
        risk_score=risk_score,
        flagged_clients=list(flagged_clients),
    )

    return {
        "abuse_detected": abuse_detected,
        "patterns_found": patterns_found,
        "risk_score": round(risk_score, 3),
        "details": details,
        "flagged_clients": list(flagged_clients),
        "analyzed_requests": len(recent),
        "window_seconds": window,
    }


def detect_bola(
    resource_id: str,
    user_id: str,
    ownership_map: dict[str, Any],
) -> bool:
    """Detect Broken Object Level Authorization (BOLA / IDOR) attempts.

    Checks whether the requesting user has legitimate ownership or
    access rights to the requested resource by consulting the ownership
    mapping.

    Args:
        resource_id: The identifier of the resource being accessed.
        user_id: The identifier of the requesting user.
        ownership_map: Dict mapping resource_ids to owner user_ids or
            access control lists. Supports formats:
            - {"resource_id": "owner_user_id"}
            - {"resource_id": {"owner": "user_id", "shared_with": ["u1", "u2"]}}
            - {"resource_id": {"acl": ["u1", "u2"]}}

    Returns:
        True if BOLA is detected (user lacks access), False if access is valid.

    Example:
        >>> ownership = {"doc-1": "user-A", "doc-2": "user-B"}
        >>> detect_bola("doc-1", "user-B", ownership)
        True
    """
    metrics = get_metrics()
    if resource_id not in ownership_map:
        metrics.inc_counter("api.bola.unknown_resource")
        logger.warning(
            "bola_unknown_resource",
            resource_id=resource_id,
            user_id=user_id,
        )
        return True

    resource_access = ownership_map[resource_id]

    if isinstance(resource_access, str):
        authorized = resource_access == user_id
    elif isinstance(resource_access, dict):
        if "owner" in resource_access:
            authorized = resource_access["owner"] == user_id
        elif "acl" in resource_access:
            authorized = user_id in resource_access["acl"]
        elif "shared_with" in resource_access:
            owner = resource_access.get("owner", "")
            shared = resource_access.get("shared_with", [])
            authorized = user_id == owner or user_id in shared
        else:
            authorized = user_id in resource_access
    elif isinstance(resource_access, (list, set)):
        authorized = user_id in resource_access
    else:
        authorized = False

    if not authorized:
        metrics.inc_counter("api.bola.detected")
        logger.warning(
            "bola_detected",
            resource_id=resource_id,
            user_id=user_id,
        )
        return True

    metrics.inc_counter("api.bola.access_granted")
    return False


def detect_broken_auth(
    auth_header: Optional[str],
    required_scopes: Optional[list[str]] = None,
    token: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Detect broken authentication and authorization issues.

    Validates the presence and format of authentication headers,
    checks token validity, and verifies required OAuth scopes.

    Args:
        auth_header: The Authorization header value (e.g., "Bearer <token>").
        required_scopes: List of OAuth scopes required for the endpoint.
        token: Pre-parsed token dictionary with claims (sub, exp, scope, etc.).

    Returns:
        dict with keys: valid (bool), issues (list[str]), missing_scopes (list[str]),
        auth_type (str), risk_level (str), details (dict).

    Example:
        >>> result = detect_broken_auth("Bearer abc123", required_scopes=["read:users"])
        >>> "valid" in result
        True
    """
    metrics = get_metrics()
    issues: list[str] = []
    details: dict[str, Any] = {}
    auth_type = "none"

    if not auth_header:
        issues.append("Missing Authorization header")
        details["header_present"] = False
    else:
        details["header_present"] = True
        parts = auth_header.split(" ", 1)
        if len(parts) != 2:
            issues.append("Malformed Authorization header")
            details["malformed"] = True
        else:
            auth_type = parts[0].lower()
            details["auth_type"] = auth_type
            token_value = parts[1]

            if auth_type == "bearer":
                if len(token_value) < 10:
                    issues.append("Suspiciously short bearer token")
                    details["short_token"] = True
                elif not re.match(r"^[A-Za-z0-9\-_\.]+$", token_value):
                    issues.append("Bearer token contains invalid characters")
                    details["invalid_chars"] = True
            elif auth_type == "basic":
                try:
                    import base64
                    decoded = base64.b64decode(token_value).decode("utf-8")
                    if ":" not in decoded:
                        issues.append("Basic auth credentials malformed")
                    elif decoded.startswith(":") or decoded.endswith(":"):
                        issues.append("Basic auth missing username or password")
                except Exception:
                    issues.append("Basic auth token is not valid base64")
            elif auth_type not in ("apikey", "digest", "hmac"):
                issues.append(f"Unsupported auth type: {auth_type}")

    if token:
        exp = token.get("exp")
        if exp is not None and time.time() > exp:
            issues.append("Token has expired")
            details["token_expired"] = True

        sub = token.get("sub")
        if not sub:
            issues.append("Token missing subject claim")

        if required_scopes:
            token_scopes = set(token.get("scope", "").split()) if isinstance(token.get("scope"), str) else set(token.get("scope", []))
            missing = [s for s in required_scopes if s not in token_scopes]
            if missing:
                issues.append(f"Missing required scopes: {missing}")
                details["missing_scopes"] = missing

    valid = len(issues) == 0
    risk_level = "critical" if not details.get("header_present") else ("high" if len(issues) >= 2 else "medium" if issues else "low")

    metrics.inc_counter("api.broken_auth_detection.total")
    metrics.inc_counter("api.broken_auth_detection.valid" if valid else "api.broken_auth_detection.invalid")

    logger.info(
        "broken_auth_detection",
        valid=valid,
        issue_count=len(issues),
        auth_type=auth_type,
        risk_level=risk_level,
    )

    return {
        "valid": valid,
        "issues": issues,
        "missing_scopes": details.get("missing_scopes", []),
        "auth_type": auth_type,
        "risk_level": risk_level,
        "details": details,
    }


def detect_mass_assignment(
    input_data: dict[str, Any],
    model_fields: set[str],
    readonly_fields: Optional[set[str]] = None,
) -> dict[str, Any]:
    """Detect mass assignment vulnerabilities in API input data.

    Identifies when client-supplied data attempts to set fields that
    should not be modifiable, such as internal IDs, roles, or audit fields.

    Args:
        input_data: Dictionary of client-supplied field values.
        model_fields: Set of all valid model field names.
        readonly_fields: Set of fields that must not be set by clients
            (e.g., id, created_at, role, is_admin).

    Returns:
        dict with keys: safe (bool), blocked_fields (list[str]),
        unknown_fields (list[str]), sanitized_data (dict), risk_level (str).

    Example:
        >>> input_data = {"name": "Alice", "role": "admin", "id": 999}
        >>> result = detect_mass_assignment(input_data, {"name", "role", "id"}, {"role", "id"})
        >>> result["blocked_fields"]
        ['id', 'role']
    """
    metrics = get_metrics()
    readonly = readonly_fields or {"id", "created_at", "updated_at", "role", "is_admin", "permissions"}
    blocked_fields: list[str] = []
    unknown_fields: list[str] = []
    sanitized_data: dict[str, Any] = {}

    for field, value in input_data.items():
        if field in readonly:
            blocked_fields.append(field)
        elif field not in model_fields:
            unknown_fields.append(field)
        else:
            sanitized_data[field] = value

    safe = len(blocked_fields) == 0
    risk_level = "critical" if any(f in readonly for f in ("is_admin", "role", "permissions")) else ("high" if len(blocked_fields) > 1 else "medium" if blocked_fields else "low")

    metrics.inc_counter("api.mass_assignment_detection.total")
    if blocked_fields:
        metrics.inc_counter("api.mass_assignment_detection.blocked")
        metrics.set_gauge("api.mass_assignment_detection.blocked_count", len(blocked_fields))

    logger.warning(
        "mass_assignment_detection",
        safe=safe,
        blocked_fields=blocked_fields,
        unknown_fields=unknown_fields,
        risk_level=risk_level,
    )

    return {
        "safe": safe,
        "blocked_fields": blocked_fields,
        "unknown_fields": unknown_fields,
        "sanitized_data": sanitized_data,
        "risk_level": risk_level,
    }


def detect_shadow_api(
    endpoint: str,
    documented_apis: set[str],
    traffic_patterns: dict[str, Any],
) -> dict[str, Any]:
    """Detect shadow APIs - undocumented endpoints receiving traffic.

    Compares observed endpoint traffic against the registry of documented
    APIs to identify potentially unauthorized or forgotten endpoints.

    Args:
        endpoint: The API endpoint path being accessed.
        documented_apis: Set of all documented/authorized endpoint paths.
        traffic_patterns: Dict with keys: request_count (int),
            unique_clients (int), first_seen (float), last_seen (float),
            methods (list[str]), avg_response_time_ms (float).

    Returns:
        dict with keys: is_shadow (bool), confidence (float 0-1),
        risk_level (str), details (dict), recommendation (str).

    Example:
        >>> documented = {"/api/v1/users", "/api/v1/health"}
        >>> result = detect_shadow_api("/api/v1/admin/debug", documented, {"request_count": 50})
        >>> result["is_shadow"]
        True
    """
    metrics = get_metrics()

    is_documented = endpoint in documented_apis

    if is_documented:
        metrics.inc_counter("api.shadow_api.documented")
        return {
            "is_shadow": False,
            "confidence": 0.0,
            "risk_level": "none",
            "details": {"documented": True},
            "recommendation": "Endpoint is documented and authorized.",
        }

    confidence = 0.5
    risk_factors: list[str] = []

    request_count = traffic_patterns.get("request_count", 0)
    unique_clients = traffic_patterns.get("unique_clients", 0)
    methods = traffic_patterns.get("methods", [])
    first_seen = traffic_patterns.get("first_seen", 0)
    last_seen = traffic_patterns.get("last_seen", 0)

    if request_count > 100:
        confidence += 0.2
        risk_factors.append("high_traffic")
    if unique_clients > 5:
        confidence += 0.1
        risk_factors.append("multiple_clients")
    if "DELETE" in methods or "PUT" in methods:
        confidence += 0.15
        risk_factors.append("destructive_methods")
    if first_seen and last_seen and (last_seen - first_seen) > 86400:
        confidence += 0.1
        risk_factors.append("long_lived")

    if "/admin" in endpoint or "/debug" in endpoint or "/internal" in endpoint:
        confidence += 0.2
        risk_factors.append("sensitive_path")

    if "/v2" in endpoint or "/beta" in endpoint or "/test" in endpoint:
        confidence += 0.1
        risk_factors.append("versioned_or_test_endpoint")

    confidence = min(confidence, 1.0)
    is_shadow = confidence > 0.4

    risk_level = "critical" if confidence > 0.8 else ("high" if confidence > 0.6 else "medium" if confidence > 0.4 else "low")

    if is_shadow:
        metrics.inc_counter("api.shadow_api.detected")
        recommendation = "Investigate and either document or disable this endpoint."
    else:
        metrics.inc_counter("api.shadow_api.possible")
        recommendation = "Monitor this endpoint for further activity."

    logger.warning(
        "shadow_api_detection",
        endpoint=endpoint,
        is_shadow=is_shadow,
        confidence=confidence,
        risk_level=risk_level,
        risk_factors=risk_factors,
    )

    return {
        "is_shadow": is_shadow,
        "confidence": round(confidence, 3),
        "risk_level": risk_level,
        "details": {
            "documented": False,
            "request_count": request_count,
            "unique_clients": unique_clients,
            "risk_factors": risk_factors,
        },
        "recommendation": recommendation,
    }


def api_threat_score(
    request: dict[str, Any],
    context: Optional[dict[str, Any]] = None,
    threat_intel: Optional[dict[str, Any]] = None,
) -> float:
    """Calculate a composite threat score for an API request.

    Combines multiple risk signals including IP reputation, request
    patterns, authentication quality, and threat intelligence feeds
    into a single 0.0-1.0 threat score.

    Args:
        request: Dict with keys: ip (str), method (str), endpoint (str),
            user_agent (str), auth_type (str), rate (float requests/sec).
        context: Optional dict with: geo_country (str), is_tor (bool),
            is_proxy (bool), is_datacenter (bool), reputation_score (float 0-1).
        threat_intel: Optional dict with: blocked_ips (list[str]),
            known_attackers (list[str]), threat_feeds (dict).

    Returns:
        float threat score from 0.0 (safe) to 1.0 (critical threat).

    Example:
        >>> request = {"ip": "1.2.3.4", "method": "POST", "endpoint": "/api/login"}
        >>> score = api_threat_score(request)
        >>> 0.0 <= score <= 1.0
        True
    """
    metrics = get_metrics()
    score = 0.0
    factors: dict[str, float] = {}

    ip = request.get("ip", "")
    method = request.get("method", "GET")
    endpoint = request.get("endpoint", "")
    user_agent = request.get("user_agent", "")
    auth_type = request.get("auth_type", "none")
    rate = request.get("rate", 0.0)

    ctx = context or {}
    intel = threat_intel or {}

    if ip in intel.get("blocked_ips", []):
        score += 0.4
        factors["blocked_ip"] = 0.4
    if ip in intel.get("known_attackers", []):
        score += 0.5
        factors["known_attacker"] = 0.5

    if ctx.get("is_tor"):
        score += 0.15
        factors["tor_exit_node"] = 0.15
    if ctx.get("is_proxy"):
        score += 0.1
        factors["proxy"] = 0.1
    if ctx.get("is_datacenter"):
        score += 0.05
        factors["datacenter_ip"] = 0.05

    rep = ctx.get("reputation_score")
    if rep is not None:
        rep_factor = max(0, (1.0 - rep)) * 0.3
        score += rep_factor
        factors["reputation"] = round(rep_factor, 3)

    if method in ("DELETE", "PUT", "PATCH"):
        score += 0.05
        factors["write_method"] = 0.05

    sensitive_paths = ["/admin", "/config", "/secret", "/internal", "/debug", "/manage"]
    if any(p in endpoint.lower() for p in sensitive_paths):
        score += 0.15
        factors["sensitive_endpoint"] = 0.15

    if auth_type == "none":
        score += 0.1
        factors["no_auth"] = 0.1
    elif auth_type == "basic":
        score += 0.05
        factors["weak_auth"] = 0.05

    if rate > 100:
        score += 0.2
        factors["high_rate"] = 0.2
    elif rate > 50:
        score += 0.1
        factors["elevated_rate"] = 0.1

    suspicious_ua = ["sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster", "wfuzz"]
    if any(s in user_agent.lower() for s in suspicious_ua):
        score += 0.3
        factors["suspicious_ua"] = 0.3
    if not user_agent or user_agent == "-":
        score += 0.1
        factors["empty_ua"] = 0.1

    score = min(score, 1.0)
    metrics.inc_counter("api.threat_score.total")
    metrics.observe_histogram("api.threat_score.value", score)

    if score > 0.7:
        metrics.inc_counter("api.threat_score.critical")
    elif score > 0.4:
        metrics.inc_counter("api.threat_score.high")

    logger.info(
        "api_threat_score",
        score=round(score, 3),
        ip=ip,
        endpoint=endpoint,
        factors=factors,
    )

    return round(score, 3)


def graphql_depth_limit(
    query: str,
    max_depth: int = DEFAULT_MAX_GRAPHQL_DEPTH,
    introspection_enabled: bool = False,
) -> dict[str, Any]:
    """Validate GraphQL query depth against a configured limit.

    Parses the query string and calculates the maximum nesting depth
    of field selections to prevent deeply nested query attacks.

    Args:
        query: The GraphQL query string.
        max_depth: Maximum allowed query depth (default 10).
        introspection_enabled: Whether introspection queries are allowed.

    Returns:
        dict with keys: valid (bool), depth (int), max_allowed (int),
        introspection_detected (bool), issues (list[str]).

    Example:
        >>> query = "{ user { posts { comments { author { name } } } } }"
        >>> result = graphql_depth_limit(query, max_depth=3)
        >>> result["depth"]
        5
    """
    metrics = get_metrics()
    issues: list[str] = []

    def _calculate_depth(q: str) -> int:
        depth = 0
        max_d = 0
        in_string = False
        escape_next = False
        for ch in q:
            if escape_next:
                escape_next = False
                continue
            if ch == "\\":
                escape_next = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == "{":
                depth += 1
                max_d = max(max_d, depth)
            elif ch == "}":
                depth = max(0, depth - 1)
        return max_d

    depth = _calculate_depth(query)

    introspection_patterns = [
        r"__schema",
        r"__type",
        r"__typename",
        r"__type\s*\(",
    ]
    introspection_detected = any(
        re.search(p, query, re.IGNORECASE) for p in introspection_patterns
    )

    if introspection_detected and not introspection_enabled:
        issues.append("Introspection query detected but not enabled")

    if depth > max_depth:
        issues.append(f"Query depth {depth} exceeds maximum allowed {max_depth}")

    valid = len(issues) == 0

    metrics.inc_counter("graphql.depth_limit.total")
    metrics.observe_histogram("graphql.depth_limit.depth", depth)
    if not valid:
        metrics.inc_counter("graphql.depth_limit.exceeded")

    logger.info(
        "graphql_depth_limit",
        valid=valid,
        depth=depth,
        max_depth=max_depth,
        introspection_detected=introspection_detected,
        issue_count=len(issues),
    )

    return {
        "valid": valid,
        "depth": depth,
        "max_allowed": max_depth,
        "introspection_detected": introspection_detected,
        "issues": issues,
    }


def graphql_cost_analysis(
    query: str,
    complexity_map: Optional[dict[str, int]] = None,
    max_cost: int = DEFAULT_MAX_GRAPHQL_COST,
) -> dict[str, Any]:
    """Analyze the computational cost of a GraphQL query.

    Estimates the cost of executing a query by summing field complexities
    and accounting for list multipliers to prevent resource exhaustion.

    Args:
        query: The GraphQL query string.
        complexity_map: Dict mapping field names to their complexity scores.
            Defaults: scalar=1, object=5, list=10, connection=25.
        max_cost: Maximum allowed query cost (default 1000).

    Returns:
        dict with keys: valid (bool), total_cost (int), max_cost (int),
        field_costs (dict), issues (list[str]).

    Example:
        >>> query = "{ users { id name posts { title } } }"
        >>> result = graphql_cost_analysis(query, max_cost=500)
        >>> result["total_cost"] > 0
        True
    """
    metrics = get_metrics()
    defaults = {"scalar": 1, "object": 5, "list": 10, "connection": 25}
    cmap = complexity_map or defaults
    issues: list[str] = []
    field_costs: dict[str, int] = {}
    total_cost = 0

    list_fields = {"users", "posts", "comments", "items", "orders", "products", "edges", "nodes", "results"}
    connection_fields = {"users", "posts", "comments", "edges", "nodes"}

    def _extract_fields(q: str) -> list[str]:
        fields = []
        in_string = False
        current = ""
        for ch in q:
            if ch == '"':
                in_string = not in_string
            if in_string:
                continue
            if ch in ("{", "}", ",", "(", ")", ":", "[", "]", "@"):
                if current.strip():
                    fields.append(current.strip())
                current = ""
                continue
            if ch == " ":
                if current.strip():
                    fields.append(current.strip())
                current = ""
                continue
            current += ch
        if current.strip():
            fields.append(current.strip())
        return [f for f in fields if f and f not in ("query", "mutation", "subscription", "fragment", "on")]

    fields = _extract_fields(query)
    multiplier = 1

    for field in fields:
        clean = field.split("(")[0].strip().split("@")[0].strip()
        if not clean or clean.startswith("..."):
            continue

        if clean in connection_fields:
            cost = cmap.get("connection", 25) * multiplier
            multiplier *= 10
        elif clean in list_fields:
            cost = cmap.get("list", 10) * multiplier
            multiplier *= 10
        elif clean[0:1].isupper():
            cost = cmap.get("object", 5) * multiplier
        else:
            cost = cmap.get("scalar", 1) * multiplier

        field_costs[clean] = cost
        total_cost += cost

    if total_cost > max_cost:
        issues.append(f"Query cost {total_cost} exceeds maximum {max_cost}")

    valid = len(issues) == 0

    metrics.inc_counter("graphql.cost_analysis.total")
    metrics.observe_histogram("graphql.cost_analysis.cost", total_cost)
    if not valid:
        metrics.inc_counter("graphql.cost_analysis.exceeded")

    logger.info(
        "graphql_cost_analysis",
        valid=valid,
        total_cost=total_cost,
        max_cost=max_cost,
        field_count=len(field_costs),
    )

    return {
        "valid": valid,
        "total_cost": total_cost,
        "max_cost": max_cost,
        "field_costs": field_costs,
        "issues": issues,
    }


def graphql_abuse_detection(
    queries: list[dict[str, Any]],
    window: int = 300,
    thresholds: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Detect GraphQL abuse patterns across multiple queries.

    Analyzes a collection of queries to identify abuse patterns including
    query flooding, alias abuse, batch attacks, and introspection scanning.

    Args:
        queries: List of query dicts with keys: query (str), timestamp (float),
            client_id (str), response_time_ms (float), error (bool).
        window: Time window in seconds to analyze (default 300).
        thresholds: Dict with keys: max_queries_per_window (int),
            max_alias_count (int), max_batch_size (int),
            max_introspection_count (int).

    Returns:
        dict with keys: abuse_detected (bool), patterns (list[str]),
        risk_score (float 0-1), flagged_clients (list[str]), details (dict).

    Example:
        >>> queries = [{"query": "{ user { name } }", "timestamp": time.time(), "client_id": "x"}]
        >>> result = graphql_abuse_detection(queries)
        >>> "abuse_detected" in result
        True
    """
    metrics = get_metrics()
    defaults = {
        "max_queries_per_window": 100,
        "max_alias_count": 10,
        "max_batch_size": 5,
        "max_introspection_count": 3,
    }
    thresh = thresholds or defaults
    now = time.time()
    window_start = now - window

    recent = [q for q in queries if q.get("timestamp", 0) > window_start]
    if not recent:
        return {
            "abuse_detected": False,
            "patterns": [],
            "risk_score": 0.0,
            "flagged_clients": [],
            "details": {},
        }

    patterns: list[str] = []
    flagged_clients: set[str] = set()
    details: dict[str, Any] = {}
    risk_score = 0.0

    client_queries: dict[str, list[dict[str, Any]]] = {}
    for q in recent:
        cid = q.get("client_id", "unknown")
        client_queries.setdefault(cid, []).append(q)

    for cid, cqs in client_queries.items():
        client_risk = 0.0

        if len(cqs) > thresh["max_queries_per_window"]:
            patterns.append("query_flood")
            flagged_clients.add(cid)
            client_risk += 0.3
            details["query_flood"] = {"count": len(cqs), "limit": thresh["max_queries_per_window"]}

        alias_pattern = re.compile(r"(\w+)\s*:\s*(\w+)\s*\{")
        for q in cqs:
            aliases = alias_pattern.findall(q.get("query", ""))
            if len(aliases) > thresh["max_alias_count"]:
                patterns.append("alias_abuse")
                flagged_clients.add(cid)
                client_risk += 0.25
                details["alias_abuse"] = {"max_aliases": len(aliases), "limit": thresh["max_alias_count"]}
                break

        introspection_count = sum(
            1 for q in cqs
            if "__schema" in q.get("query", "") or "__type" in q.get("query", "")
        )
        if introspection_count > thresh["max_introspection_count"]:
            patterns.append("introspection_scan")
            flagged_clients.add(cid)
            client_risk += 0.3
            details["introspection_scan"] = {"count": introspection_count}

        error_count = sum(1 for q in cqs if q.get("error", False))
        if error_count > len(cqs) * 0.5 and len(cqs) > 10:
            patterns.append("batch_attack")
            flagged_clients.add(cid)
            client_risk += 0.35
            details["batch_attack"] = {"error_rate": round(error_count / len(cqs), 3)}

        avg_time = sum(q.get("response_time_ms", 0) for q in cqs) / max(len(cqs), 1)
        if avg_time > 5000 and len(cqs) > 20:
            patterns.append("resource_exhaustion")
            flagged_clients.add(cid)
            client_risk += 0.4
            details["resource_exhaustion"] = {"avg_response_ms": round(avg_time, 1)}

        risk_score = max(risk_score, min(client_risk, 1.0))

    patterns = list(set(patterns))
    abuse_detected = len(patterns) > 0

    metrics.inc_counter("graphql.abuse_detection.total")
    if abuse_detected:
        metrics.inc_counter("graphql.abuse_detection.detected")
        metrics.set_gauge("graphql.abuse_detection.risk_score", risk_score)

    logger.warning(
        "graphql_abuse_detection",
        abuse_detected=abuse_detected,
        patterns=patterns,
        risk_score=risk_score,
        flagged_clients=list(flagged_clients),
    )

    return {
        "abuse_detected": abuse_detected,
        "patterns": patterns,
        "risk_score": round(risk_score, 3),
        "flagged_clients": list(flagged_clients),
        "details": details,
        "analyzed_queries": len(recent),
        "window_seconds": window,
    }


def grpc_security_validation(
    metadata: dict[str, str],
    required_headers: Optional[list[str]] = None,
    tls_info: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Validate gRPC request security including metadata and TLS.

    Checks that required metadata headers are present, validates
    TLS connection properties, and detects insecure gRPC configurations.

    Args:
        metadata: Dict of gRPC metadata key-value pairs.
        required_headers: List of required metadata header names
            (e.g., ["authorization", "x-request-id"]).
        tls_info: Dict with keys: tls_version (str), cipher (str),
            peer_cert_valid (bool), peer_cert_issuer (str).

    Returns:
        dict with keys: valid (bool), issues (list[str]), tls_valid (bool),
        missing_headers (list[str]), risk_level (str).

    Example:
        >>> metadata = {"authorization": "Bearer token123", "x-request-id": "abc"}
        >>> result = grpc_security_validation(metadata, required_headers=["authorization"])
        >>> result["valid"]
        True
    """
    metrics = get_metrics()
    issues: list[str] = []
    missing_headers: list[str] = []
    required = required_headers or ["authorization"]

    for header in required:
        if header.lower() not in {k.lower() for k in metadata}:
            missing_headers.append(header)
            issues.append(f"Missing required header: {header}")

    tls_valid = False
    if tls_info:
        tls_version = tls_info.get("tls_version", "")
        cipher = tls_info.get("cipher", "")
        peer_cert_valid = tls_info.get("peer_cert_valid", False)

        insecure_versions = {"1.0", "1.1", "SSLv3", "SSLv2"}
        if tls_version in insecure_versions:
            issues.append(f"Insecure TLS version: {tls_version}")

        weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon"]
        if any(w in cipher.upper() for w in weak_ciphers):
            issues.append(f"Weak cipher suite: {cipher}")

        if not peer_cert_valid:
            issues.append("Peer certificate validation failed")

        tls_valid = not any(
            v in insecure_versions for v in [tls_version]
        ) and not any(w in cipher.upper() for w in weak_ciphers) and peer_cert_valid
    else:
        issues.append("No TLS information provided - connection may be unencrypted")

    auth_value = metadata.get("authorization", "")
    if auth_value and len(auth_value) < 20:
        issues.append("Suspiciously short authorization token")

    valid = len(issues) == 0
    risk_level = "critical" if not tls_info else ("high" if len(issues) >= 3 else "medium" if issues else "low")

    metrics.inc_counter("grpc.security_validation.total")
    metrics.inc_counter("grpc.security_validation.valid" if valid else "grpc.security_validation.invalid")

    logger.info(
        "grpc_security_validation",
        valid=valid,
        issue_count=len(issues),
        tls_valid=tls_valid,
        missing_headers=missing_headers,
        risk_level=risk_level,
    )

    return {
        "valid": valid,
        "issues": issues,
        "tls_valid": tls_valid,
        "missing_headers": missing_headers,
        "risk_level": risk_level,
    }


def secure_websocket(
    origin: Optional[str],
    allowed_origins: Optional[list[str]] = None,
    subprotocols: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Configure and validate secure WebSocket connection parameters.

    Validates the WebSocket origin against an allowlist, checks
    subprotocol safety, and returns secure configuration recommendations.

    Args:
        origin: The Origin header value from the WebSocket handshake.
        allowed_origins: List of allowed origin patterns (supports wildcards).
        subprotocols: List of requested WebSocket subprotocols.

    Returns:
        dict with keys: origin_valid (bool), subprotocols_valid (bool),
        secure (bool), recommendations (list[str]), risk_level (str).

    Example:
        >>> result = secure_websocket("https://app.example.com", allowed_origins=["https://*.example.com"])
        >>> result["origin_valid"]
        True
    """
    metrics = get_metrics()
    recommendations: list[str] = []
    origin_valid = False
    subprotocols_valid = True

    if origin:
        allowed = allowed_origins or []
        for pattern in allowed:
            regex_pattern = re.escape(pattern).replace(r"\*", ".*")
            if re.fullmatch(regex_pattern, origin, re.IGNORECASE):
                origin_valid = True
                break
        if not origin_valid and origin in allowed:
            origin_valid = True
    else:
        recommendations.append("No origin provided - consider requiring origin validation")

    if origin and not origin.startswith("https://") and not origin.startswith("wss://"):
        recommendations.append("Origin uses insecure protocol (http/ws)")

    unsafe_subprotocols = {"debug", "admin", "shell", "exec", "eval"}
    if subprotocols:
        for sp in subprotocols:
            if sp.lower() in unsafe_subprotocols:
                subprotocols_valid = False
                recommendations.append(f"Unsafe subprotocol detected: {sp}")
    else:
        recommendations.append("No subprotocols specified")

    secure = origin_valid and subprotocols_valid and len(recommendations) == 0
    risk_level = "critical" if not origin_valid else ("high" if not subprotocols_valid else "medium" if recommendations else "low")

    metrics.inc_counter("websocket.secure_check.total")
    metrics.inc_counter("websocket.secure_check.passed" if secure else "websocket.secure_check.failed")

    logger.info(
        "secure_websocket",
        origin_valid=origin_valid,
        subprotocols_valid=subprotocols_valid,
        secure=secure,
        risk_level=risk_level,
    )

    return {
        "origin_valid": origin_valid,
        "subprotocols_valid": subprotocols_valid,
        "secure": secure,
        "recommendations": recommendations,
        "risk_level": risk_level,
    }


def websocket_origin_validation(
    origin: Optional[str],
    allowed_origins: list[str],
) -> bool:
    """Validate a WebSocket connection origin against an allowlist.

    Supports exact matching and wildcard patterns for origin validation
    during the WebSocket handshake.

    Args:
        origin: The Origin header value from the WebSocket handshake.
        allowed_origins: List of allowed origin patterns. Supports
            wildcards (e.g., "https://*.example.com").

    Returns:
        True if the origin is allowed, False otherwise.

    Example:
        >>> websocket_origin_validation("https://app.example.com", ["https://*.example.com"])
        True
    """
    metrics = get_metrics()

    if not origin:
        metrics.inc_counter("websocket.origin_validation.rejected_no_origin")
        return False

    for pattern in allowed_origins:
        if pattern == origin:
            metrics.inc_counter("websocket.origin_validation.allowed_exact")
            return True
        if "*" in pattern:
            regex_pattern = re.escape(pattern).replace(r"\*", ".*")
            if re.fullmatch(regex_pattern, origin, re.IGNORECASE):
                metrics.inc_counter("websocket.origin_validation.allowed_wildcard")
                return True

    metrics.inc_counter("websocket.origin_validation.rejected")
    logger.warning(
        "websocket_origin_rejected",
        origin=origin,
    )
    return False


def websocket_flood_protection(
    client_id: str,
    connections: list[dict[str, Any]],
    max_connections: int = DEFAULT_MAX_WEBSOCKET_CONNECTIONS,
    window: int = DEFAULT_FLOOD_WINDOW,
) -> dict[str, Any]:
    """Protect against WebSocket connection flooding attacks.

    Monitors per-client WebSocket connections and detects flooding
    patterns including rapid connect/disconnect and excessive
    concurrent connections.

    Args:
        client_id: Unique identifier for the WebSocket client.
        connections: List of connection dicts with keys: timestamp (float),
            status (str: "open"|"closed"), duration_ms (float).
        max_connections: Maximum allowed concurrent connections (default 10).
        window: Time window in seconds for analysis (default 60).

    Returns:
        dict with keys: allowed (bool), current_connections (int),
        max_allowed (int), flood_detected (bool), risk_level (str),
        recommendations (list[str]).

    Example:
        >>> connections = [{"timestamp": time.time(), "status": "open"}]
        >>> result = websocket_flood_protection("client-1", connections)
        >>> result["allowed"]
        True
    """
    metrics = get_metrics()
    now = time.time()
    window_start = now - window
    recommendations: list[str] = []

    recent = [c for c in connections if c.get("timestamp", 0) > window_start]
    open_connections = sum(1 for c in recent if c.get("status") == "open")
    closed_connections = sum(1 for c in recent if c.get("status") == "closed")
    total_connections = len(recent)

    flood_detected = False
    risk_level = "low"

    if open_connections > max_connections:
        flood_detected = True
        risk_level = "critical"
        recommendations.append(f"Open connections {open_connections} exceeds limit {max_connections}")

    if total_connections > max_connections * 5:
        flood_detected = True
        risk_level = "high"
        recommendations.append(f"Excessive connection attempts: {total_connections} in {window}s window")

    if closed_connections > total_connections * 0.8 and total_connections > 20:
        flood_detected = True
        risk_level = "high"
        recommendations.append("Rapid connect/disconnect pattern detected")

    short_connections = sum(1 for c in recent if c.get("duration_ms", 0) < 1000)
    if short_connections > total_connections * 0.5 and total_connections > 10:
        flood_detected = True
        if risk_level == "low":
            risk_level = "medium"
        recommendations.append(f"Many short-lived connections: {short_connections}")

    allowed = not flood_detected and open_connections <= max_connections

    metrics.inc_counter("websocket.flood_protection.total")
    if flood_detected:
        metrics.inc_counter("websocket.flood_protection.flood_detected")
        metrics.set_gauge("websocket.flood_protection.connections", open_connections)

    logger.info(
        "websocket_flood_protection",
        client_id=client_id,
        allowed=allowed,
        open_connections=open_connections,
        flood_detected=flood_detected,
        risk_level=risk_level,
    )

    return {
        "allowed": allowed,
        "current_connections": open_connections,
        "max_allowed": max_connections,
        "flood_detected": flood_detected,
        "risk_level": risk_level,
        "recommendations": recommendations,
        "total_in_window": total_connections,
    }


def api_key_rotation(
    current_key: str,
    algorithm: str = "sha256",
    expiry_days: int = DEFAULT_API_KEY_EXPIRY_DAYS,
) -> dict[str, Any]:
    """Generate a new API key with secure rotation parameters.

    Creates a cryptographically secure replacement API key with
    configurable algorithm for the key fingerprint and expiry period.

    Args:
        current_key: The current API key being rotated (for fingerprinting).
        algorithm: Hash algorithm for key fingerprint (sha256, sha512, sha384).
        expiry_days: Number of days until the new key expires (default 90).

    Returns:
        dict with keys: new_key (str), fingerprint (str), created_at (float),
        expires_at (float), expiry_days (int), algorithm (str),
        rotation_id (str).

    Example:
        >>> result = api_key_rotation("old-key-123", algorithm="sha256", expiry_days=30)
        >>> len(result["new_key"]) > 32
        True
    """
    metrics = get_metrics()
    hash_funcs = {
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
        "sha384": hashlib.sha384,
    }
    hash_func = hash_funcs.get(algorithm, hashlib.sha256)

    new_key = secrets.token_urlsafe(48)
    fingerprint = hash_func(new_key.encode()).hexdigest()[:16]
    rotation_id = secrets.token_hex(8)

    now = time.time()
    expires_at = now + (expiry_days * 86400)

    old_fingerprint = hash_func(current_key.encode()).hexdigest()[:16] if current_key else "none"

    metrics.inc_counter("api.key_rotation.total")
    metrics.inc_counter(f"api.key_rotation.{algorithm}")

    logger.info(
        "api_key_rotation",
        rotation_id=rotation_id,
        algorithm=algorithm,
        expiry_days=expiry_days,
        old_fingerprint=old_fingerprint,
        new_fingerprint=fingerprint,
    )

    return {
        "new_key": new_key,
        "fingerprint": fingerprint,
        "created_at": now,
        "expires_at": expires_at,
        "expiry_days": expiry_days,
        "algorithm": algorithm,
        "rotation_id": rotation_id,
    }


def api_key_validation(
    api_key: str,
    valid_keys: dict[str, Any],
    scopes: Optional[list[str]] = None,
    required_scope: Optional[str] = None,
) -> dict[str, Any]:
    """Validate an API key against a registry of known keys.

    Checks key existence, expiry, revocation status, IP allowlist,
    rate limits, and scope authorization.

    Args:
        api_key: The API key to validate.
        valid_keys: Dict mapping API key strings to their metadata:
            {"key": {"active": bool, "expires_at": float, "scopes": list,
            "allowed_ips": list, "rate_limit": int, "owner": str}}.
        scopes: List of scopes the request requires.
        required_scope: A single required scope string.

    Returns:
        dict with keys: valid (bool), key_info (dict), issues (list[str]),
        remaining_requests (int), risk_level (str).

    Example:
        >>> keys = {"sk-abc": {"active": True, "scopes": ["read", "write"]}}
        >>> result = api_key_validation("sk-abc", keys, required_scope="read")
        >>> result["valid"]
        True
    """
    metrics = get_metrics()
    issues: list[str] = []
    key_info: dict[str, Any] = {}

    if api_key not in valid_keys:
        metrics.inc_counter("api.key_validation.invalid_key")
        logger.warning("api_key_validation_failed", reason="key_not_found")
        return {
            "valid": False,
            "key_info": {},
            "issues": ["API key not found"],
            "remaining_requests": 0,
            "risk_level": "high",
        }

    meta = valid_keys[api_key]
    key_info = {"owner": meta.get("owner", "unknown")}

    if not meta.get("active", True):
        issues.append("API key has been deactivated")

    expires_at = meta.get("expires_at")
    if expires_at is not None and time.time() > expires_at:
        issues.append("API key has expired")

    if meta.get("revoked", False):
        issues.append("API key has been revoked")

    allowed_ips = meta.get("allowed_ips")
    if allowed_ips:
        cache = get_cache()
        current_ip = cache.get(f"key_ip:{api_key}")
        if current_ip and current_ip not in allowed_ips:
            issues.append(f"Request IP {current_ip} not in allowed IPs")

    key_scopes = set(meta.get("scopes", []))
    required = set()
    if required_scope:
        required.add(required_scope)
    if scopes:
        required.update(scopes)

    if required and not required.issubset(key_scopes):
        missing = required - key_scopes
        issues.append(f"Missing required scopes: {sorted(missing)}")

    valid = len(issues) == 0
    risk_level = "critical" if meta.get("revoked") else ("high" if len(issues) >= 2 else "medium" if issues else "low")

    rate_limit = meta.get("rate_limit", DEFAULT_RATE_LIMIT_MAX_REQUESTS)
    cache = get_cache()
    rate_key = f"key_rate:{api_key}"
    current_usage = cache.get(rate_key)
    usage = int(current_usage) if current_usage else 0
    remaining = max(0, rate_limit - usage)

    metrics.inc_counter("api.key_validation.total")
    metrics.inc_counter("api.key_validation.valid" if valid else "api.key_validation.invalid")

    logger.info(
        "api_key_validation",
        valid=valid,
        issue_count=len(issues),
        owner=key_info.get("owner"),
        risk_level=risk_level,
    )

    return {
        "valid": valid,
        "key_info": key_info,
        "issues": issues,
        "remaining_requests": remaining,
        "risk_level": risk_level,
    }


__all__ = [
    "validate_json_schema",
    "validate_input",
    "sanitize_json",
    "api_rate_limit",
    "adaptive_rate_limit",
    "detect_api_abuse",
    "detect_bola",
    "detect_broken_auth",
    "detect_mass_assignment",
    "detect_shadow_api",
    "api_threat_score",
    "graphql_depth_limit",
    "graphql_cost_analysis",
    "graphql_abuse_detection",
    "grpc_security_validation",
    "secure_websocket",
    "websocket_origin_validation",
    "websocket_flood_protection",
    "api_key_rotation",
    "api_key_validation",
]
