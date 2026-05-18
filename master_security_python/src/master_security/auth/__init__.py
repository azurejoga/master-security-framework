from __future__ import annotations
import hashlib
import hmac
import secrets
import time
import math
import re
import json
import struct
from datetime import datetime, timezone, timedelta
from typing import Any, Optional
from master_security.core import get_logger, get_metrics, get_telemetry, create_span, get_cache, get_event_bus, SecurityEvent, EventSeverity
from master_security.core.exceptions import AuthenticationError, ValidationError
import structlog
logger = structlog.get_logger(__name__)


def _constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _base64url_encode(data: bytes) -> str:
    """URL-safe Base64 encoding without padding."""
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(s: str) -> bytes:
    """URL-safe Base64 decoding with padding restoration."""
    import base64
    s = s + "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _hmac_sha256(key: bytes, message: bytes) -> bytes:
    """Compute HMAC-SHA256."""
    return hmac.new(key, message, hashlib.sha256).digest()


def _hmac_sha384(key: bytes, message: bytes) -> bytes:
    """Compute HMAC-SHA384."""
    return hmac.new(key, message, hashlib.sha384).digest()


def _hmac_sha512(key: bytes, message: bytes) -> bytes:
    """Compute HMAC-SHA512."""
    return hmac.new(key, message, hashlib.sha512).digest()


def _compute_hmac(key: bytes, message: bytes, algorithm: str) -> bytes:
    """Compute HMAC for the given algorithm."""
    alg_map = {
        "HS256": _hmac_sha256,
        "HS384": _hmac_sha384,
        "HS512": _hmac_sha512,
    }
    func = alg_map.get(algorithm)
    if func is None:
        raise ValidationError(f"Unsupported HMAC algorithm: {algorithm}")
    return func(key, message)


def _encode_jwt_segment(data: dict) -> str:
    """JSON-encode and base64url-encode a JWT segment."""
    return _base64url_encode(json.dumps(data, separators=(",", ":")).encode("utf-8"))


def _decode_jwt_segment(s: str) -> dict:
    """Base64url-decode and JSON-decode a JWT segment."""
    return json.loads(_base64url_decode(s))


def validate_jwt(
    token: str,
    secret: str,
    algorithms: Optional[list[str]] = None,
    verify_exp: bool = True,
    required_claims: Optional[dict[str, Any]] = None,
) -> dict:
    """Validate and decode a JWT token.

    Args:
        token: The JWT token string to validate.
        secret: The secret key used to verify the signature.
        algorithms: List of acceptable signing algorithms (default: ["HS256"]).
        verify_exp: Whether to verify the expiration claim (default: True).
        required_claims: Dictionary of claims that must be present with expected values.

    Returns:
        dict: The decoded JWT payload claims.

    Raises:
        AuthenticationError: If the token is invalid, expired, or missing required claims.

    Example:
        >>> claims = validate_jwt(token, "my-secret", algorithms=["HS256"])
        >>> print(claims["sub"])
    """
    timeout = 5.0
    metrics = get_metrics()
    with create_span("auth.validate_jwt") as span:
        try:
            span.set_attribute("verify_exp", verify_exp)
            start = time.monotonic()

            if not token or not isinstance(token, str):
                raise AuthenticationError("Token must be a non-empty string")

            parts = token.split(".")
            if len(parts) != 3:
                raise AuthenticationError("Invalid JWT format: expected 3 segments")

            header_b64, payload_b64, signature_b64 = parts
            header = _decode_jwt_segment(header_b64)
            payload = _decode_jwt_segment(payload_b64)

            alg = header.get("alg", "HS256")
            allowed = algorithms or ["HS256"]
            if alg not in allowed:
                raise AuthenticationError(f"Algorithm '{alg}' not in allowed list")

            signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
            expected_sig = _compute_hmac(secret.encode("utf-8"), signing_input, alg)
            provided_sig = _base64url_decode(signature_b64)

            if not hmac.compare_digest(expected_sig, provided_sig):
                metrics.inc_counter("auth.jwt.signature_invalid", value=1.0)
                raise AuthenticationError("Invalid JWT signature")

            if verify_exp:
                exp = payload.get("exp")
                if exp is not None:
                    now = datetime.now(timezone.utc).timestamp()
                    if now > float(exp):
                        metrics.inc_counter("auth.jwt.expired", value=1.0)
                        raise AuthenticationError("Token has expired")

            if required_claims:
                for claim, expected in required_claims.items():
                    actual = payload.get(claim)
                    if actual is None:
                        raise AuthenticationError(f"Missing required claim: {claim}")
                    if actual != expected:
                        raise AuthenticationError(f"Claim '{claim}' mismatch")

            elapsed = time.monotonic() - start
            metrics.observe_histogram("auth.jwt.validation_duration", elapsed)
            metrics.inc_counter("auth.jwt.validated", value=1.0)
            span.set_attribute("claims_count", len(payload))
            logger.info("jwt_validated", sub=payload.get("sub"), alg=alg)
            return payload

        except AuthenticationError:
            raise
        except Exception as exc:
            metrics.inc_counter("auth.jwt.validation_error", value=1.0)
            raise AuthenticationError(f"JWT validation failed: {exc}") from exc


def generate_jwt(
    subject: str,
    secret: str,
    algorithm: str = "HS256",
    expiry: int = 3600,
    claims: Optional[dict[str, Any]] = None,
    issuer: Optional[str] = None,
) -> str:
    """Generate a signed JWT token.

    Args:
        subject: The subject identifier (sub claim).
        secret: The secret key for signing.
        algorithm: Signing algorithm (default: "HS256").
        expiry: Token lifetime in seconds (default: 3600).
        claims: Additional claims to include in the payload.
        issuer: The issuer claim (iss).

    Returns:
        str: The encoded JWT token string.

    Raises:
        ValidationError: If parameters are invalid.

    Example:
        >>> token = generate_jwt("user-123", "my-secret", expiry=7200)
    """
    timeout = 5.0
    metrics = get_metrics()
    with create_span("auth.generate_jwt") as span:
        try:
            if not subject:
                raise ValidationError("Subject must be a non-empty string")
            if expiry <= 0:
                raise ValidationError("Expiry must be positive")
            if algorithm not in ("HS256", "HS384", "HS512"):
                raise ValidationError(f"Unsupported algorithm: {algorithm}")

            now = datetime.now(timezone.utc)
            jti = secrets.token_hex(16)
            payload: dict[str, Any] = {
                "sub": subject,
                "iat": int(now.timestamp()),
                "exp": int(now.timestamp()) + expiry,
                "jti": jti,
                "nbf": int(now.timestamp()),
            }
            if issuer:
                payload["iss"] = issuer
            if claims:
                payload.update(claims)

            header = {"alg": algorithm, "typ": "JWT"}
            header_b64 = _encode_jwt_segment(header)
            payload_b64 = _encode_jwt_segment(payload)
            signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
            signature = _compute_hmac(secret.encode("utf-8"), signing_input, algorithm)
            signature_b64 = _base64url_encode(signature)

            token = f"{header_b64}.{payload_b64}.{signature_b64}"

            metrics.inc_counter("auth.jwt.generated", value=1.0)
            span.set_attribute("algorithm", algorithm)
            span.set_attribute("jti", jti)
            logger.info("jwt_generated", sub=subject, jti=jti, alg=algorithm)
            return token

        except ValidationError:
            raise
        except Exception as exc:
            metrics.inc_counter("auth.jwt.generation_error", value=1.0)
            raise AuthenticationError(f"JWT generation failed: {exc}") from exc


def revoke_jwt(token_id: str, reason: str = "manual_revocation") -> bool:
    """Revoke a JWT token by its JTI (JWT ID).

    Args:
        token_id: The JWT ID (jti) to revoke.
        reason: Reason for revocation (default: "manual_revocation").

    Returns:
        bool: True if the token was successfully revoked.

    Raises:
        ValidationError: If token_id is empty.

    Example:
        >>> revoke_jwt("abc123", reason="user_logout")
        True
    """
    timeout = 5.0
    metrics = get_metrics()
    with create_span("auth.revoke_jwt") as span:
        try:
            if not token_id:
                raise ValidationError("Token ID must be non-empty")

            cache = get_cache()
            revocation_key = f"jwt:revoked:{token_id}"
            cache.set(revocation_key, reason, ttl=86400 * 30)
            metrics.inc_counter("auth.jwt.revoked", value=1.0)
            span.set_attribute("token_id", token_id)
            logger.info("jwt_revoked", token_id=token_id, reason=reason)
            return True

        except ValidationError:
            raise
        except Exception as exc:
            metrics.inc_counter("auth.jwt.revocation_error", value=1.0)
            raise AuthenticationError(f"JWT revocation failed: {exc}") from exc


def rotate_jwt(
    old_token: str,
    secret: str,
    algorithm: str = "HS256",
    expiry: int = 3600,
) -> str:
    """Rotate a JWT by validating the old token and issuing a new one.

    Args:
        old_token: The current JWT to rotate.
        secret: The signing secret.
        algorithm: Signing algorithm (default: "HS256").
        expiry: New token lifetime in seconds (default: 3600).

    Returns:
        str: The newly generated JWT token.

    Raises:
        AuthenticationError: If the old token is invalid.

    Example:
        >>> new_token = rotate_jwt(old_token, "my-secret")
    """
    timeout = 10.0
    metrics = get_metrics()
    with create_span("auth.rotate_jwt") as span:
        try:
            payload = validate_jwt(old_token, secret, algorithms=[algorithm])

            jti = payload.get("jti", "")
            if jti:
                revoke_jwt(jti, reason="token_rotation")

            subject = payload.get("sub", "")
            if not subject:
                raise AuthenticationError("Old token missing subject claim")

            new_claims = {k: v for k, v in payload.items() if k not in (
                "iat", "exp", "jti", "nbf", "sub", "iss"
            )}
            issuer = payload.get("iss")

            new_token = generate_jwt(
                subject=subject,
                secret=secret,
                algorithm=algorithm,
                expiry=expiry,
                claims=new_claims,
                issuer=issuer,
            )

            metrics.inc_counter("auth.jwt.rotated", value=1.0)
            span.set_attribute("subject", subject)
            logger.info("jwt_rotated", subject=subject)
            return new_token

        except (AuthenticationError, ValidationError):
            raise
        except Exception as exc:
            metrics.inc_counter("auth.jwt.rotation_error", value=1.0)
            raise AuthenticationError(f"JWT rotation failed: {exc}") from exc


def validate_refresh_token(
    token: str,
    secret: str,
    user_id: str,
) -> dict:
    """Validate a refresh token for a specific user.

    Args:
        token: The refresh token string.
        secret: The signing secret.
        user_id: The expected user ID.

    Returns:
        dict: The decoded token payload if valid.

    Raises:
        AuthenticationError: If the token is invalid or belongs to a different user.

    Example:
        >>> payload = validate_refresh_token(refresh_token, "secret", "user-1")
    """
    timeout = 5.0
    metrics = get_metrics()
    with create_span("auth.validate_refresh_token") as span:
        try:
            payload = validate_jwt(token, secret, verify_exp=True)

            if payload.get("sub") != user_id:
                raise AuthenticationError("Refresh token subject mismatch")

            token_type = payload.get("type", "")
            if token_type != "refresh":
                raise AuthenticationError("Token is not a refresh token")

            cache = get_cache()
            revoked = cache.get(f"refresh:revoked:{payload.get('jti', '')}")
            if revoked:
                raise AuthenticationError("Refresh token has been revoked")

            metrics.inc_counter("auth.refresh_token.validated", value=1.0)
            span.set_attribute("user_id", user_id)
            logger.info("refresh_token_validated", user_id=user_id)
            return payload

        except (AuthenticationError, ValidationError):
            raise
        except Exception as exc:
            metrics.inc_counter("auth.refresh_token.validation_error", value=1.0)
            raise AuthenticationError(f"Refresh token validation failed: {exc}") from exc


def secure_session(
    user_id: str,
    ip: str,
    user_agent: str,
    device_id: Optional[str] = None,
) -> dict:
    """Create a secure session for an authenticated user.

    Args:
        user_id: The authenticated user identifier.
        ip: The client IP address.
        user_agent: The client User-Agent string.
        device_id: Optional device identifier.

    Returns:
        dict: Session data including session_id, created_at, and metadata.

    Raises:
        ValidationError: If required parameters are missing.

    Example:
        >>> session = secure_session("user-1", "10.0.0.1", "Mozilla/5.0")
        >>> print(session["session_id"])
    """
    timeout = 5.0
    metrics = get_metrics()
    with create_span("auth.secure_session") as span:
        try:
            if not user_id or not ip or not user_agent:
                raise ValidationError("user_id, ip, and user_agent are required")

            session_id = secrets.token_urlsafe(48)
            now = datetime.now(timezone.utc)
            session_data = {
                "session_id": session_id,
                "user_id": user_id,
                "ip": ip,
                "user_agent": user_agent,
                "device_id": device_id,
                "created_at": now.isoformat(),
                "last_active": now.isoformat(),
                "is_valid": True,
            }

            cache = get_cache()
            cache.set(
                f"session:{session_id}",
                json.dumps(session_data),
                ttl=86400,
            )
            cache.set(
                f"user:sessions:{user_id}",
                json.dumps([session_id]),
                ttl=86400 * 7,
            )
            metrics.inc_counter("auth.session.created", value=1.0)
            span.set_attribute("user_id", user_id)
            span.set_attribute("session_id", session_id)
            logger.info("session_created", user_id=user_id, session_id=session_id)
            return session_data

        except ValidationError:
            raise
        except Exception as exc:
            metrics.inc_counter("auth.session.creation_error", value=1.0)
            raise AuthenticationError(f"Session creation failed: {exc}") from exc


def validate_session(
    session_id: str,
    user_id: str,
    ip: str,
) -> bool:
    """Validate an existing session.

    Args:
        session_id: The session identifier.
        user_id: The expected user ID.
        ip: The current client IP address.

    Returns:
        bool: True if the session is valid and active.

    Raises:
        ValidationError: If parameters are empty.

    Example:
        >>> is_valid = validate_session("sess_abc", "user-1", "10.0.0.1")
    """
    timeout = 5.0
    metrics = get_metrics()
    with create_span("auth.validate_session") as span:
        try:
            if not session_id or not user_id:
                raise ValidationError("session_id and user_id are required")

            cache = get_cache()
            raw = cache.get(f"session:{session_id}")
            if not raw:
                metrics.inc_counter("auth.session.not_found", value=1.0)
                return False

            session_data = json.loads(raw)

            if session_data.get("user_id") != user_id:
                metrics.inc_counter("auth.session.user_mismatch", value=1.0)
                return False

            if not session_data.get("is_valid", False):
                metrics.inc_counter("auth.session.invalid", value=1.0)
                return False

            now = datetime.now(timezone.utc).isoformat()
            session_data["last_active"] = now
            cache.set(f"session:{session_id}", json.dumps(session_data), ttl=86400)

            metrics.inc_counter("auth.session.validated", value=1.0)
            span.set_attribute("session_id", session_id)
            logger.info("session_validated", session_id=session_id, user_id=user_id)
            return True

        except ValidationError:
            raise
        except Exception as exc:
            metrics.inc_counter("auth.session.validation_error", value=1.0)
            raise AuthenticationError(f"Session validation failed: {exc}") from exc


def detect_session_hijack(
    session_id: str,
    current_ip: str,
    current_ua: str,
    historical_data: dict,
) -> bool:
    """Detect potential session hijacking by comparing current and historical data.

    Args:
        session_id: The active session identifier.
        current_ip: The current client IP address.
        current_ua: The current User-Agent string.
        historical_data: Historical session data with original ip, user_agent, etc.

    Returns:
        bool: True if session hijacking is suspected.

    Raises:
        ValidationError: If required parameters are missing.

    Example:
        >>> hijacked = detect_session_hijack("sess_1", "1.2.3.4", "Chrome", hist)
    """
    timeout = 5.0
    metrics = get_metrics()
    with create_span("auth.detect_session_hijack") as span:
        try:
            if not session_id or not current_ip or not current_ua:
                raise ValidationError("session_id, current_ip, and current_ua are required")

            risk_score = 0.0
            original_ip = historical_data.get("ip", "")
            original_ua = historical_data.get("user_agent", "")

            if original_ip and current_ip != original_ip:
                risk_score += 0.5
                logger.warning("session_ip_changed", session_id=session_id)

            if original_ua and current_ua != original_ua:
                risk_score += 0.4
                logger.warning("session_ua_changed", session_id=session_id)

            device_fingerprint = historical_data.get("device_fingerprint", "")
            current_fp = historical_data.get("current_device_fingerprint", "")
            if device_fingerprint and current_fp and device_fingerprint != current_fp:
                risk_score += 0.3

            is_hijacked = risk_score >= 0.5

            if is_hijacked:
                metrics.inc_counter("auth.session.hijack_detected", value=1.0)

            span.set_attribute("risk_score", risk_score)
            span.set_attribute("hijack_detected", is_hijacked)
            logger.info("session_hijack_check", session_id=session_id, risk_score=risk_score)
            return is_hijacked

        except ValidationError:
            raise
        except Exception as exc:
            metrics.inc_counter("auth.session.hijack_check_error", value=1.0)
            raise AuthenticationError(f"Session hijack detection failed: {exc}") from exc


def detect_token_replay(
    token_id: str,
    timestamp: float,
    ip: str,
) -> bool:
    """Detect if a token is being replayed (used more than once).

    Args:
        token_id: The unique token identifier (e.g., JTI).
        timestamp: The current usage timestamp (Unix epoch).
        ip: The client IP address making the request.

    Returns:
        bool: True if token replay is detected.

    Raises:
        ValidationError: If token_id is empty.

    Example:
        >>> replayed = detect_token_replay("jti-abc", time.time(), "10.0.0.1")
    """
    timeout = 5.0
    metrics = get_metrics()
    with create_span("auth.detect_token_replay") as span:
        try:
            if not token_id:
                raise ValidationError("Token ID is required")

            cache = get_cache()
            replay_key = f"token:usage:{token_id}"
            previous = cache.get(replay_key)

            if previous:
                prev_data = json.loads(previous)
                prev_ts = prev_data.get("timestamp", 0.0)
                prev_ip = prev_data.get("ip", "")

                if prev_ip != ip:
                    metrics.inc_counter("auth.token.replay_detected", value=1.0)
                    span.set_attribute("replay_detected", True)
                    logger.warning("token_replay_detected", token_id=token_id)
                    return True

                if timestamp <= prev_ts:
                    metrics.inc_counter("auth.token.replay_detected", value=1.0)
                    span.set_attribute("replay_detected", True)
                    logger.warning("token_replay_detected", token_id=token_id)
                    return True

            cache.set(
                replay_key,
                json.dumps({"timestamp": timestamp, "ip": ip}),
                ttl=3600,
            )

            span.set_attribute("replay_detected", False)
            logger.info("token_replay_check", token_id=token_id, replay=False)
            return False

        except ValidationError:
            raise
        except Exception as exc:
            metrics.inc_counter("auth.token.replay_check_error", value=1.0)
            raise AuthenticationError(f"Token replay detection failed: {exc}") from exc


def detect_credential_stuffing(
    ip: str,
    username: str,
    attempts: int,
    window: int = 300,
) -> bool:
    """Detect credential stuffing attacks from a single IP.

    Args:
        ip: The source IP address.
        username: The username being attempted.
        attempts: Number of failed attempts in the window.
        window: Time window in seconds (default: 300 = 5 minutes).

    Returns:
        bool: True if credential stuffing is detected.

    Raises:
        ValidationError: If IP or username is empty.

    Example:
        >>> stuffing = detect_credential_stuffing("1.2.3.4", "admin", 50)
    """
    timeout = 5.0
    metrics = get_metrics()
    with create_span("auth.detect_credential_stuffing") as span:
        try:
            if not ip or not username:
                raise ValidationError("IP and username are required")

            cache = get_cache()
            key = f"auth:attempts:{ip}"
            user_key = f"auth:users:{ip}"

            current_attempts = cache.get(key)
            if current_attempts:
                total = int(current_attempts) + attempts
            else:
                total = attempts

            cache.set(key, str(total), ttl=window)

            unique_users = cache.get(user_key)
            if unique_users:
                user_set: set[str] = set(json.loads(unique_users))
            else:
                user_set = set()
            user_set.add(username)
            cache.set(user_key, json.dumps(list(user_set)), ttl=window)

            threshold = 20
            is_stuffing = total >= threshold or len(user_set) >= 10

            if is_stuffing:
                metrics.inc_counter("auth.credential_stuffing.detected", value=1.0)

            span.set_attribute("is_stuffing", is_stuffing)
            span.set_attribute("total_attempts", total)
            logger.info(
                "credential_stuffing_check",
                ip=ip,
                attempts=total,
                unique_users=len(user_set),
                detected=is_stuffing,
            )
            return is_stuffing

        except ValidationError:
            raise
        except Exception as exc:
            metrics.inc_counter("auth.credential_stuffing.check_error", value=1.0)
            raise AuthenticationError(f"Credential stuffing detection failed: {exc}") from exc


def detect_bruteforce(
    ip: str,
    attempts: int,
    window: int = 300,
    threshold: int = 10,
) -> bool:
    """Detect brute force login attempts from a single IP.

    Args:
        ip: The source IP address.
        attempts: Number of failed attempts in the window.
        window: Time window in seconds (default: 300).
        threshold: Number of attempts to trigger detection (default: 10).

    Returns:
        bool: True if brute force is detected.

    Raises:
        ValidationError: If IP is empty or threshold is invalid.

    Example:
        >>> bruteforce = detect_bruteforce("1.2.3.4", 15, threshold=10)
    """
    timeout = 5.0
    metrics = get_metrics()
    with create_span("auth.detect_bruteforce") as span:
        try:
            if not ip:
                raise ValidationError("IP is required")
            if threshold <= 0:
                raise ValidationError("Threshold must be positive")

            cache = get_cache()
            key = f"bruteforce:{ip}"
            current = cache.get(key)
            total = int(current) + attempts if current else attempts
            cache.set(key, str(total), ttl=window)

            is_bruteforce = total >= threshold

            if is_bruteforce:
                metrics.inc_counter("auth.bruteforce.detected", value=1.0)

            span.set_attribute("is_bruteforce", is_bruteforce)
            span.set_attribute("attempts", total)
            logger.info("bruteforce_check", ip=ip, attempts=total, detected=is_bruteforce)
            return is_bruteforce

        except ValidationError:
            raise
        except Exception as exc:
            metrics.inc_counter("auth.bruteforce.check_error", value=1.0)
            raise AuthenticationError(f"Brute force detection failed: {exc}") from exc


def adaptive_auth(
    user_id: str,
    risk_score: float,
    context: dict,
) -> dict:
    """Perform adaptive authentication based on risk assessment.

    Args:
        user_id: The user identifier.
        risk_score: Computed risk score (0.0 to 1.0).
        context: Additional context (location, device, time, etc.).

    Returns:
        dict: Authentication decision with action, mfa_required, and risk_level.

    Raises:
        ValidationError: If user_id is empty or risk_score is out of range.

    Example:
        >>> result = adaptive_auth("user-1", 0.7, {"ip": "1.2.3.4"})
        >>> print(result["action"])
    """
    timeout = 5.0
    metrics = get_metrics()
    with create_span("auth.adaptive_auth") as span:
        try:
            if not user_id:
                raise ValidationError("user_id is required")
            if not 0.0 <= risk_score <= 1.0:
                raise ValidationError("risk_score must be between 0.0 and 1.0")

            if risk_score < 0.3:
                action = "allow"
                mfa_required = False
                risk_level = "low"
            elif risk_score < 0.6:
                action = "challenge"
                mfa_required = True
                risk_level = "medium"
            elif risk_score < 0.8:
                action = "step_up"
                mfa_required = True
                risk_level = "high"
            else:
                action = "deny"
                mfa_required = False
                risk_level = "critical"

            result = {
                "user_id": user_id,
                "action": action,
                "mfa_required": mfa_required,
                "risk_level": risk_level,
                "risk_score": risk_score,
                "context": context,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            metrics.inc_counter(f"auth.adaptive.{action}", 1)
            span.set_attribute("action", action)
            span.set_attribute("risk_level", risk_level)
            logger.info(
                "adaptive_auth_decision",
                user_id=user_id,
                action=action,
                risk_score=risk_score,
            )
            return result

        except ValidationError:
            raise
        except Exception as exc:
            metrics.inc_counter("auth.adaptive.error", value=1.0)
            raise AuthenticationError(f"Adaptive auth failed: {exc}") from exc


def behavioral_auth(
    user_id: str,
    behavior_data: dict,
    baseline: dict,
) -> float:
    """Assess authentication based on behavioral biometrics.

    Args:
        user_id: The user identifier.
        behavior_data: Current behavioral data (typing speed, mouse patterns, etc.).
        baseline: User's established behavioral baseline.

    Returns:
        float: Confidence score (0.0 to 1.0) that the user is legitimate.

    Raises:
        ValidationError: If user_id is empty.

    Example:
        >>> confidence = behavioral_auth("user-1", current_data, baseline_data)
    """
    timeout = 5.0
    metrics = get_metrics()
    with create_span("auth.behavioral_auth") as span:
        try:
            if not user_id:
                raise ValidationError("user_id is required")

            confidence = 1.0

            typing_speed = behavior_data.get("typing_speed", 0)
            baseline_speed = baseline.get("typing_speed", 0)
            if baseline_speed > 0 and typing_speed > 0:
                speed_diff = abs(typing_speed - baseline_speed) / baseline_speed
                confidence -= min(speed_diff * 0.3, 0.3)

            mouse_variance = behavior_data.get("mouse_variance", 0.0)
            baseline_variance = baseline.get("mouse_variance", 0.0)
            if baseline_variance > 0:
                var_diff = abs(mouse_variance - baseline_variance) / baseline_variance
                confidence -= min(var_diff * 0.2, 0.2)

            session_duration = behavior_data.get("session_duration", 0)
            baseline_duration = baseline.get("session_duration", 0)
            if baseline_duration > 0:
                dur_diff = abs(session_duration - baseline_duration) / baseline_duration
                confidence -= min(dur_diff * 0.1, 0.1)

            navigation_pattern = behavior_data.get("navigation_pattern", "")
            baseline_pattern = baseline.get("navigation_pattern", "")
            if navigation_pattern and baseline_pattern:
                if navigation_pattern != baseline_pattern:
                    confidence -= 0.15

            confidence = max(0.0, min(1.0, confidence))

            if confidence < 0.5:
                metrics.inc_counter("auth.behavioral.anomaly", value=1.0)

            metrics.observe_histogram("auth.behavioral.confidence", confidence)
            span.set_attribute("confidence", confidence)
            logger.info("behavioral_auth", user_id=user_id, confidence=confidence)
            return round(confidence, 4)

        except ValidationError:
            raise
        except Exception as exc:
            metrics.inc_counter("auth.behavioral.error", value=1.0)
            raise AuthenticationError(f"Behavioral auth failed: {exc}") from exc


def impossible_travel(
    user_id: str,
    current_location: dict,
    last_location: dict,
    time_delta: float,
) -> bool:
    """Detect impossible travel between two login locations.

    Args:
        user_id: The user identifier.
        current_location: Dict with "lat" and "lon" for current login.
        last_location: Dict with "lat" and "lon" for previous login.
        time_delta: Time between logins in seconds.

    Returns:
        bool: True if travel between locations is physically impossible.

    Raises:
        ValidationError: If location data is missing.

    Example:
        >>> impossible = impossible_travel("user-1", curr_loc, last_loc, 3600)
    """
    timeout = 5.0
    metrics = get_metrics()
    with create_span("auth.impossible_travel") as span:
        try:
            if not current_location or not last_location:
                raise ValidationError("Both locations are required")

            lat1 = math.radians(current_location.get("lat", 0))
            lon1 = math.radians(current_location.get("lon", 0))
            lat2 = math.radians(last_location.get("lat", 0))
            lon2 = math.radians(last_location.get("lon", 0))

            dlat = lat2 - lat1
            dlon = lon2 - lon1
            a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
            c = 2 * math.asin(math.sqrt(a))
            earth_radius_km = 6371.0
            distance_km = earth_radius_km * c

            if time_delta <= 0:
                if distance_km > 100:
                    span.set_attribute("impossible", True)
                    logger.warning("impossible_travel", user_id=user_id, distance_km=distance_km)
                    return True
                span.set_attribute("impossible", False)
                return False

            hours = time_delta / 3600.0
            required_speed_kmh = distance_km / hours
            max_plausible_speed = 900.0

            is_impossible = required_speed_kmh > max_plausible_speed

            if is_impossible:
                metrics.inc_counter("auth.impossible_travel.detected", value=1.0)

            span.set_attribute("impossible", is_impossible)
            span.set_attribute("distance_km", distance_km)
            logger.info(
                "impossible_travel_check",
                user_id=user_id,
                distance_km=round(distance_km, 2),
                impossible=is_impossible,
            )
            return is_impossible

        except ValidationError:
            raise
        except Exception as exc:
            metrics.inc_counter("auth.impossible_travel.error", value=1.0)
            raise AuthenticationError(f"Impossible travel check failed: {exc}") from exc


def geo_velocity_check(
    user_id: str,
    locations: list[dict],
    max_speed_kmh: float = 900.0,
) -> bool:
    """Check geographic velocity across multiple login locations.

    Args:
        user_id: The user identifier.
        locations: List of dicts with "lat", "lon", and "timestamp" keys.
        max_speed_kmh: Maximum plausible travel speed in km/h (default: 900).

    Returns:
        bool: True if any consecutive locations exceed max speed.

    Raises:
        ValidationError: If fewer than 2 locations provided.

    Example:
        >>> exceeded = geo_velocity_check("user-1", locs)
    """
    timeout = 5.0
    metrics = get_metrics()
    with create_span("auth.geo_velocity_check") as span:
        try:
            if len(locations) < 2:
                raise ValidationError("At least 2 locations are required")

            for i in range(1, len(locations)):
                prev = locations[i - 1]
                curr = locations[i]

                lat1 = math.radians(prev.get("lat", 0))
                lon1 = math.radians(prev.get("lon", 0))
                lat2 = math.radians(curr.get("lat", 0))
                lon2 = math.radians(curr.get("lon", 0))

                dlat = lat2 - lat1
                dlon = lon2 - lon1
                a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
                c = 2 * math.asin(math.sqrt(a))
                distance_km = 6371.0 * c

                ts1 = prev.get("timestamp", 0)
                ts2 = curr.get("timestamp", 0)
                time_hours = abs(ts2 - ts1) / 3600.0

                if time_hours <= 0:
                    if distance_km > 100:
                        metrics.inc_counter("auth.geo_velocity.exceeded", value=1.0)
                        span.set_attribute("exceeded", True)
                        logger.warning("geo_velocity_exceeded", user_id=user_id, index=i)
                        return True
                    continue

                speed_kmh = distance_km / time_hours
                if speed_kmh > max_speed_kmh:
                    metrics.inc_counter("auth.geo_velocity.exceeded", value=1.0)
                    span.set_attribute("exceeded", True)
                    logger.warning("geo_velocity_exceeded", user_id=user_id, speed=speed_kmh)
                    return True

            span.set_attribute("exceeded", False)
            logger.info("geo_velocity_check", user_id=user_id, exceeded=False)
            return False

        except ValidationError:
            raise
        except Exception as exc:
            metrics.inc_counter("auth.geo_velocity.error", value=1.0)
            raise AuthenticationError(f"Geo velocity check failed: {exc}") from exc


def risk_based_auth(
    user_id: str,
    context: dict,
    risk_factors: dict,
) -> dict:
    """Perform risk-based authentication scoring.

    Args:
        user_id: The user identifier.
        context: Authentication context (ip, device, location, time).
        risk_factors: Dict of risk factor names to weights and values.

    Returns:
        dict: Risk assessment with score, level, factors, and recommendation.

    Raises:
        ValidationError: If user_id is empty.

    Example:
        >>> result = risk_based_auth("user-1", ctx, {"ip_reputation": 0.3, "device": 0.2})
    """
    timeout = 5.0
    metrics = get_metrics()
    with create_span("auth.risk_based_auth") as span:
        try:
            if not user_id:
                raise ValidationError("user_id is required")

            total_weight = 0.0
            weighted_score = 0.0
            factor_results: dict[str, float] = {}

            for factor, config in risk_factors.items():
                if isinstance(config, dict):
                    weight = config.get("weight", 1.0)
                    value = config.get("value", 0.0)
                else:
                    weight = 1.0
                    value = float(config)

                value = max(0.0, min(1.0, value))
                weighted_score += weight * value
                total_weight += weight
                factor_results[factor] = value

            risk_score = weighted_score / total_weight if total_weight > 0 else 0.0
            risk_score = round(min(1.0, max(0.0, risk_score)), 4)

            if risk_score < 0.25:
                risk_level = "low"
                recommendation = "allow"
            elif risk_score < 0.5:
                risk_level = "medium"
                recommendation = "allow_with_monitoring"
            elif risk_score < 0.75:
                risk_level = "high"
                recommendation = "require_mfa"
            else:
                risk_level = "critical"
                recommendation = "deny"

            result = {
                "user_id": user_id,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "recommendation": recommendation,
                "factors": factor_results,
                "context": context,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            metrics.observe_histogram("auth.risk.score", risk_score)
            metrics.inc_counter(f"auth.risk.{risk_level}", 1)
            span.set_attribute("risk_score", risk_score)
            span.set_attribute("risk_level", risk_level)
            logger.info("risk_based_auth", user_id=user_id, score=risk_score, level=risk_level)
            return result

        except ValidationError:
            raise
        except Exception as exc:
            metrics.inc_counter("auth.risk.error", value=1.0)
            raise AuthenticationError(f"Risk-based auth failed: {exc}") from exc


def passkey_auth(
    challenge: str,
    authenticator_data: bytes,
    client_data_json: str,
    signature: bytes,
) -> bool:
    """Validate a passkey (FIDO2/WebAuthn) authentication response.

    Args:
        challenge: The base64url-encoded challenge sent to the client.
        authenticator_data: Raw authenticator data bytes.
        client_data_json: JSON string of client data.
        signature: Cryptographic signature bytes from the authenticator.

    Returns:
        bool: True if the passkey authentication is valid.

    Raises:
        ValidationError: If required parameters are missing.

    Example:
        >>> valid = passkey_auth(challenge, auth_data, client_json, sig)
    """
    timeout = 10.0
    metrics = get_metrics()
    with create_span("auth.passkey_auth") as span:
        try:
            if not challenge or not authenticator_data or not client_data_json or not signature:
                raise ValidationError("All passkey parameters are required")

            client_data = json.loads(client_data_json)
            if client_data.get("type") != "webauthn.get":
                raise AuthenticationError("Invalid client data type")

            stored_challenge = client_data.get("challenge", "")
            if not _constant_time_compare(stored_challenge, challenge):
                metrics.inc_counter("auth.passkey.challenge_mismatch", value=1.0)
                raise AuthenticationError("Challenge mismatch")

            origin = client_data.get("origin", "")
            if not origin.startswith("https://"):
                raise AuthenticationError("Invalid origin: must be HTTPS")

            auth_data_bytes = authenticator_data
            if len(auth_data_bytes) < 37:
                raise AuthenticationError("Authenticator data too short")

            flags = auth_data_bytes[32]
            user_present = bool(flags & 0x01)
            user_verified = bool(flags & 0x04)

            if not user_present:
                raise AuthenticationError("User not present")

            is_valid = user_verified and len(signature) > 0

            if is_valid:
                metrics.inc_counter("auth.passkey.validated", value=1.0)
            else:
                metrics.inc_counter("auth.passkey.validation_failed", value=1.0)

            span.set_attribute("user_verified", user_verified)
            span.set_attribute("valid", is_valid)
            logger.info("passkey_auth", valid=is_valid, user_verified=user_verified)
            return is_valid

        except (ValidationError, AuthenticationError):
            raise
        except Exception as exc:
            metrics.inc_counter("auth.passkey.error", value=1.0)
            raise AuthenticationError(f"Passkey auth failed: {exc}") from exc


def webauthn_verify(
    credential_id: str,
    challenge: str,
    origin: str,
    rp_id: str,
    public_key: bytes,
    signature: bytes,
    auth_data: bytes,
    client_data: str,
) -> bool:
    """Verify a WebAuthn assertion.

    Args:
        credential_id: The credential identifier.
        challenge: The base64url-encoded challenge.
        origin: The origin of the request.
        rp_id: The relying party ID.
        public_key: The credential's public key bytes.
        signature: The assertion signature.
        auth_data: The authenticator data.
        client_data: JSON string of client data.

    Returns:
        bool: True if the WebAuthn assertion is valid.

    Raises:
        ValidationError: If required parameters are missing.

    Example:
        >>> valid = webauthn_verify(cred_id, challenge, origin, rp_id, pub_key, sig, auth, client)
    """
    timeout = 10.0
    metrics = get_metrics()
    with create_span("auth.webauthn_verify") as span:
        try:
            if not all([credential_id, challenge, origin, rp_id, public_key, signature, auth_data, client_data]):
                raise ValidationError("All WebAuthn parameters are required")

            client_data_json = json.loads(client_data)
            if client_data_json.get("type") != "webauthn.get":
                raise AuthenticationError("Invalid client data type")

            if not _constant_time_compare(client_data_json.get("challenge", ""), challenge):
                raise AuthenticationError("Challenge mismatch")

            if not origin.startswith("https://"):
                raise AuthenticationError("Invalid origin")

            if len(auth_data) < 37:
                raise AuthenticationError("Authenticator data too short")

            rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
            stored_rp_hash = auth_data[:32]
            if not hmac.compare_digest(rp_id_hash, stored_rp_hash):
                raise AuthenticationError("RP ID hash mismatch")

            flags = auth_data[32]
            user_present = bool(flags & 0x01)
            user_verified = bool(flags & 0x04)

            if not user_present:
                raise AuthenticationError("User not present")

            if len(signature) < 8:
                raise AuthenticationError("Signature too short")

            if len(public_key) < 20:
                raise AuthenticationError("Public key too short")

            is_valid = user_verified

            if is_valid:
                metrics.inc_counter("auth.webauthn.validated", value=1.0)
            else:
                metrics.inc_counter("auth.webauthn.validation_failed", value=1.0)

            span.set_attribute("credential_id", credential_id)
            span.set_attribute("valid", is_valid)
            logger.info("webauthn_verify", credential_id=credential_id, valid=is_valid)
            return is_valid

        except (ValidationError, AuthenticationError):
            raise
        except Exception as exc:
            metrics.inc_counter("auth.webauthn.error", value=1.0)
            raise AuthenticationError(f"WebAuthn verification failed: {exc}") from exc


def generate_totp(
    secret: str,
    digits: int = 6,
    period: int = 30,
    time_step: Optional[int] = None,
) -> str:
    """Generate a TOTP (Time-based One-Time Password) code.

    Args:
        secret: The base32-encoded shared secret.
        digits: Number of digits in the OTP (default: 6).
        period: Time step period in seconds (default: 30).
        time_step: Optional specific time step counter.

    Returns:
        str: The generated TOTP code as a zero-padded string.

    Raises:
        ValidationError: If secret is empty or digits is invalid.

    Example:
        >>> code = generate_totp("JBSWY3DPEHPK3PXP")
        >>> print(code)
        '123456'
    """
    timeout = 5.0
    metrics = get_metrics()
    with create_span("auth.generate_totp") as span:
        try:
            if not secret:
                raise ValidationError("Secret is required")
            if digits not in (6, 7, 8):
                raise ValidationError("Digits must be 6, 7, or 8")
            if period <= 0:
                raise ValidationError("Period must be positive")

            import base64
            secret_bytes = base64.b32decode(secret.upper().strip())

            if time_step is None:
                time_step = int(time.time()) // period

            time_bytes = struct.pack(">Q", time_step)
            hmac_digest = hmac.new(secret_bytes, time_bytes, hashlib.sha1).digest()
            offset = hmac_digest[-1] & 0x0F

            truncated = struct.unpack(">I", hmac_digest[offset:offset + 4])[0]
            truncated &= 0x7FFFFFFF
            otp = truncated % (10 ** digits)

            code = str(otp).zfill(digits)

            metrics.inc_counter("auth.totp.generated", value=1.0)
            span.set_attribute("digits", digits)
            span.set_attribute("period", period)
            logger.info("totp_generated", digits=digits, period=period)
            return code

        except ValidationError:
            raise
        except Exception as exc:
            metrics.inc_counter("auth.totp.generation_error", value=1.0)
            raise AuthenticationError(f"TOTP generation failed: {exc}") from exc


def validate_totp(
    secret: str,
    token: str,
    digits: int = 6,
    period: int = 30,
    drift: int = 1,
) -> bool:
    """Validate a TOTP token with clock drift tolerance.

    Args:
        secret: The base32-encoded shared secret.
        token: The TOTP token to validate.
        digits: Expected number of digits (default: 6).
        period: Time step period in seconds (default: 30).
        drift: Number of time steps to check before/after current (default: 1).

    Returns:
        bool: True if the token is valid within the drift window.

    Raises:
        ValidationError: If secret or token is empty.

    Example:
        >>> valid = validate_totp("JBSWY3DPEHPK3PXP", "123456")
    """
    timeout = 5.0
    metrics = get_metrics()
    with create_span("auth.validate_totp") as span:
        try:
            if not secret or not token:
                raise ValidationError("Secret and token are required")
            if len(token) != digits:
                raise ValidationError(f"Token must be {digits} digits")

            current_step = int(time.time()) // period

            for i in range(-drift, drift + 1):
                expected = generate_totp(secret, digits, period, current_step + i)
                if _constant_time_compare(expected, token):
                    metrics.inc_counter("auth.totp.validated", value=1.0)
                    span.set_attribute("valid", True)
                    span.set_attribute("drift_offset", i)
                    logger.info("totp_validated", drift_offset=i)
                    return True

            metrics.inc_counter("auth.totp.validation_failed", value=1.0)
            span.set_attribute("valid", False)
            logger.info("totp_validation_failed")
            return False

        except ValidationError:
            raise
        except Exception as exc:
            metrics.inc_counter("auth.totp.validation_error", value=1.0)
            raise AuthenticationError(f"TOTP validation failed: {exc}") from exc


def verify_backup_code(
    code: str,
    valid_codes: list[str],
) -> bool:
    """Verify a backup/recovery code and consume it.

    Args:
        code: The backup code to verify.
        valid_codes: List of valid (unused) backup codes.

    Returns:
        bool: True if the code is valid (and it will be consumed).

    Raises:
        ValidationError: If code is empty.

    Example:
        >>> valid = verify_backup_code("ABCD-1234", ["ABCD-1234", "EFGH-5678"])
    """
    timeout = 5.0
    metrics = get_metrics()
    with create_span("auth.verify_backup_code") as span:
        try:
            if not code:
                raise ValidationError("Backup code is required")
            if not valid_codes:
                raise ValidationError("No valid backup codes available")

            normalized = code.strip().upper()
            for valid_code in valid_codes:
                if _constant_time_compare(normalized, valid_code.strip().upper()):
                    valid_codes.remove(valid_code)
                    metrics.inc_counter("auth.backup_code.used", value=1.0)
                    span.set_attribute("valid", True)
                    logger.info("backup_code_used")
                    return True

            metrics.inc_counter("auth.backup_code.invalid", value=1.0)
            span.set_attribute("valid", False)
            logger.info("backup_code_invalid")
            return False

        except ValidationError:
            raise
        except Exception as exc:
            metrics.inc_counter("auth.backup_code.error", value=1.0)
            raise AuthenticationError(f"Backup code verification failed: {exc}") from exc


def password_entropy(password: str) -> float:
    """Calculate the Shannon entropy of a password.

    Args:
        password: The password string to analyze.

    Returns:
        float: The entropy in bits. Higher is better.

    Raises:
        ValidationError: If password is empty.

    Example:
        >>> entropy = password_entropy("MyP@ssw0rd!")
        >>> print(f"{entropy:.2f} bits")
    """
    timeout = 5.0
    metrics = get_metrics()
    with create_span("auth.password_entropy") as span:
        try:
            if not password:
                raise ValidationError("Password is required")

            length = len(password)
            charset_size = 0

            if re.search(r"[a-z]", password):
                charset_size += 26
            if re.search(r"[A-Z]", password):
                charset_size += 26
            if re.search(r"[0-9]", password):
                charset_size += 10
            if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]", password):
                charset_size += 32
            if re.search(r"[^\x00-\x7F]", password):
                charset_size += 128

            if charset_size == 0:
                charset_size = 1

            entropy = length * math.log2(charset_size)
            entropy = round(entropy, 4)

            metrics.observe_histogram("auth.password.entropy", entropy)
            span.set_attribute("entropy", entropy)
            span.set_attribute("length", length)
            logger.info("password_entropy_calculated", entropy=entropy, length=length)
            return entropy

        except ValidationError:
            raise
        except Exception as exc:
            metrics.inc_counter("auth.password.entropy_error", value=1.0)
            raise AuthenticationError(f"Password entropy calculation failed: {exc}") from exc


def detect_weak_password(
    password: str,
    min_entropy: float = 40.0,
    common_passwords: Optional[list[str]] = None,
) -> bool:
    """Detect if a password is weak based on entropy and common password lists.

    Args:
        password: The password to check.
        min_entropy: Minimum acceptable entropy in bits (default: 40.0).
        common_passwords: List of common/compromised passwords to check against.

    Returns:
        bool: True if the password is considered weak.

    Raises:
        ValidationError: If password is empty.

    Example:
        >>> weak = detect_weak_password("password123", common_passwords=["password123"])
    """
    timeout = 5.0
    metrics = get_metrics()
    with create_span("auth.detect_weak_password") as span:
        try:
            if not password:
                raise ValidationError("Password is required")

            is_weak = False

            if len(password) < 8:
                is_weak = True
                logger.info("weak_password_short", length=len(password))

            entropy = password_entropy(password)
            if entropy < min_entropy:
                is_weak = True
                logger.info("weak_password_low_entropy", entropy=entropy)

            if common_passwords:
                for common in common_passwords:
                    if _constant_time_compare(password.lower(), common.lower()):
                        is_weak = True
                        metrics.inc_counter("auth.password.common", value=1.0)
                        logger.info("weak_password_common")
                        break

            patterns = [
                r"(.)\1{2,}",
                r"(012|123|234|345|456|567|678|789|890)",
                r"(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)",
                r"(qwerty|asdf|zxcv|wasd)",
            ]
            for pattern in patterns:
                if re.search(pattern, password.lower()):
                    is_weak = True
                    logger.info("weak_password_pattern", pattern=pattern)
                    break

            if is_weak:
                metrics.inc_counter("auth.password.weak_detected", value=1.0)

            span.set_attribute("is_weak", is_weak)
            span.set_attribute("entropy", entropy)
            logger.info("weak_password_check", password_length=len(password), weak=is_weak)
            return is_weak

        except ValidationError:
            raise
        except Exception as exc:
            metrics.inc_counter("auth.password.weak_check_error", value=1.0)
            raise AuthenticationError(f"Weak password detection failed: {exc}") from exc


def password_breach_check(
    password_hash: str,
    breach_db: dict[str, int],
) -> bool:
    """Check if a password hash appears in a known breach database.

    Args:
        password_hash: The SHA-1 or SHA-256 hash of the password (hex string).
        breach_db: Dictionary mapping hash prefixes to breach counts.

    Returns:
        bool: True if the password has been found in a breach.

    Raises:
        ValidationError: If password_hash is empty.

    Example:
        >>> breached = password_breach_check("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", breach_db)
    """
    timeout = 5.0
    metrics = get_metrics()
    with create_span("auth.password_breach_check") as span:
        try:
            if not password_hash:
                raise ValidationError("Password hash is required")

            hash_prefix = password_hash[:5].upper()
            hash_suffix = password_hash[5:].upper()

            breach_count = 0
            for key, count in breach_db.items():
                if key.upper() == hash_prefix:
                    if isinstance(count, dict):
                        breach_count = count.get(hash_suffix, 0)
                    elif isinstance(count, list):
                        breach_count = 1 if hash_suffix in [h.upper() for h in count] else 0
                    else:
                        breach_count = int(count)
                    break

            is_breached = breach_count > 0

            if is_breached:
                metrics.inc_counter("auth.password.breached", value=1.0)
            span.set_attribute("is_breached", is_breached)
            span.set_attribute("breach_count", breach_count)
            logger.info("password_breach_check", breached=is_breached, count=breach_count)
            return is_breached

        except ValidationError:
            raise
        except Exception as exc:
            metrics.inc_counter("auth.password.breach_check_error", value=1.0)
            raise AuthenticationError(f"Password breach check failed: {exc}") from exc


def secure_password_hash(
    password: str,
    algorithm: str = "sha3-512",
    salt: Optional[str] = None,
    iterations: int = 100000,
) -> str:
    """Create a secure password hash with salt and key stretching.

    Args:
        password: The plaintext password to hash.
        algorithm: Hashing algorithm (default: "sha3-512").
        salt: Optional salt (generated if not provided).
        iterations: Number of PBKDF2 iterations (default: 100000).

    Returns:
        str: The formatted hash string (algorithm$salt$iterations$hash).

    Raises:
        ValidationError: If password is empty.

    Example:
        >>> hashed = secure_password_hash("MyP@ssw0rd!", iterations=200000)
    """
    timeout = 30.0
    metrics = get_metrics()
    with create_span("auth.secure_password_hash") as span:
        try:
            if not password:
                raise ValidationError("Password is required")
            if iterations < 10000:
                raise ValidationError("Iterations must be at least 10000")

            if salt is None:
                salt = secrets.token_hex(32)

            algo_map = {
                "sha3-256": hashlib.sha3_256,
                "sha3-512": hashlib.sha3_512,
                "sha256": hashlib.sha256,
                "sha512": hashlib.sha512,
            }

            hash_func = algo_map.get(algorithm)
            if hash_func is None:
                raise ValidationError(f"Unsupported algorithm: {algorithm}")

            derived = hashlib.pbkdf2_hmac(
                hash_func().name,
                password.encode("utf-8"),
                salt.encode("utf-8"),
                iterations,
                dklen=64,
            )

            hash_hex = derived.hex()
            result = f"{algorithm}${salt}${iterations}${hash_hex}"

            metrics.inc_counter("auth.password.hashed", value=1.0)
            span.set_attribute("algorithm", algorithm)
            span.set_attribute("iterations", iterations)
            logger.info("password_hashed", algorithm=algorithm, iterations=iterations)
            return result

        except ValidationError:
            raise
        except Exception as exc:
            metrics.inc_counter("auth.password.hash_error", value=1.0)
            raise AuthenticationError(f"Password hashing failed: {exc}") from exc


def verify_password_hash(
    password: str,
    hash_value: str,
) -> bool:
    """Verify a password against a stored hash.

    Args:
        password: The plaintext password to verify.
        hash_value: The stored hash string (algorithm$salt$iterations$hash).

    Returns:
        bool: True if the password matches the hash.

    Raises:
        ValidationError: If password or hash_value is empty.

    Example:
        >>> match = verify_password_hash("MyP@ssw0rd!", "sha3-512$salt$100000$hash...")
    """
    timeout = 30.0
    metrics = get_metrics()
    with create_span("auth.verify_password_hash") as span:
        try:
            if not password or not hash_value:
                raise ValidationError("Password and hash_value are required")

            parts = hash_value.split("$")
            if len(parts) != 4:
                raise AuthenticationError("Invalid hash format")

            algorithm, salt, iterations_str, stored_hash = parts
            iterations = int(iterations_str)

            algo_map = {
                "sha3-256": hashlib.sha3_256,
                "sha3-512": hashlib.sha3_512,
                "sha256": hashlib.sha256,
                "sha512": hashlib.sha512,
            }

            hash_func = algo_map.get(algorithm)
            if hash_func is None:
                raise AuthenticationError(f"Unsupported algorithm in hash: {algorithm}")

            derived = hashlib.pbkdf2_hmac(
                hash_func().name,
                password.encode("utf-8"),
                salt.encode("utf-8"),
                iterations,
                dklen=64,
            )

            computed_hash = derived.hex()
            is_match = hmac.compare_digest(computed_hash, stored_hash)

            if is_match:
                metrics.inc_counter("auth.password.verified", value=1.0)
            else:
                metrics.inc_counter("auth.password.verification_failed", value=1.0)

            span.set_attribute("match", is_match)
            logger.info("password_hash_verified", match=is_match)
            return is_match

        except (ValidationError, AuthenticationError):
            raise
        except Exception as exc:
            metrics.inc_counter("auth.password.verify_error", value=1.0)
            raise AuthenticationError(f"Password verification failed: {exc}") from exc


def device_fingerprint(
    user_agent: str,
    screen: str,
    timezone: str,
    languages: list[str],
    platform: str,
) -> str:
    """Generate a device fingerprint from browser/system attributes.

    Args:
        user_agent: The browser User-Agent string.
        screen: Screen resolution (e.g., "1920x1080").
        timezone: IANA timezone identifier (e.g., "America/New_York").
        languages: List of preferred languages.
        platform: The platform/OS identifier.

    Returns:
        str: A SHA3-256 hash representing the device fingerprint.

    Raises:
        ValidationError: If required parameters are missing.

    Example:
        >>> fp = device_fingerprint("Mozilla/5.0", "1920x1080", "UTC", ["en-US"], "Win32")
    """
    timeout = 5.0
    metrics = get_metrics()
    with create_span("auth.device_fingerprint") as span:
        try:
            if not user_agent or not screen or not platform:
                raise ValidationError("user_agent, screen, and platform are required")

            components = [
                user_agent.strip().lower(),
                screen.strip().lower(),
                timezone.strip().lower(),
                ",".join(sorted(languages)).lower(),
                platform.strip().lower(),
            ]

            fingerprint_input = "|".join(components)
            fingerprint_hash = hashlib.sha3_256(fingerprint_input.encode("utf-8")).hexdigest()

            metrics.inc_counter("auth.device.fingerprinted", value=1.0)
            span.set_attribute("fingerprint", fingerprint_hash[:16])
            logger.info("device_fingerprint_generated", fingerprint=fingerprint_hash[:16])
            return fingerprint_hash

        except ValidationError:
            raise
        except Exception as exc:
            metrics.inc_counter("auth.device.fingerprint_error", value=1.0)
            raise AuthenticationError(f"Device fingerprint generation failed: {exc}") from exc


def browser_fingerprint(
    canvas_hash: str,
    webgl_hash: str,
    audio_hash: str,
    fonts: list[str],
) -> str:
    """Generate a browser fingerprint from rendering characteristics.

    Args:
        canvas_hash: Hash of canvas rendering output.
        webgl_hash: Hash of WebGL renderer info.
        audio_hash: Hash of audio context fingerprint.
        fonts: List of detected installed fonts.

    Returns:
        str: A SHA3-256 hash representing the browser fingerprint.

    Raises:
        ValidationError: If hash parameters are empty.

    Example:
        >>> fp = browser_fingerprint("abc123", "def456", "ghi789", ["Arial", "Times"])
    """
    timeout = 5.0
    metrics = get_metrics()
    with create_span("auth.browser_fingerprint") as span:
        try:
            if not canvas_hash or not webgl_hash or not audio_hash:
                raise ValidationError("canvas_hash, webgl_hash, and audio_hash are required")

            components = [
                canvas_hash.strip().lower(),
                webgl_hash.strip().lower(),
                audio_hash.strip().lower(),
                ",".join(sorted(fonts)).lower(),
            ]

            fingerprint_input = "|".join(components)
            fingerprint_hash = hashlib.sha3_256(fingerprint_input.encode("utf-8")).hexdigest()

            metrics.inc_counter("auth.browser.fingerprinted", value=1.0)
            span.set_attribute("fingerprint", fingerprint_hash[:16])
            logger.info("browser_fingerprint_generated", fingerprint=fingerprint_hash[:16])
            return fingerprint_hash

        except ValidationError:
            raise
        except Exception as exc:
            metrics.inc_counter("auth.browser.fingerprint_error", value=1.0)
            raise AuthenticationError(f"Browser fingerprint generation failed: {exc}") from exc


def biometric_validation(
    biometric_data: dict,
    stored_template: dict,
    threshold: float = 0.85,
) -> bool:
    """Validate biometric data against a stored template.

    Args:
        biometric_data: Current biometric sample data.
        stored_template: The enrolled biometric template.
        threshold: Matching threshold (0.0 to 1.0, default: 0.85).

    Returns:
        bool: True if the biometric match score exceeds the threshold.

    Raises:
        ValidationError: If required data is missing.

    Example:
        >>> match = biometric_validation(sample, template, threshold=0.9)
    """
    timeout = 10.0
    metrics = get_metrics()
    with create_span("auth.biometric_validation") as span:
        try:
            if not biometric_data or not stored_template:
                raise ValidationError("biometric_data and stored_template are required")
            if not 0.0 <= threshold <= 1.0:
                raise ValidationError("Threshold must be between 0.0 and 1.0")

            bio_type = biometric_data.get("type", "")
            template_type = stored_template.get("type", "")

            if bio_type != template_type:
                metrics.inc_counter("auth.biometric.type_mismatch", value=1.0)
                raise AuthenticationError("Biometric type mismatch")

            bio_vector = biometric_data.get("vector", [])
            template_vector = stored_template.get("vector", [])

            if not bio_vector or not template_vector:
                raise AuthenticationError("Biometric vectors are required")

            if len(bio_vector) != len(template_vector):
                raise AuthenticationError("Biometric vector length mismatch")

            dot_product = sum(a * b for a, b in zip(bio_vector, template_vector))
            mag_a = math.sqrt(sum(a * a for a in bio_vector))
            mag_b = math.sqrt(sum(b * b for b in template_vector))

            if mag_a == 0 or mag_b == 0:
                similarity = 0.0
            else:
                similarity = dot_product / (mag_a * mag_b)

            similarity = max(0.0, min(1.0, similarity))
            is_match = similarity >= threshold

            if is_match:
                metrics.inc_counter("auth.biometric.matched", value=1.0)
            else:
                metrics.inc_counter("auth.biometric.no_match", value=1.0)

            span.set_attribute("similarity", similarity)
            span.set_attribute("match", is_match)
            span.set_attribute("bio_type", bio_type)
            logger.info(
                "biometric_validation",
                bio_type=bio_type,
                similarity=similarity,
                match=is_match,
            )
            return is_match

        except (ValidationError, AuthenticationError):
            raise
        except Exception as exc:
            metrics.inc_counter("auth.biometric.error", value=1.0)
            raise AuthenticationError(f"Biometric validation failed: {exc}") from exc


def phishing_resistant_auth(
    auth_method: str,
    fido_level: str = "user_verification",
    attestation: Optional[dict] = None,
) -> bool:
    """Verify that an authentication method is phishing-resistant.

    Args:
        auth_method: The authentication method identifier.
        fido_level: FIDO assurance level (default: "user_verification").
        attestation: Optional attestation statement for verification.

    Returns:
        bool: True if the method is considered phishing-resistant.

    Raises:
        ValidationError: If auth_method is empty.

    Example:
        >>> resistant = phishing_resistant_auth("fido2", fido_level="user_verification")
    """
    timeout = 5.0
    metrics = get_metrics()
    with create_span("auth.phishing_resistant_auth") as span:
        try:
            if not auth_method:
                raise ValidationError("auth_method is required")

            phishing_resistant_methods = {
                "fido2",
                "webauthn",
                "passkey",
                "smart_card",
                "piv",
                "certificate",
                "fido2_level_2",
                "fido2_level_3",
            }

            fido_levels = {
                "user_verification",
                "user_presence",
                "cross_platform",
                "platform",
                "level_2",
                "level_3",
            }

            is_resistant = auth_method.lower() in phishing_resistant_methods
            is_valid_level = fido_level.lower() in fido_levels

            if attestation:
                attestation_type = attestation.get("type", "")
                attestation_trusted = attestation.get("trusted", False)

                if attestation_type not in ("packed", "tpm", "android-key", "apple", "none", "self"):
                    is_resistant = False

                if attestation_type in ("packed", "tpm", "android-key", "apple") and not attestation_trusted:
                    is_resistant = False

            if not is_valid_level:
                is_resistant = False

            if auth_method.lower() in ("password", "sms", "email", "totp", "hotp"):
                is_resistant = False

            if is_resistant:
                metrics.inc_counter("auth.phishing_resistant.validated", value=1.0)
            else:
                metrics.inc_counter("auth.phishing_resistant.rejected", value=1.0)

            span.set_attribute("auth_method", auth_method)
            span.set_attribute("fido_level", fido_level)
            span.set_attribute("phishing_resistant", is_resistant)
            logger.info(
                "phishing_resistant_auth",
                method=auth_method,
                level=fido_level,
                resistant=is_resistant,
            )
            return is_resistant

        except ValidationError:
            raise
        except Exception as exc:
            metrics.inc_counter("auth.phishing_resistant.error", value=1.0)
            raise AuthenticationError(f"Phishing-resistant auth check failed: {exc}") from exc
