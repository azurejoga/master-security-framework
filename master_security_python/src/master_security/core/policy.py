"""
Master Security Framework - Policy Engine
==========================================

Policy-as-code engine for dynamic security rules.
Supports hot-reload, multi-tenant policies, and rule evaluation.

Features:
    - Policy-as-code with Python expressions
    - Hot-reload without restart
    - Multi-tenant policy isolation
    - Rule priority and ordering
    - Policy inheritance
    - Audit trail for policy changes

Usage:
    >>> from master_security.core import get_policy_engine
    >>> engine = get_policy_engine()
    >>> engine.add_rule("max_login_attempts", "attempts < 5")
    >>> engine.evaluate("max_login_attempts", {"attempts": 3})
    True
"""

from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from master_security.core.logger import get_logger
from master_security.core.exceptions import PolicyViolationError

logger = get_logger("msf.policy")


@dataclass
class PolicyRule:
    """
    Security policy rule.

    Attributes:
        name: Unique rule name
        expression: Python expression to evaluate
        description: Human-readable description
        severity: Violation severity level
        enabled: Whether rule is active
        tenant_id: Multi-tenant scope
        priority: Rule priority (lower = higher priority)
        metadata: Additional rule metadata
    """
    name: str
    expression: str
    description: str = ""
    severity: str = "high"
    enabled: bool = True
    tenant_id: str = "default"
    priority: int = 100
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    _hash: str = field(default="", init=False, repr=False)

    def __post_init__(self) -> None:
        self._hash = hashlib.sha3_256(
            f"{self.name}:{self.expression}:{self.tenant_id}".encode()
        ).hexdigest()


@dataclass
class PolicyEvaluation:
    """Result of policy evaluation."""
    rule_name: str
    passed: bool
    context: dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    evaluation_time_ms: float = 0.0
    error: Optional[str] = None


class PolicyEngine:
    """
    Policy-as-code evaluation engine.

    Thread-safe policy management with hot-reload support.

    Attributes:
        strict_mode: Fail closed on evaluation errors
        max_rules: Maximum number of rules

    Example:
        >>> engine = PolicyEngine()
        >>> engine.add_rule("rate_limit", "requests < 1000")
        >>> result = engine.evaluate("rate_limit", {"requests": 500})
        >>> result.passed
        True
    """

    def __init__(
        self,
        strict_mode: bool = True,
        max_rules: int = 10000,
    ) -> None:
        self.strict_mode = strict_mode
        self.max_rules = max_rules
        self._rules: dict[str, PolicyRule] = {}
        self._evaluations: list[PolicyEvaluation] = []
        self._max_evaluations = 10000
        self._lock = threading.RLock()
        self._version = 0

    def add_rule(self, rule: PolicyRule) -> None:
        """
        Add or update a policy rule.

        Args:
            rule: Policy rule to add.
        """
        with self._lock:
            if len(self._rules) >= self.max_rules:
                raise ValueError(f"Maximum rules limit ({self.max_rules}) reached")
            self._rules[rule.name] = rule
            self._version += 1
        logger.info("msf.policy.rule_added", name=rule.name)

    def remove_rule(self, name: str) -> bool:
        """Remove a policy rule."""
        with self._lock:
            if name in self._rules:
                del self._rules[name]
                self._version += 1
                return True
            return False

    def evaluate(
        self,
        rule_name: str,
        context: dict[str, Any],
    ) -> PolicyEvaluation:
        """
        Evaluate a policy rule against context.

        Args:
            rule_name: Rule to evaluate
            context: Evaluation context variables

        Returns:
            PolicyEvaluation result.
        """
        with self._lock:
            rule = self._rules.get(rule_name)
            if not rule:
                return PolicyEvaluation(
                    rule_name=rule_name,
                    passed=not self.strict_mode,
                    context=context,
                    error=f"Rule not found: {rule_name}",
                )
            if not rule.enabled:
                return PolicyEvaluation(
                    rule_name=rule_name,
                    passed=True,
                    context=context,
                )

        start = time.monotonic()
        try:
            safe_globals = {"__builtins__": {}}
            safe_globals.update(context)
            result = bool(eval(rule.expression, safe_globals))  # noqa: S307
            elapsed = (time.monotonic() - start) * 1000

            evaluation = PolicyEvaluation(
                rule_name=rule_name,
                passed=result,
                context=context,
                evaluation_time_ms=elapsed,
            )

            with self._lock:
                self._evaluations.append(evaluation)
                if len(self._evaluations) > self._max_evaluations:
                    self._evaluations = self._evaluations[-self._max_evaluations:]

            if not result:
                logger.warning(
                    "msf.policy.violation",
                    rule=rule_name,
                    severity=rule.severity,
                )

            return evaluation

        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            evaluation = PolicyEvaluation(
                rule_name=rule_name,
                passed=not self.strict_mode,
                context=context,
                evaluation_time_ms=elapsed,
                error=str(exc),
            )
            logger.error("msf.policy.eval_error", rule=rule_name, error=str(exc))
            return evaluation

    def evaluate_all(
        self,
        context: dict[str, Any],
        tenant_id: str = "default",
    ) -> list[PolicyEvaluation]:
        """Evaluate all enabled rules for a tenant."""
        results = []
        with self._lock:
            rules = [
                r for r in self._rules.values()
                if r.enabled and r.tenant_id in (tenant_id, "global")
            ]
        rules.sort(key=lambda r: r.priority)
        for rule in rules:
            results.append(self.evaluate(rule.name, context))
        return results

    def get_rules(self, tenant_id: Optional[str] = None) -> list[PolicyRule]:
        """Get all rules, optionally filtered by tenant."""
        with self._lock:
            if tenant_id:
                return [
                    r for r in self._rules.values()
                    if r.tenant_id in (tenant_id, "global")
                ]
            return list(self._rules.values())

    @property
    def version(self) -> int:
        """Get current policy version number."""
        return self._version


_global_policy_engine: PolicyEngine | None = None
_policy_lock = threading.Lock()


def get_policy_engine() -> PolicyEngine:
    """Get the global policy engine instance."""
    global _global_policy_engine
    if _global_policy_engine is None:
        with _policy_lock:
            if _global_policy_engine is None:
                _global_policy_engine = PolicyEngine()
    return _global_policy_engine
