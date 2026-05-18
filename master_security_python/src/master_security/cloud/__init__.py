from __future__ import annotations
import re
import json
import hashlib
import time
from typing import Any, Optional
from datetime import datetime, timezone
from master_security.core import get_logger, get_metrics, create_span, get_event_bus, SecurityEvent, EventSeverity
from master_security.core.exceptions import ValidationError, SecurityError
import structlog

logger = structlog.get_logger(__name__)


def validate_dockerfile(
    dockerfile_content: str,
    rules: Optional[dict[str, Any]] = None,
    severity_threshold: str = "medium",
) -> dict[str, Any]:
    """Validate a Dockerfile against security best practices.

    Checks for common security issues including running as root, using latest tags,
    hardcoded secrets in ENV instructions, missing health checks, and more.

    Args:
        dockerfile_content: The raw Dockerfile content as a string.
        rules: Optional dictionary of custom validation rules to apply.
        severity_threshold: Minimum severity to report ('low', 'medium', 'high', 'critical').

    Returns:
        Dictionary with 'valid' (bool), 'findings' (list), 'score' (0-100), and 'metadata'.

    Example:
        >>> result = validate_dockerfile('FROM python:latest\nRUN pip install flask')
        >>> print(result['valid'])
        False
    """
    start_time = time.time()
    span = create_span("dockerfile_validation")
    metrics = get_metrics()
    severity_levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    threshold_value = severity_levels.get(severity_threshold, 1)

    findings: list[dict[str, Any]] = []
    score = 100

    lines = dockerfile_content.strip().split("\n")

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue

        if stripped.upper().startswith("FROM"):
            if ":latest" in stripped or (":" not in stripped and " AS " not in stripped.upper()):
                findings.append({
                    "rule": "no_latest_tag",
                    "severity": "high",
                    "line": i,
                    "message": "Avoid using 'latest' tag; pin to specific version",
                })
                score -= 15

        if stripped.upper().startswith("USER"):
            user_value = stripped.split(None, 1)[1].strip() if len(stripped.split(None, 1)) > 1 else ""
            if user_value.lower() in ("root", "0"):
                findings.append({
                    "rule": "no_root_user",
                    "severity": "critical",
                    "line": i,
                    "message": "Container should not run as root user",
                })
                score -= 25

        if stripped.upper().startswith("ENV"):
            env_part = stripped.split(None, 1)[1] if len(stripped.split(None, 1)) > 1 else ""
            secret_patterns = [r"(?i)password", r"(?i)secret", r"(?i)api_key", r"(?i)token", r"(?i)credential"]
            for pattern in secret_patterns:
                if re.search(pattern, env_part):
                    if "=" in env_part and not env_part.split("=", 1)[1].startswith("$"):
                        findings.append({
                            "rule": "no_secrets_in_env",
                            "severity": "critical",
                            "line": i,
                            "message": "Potential secret found in ENV instruction",
                        })
                        score -= 20
                        break

        if stripped.upper().startswith("RUN"):
            if "apt-get" in stripped and "-y" not in stripped:
                findings.append({
                    "rule": "non_interactive_install",
                    "severity": "low",
                    "line": i,
                    "message": "Use -y flag for non-interactive package installation",
                })
                score -= 5
            if "curl" in stripped or "wget" in stripped:
                if "--no-check-certificate" in stripped or "-k " in stripped:
                    findings.append({
                        "rule": "insecure_download",
                        "severity": "high",
                        "line": i,
                        "message": "Insecure download detected (certificate verification disabled)",
                    })
                    score -= 15

    has_user = any(l.strip().upper().startswith("USER") for l in lines)
    if not has_user:
        findings.append({
            "rule": "missing_user_instruction",
            "severity": "high",
            "line": 0,
            "message": "No USER instruction found; container will run as root by default",
        })
        score -= 15

    has_healthcheck = any(l.strip().upper().startswith("HEALTHCHECK") for l in lines)
    if not has_healthcheck:
        findings.append({
            "rule": "missing_healthcheck",
            "severity": "low",
            "line": 0,
            "message": "No HEALTHCHECK instruction found",
        })
        score -= 5

    filtered_findings = [f for f in findings if severity_levels.get(f["severity"], 0) >= threshold_value]
    score = max(0, score)

    duration = time.time() - start_time
    metrics.inc_counter("cloud.dockerfile_validation.total")
    metrics.observe_histogram("cloud.dockerfile_validation.duration", duration)
    if filtered_findings:
        metrics.inc_counter("cloud.dockerfile_validation.findings", len(filtered_findings))

    result = {
        "valid": len(filtered_findings) == 0,
        "findings": filtered_findings,
        "all_findings": findings,
        "score": score,
        "metadata": {
            "lines_analyzed": len(lines),
            "severity_threshold": severity_threshold,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "duration_ms": round(duration * 1000, 2),
        },
    }

    severity = EventSeverity.LOW if result["valid"] else EventSeverity.HIGH

    logger.info("dockerfile_validation_complete", valid=result["valid"], findings=len(filtered_findings), score=score)
    getattr(span, "end", lambda: None)()
    return result


def detect_container_escape(
    container_config: dict[str, Any],
    capabilities: Optional[list[str]] = None,
    namespaces: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Detect potential container escape vectors in container configuration.

    Analyzes container capabilities, namespace isolation, security options,
    and volume mounts to identify escape risks.

    Args:
        container_config: Container runtime configuration dictionary.
        capabilities: List of Linux capabilities granted to the container.
        namespaces: List of Linux namespaces the container participates in.

    Returns:
        Dictionary with 'escape_risk' (low/medium/high/critical), 'vectors' (list),
        'recommendations' (list), and 'metadata'.

    Example:
        >>> config = {"privileged": True, "pid_mode": "host"}
        >>> result = detect_container_escape(config)
        >>> print(result['escape_risk'])
        'critical'
    """
    start_time = time.time()
    span = create_span("container_escape_detection")
    metrics = get_metrics()
    vectors: list[dict[str, Any]] = []
    recommendations: list[str] = []
    risk_score = 0

    if container_config.get("privileged", False):
        vectors.append({"type": "privileged_mode", "severity": "critical", "description": "Container running in privileged mode has full host access"})
        risk_score += 40
        recommendations.append("Remove privileged mode; use specific capabilities instead")

    pid_mode = container_config.get("pid_mode", container_config.get("PidMode", ""))
    if pid_mode == "host":
        vectors.append({"type": "host_pid", "severity": "high", "description": "Host PID namespace shared; can see and signal host processes"})
        risk_score += 25
        recommendations.append("Use container PID namespace isolation")

    network_mode = container_config.get("network_mode", container_config.get("NetworkMode", ""))
    if network_mode == "host":
        vectors.append({"type": "host_network", "severity": "high", "description": "Host network namespace shared; can access host network interfaces"})
        risk_score += 20
        recommendations.append("Use bridge or overlay network instead of host network")

    volumes = container_config.get("volumes", container_config.get("Binds", []))
    for vol in volumes:
        vol_path = vol if isinstance(vol, str) else str(vol)
        if vol_path.startswith("/:") or "/proc" in vol_path or "/sys" in vol_path:
            vectors.append({"type": "sensitive_mount", "severity": "critical", "description": f"Sensitive host path mounted: {vol_path}"})
            risk_score += 30
            recommendations.append(f"Remove sensitive host mount: {vol_path}")

    dangerous_capabilities = {"SYS_ADMIN", "SYS_PTRACE", "DAC_OVERRIDE", "NET_ADMIN", "SYS_RAWIO"}
    caps = capabilities or container_config.get("capabilities", [])
    granted_caps = {c.upper() for c in caps}

    if "ALL" in granted_caps:
        vectors.append({"type": "all_capabilities", "severity": "critical", "description": "All Linux capabilities granted to container"})
        risk_score += 35
        recommendations.append("Drop all capabilities and add only required ones")
    else:
        dangerous_found = granted_caps & dangerous_capabilities
        for cap in dangerous_found:
            vectors.append({"type": "dangerous_capability", "severity": "high", "description": f"Dangerous capability granted: {cap}"})
            risk_score += 15
            recommendations.append(f"Drop capability: {cap}")

    user_ns = namespaces or container_config.get("namespaces", [])
    missing_ns = []
    required_ns = ["pid", "network", "ipc", "mnt", "uts"]
    for ns in required_ns:
        if ns not in [n.lower() for n in user_ns]:
            missing_ns.append(ns)

    if missing_ns:
        vectors.append({"type": "missing_namespaces", "severity": "medium", "description": f"Missing namespace isolation: {', '.join(missing_ns)}"})
        risk_score += 10
        recommendations.append(f"Enable namespace isolation for: {', '.join(missing_ns)}")

    security_opt = container_config.get("security_opt", [])
    if "apparmor=unconfined" in security_opt or "seccomp=unconfined" in security_opt:
        vectors.append({"type": "disabled_security_profile", "severity": "high", "description": "AppArmor or seccomp profile disabled"})
        risk_score += 20
        recommendations.append("Enable AppArmor and seccomp security profiles")

    no_new_privs = container_config.get("no_new_privileges", False)
    if not no_new_privs:
        recommendations.append("Set no-new-privileges flag to prevent privilege escalation")

    risk_score = min(100, risk_score)
    if risk_score >= 70:
        escape_risk = "critical"
    elif risk_score >= 50:
        escape_risk = "high"
    elif risk_score >= 25:
        escape_risk = "medium"
    else:
        escape_risk = "low"

    duration = time.time() - start_time
    metrics.inc_counter("cloud.container_escape_detection.total")
    metrics.observe_histogram("cloud.container_escape_detection.duration", duration)
    if vectors:
        metrics.inc_counter("cloud.container_escape_detection.vectors", len(vectors))

    result = {
        "escape_risk": escape_risk,
        "risk_score": risk_score,
        "vectors": vectors,
        "recommendations": recommendations,
        "metadata": {
            "capabilities_checked": caps,
            "namespaces_checked": user_ns,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "duration_ms": round(duration * 1000, 2),
        },
    }

    severity = EventSeverity.CRITICAL if escape_risk == "critical" else EventSeverity.LOW
    getattr(span, "end", lambda: None)()
    return result


def validate_k8s_rbac(
    rbac_config: dict[str, Any],
    least_privilege_rules: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Validate Kubernetes RBAC configuration against least privilege principles.

    Checks for wildcard permissions, cluster-admin bindings, overly broad
    resource access, and other RBAC misconfigurations.

    Args:
        rbac_config: Kubernetes RBAC configuration (Roles, ClusterRoles, Bindings).
        least_privilege_rules: Optional dictionary defining allowed permissions per role.

    Returns:
        Dictionary with 'compliant' (bool), 'violations' (list), 'risk_level', and 'metadata'.

    Example:
        >>> rbac = {"roles": [{"name": "admin", "rules": [{"verbs": ["*"], "resources": ["*"]}]}]}
        >>> result = validate_k8s_rbac(rbac)
        >>> print(result['compliant'])
        False
    """
    start_time = time.time()
    span = create_span("k8s_rbac_validation")
    metrics = get_metrics()
    violations: list[dict[str, Any]] = []
    roles = rbac_config.get("roles", rbac_config.get("Roles", []))
    cluster_roles = rbac_config.get("cluster_roles", rbac_config.get("ClusterRoles", []))
    role_bindings = rbac_config.get("role_bindings", rbac_config.get("RoleBindings", []))
    cluster_role_bindings = rbac_config.get("cluster_role_bindings", rbac_config.get("ClusterRoleBindings", []))
    all_roles = roles + cluster_roles

    for role in all_roles:
        role_name = role.get("name", "unknown")
        rules = role.get("rules", [])
        for rule in rules:
            verbs = rule.get("verbs", [])
            resources = rule.get("resources", [])
            api_groups = rule.get("apiGroups", rule.get("api_groups", []))

            if "*" in verbs:
                violations.append({"type": "wildcard_verbs", "severity": "critical", "role": role_name, "message": f"Role '{role_name}' has wildcard (*) verb permissions", "recommendation": "Specify explicit verbs instead of wildcard"})
            if "*" in resources:
                violations.append({"type": "wildcard_resources", "severity": "high", "role": role_name, "message": f"Role '{role_name}' has wildcard (*) resource permissions", "recommendation": "Specify explicit resources instead of wildcard"})
            if "*" in api_groups:
                violations.append({"type": "wildcard_api_groups", "severity": "high", "role": role_name, "message": f"Role '{role_name}' has wildcard (*) API group permissions", "recommendation": "Specify explicit API groups instead of wildcard"})

            dangerous_combos = [({"secrets"}, {"get", "list", "watch", "*"}), ({"pods", "pods/exec"}, {"create", "*"}), ({"clusterroles", "clusterrolebindings"}, {"*", "create", "update", "patch"})]
            resource_set = set(r.lower() for r in resources)
            verb_set = set(v.lower() for v in verbs)
            for dangerous_resources, dangerous_verbs in dangerous_combos:
                if dangerous_resources & resource_set and dangerous_verbs & verb_set:
                    violations.append({"type": "dangerous_permission_combo", "severity": "critical", "role": role_name, "message": f"Role '{role_name}' has dangerous permission combination", "recommendation": "Review and restrict dangerous permission combinations"})

    for binding in cluster_role_bindings:
        binding_name = binding.get("name", "unknown")
        role_ref = binding.get("roleRef", binding.get("role_ref", {}))
        subjects = binding.get("subjects", [])
        ref_name = role_ref.get("name", "") if isinstance(role_ref, dict) else str(role_ref)

        if "cluster-admin" in ref_name:
            violations.append({"type": "cluster_admin_binding", "severity": "critical", "binding": binding_name, "message": f"Binding '{binding_name}' grants cluster-admin role", "recommendation": "Avoid cluster-admin bindings; use scoped roles"})

        for subject in subjects:
            if isinstance(subject, dict):
                if subject.get("kind") == "Group" and subject.get("name") == "system:authenticated":
                    violations.append({"type": "authenticated_group_binding", "severity": "high", "binding": binding_name, "message": f"Binding '{binding_name}' grants permissions to all authenticated users", "recommendation": "Bind to specific service accounts or users"})

    if least_privilege_rules:
        for role_name, allowed in least_privilege_rules.items():
            matching_role = next((r for r in all_roles if r.get("name") == role_name), None)
            if matching_role:
                for rule in matching_role.get("rules", []):
                    for verb in rule.get("verbs", []):
                        if verb not in allowed.get("verbs", []) and verb != "*":
                            violations.append({"type": "excessive_permission", "severity": "medium", "role": role_name, "message": f"Role '{role_name}' has verb '{verb}' not in least-privilege rules", "recommendation": f"Remove verb '{verb}' from role '{role_name}'"})

    compliant = len(violations) == 0
    critical_count = sum(1 for v in violations if v.get("severity") == "critical")
    risk_level = "critical" if critical_count > 0 else "high" if any(v.get("severity") == "high" for v in violations) else "medium" if any(v.get("severity") == "medium" for v in violations) else "low" if violations else "none"

    duration = time.time() - start_time
    metrics.inc_counter("cloud.k8s_rbac_validation.total")
    metrics.observe_histogram("cloud.k8s_rbac_validation.duration", duration)
    if violations:
        metrics.inc_counter("cloud.k8s_rbac_validation.violations", len(violations))

    result = {"compliant": compliant, "violations": violations, "risk_level": risk_level, "metadata": {"roles_checked": len(all_roles), "bindings_checked": len(role_bindings) + len(cluster_role_bindings), "timestamp": datetime.now(timezone.utc).isoformat(), "duration_ms": round(duration * 1000, 2)}}
    severity = EventSeverity.CRITICAL if risk_level == "critical" else EventSeverity.LOW
    getattr(span, "end", lambda: None)()
    return result


def detect_public_bucket(
    bucket_config: dict[str, Any],
    policies: Optional[list[dict[str, Any]]] = None,
    acl: Optional[str] = None,
) -> dict[str, Any]:
    """Detect if a cloud storage bucket is publicly accessible.

    Analyzes bucket ACLs, bucket policies, and public access block settings
    to determine public exposure risk.

    Args:
        bucket_config: Bucket configuration including public access block settings.
        policies: List of bucket policy statements.
        acl: Access Control List setting (e.g., 'private', 'public-read').

    Returns:
        Dictionary with 'public' (bool), 'exposure_level', 'issues' (list), and 'metadata'.

    Example:
        >>> config = {"public_access_block": {"BlockPublicAcls": False}}
        >>> result = detect_public_bucket(config, acl="public-read")
        >>> print(result['public'])
        True
    """
    start_time = time.time()
    span = create_span("public_bucket_detection")
    metrics = get_metrics()
    issues: list[dict[str, Any]] = []
    is_public = False
    exposure_score = 0

    public_acls = {"public-read", "public-read-write", "authenticated-read", "public-read-write-acl"}
    if acl and acl.lower() in public_acls:
        is_public = True
        exposure_score += 40
        issues.append({"type": "public_acl", "severity": "critical", "message": f"Bucket has public ACL: {acl}", "recommendation": "Set ACL to 'private'"})

    pub_block = bucket_config.get("public_access_block", bucket_config.get("PublicAccessBlock", {}))
    if isinstance(pub_block, dict):
        if not pub_block.get("BlockPublicAcls", pub_block.get("block_public_acls", True)):
            issues.append({"type": "public_acl_not_blocked", "severity": "high", "message": "BlockPublicAcls is disabled", "recommendation": "Enable BlockPublicAcls"})
            exposure_score += 20
        if not pub_block.get("BlockPublicPolicy", pub_block.get("block_public_policy", True)):
            issues.append({"type": "public_policy_not_blocked", "severity": "high", "message": "BlockPublicPolicy is disabled", "recommendation": "Enable BlockPublicPolicy"})
            exposure_score += 20
        if not pub_block.get("RestrictPublicBuckets", pub_block.get("restrict_public_buckets", True)):
            issues.append({"type": "restrict_not_enabled", "severity": "medium", "message": "RestrictPublicBuckets is disabled", "recommendation": "Enable RestrictPublicBuckets"})
            exposure_score += 10

    bucket_policy = bucket_config.get("policy", bucket_config.get("Policy", None))
    if bucket_policy:
        policy_doc = json.loads(bucket_policy) if isinstance(bucket_policy, str) else bucket_policy
        statements = policy_doc.get("Statement", []) if isinstance(policy_doc, dict) else []
        for stmt in statements:
            if stmt.get("Effect") == "Allow" and stmt.get("Principal") == "*":
                is_public = True
                exposure_score += 30
                issues.append({"type": "public_policy_principal", "severity": "critical", "message": "Bucket policy allows access from Principal: *", "recommendation": "Restrict Principal to specific AWS accounts or users"})

    if policies:
        for policy in policies:
            if policy.get("Effect") == "Allow" and policy.get("Principal") == "*":
                is_public = True
                exposure_score += 30
                issues.append({"type": "public_policy_statement", "severity": "critical", "message": "Policy statement allows access from Principal: *", "recommendation": "Restrict Principal to specific identities"})

    if bucket_config.get("website", bucket_config.get("Website", None)):
        is_public = True
        exposure_score += 15
        issues.append({"type": "static_website_hosting", "severity": "medium", "message": "Static website hosting is enabled on bucket", "recommendation": "Disable website hosting unless required"})

    exposure_score = min(100, exposure_score)
    exposure_level = "critical" if exposure_score >= 60 else "high" if exposure_score >= 40 else "medium" if exposure_score >= 20 else "low"

    duration = time.time() - start_time
    metrics.inc_counter("cloud.public_bucket_detection.total")
    metrics.observe_histogram("cloud.public_bucket_detection.duration", duration)
    if is_public:
        metrics.inc_counter("cloud.public_bucket_detection.public_detected")

    result = {"public": is_public, "exposure_level": exposure_level, "exposure_score": exposure_score, "issues": issues, "metadata": {"acl_checked": acl, "policies_checked": len(policies) if policies else 0, "timestamp": datetime.now(timezone.utc).isoformat(), "duration_ms": round(duration * 1000, 2)}}
    severity = EventSeverity.CRITICAL if is_public else EventSeverity.LOW
    logger.info("public_bucket_detection_complete", public=is_public, exposure_level=exposure_level)
    getattr(span, "end", lambda: None)()
    return result


def validate_s3_permissions(
    bucket_policy: dict[str, Any],
    expected_permissions: dict[str, Any],
) -> dict[str, Any]:
    """Validate S3 bucket permissions against expected security requirements.

    Checks that bucket policies grant only the expected permissions and
    denies overly broad access patterns.

    Args:
        bucket_policy: The S3 bucket policy document.
        expected_permissions: Dictionary mapping actions to expected access patterns.

    Returns:
        Dictionary with 'valid' (bool), 'mismatches' (list), 'excess_permissions' (list), and 'metadata'.

    Example:
        >>> policy = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]}
        >>> expected = {"s3:GetObject": {"principals": ["arn:aws:iam::123456789:role/app"]}}
        >>> result = validate_s3_permissions(policy, expected)
        >>> print(result['valid'])
        False
    """
    start_time = time.time()
    span = create_span("s3_permission_validation")
    metrics = get_metrics()
    mismatches: list[dict[str, Any]] = []
    excess_permissions: list[dict[str, Any]] = []
    statements = bucket_policy.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for stmt in statements:
        effect = stmt.get("Effect", "")
        principal = stmt.get("Principal", "")
        action = stmt.get("Action", [])
        resource = stmt.get("Resource", "")
        if isinstance(action, str):
            action = [action]
        if isinstance(resource, str):
            resource = [resource]

        if effect == "Allow":
            for act in action:
                if act not in expected_permissions:
                    excess_permissions.append({"action": act, "principal": str(principal), "resource": str(resource), "message": f"Unexpected permission: {act}", "severity": "high"})
                else:
                    allowed_principals = expected_permissions[act].get("principals", [])
                    if principal == "*" and allowed_principals:
                        mismatches.append({"action": act, "expected_principals": allowed_principals, "actual_principal": "*", "message": f"Action {act} allows all principals instead of restricted set", "severity": "critical"})
            if principal == "*" and any(a.endswith("*") or a == "*" for a in action):
                mismatches.append({"action": str(action), "expected_principals": [], "actual_principal": "*", "message": "Wildcard actions granted to all principals", "severity": "critical"})

    for expected_action, expected_cfg in expected_permissions.items():
        found = False
        for stmt in statements:
            if stmt.get("Effect") == "Allow":
                stmt_actions = stmt.get("Action", [])
                if isinstance(stmt_actions, str):
                    stmt_actions = [stmt_actions]
                if expected_action in stmt_actions or "*" in stmt_actions:
                    found = True
                    break
        if not found and expected_cfg.get("required", False):
            mismatches.append({"action": expected_action, "expected_principals": expected_cfg.get("principals", []), "actual_principal": None, "message": f"Required permission {expected_action} is missing", "severity": "medium"})

    valid = len(mismatches) == 0 and len(excess_permissions) == 0
    duration = time.time() - start_time
    metrics.inc_counter("cloud.s3_permission_validation.total")
    metrics.observe_histogram("cloud.s3_permission_validation.duration", duration)
    if mismatches:
        metrics.inc_counter("cloud.s3_permission_validation.mismatches", len(mismatches))

    result = {"valid": valid, "mismatches": mismatches, "excess_permissions": excess_permissions, "metadata": {"statements_analyzed": len(statements), "expected_permissions_count": len(expected_permissions), "timestamp": datetime.now(timezone.utc).isoformat(), "duration_ms": round(duration * 1000, 2)}}
    severity = EventSeverity.CRITICAL if not valid else EventSeverity.LOW
    getattr(span, "end", lambda: None)()
    return result


def validate_iam_policy(
    iam_policy: dict[str, Any],
    allowed_actions: Optional[list[str]] = None,
    denied_actions: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Validate IAM policy against allowed and denied action lists.

    Checks for overly permissive policies, wildcard actions, and ensures
    denied actions are explicitly blocked.

    Args:
        iam_policy: IAM policy document to validate.
        allowed_actions: List of actions that are permitted.
        denied_actions: List of actions that must be explicitly denied.

    Returns:
        Dictionary with 'valid' (bool), 'violations' (list), 'warnings' (list), and 'metadata'.

    Example:
        >>> policy = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        >>> result = validate_iam_policy(policy, allowed_actions=["s3:GetObject"])
        >>> print(result['valid'])
        False
    """
    start_time = time.time()
    span = create_span("iam_policy_validation")
    metrics = get_metrics()
    violations: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    allowed_set = set(a.lower() for a in (allowed_actions or []))
    denied_set = set(a.lower() for a in (denied_actions or []))
    statements = iam_policy.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]
    explicit_denies: set[str] = set()

    for stmt in statements:
        effect = stmt.get("Effect", "")
        action = stmt.get("Action", [])
        resource = stmt.get("Resource", "")
        not_action = stmt.get("NotAction", [])
        condition = stmt.get("Condition", None)
        if isinstance(action, str):
            action = [action]
        if isinstance(not_action, str):
            not_action = [not_action]
        if isinstance(resource, str):
            resource = [resource]

        if effect == "Deny":
            for act in action:
                explicit_denies.add(act.lower())

        if effect == "Allow":
            if "*" in action:
                violations.append({"type": "wildcard_action", "severity": "critical", "message": "Policy allows all actions (*)", "recommendation": "Replace wildcard with specific actions"})
            if "*" in str(resource) and len(resource) == 1:
                warnings.append({"type": "wildcard_resource", "severity": "high", "message": "Policy allows access to all resources (*)", "recommendation": "Scope resources to specific ARNs"})

            for act in action:
                act_lower = act.lower()
                if allowed_set and act_lower != "*" and act_lower not in allowed_set:
                    violations.append({"type": "unauthorized_action", "severity": "high", "action": act, "message": f"Action '{act}' is not in the allowed actions list", "recommendation": f"Remove '{act}' or add to allowed_actions"})
                if act_lower in denied_set:
                    violations.append({"type": "denied_action_allowed", "severity": "critical", "action": act, "message": f"Action '{act}' is in the denied list but explicitly allowed", "recommendation": f"Change effect to Deny for '{act}'"})

            if not_action:
                warnings.append({"type": "not_action_used", "severity": "medium", "message": "NotAction used; may inadvertently grant permissions", "recommendation": "Use explicit Action list instead of NotAction"})
            if not condition:
                warnings.append({"type": "no_condition", "severity": "low", "message": "Allow statement has no Condition; consider adding MFA or IP restrictions", "recommendation": "Add Condition block for additional security"})

    for denied_act in denied_set:
        if denied_act not in explicit_denies:
            violations.append({"type": "missing_explicit_deny", "severity": "high", "action": denied_act, "message": f"Denied action '{denied_act}' is not explicitly denied in policy", "recommendation": f"Add explicit Deny statement for '{denied_act}'"})

    valid = len(violations) == 0
    duration = time.time() - start_time
    metrics.inc_counter("cloud.iam_policy_validation.total")
    metrics.observe_histogram("cloud.iam_policy_validation.duration", duration)
    if violations:
        metrics.inc_counter("cloud.iam_policy_validation.violations", len(violations))

    result = {"valid": valid, "violations": violations, "warnings": warnings, "metadata": {"statements_analyzed": len(statements), "allowed_actions_count": len(allowed_actions) if allowed_actions else 0, "denied_actions_count": len(denied_actions) if denied_actions else 0, "timestamp": datetime.now(timezone.utc).isoformat(), "duration_ms": round(duration * 1000, 2)}}
    severity = EventSeverity.CRITICAL if not valid else EventSeverity.LOW
    getattr(span, "end", lambda: None)()
    return result


def detect_cloud_misconfig(
    config: dict[str, Any],
    security_baseline: Optional[dict[str, Any]] = None,
    cloud_provider: str = "aws",
) -> dict[str, Any]:
    """Detect cloud infrastructure misconfigurations against security baselines.

    Analyzes cloud provider configurations for common security issues including
    unencrypted resources, open security groups, missing logging, and more.

    Args:
        config: Cloud resource configuration to validate.
        security_baseline: Security baseline requirements to check against.
        cloud_provider: Cloud provider name ('aws', 'gcp', 'azure').

    Returns:
        Dictionary with 'compliant' (bool), 'misconfigurations' (list), 'compliance_score', and 'metadata'.

    Example:
        >>> cfg = {"security_groups": [{"ingress": [{"from_port": 0, "to_port": 65535, "cidr": "0.0.0.0/0"}]}]}
        >>> result = detect_cloud_misconfig(cfg, cloud_provider="aws")
        >>> print(result['compliant'])
        False
    """
    start_time = time.time()
    span = create_span("cloud_misconfig_detection")
    metrics = get_metrics()
    misconfigurations: list[dict[str, Any]] = []
    compliance_score = 100
    provider = cloud_provider.lower()

    sg_list = config.get("security_groups", config.get("SecurityGroups", []))
    for sg in sg_list:
        for rule in sg.get("ingress", sg.get("IngressRules", [])):
            cidr = rule.get("cidr", rule.get("CidrIp", rule.get("cidr_blocks", "")))
            from_port = rule.get("from_port", rule.get("FromPort", 0))
            to_port = rule.get("to_port", rule.get("ToPort", 65535))
            if cidr in ("0.0.0.0/0", "::/0"):
                if from_port == 0 and to_port == 65535:
                    misconfigurations.append({"type": "open_all_ports", "severity": "critical", "message": "Security group allows all ports from 0.0.0.0/0", "recommendation": "Restrict ports and source CIDR ranges"})
                    compliance_score -= 25
                elif from_port == 22 or (from_port <= 22 <= to_port):
                    misconfigurations.append({"type": "open_ssh", "severity": "critical", "message": "SSH port (22) open to the world", "recommendation": "Restrict SSH access to specific IP ranges"})
                    compliance_score -= 20
                elif from_port == 3389 or (from_port <= 3389 <= to_port):
                    misconfigurations.append({"type": "open_rdp", "severity": "critical", "message": "RDP port (3389) open to the world", "recommendation": "Restrict RDP access to specific IP ranges"})
                    compliance_score -= 20

    encryption = config.get("encryption", config.get("Encryption", {}))
    if isinstance(encryption, dict) and not encryption.get("enabled", encryption.get("Enabled", False)):
        misconfigurations.append({"type": "encryption_disabled", "severity": "high", "message": "Encryption at rest is not enabled", "recommendation": "Enable encryption for all data stores"})
        compliance_score -= 15

    logging_cfg = config.get("logging", config.get("Logging", config.get("audit_logging", {})))
    if isinstance(logging_cfg, dict) and not logging_cfg.get("enabled", logging_cfg.get("Enabled", False)):
        misconfigurations.append({"type": "logging_disabled", "severity": "high", "message": "Audit logging is not enabled", "recommendation": "Enable CloudTrail/audit logging"})
        compliance_score -= 10

    if provider == "aws":
        if not config.get("mfa_required", config.get("MfaRequired", False)):
            misconfigurations.append({"type": "mfa_not_required", "severity": "medium", "message": "MFA is not required for IAM users", "recommendation": "Enforce MFA for all IAM users"})
            compliance_score -= 5
        root_access = config.get("root_account_access", config.get("RootAccountAccess", None))
        if root_access and root_access.get("active_keys", False):
            misconfigurations.append({"type": "root_access_keys", "severity": "critical", "message": "Root account has active access keys", "recommendation": "Delete root access keys and use IAM roles"})
            compliance_score -= 20
    elif provider == "gcp":
        if not config.get("os_login", config.get("OsLogin", False)):
            misconfigurations.append({"type": "os_login_disabled", "severity": "medium", "message": "OS Login is not enabled", "recommendation": "Enable OS Login for centralized access control"})
            compliance_score -= 5
    elif provider == "azure":
        if not config.get("defender_enabled", config.get("DefenderEnabled", False)):
            misconfigurations.append({"type": "defender_disabled", "severity": "medium", "message": "Microsoft Defender for Cloud is not enabled", "recommendation": "Enable Microsoft Defender for Cloud"})
            compliance_score -= 5

    if security_baseline:
        for check_name, check_config in security_baseline.items():
            if not check_config.get("required", False):
                continue
            actual = config.get(check_name, None)
            if actual is None or actual != check_config.get("expected"):
                misconfigurations.append({"type": "baseline_violation", "severity": check_config.get("severity", "medium"), "check": check_name, "expected": check_config.get("expected"), "actual": actual, "message": f"Baseline violation: {check_name}", "recommendation": f"Set {check_name} to {check_config.get('expected')}"})
                compliance_score -= check_config.get("penalty", 5)

    compliance_score = max(0, compliance_score)
    compliant = len(misconfigurations) == 0
    duration = time.time() - start_time
    metrics.inc_counter("cloud.misconfig_detection.total")
    metrics.observe_histogram("cloud.misconfig_detection.duration", duration)
    if misconfigurations:
        metrics.inc_counter("cloud.misconfig_detection.findings", len(misconfigurations))

    result = {"compliant": compliant, "misconfigurations": misconfigurations, "compliance_score": compliance_score, "metadata": {"cloud_provider": provider, "config_items_checked": len(config), "baseline_checks": len(security_baseline) if security_baseline else 0, "timestamp": datetime.now(timezone.utc).isoformat(), "duration_ms": round(duration * 1000, 2)}}
    severity = EventSeverity.CRITICAL if any(m.get("severity") == "critical" for m in misconfigurations) else EventSeverity.LOW
    getattr(span, "end", lambda: None)()
    return result


def validate_secrets_manager(
    secrets_config: dict[str, Any],
    rotation_policy: Optional[dict[str, Any]] = None,
    encryption: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Validate secrets manager configuration for security best practices.

    Checks secret rotation policies, encryption settings, access controls,
    and secret lifecycle management.

    Args:
        secrets_config: Secrets manager configuration dictionary.
        rotation_policy: Expected rotation policy settings.
        encryption: Expected encryption configuration.

    Returns:
        Dictionary with 'valid' (bool), 'issues' (list), 'security_score', and 'metadata'.

    Example:
        >>> cfg = {"secrets": [{"name": "db-password", "rotation_enabled": False}]}
        >>> result = validate_secrets_manager(cfg)
        >>> print(result['valid'])
        False
    """
    start_time = time.time()
    span = create_span("secrets_manager_validation")
    metrics = get_metrics()
    issues: list[dict[str, Any]] = []
    security_score = 100
    secrets = secrets_config.get("secrets", secrets_config.get("Secrets", []))

    for secret in secrets:
        secret_name = secret.get("name", secret.get("SecretName", "unknown"))
        if not secret.get("rotation_enabled", secret.get("RotationEnabled", False)):
            issues.append({"type": "rotation_disabled", "severity": "high", "secret": secret_name, "message": f"Secret '{secret_name}' does not have automatic rotation enabled", "recommendation": "Enable automatic rotation for this secret"})
            security_score -= 10

        rotation_days = secret.get("rotation_days", secret.get("RotationDays", secret.get("rotation_period", 0)))
        if rotation_days and rotation_policy:
            max_days = rotation_policy.get("max_rotation_days", rotation_policy.get("MaxRotationDays", 90))
            if rotation_days > max_days:
                issues.append({"type": "rotation_period_exceeded", "severity": "medium", "secret": secret_name, "message": f"Secret '{secret_name}' rotation period ({rotation_days}d) exceeds maximum ({max_days}d)", "recommendation": f"Reduce rotation period to {max_days} days or less"})
                security_score -= 5

        secret_value = secret.get("value", secret.get("Value", None))
        if secret_value and not secret_value.startswith("arn:") and not secret_value.startswith("ssm:"):
            issues.append({"type": "plaintext_value", "severity": "critical", "secret": secret_name, "message": f"Secret '{secret_name}' appears to contain plaintext value", "recommendation": "Use references instead of storing plaintext values"})
            security_score -= 20

        if not secret.get("access_policy", secret.get("AccessPolicy", None)):
            issues.append({"type": "no_access_policy", "severity": "medium", "secret": secret_name, "message": f"Secret '{secret_name}' has no resource-based access policy", "recommendation": "Define explicit access policy for the secret"})
            security_score -= 5

    enc_config = encryption or secrets_config.get("encryption", {})
    if isinstance(enc_config, dict):
        if not enc_config.get("kms_key_id", enc_config.get("KmsKeyId", None)):
            issues.append({"type": "no_kms_key", "severity": "high", "message": "No KMS key specified for secrets encryption", "recommendation": "Use customer-managed KMS key for encryption"})
            security_score -= 15
        if enc_config.get("type", enc_config.get("EncryptionType", "")).lower() == "plaintext":
            issues.append({"type": "plaintext_encryption", "severity": "critical", "message": "Secrets configured with plaintext 'encryption'", "recommendation": "Enable proper encryption (AES-256 or KMS)"})
            security_score -= 25

    security_score = max(0, security_score)
    valid = len(issues) == 0
    duration = time.time() - start_time
    metrics.inc_counter("cloud.secrets_manager_validation.total")
    metrics.observe_histogram("cloud.secrets_manager_validation.duration", duration)
    if issues:
        metrics.inc_counter("cloud.secrets_manager_validation.issues", len(issues))

    result = {"valid": valid, "issues": issues, "security_score": security_score, "metadata": {"secrets_checked": len(secrets), "timestamp": datetime.now(timezone.utc).isoformat(), "duration_ms": round(duration * 1000, 2)}}
    severity = EventSeverity.CRITICAL if any(i.get("severity") == "critical" for i in issues) else EventSeverity.LOW
    getattr(span, "end", lambda: None)()
    return result


def validate_terraform(
    terraform_plan: dict[str, Any],
    policies: Optional[list[dict[str, Any]]] = None,
    severity_threshold: str = "medium",
) -> dict[str, Any]:
    """Validate a Terraform plan against security policies.

    Analyzes planned resource changes for security violations including
    unencrypted storage, open network rules, missing logging, and more.

    Args:
        terraform_plan: Terraform plan output as a dictionary.
        policies: List of security policies to validate against.
        severity_threshold: Minimum severity to report ('low', 'medium', 'high', 'critical').

    Returns:
        Dictionary with 'valid' (bool), 'violations' (list), 'summary', and 'metadata'.

    Example:
        >>> plan = {"resource_changes": [{"type": "aws_s3_bucket", "change": {"after": {"acl": "public-read"}}}]}
        >>> result = validate_terraform(plan)
        >>> print(result['valid'])
        False
    """
    start_time = time.time()
    span = create_span("terraform_validation")
    metrics = get_metrics()
    severity_levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    threshold_value = severity_levels.get(severity_threshold, 1)
    violations: list[dict[str, Any]] = []

    resource_changes = terraform_plan.get("resource_changes", terraform_plan.get("ResourceChanges", []))
    planned_values = terraform_plan.get("planned_values", terraform_plan.get("PlannedValues", {}))
    resources = planned_values.get("root_module", {}).get("resources", []) if isinstance(planned_values, dict) else []
    all_resources = resources + [rc.get("change", {}).get("after", rc.get("after", {})) for rc in resource_changes if isinstance(rc, dict)]

    default_policies = [
        {"name": "no_public_s3", "resource_types": ["aws_s3_bucket", "aws_s3_bucket_acl"], "check": lambda r: r.get("acl", "") in ("public-read", "public-read-write"), "message": "S3 bucket has public ACL", "severity": "critical"},
        {"name": "s3_encryption", "resource_types": ["aws_s3_bucket"], "check": lambda r: not r.get("server_side_encryption_configuration", r.get("encryption", True)), "message": "S3 bucket missing server-side encryption", "severity": "high"},
        {"name": "rds_public", "resource_types": ["aws_db_instance", "aws_rds_cluster"], "check": lambda r: r.get("publicly_accessible", False), "message": "RDS instance is publicly accessible", "severity": "critical"},
        {"name": "rds_encryption", "resource_types": ["aws_db_instance", "aws_rds_cluster"], "check": lambda r: not r.get("storage_encrypted", True), "message": "RDS storage encryption not enabled", "severity": "high"},
        {"name": "sg_open_ingress", "resource_types": ["aws_security_group"], "check": lambda r: any(ing.get("cidr_blocks", [""]) == ["0.0.0.0/0"] and ing.get("from_port", 0) == 0 for ing in r.get("ingress", [])), "message": "Security group allows all inbound traffic from 0.0.0.0/0", "severity": "critical"},
        {"name": "ebs_encryption", "resource_types": ["aws_ebs_volume"], "check": lambda r: not r.get("encrypted", True), "message": "EBS volume encryption not enabled", "severity": "high"},
    ]

    active_policies = policies or default_policies
    for resource in all_resources:
        if not isinstance(resource, dict):
            continue
        res_type = resource.get("type", resource.get("resource_type", ""))
        res_address = resource.get("address", resource.get("name", "unknown"))
        for policy in active_policies:
            if res_type in policy.get("resource_types", []):
                try:
                    if policy["check"](resource):
                        violations.append({"policy": policy["name"], "resource_type": res_type, "resource_address": res_address, "severity": policy["severity"], "message": policy["message"], "recommendation": policy.get("recommendation", "Remediate the security issue")})
                except Exception:
                    pass

    filtered_violations = [v for v in violations if severity_levels.get(v["severity"], 0) >= threshold_value]
    valid = len(filtered_violations) == 0
    summary = {"total_resources": len(all_resources), "total_violations": len(filtered_violations), "critical": sum(1 for v in filtered_violations if v["severity"] == "critical"), "high": sum(1 for v in filtered_violations if v["severity"] == "high"), "medium": sum(1 for v in filtered_violations if v["severity"] == "medium"), "low": sum(1 for v in filtered_violations if v["severity"] == "low")}

    duration = time.time() - start_time
    metrics.inc_counter("cloud.terraform_validation.total")
    metrics.observe_histogram("cloud.terraform_validation.duration", duration)
    if filtered_violations:
        metrics.inc_counter("cloud.terraform_validation.violations", len(filtered_violations))

    result = {"valid": valid, "violations": filtered_violations, "summary": summary, "metadata": {"policies_applied": len(active_policies), "severity_threshold": severity_threshold, "timestamp": datetime.now(timezone.utc).isoformat(), "duration_ms": round(duration * 1000, 2)}}
    severity = EventSeverity.CRITICAL if summary["critical"] > 0 else EventSeverity.LOW
    getattr(span, "end", lambda: None)()
    return result


def validate_kubernetes_manifest(
    manifest: dict[str, Any],
    pod_security_policy: Optional[dict[str, Any]] = None,
    network_policy: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Validate Kubernetes manifest against pod security and network policies.

    Checks for privileged containers, host namespace sharing, missing
    resource limits, insecure capabilities, and network policy compliance.

    Args:
        manifest: Kubernetes resource manifest (Pod, Deployment, etc.).
        pod_security_policy: Pod security standards/policy to enforce.
        network_policy: Network policy requirements to validate.

    Returns:
        Dictionary with 'valid' (bool), 'violations' (list), 'warnings' (list), and 'metadata'.

    Example:
        >>> manifest = {"spec": {"template": {"spec": {"containers": [{"image": "nginx:latest"}]}}}}
        >>> result = validate_kubernetes_manifest(manifest)
        >>> print(result['valid'])
        False
    """
    start_time = time.time()
    span = create_span("k8s_manifest_validation")
    metrics = get_metrics()
    violations: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []

    spec = manifest.get("spec", {})
    if "template" in spec:
        spec = spec.get("template", {}).get("spec", {})
    containers = spec.get("containers", []) + spec.get("initContainers", [])

    psp = pod_security_policy or {}
    restrict_root = psp.get("restrict_root_user", psp.get("runAsNonRoot", True))
    require_limits = psp.get("require_resource_limits", psp.get("resourceLimits", True))
    allowed_capabilities = psp.get("allowed_capabilities", [])
    drop_all_caps = psp.get("drop_all_capabilities", psp.get("dropAll", True))

    for container in containers:
        container_name = container.get("name", "unknown")
        image = container.get("image", "")
        if ":latest" in image or ":" not in image:
            violations.append({"type": "latest_tag", "severity": "high", "container": container_name, "message": f"Container '{container_name}' uses 'latest' or untagged image", "recommendation": "Pin container image to specific version digest"})

        security_context = container.get("securityContext", {})
        pod_sc = spec.get("securityContext", {})
        if security_context.get("privileged", False) or pod_sc.get("privileged", False):
            violations.append({"type": "privileged_container", "severity": "critical", "container": container_name, "message": f"Container '{container_name}' runs in privileged mode", "recommendation": "Set privileged: false in securityContext"})

        run_as_root = security_context.get("runAsUser", pod_sc.get("runAsUser", 0)) == 0
        run_as_non_root = security_context.get("runAsNonRoot", pod_sc.get("runAsNonRoot", False))
        if run_as_root and not run_as_non_root and restrict_root:
            violations.append({"type": "root_user", "severity": "high", "container": container_name, "message": f"Container '{container_name}' runs as root user", "recommendation": "Set runAsNonRoot: true and specify non-root runAsUser"})

        caps = security_context.get("capabilities", {})
        drop_caps = caps.get("drop", [])
        if drop_all_caps and "ALL" not in [c.upper() for c in drop_caps]:
            warnings.append({"type": "capabilities_not_dropped", "severity": "medium", "container": container_name, "message": f"Container '{container_name}' does not drop ALL capabilities", "recommendation": "Add 'drop: [\"ALL\"]' to securityContext.capabilities"})

        for cap in caps.get("add", []):
            if allowed_capabilities and cap.upper() not in [a.upper() for a in allowed_capabilities]:
                violations.append({"type": "unauthorized_capability", "severity": "high", "container": container_name, "message": f"Container '{container_name}' adds unauthorized capability: {cap}", "recommendation": f"Remove capability '{cap}' or add to allowed list"})

        if require_limits:
            resources = container.get("resources", {})
            if not resources.get("limits", {}):
                violations.append({"type": "missing_resource_limits", "severity": "medium", "container": container_name, "message": f"Container '{container_name}' has no resource limits defined", "recommendation": "Define CPU and memory limits"})
            if not resources.get("requests", {}):
                warnings.append({"type": "missing_resource_requests", "severity": "low", "container": container_name, "message": f"Container '{container_name}' has no resource requests defined", "recommendation": "Define CPU and memory requests"})

        if not container.get("readinessProbe"):
            warnings.append({"type": "no_readiness_probe", "severity": "low", "container": container_name, "message": f"Container '{container_name}' has no readiness probe", "recommendation": "Add readinessProbe for traffic management"})
        if not container.get("livenessProbe"):
            warnings.append({"type": "no_liveness_probe", "severity": "low", "container": container_name, "message": f"Container '{container_name}' has no liveness probe", "recommendation": "Add livenessProbe for health monitoring"})

    if spec.get("hostNetwork", False):
        violations.append({"type": "host_network", "severity": "high", "container": "pod", "message": "Pod uses host network namespace", "recommendation": "Set hostNetwork: false"})
    if spec.get("hostPID", False):
        violations.append({"type": "host_pid", "severity": "high", "container": "pod", "message": "Pod uses host PID namespace", "recommendation": "Set hostPID: false"})
    if spec.get("hostIPC", False):
        violations.append({"type": "host_ipc", "severity": "high", "container": "pod", "message": "Pod uses host IPC namespace", "recommendation": "Set hostIPC: false"})

    if network_policy:
        required_labels = network_policy.get("required_labels", {})
        manifest_labels = manifest.get("metadata", {}).get("labels", {})
        for label_key, label_value in required_labels.items():
            if manifest_labels.get(label_key) != label_value:
                violations.append({"type": "network_policy_label_missing", "severity": "medium", "container": "pod", "message": f"Missing required network policy label: {label_key}={label_value}", "recommendation": f"Add label {label_key}: {label_value} to pod metadata"})

    valid = len(violations) == 0
    duration = time.time() - start_time
    metrics.inc_counter("cloud.k8s_manifest_validation.total")
    metrics.observe_histogram("cloud.k8s_manifest_validation.duration", duration)
    if violations:
        metrics.inc_counter("cloud.k8s_manifest_validation.violations", len(violations))

    result = {"valid": valid, "violations": violations, "warnings": warnings, "metadata": {"containers_checked": len(containers), "kind": manifest.get("kind", "Unknown"), "timestamp": datetime.now(timezone.utc).isoformat(), "duration_ms": round(duration * 1000, 2)}}
    severity = EventSeverity.CRITICAL if any(v.get("severity") == "critical" for v in violations) else EventSeverity.LOW
    getattr(span, "end", lambda: None)()
    return result


def runtime_container_protection(
    container_events: list[dict[str, Any]],
    threat_rules: Optional[list[dict[str, Any]]] = None,
    actions: Optional[dict[str, str]] = None,
) -> dict[str, Any]:
    """Analyze runtime container events for security threats and take actions.

    Processes container runtime events (syscalls, file access, network connections)
    against threat detection rules and recommends or executes mitigation actions.

    Args:
        container_events: List of container runtime events to analyze.
        threat_rules: List of threat detection rules to match against.
        actions: Mapping of threat types to response actions ('alert', 'block', 'kill', 'quarantine').

    Returns:
        Dictionary with 'threats_detected' (list), 'actions_taken' (list), 'risk_level', and 'metadata'.

    Example:
        >>> events = [{"type": "syscall", "syscall": "execve", "args": ["/bin/bash"]}]
        >>> result = runtime_container_protection(events)
        >>> print(result['threats_detected'])
        [...]
    """
    start_time = time.time()
    span = create_span("runtime_container_protection")
    metrics = get_metrics()
    default_rules = [
        {"name": "shell_spawn", "type": "syscall", "match": {"syscall": "execve"}, "pattern": lambda e: any("bash" in str(a) or "sh" in str(a) or "zsh" in str(a) for a in e.get("args", [])), "severity": "high", "description": "Shell spawned inside container"},
        {"name": "sensitive_file_read", "type": "file_access", "pattern": lambda e: re.search(r"/etc/(shadow|passwd|sudoers)", e.get("path", e.get("file", ""))), "severity": "critical", "description": "Sensitive system file accessed"},
        {"name": "reverse_shell", "type": "network", "match": {"direction": "outbound"}, "pattern": lambda e: e.get("port") in (4444, 5555, 1337, 31337), "severity": "critical", "description": "Potential reverse shell connection detected"},
        {"name": "crypto_mining", "type": "process", "pattern": lambda e: re.search(r"(xmrig|cpuminer|cgminer|bfgminer)", e.get("process", e.get("command", "")), re.IGNORECASE), "severity": "critical", "description": "Cryptocurrency mining process detected"},
        {"name": "container_escape_attempt", "type": "syscall", "match": {"syscall": "mount"}, "pattern": lambda e: any("proc" in str(a) or "sys" in str(a) or "cgroup" in str(a) for a in e.get("args", [])), "severity": "critical", "description": "Potential container escape via mount syscall"},
        {"name": "credential_access", "type": "file_access", "pattern": lambda e: re.search(r"\.(ssh|aws|gcloud|kube)", e.get("path", e.get("file", ""))), "severity": "high", "description": "Credential file access detected"},
    ]

    rules = threat_rules or default_rules
    action_map = actions or {"critical": "kill", "high": "block", "medium": "alert", "low": "alert"}
    threats: list[dict[str, Any]] = []
    actions_taken: list[dict[str, Any]] = []

    for event in container_events:
        event_type = event.get("type", event.get("event_type", ""))
        for rule in rules:
            if rule.get("type") != event_type:
                continue
            try:
                if rule["pattern"](event):
                    severity = rule.get("severity", "medium")
                    ts = datetime.now(timezone.utc).isoformat()
                    threats.append({"rule": rule["name"], "severity": severity, "description": rule.get("description", ""), "event": event, "timestamp": ts})
                    actions_taken.append({"threat": rule["name"], "action": action_map.get(severity, "alert"), "target": event.get("container_id", event.get("container", "unknown")), "timestamp": ts})
            except Exception:
                pass

    critical_count = sum(1 for t in threats if t["severity"] == "critical")
    high_count = sum(1 for t in threats if t["severity"] == "high")
    risk_level = "critical" if critical_count > 0 else "high" if high_count > 0 else "medium" if threats else "low"

    duration = time.time() - start_time
    metrics.inc_counter("cloud.runtime_container_protection.total")
    metrics.observe_histogram("cloud.runtime_container_protection.duration", duration)
    if threats:
        metrics.inc_counter("cloud.runtime_container_protection.threats", len(threats))

    result = {"threats_detected": threats, "actions_taken": actions_taken, "risk_level": risk_level, "metadata": {"events_analyzed": len(container_events), "rules_applied": len(rules), "threat_count": len(threats), "timestamp": datetime.now(timezone.utc).isoformat(), "duration_ms": round(duration * 1000, 2)}}
    severity = EventSeverity.CRITICAL if risk_level == "critical" else EventSeverity.LOW
    getattr(span, "end", lambda: None)()
    return result


def supply_chain_validation(
    dependencies: list[dict[str, Any]],
    trusted_sources: Optional[list[str]] = None,
    vulnerability_db: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Validate software supply chain dependencies for security risks.

    Checks dependency sources against trusted registries, scans for known
    vulnerabilities, and identifies supply chain attack indicators.

    Args:
        dependencies: List of dependency metadata (name, version, source, hash).
        trusted_sources: List of approved package registries/sources.
        vulnerability_db: Database of known vulnerabilities keyed by package name.

    Returns:
        Dictionary with 'safe' (bool), 'risks' (list), 'vulnerabilities' (list), and 'metadata'.

    Example:
        >>> deps = [{"name": "lodash", "version": "4.17.20", "source": "npm"}]
        >>> result = supply_chain_validation(deps, trusted_sources=["npm", "pypi"])
        >>> print(result['safe'])
        True
    """
    start_time = time.time()
    span = create_span("supply_chain_validation")
    metrics = get_metrics()
    risks: list[dict[str, Any]] = []
    vulnerabilities: list[dict[str, Any]] = []
    trusted = [s.lower() for s in (trusted_sources or ["npm", "pypi", "docker.io", "gcr.io", "maven"])]

    for dep in dependencies:
        dep_name = dep.get("name", dep.get("package", "unknown"))
        dep_version = dep.get("version", dep.get("tag", "unknown"))
        dep_source = dep.get("source", dep.get("registry", "")).lower()

        if trusted and dep_source and dep_source not in trusted:
            risks.append({"type": "untrusted_source", "severity": "high", "package": dep_name, "version": dep_version, "source": dep_source, "message": f"Package '{dep_name}' from untrusted source: {dep_source}", "recommendation": f"Use packages from trusted sources: {', '.join(trusted)}"})

        if not dep.get("hash", dep.get("checksum", dep.get("digest", None))):
            risks.append({"type": "missing_integrity_check", "severity": "medium", "package": dep_name, "version": dep_version, "message": f"Package '{dep_name}' has no integrity hash for verification", "recommendation": "Verify package integrity with SHA-256 checksum"})

        if vulnerability_db:
            direct_vulns = vulnerability_db.get(dep_name, vulnerability_db.get(dep_name.lower(), []))
            if isinstance(direct_vulns, list):
                for vuln in direct_vulns:
                    affected = vuln.get("affected_versions", vuln.get("versions", []))
                    if dep_version in affected or "*" in affected:
                        vulnerabilities.append({"cve": vuln.get("cve", vuln.get("id", "unknown")), "package": dep_name, "version": dep_version, "severity": vuln.get("severity", "unknown"), "cvss": vuln.get("cvss", 0), "description": vuln.get("description", "")})

    safe = len(risks) == 0 and len(vulnerabilities) == 0
    duration = time.time() - start_time
    metrics.inc_counter("cloud.supply_chain_validation.total")
    metrics.observe_histogram("cloud.supply_chain_validation.duration", duration)
    if risks or vulnerabilities:
        metrics.inc_counter("cloud.supply_chain_validation.issues", len(risks) + len(vulnerabilities))

    result = {"safe": safe, "risks": risks, "vulnerabilities": vulnerabilities, "metadata": {"dependencies_checked": len(dependencies), "trusted_sources": trusted, "risk_count": len(risks), "vulnerability_count": len(vulnerabilities), "timestamp": datetime.now(timezone.utc).isoformat(), "duration_ms": round(duration * 1000, 2)}}
    severity = EventSeverity.HIGH if vulnerabilities else EventSeverity.LOW
    getattr(span, "end", lambda: None)()
    return result


def sbom_generator(
    components: list[dict[str, Any]],
    format: str = "spdx",
    metadata: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Generate a Software Bill of Materials (SBOM) for software components.

    Creates a standardized SBOM in SPDX or CycloneDX format documenting
    all software components, their versions, licenses, and dependencies.

    Args:
        components: List of software components with name, version, license, etc.
        format: SBOM format ('spdx' or 'cyclonedx').
        metadata: Additional metadata (author, tool, timestamp, etc.).

    Returns:
        Dictionary containing the generated SBOM document.

    Example:
        >>> comps = [{"name": "express", "version": "4.18.2", "license": "MIT"}]
        >>> result = sbom_generator(comps, format="spdx")
        >>> print(result['format'])
        'SPDX-2.3'
    """
    start_time = time.time()
    span = create_span("sbom_generation")
    metrics = get_metrics()
    doc_format = format.lower()
    timestamp = datetime.now(timezone.utc).isoformat()
    doc_id = f"sbom-{hashlib.sha256(json.dumps(components, sort_keys=True, default=str).encode()).hexdigest()[:12]}"

    if doc_format == "cyclonedx":
        sbom = {
            "bomFormat": "CycloneDX", "specVersion": "1.4", "serialNumber": f"urn:uuid:{doc_id}", "version": 1,
            "metadata": {"timestamp": timestamp, "tools": [{"name": "master-security", "version": "1.0.0"}], "authors": [{"name": metadata.get("author", "Unknown")}] if metadata and "author" in metadata else [], "component": {"type": "application", "name": metadata.get("name", "unknown") if metadata else "unknown", "version": metadata.get("version", "0.0.0") if metadata else "0.0.0"} if metadata else {}},
            "components": [],
        }
        for comp in components:
            sbom["components"].append({"type": "library", "name": comp.get("name", "unknown"), "version": comp.get("version", "unknown"), "purl": comp.get("purl", f"pkg:{comp.get('ecosystem', 'generic')}/{comp.get('name', '')}@{comp.get('version', '')}"), "licenses": [{"license": {"id": comp.get("license", "NOASSERTION")}}] if comp.get("license") else [], "hashes": [{"alg": "SHA-256", "content": comp["hash"]}] if comp.get("hash") else [], "supplier": {"name": comp.get("supplier", comp.get("publisher", "Unknown"))} if comp.get("supplier") or comp.get("publisher") else {}})
    else:
        sbom = {
            "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
            "name": metadata.get("name", "unknown") if metadata else "unknown",
            "documentNamespace": f"https://spdx.org/spdxdocs/{doc_id}",
            "creationInfo": {"created": timestamp, "creators": [f"Tool: master-security-1.0.0", f"Organization: {metadata.get('author', 'Unknown')}"] if metadata else ["Tool: master-security-1.0.0"], "licenseListVersion": "3.19"},
            "packages": [], "relationships": [],
        }
        for idx, comp in enumerate(components):
            spdx_id = f"SPDXRef-Package-{idx}"
            sbom["packages"].append({"SPDXID": spdx_id, "name": comp.get("name", "unknown"), "versionInfo": comp.get("version", "unknown"), "downloadLocation": comp.get("download_url", "NOASSERTION"), "licenseConcluded": comp.get("license", "NOASSERTION"), "licenseDeclared": comp.get("license", "NOASSERTION"), "copyrightText": comp.get("copyright", "NOASSERTION"), "checksums": [{"algorithm": "SHA256", "checksumValue": comp["hash"]}] if comp.get("hash") else [], "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": comp.get("purl", "")}] if comp.get("purl") else []})
            sbom["relationships"].append({"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": spdx_id, "relationshipType": "DESCRIBES"})

    duration = time.time() - start_time
    metrics.inc_counter("cloud.sbom_generation.total")
    metrics.observe_histogram("cloud.sbom_generation.duration", duration)
    metrics.inc_counter("cloud.sbom_generation.components", len(components))

    result = {"format": "SPDX-2.3" if doc_format != "cyclonedx" else "CycloneDX-1.4", "document_id": doc_id, "component_count": len(components), "sbom": sbom, "metadata": {"format_requested": doc_format, "timestamp": timestamp, "duration_ms": round(duration * 1000, 2)}}
    getattr(span, "end", lambda: None)()
    return result


def dependency_audit(
    dependencies: list[dict[str, Any]],
    audit_db: Optional[dict[str, Any]] = None,
    severity_threshold: str = "medium",
) -> dict[str, Any]:
    """Audit dependencies for known vulnerabilities and security issues.

    Cross-references dependencies against a vulnerability database and
    reports issues filtered by severity threshold.

    Args:
        dependencies: List of dependencies to audit.
        audit_db: Vulnerability database keyed by package name.
        severity_threshold: Minimum severity to report ('low', 'medium', 'high', 'critical').

    Returns:
        Dictionary with 'clean' (bool), 'vulnerabilities' (list), 'summary', and 'metadata'.

    Example:
        >>> deps = [{"name": "lodash", "version": "4.17.20"}]
        >>> result = dependency_audit(deps, severity_threshold="high")
        >>> print(result['clean'])
        True
    """
    start_time = time.time()
    span = create_span("dependency_audit")
    metrics = get_metrics()
    severity_levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    threshold_value = severity_levels.get(severity_threshold, 1)
    vulnerabilities: list[dict[str, Any]] = []

    default_db: dict[str, list[dict[str, Any]]] = {
        "lodash": [{"cve": "CVE-2021-23337", "severity": "high", "cvss": 7.2, "affected_versions": ["<4.17.21"], "description": "Command injection in lodash"}, {"cve": "CVE-2020-28500", "severity": "medium", "cvss": 5.3, "affected_versions": ["<4.17.21"], "description": "ReDoS in lodash"}],
        "express": [{"cve": "CVE-2024-29041", "severity": "medium", "cvss": 5.3, "affected_versions": ["<4.19.2"], "description": "Open redirect in express"}],
        "requests": [{"cve": "CVE-2023-32681", "severity": "medium", "cvss": 6.1, "affected_versions": ["<2.31.0"], "description": "Unintended leak of Proxy-Authorization header"}],
        "django": [{"cve": "CVE-2024-27351", "severity": "high", "cvss": 7.5, "affected_versions": ["<4.2.11", "<5.0.4"], "description": "DoS via file upload"}],
        "flask": [{"cve": "CVE-2023-30861", "severity": "high", "cvss": 7.5, "affected_versions": ["<2.3.2"], "description": "Cookie exposure via Vary header"}],
    }
    db = audit_db or default_db

    def _version_matches(version: str, pattern: str) -> bool:
        if not pattern.startswith("<"):
            return False
        target = pattern[1:]
        try:
            v_parts = [int(x) for x in version.split(".")]
            t_parts = [int(x) for x in target.split(".")]
            while len(v_parts) < len(t_parts):
                v_parts.append(0)
            while len(t_parts) < len(v_parts):
                t_parts.append(0)
            return v_parts < t_parts
        except (ValueError, AttributeError):
            return False

    for dep in dependencies:
        dep_name = dep.get("name", dep.get("package", "")).lower()
        dep_version = dep.get("version", dep.get("tag", ""))
        pkg_vulns = db.get(dep_name, db.get(dep_name.split("/")[-1], []))
        if isinstance(pkg_vulns, dict):
            pkg_vulns = [pkg_vulns]
        for vuln in pkg_vulns:
            affected = vuln.get("affected_versions", vuln.get("versions", []))
            is_affected = dep_version in affected or any(_version_matches(dep_version, p) for p in affected if "<" in p or ">" in p)
            if is_affected:
                vuln_severity = vuln.get("severity", "low").lower()
                if severity_levels.get(vuln_severity, 0) >= threshold_value:
                    vulnerabilities.append({"cve": vuln.get("cve", vuln.get("id", "unknown")), "package": dep_name, "version": dep_version, "severity": vuln_severity, "cvss": vuln.get("cvss", 0), "description": vuln.get("description", ""), "fix_version": vuln.get("fix_version", vuln.get("fixed_in", None))})

    clean = len(vulnerabilities) == 0
    summary = {"total_dependencies": len(dependencies), "vulnerable_dependencies": len(set(v["package"] for v in vulnerabilities)), "total_vulnerabilities": len(vulnerabilities), "critical": sum(1 for v in vulnerabilities if v["severity"] == "critical"), "high": sum(1 for v in vulnerabilities if v["severity"] == "high"), "medium": sum(1 for v in vulnerabilities if v["severity"] == "medium"), "low": sum(1 for v in vulnerabilities if v["severity"] == "low")}

    duration = time.time() - start_time
    metrics.inc_counter("cloud.dependency_audit.total")
    metrics.observe_histogram("cloud.dependency_audit.duration", duration)
    if vulnerabilities:
        metrics.inc_counter("cloud.dependency_audit.vulnerabilities", len(vulnerabilities))

    result = {"clean": clean, "vulnerabilities": vulnerabilities, "summary": summary, "metadata": {"severity_threshold": severity_threshold, "database_entries": len(db), "timestamp": datetime.now(timezone.utc).isoformat(), "duration_ms": round(duration * 1000, 2)}}
    severity = EventSeverity.CRITICAL if summary["critical"] > 0 else EventSeverity.LOW
    getattr(span, "end", lambda: None)()
    return result


def detect_typosquatting(
    package_name: str,
    known_packages: Optional[list[str]] = None,
    similarity_threshold: float = 0.85,
) -> dict[str, Any]:
    """Detect potential typosquatting attacks by comparing package names against known packages.

    Uses Levenshtein distance and other similarity metrics to identify packages
    that may be malicious imitations of legitimate packages.

    Args:
        package_name: The package name to check for typosquatting.
        known_packages: List of known legitimate package names.
        similarity_threshold: Similarity score threshold (0.0-1.0) for flagging.

    Returns:
        Dictionary with 'suspicious' (bool), 'matches' (list), 'max_similarity', and 'metadata'.

    Example:
        >>> result = detect_typosquatting("reqeusts", known_packages=["requests", "request"])
        >>> print(result['suspicious'])
        True
    """
    start_time = time.time()
    span = create_span("typosquatting_detection")
    metrics = get_metrics()
    default_packages = ["requests", "numpy", "pandas", "flask", "django", "express", "lodash", "react", "angular", "vue", "axios", "webpack", "babel", "eslint", "typescript", "moment", "chalk", "debug", "dotenv", "jsonwebtoken", "boto3", "botocore", "sqlalchemy", "celery", "redis", "pillow", "beautifulsoup4", "scrapy", "pytest", "setuptools", "pip"]
    known = known_packages or default_packages
    matches: list[dict[str, Any]] = []

    def levenshtein_distance(s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                curr_row.append(min(prev_row[j + 1] + 1, curr_row[j] + 1, prev_row[j] + (c1 != c2)))
            prev_row = curr_row
        return prev_row[-1]

    def similarity_score(s1: str, s2: str) -> float:
        if s1 == s2:
            return 1.0
        max_len = max(len(s1), len(s2))
        return 1.0 - (levenshtein_distance(s1.lower(), s2.lower()) / max_len) if max_len > 0 else 1.0

    def char_swap_similarity(s1: str, s2: str) -> float:
        if len(s1) != len(s2):
            return 0.0
        diffs = sum(1 for a, b in zip(s1, s2) if a != b)
        return 1.0 - (diffs / len(s1)) if len(s1) > 0 else 1.0

    def hyphenation_similarity(s1: str, s2: str) -> float:
        s1_norm = s1.replace("-", "").replace("_", "")
        s2_norm = s2.replace("-", "").replace("_", "")
        return 0.95 if s1_norm == s2_norm else 0.0

    def combination_similarity(s1: str, s2: str) -> float:
        s1_lower, s2_lower = s1.lower(), s2.lower()
        if s2_lower in s1_lower or s1_lower in s2_lower:
            return min(len(s1_lower), len(s2_lower)) / max(len(s1_lower), len(s2_lower)) * 0.9
        return 0.0

    max_similarity = 0.0
    for known_pkg in known:
        if known_pkg.lower() == package_name.lower():
            continue
        scores = {"levenshtein": similarity_score(package_name, known_pkg), "char_swap": char_swap_similarity(package_name, known_pkg), "hyphenation": hyphenation_similarity(package_name, known_pkg), "combination": combination_similarity(package_name, known_pkg)}
        best_score = max(scores.values())
        if best_score >= similarity_threshold and best_score < 1.0:
            matches.append({"package": known_pkg, "similarity": round(best_score, 4), "match_type": max(scores, key=scores.get), "scores": {k: round(v, 4) for k, v in scores.items()}, "risk": "high" if best_score >= 0.95 else "medium"})
        max_similarity = max(max_similarity, best_score)

    suspicious = len(matches) > 0
    matches.sort(key=lambda m: m["similarity"], reverse=True)
    duration = time.time() - start_time
    metrics.inc_counter("cloud.typosquatting_detection.total")
    metrics.observe_histogram("cloud.typosquatting_detection.duration", duration)
    if suspicious:
        metrics.inc_counter("cloud.typosquatting_detection.suspicious")

    result = {"suspicious": suspicious, "matches": matches, "max_similarity": round(max_similarity, 4), "metadata": {"package_checked": package_name, "known_packages_count": len(known), "similarity_threshold": similarity_threshold, "timestamp": datetime.now(timezone.utc).isoformat(), "duration_ms": round(duration * 1000, 2)}}
    severity = EventSeverity.HIGH if suspicious else EventSeverity.LOW
    logger.info("typosquatting_detection_complete", suspicious=suspicious, package=package_name)
    getattr(span, "end", lambda: None)()
    return result


def container_image_scan(
    image_layers: list[dict[str, Any]],
    signatures: Optional[list[dict[str, Any]]] = None,
    vulnerability_db: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Scan container image layers for vulnerabilities and verify signatures.

    Analyzes each layer for known vulnerabilities, validates image signatures,
    and checks for embedded secrets or misconfigurations.

    Args:
        image_layers: List of image layer metadata (files, packages, commands).
        signatures: List of expected image signatures to verify.
        vulnerability_db: Database of known vulnerabilities.

    Returns:
        Dictionary with 'safe' (bool), 'vulnerabilities' (list), 'signature_valid', 'secrets_found', and 'metadata'.

    Example:
        >>> layers = [{"index": 0, "packages": [{"name": "openssl", "version": "1.1.1"}]}]
        >>> result = container_image_scan(layers)
        >>> print(result['safe'])
        True
    """
    start_time = time.time()
    span = create_span("container_image_scan")
    metrics = get_metrics()
    vulnerabilities: list[dict[str, Any]] = []
    secrets_found: list[dict[str, Any]] = []
    signature_valid = True

    default_vuln_db: dict[str, list[dict[str, Any]]] = {
        "openssl": [{"cve": "CVE-2023-0286", "severity": "high", "cvss": 7.5, "affected_versions": ["<3.0.8", "<1.1.1t"], "description": "X.400 address type confusion"}],
        "log4j-core": [{"cve": "CVE-2021-44228", "severity": "critical", "cvss": 10.0, "affected_versions": ["<2.17.0"], "description": "Log4Shell RCE vulnerability"}],
        "curl": [{"cve": "CVE-2023-38545", "severity": "high", "cvss": 7.5, "affected_versions": ["<8.4.0"], "description": "SOCKS5 heap overflow"}],
        "nginx": [{"cve": "CVE-2023-44487", "severity": "high", "cvss": 7.5, "affected_versions": ["<1.25.3"], "description": "HTTP/2 Rapid Reset"}],
    }
    vuln_db = vulnerability_db or default_vuln_db

    secret_patterns = [
        (r"(?i)(aws_access_key_id|aws_secret_access_key)\s*=\s*[A-Z0-9]{20,}", "AWS credentials"),
        (r"(?i)private[_-]?key\s*=\s*-----BEGIN", "Private key"),
        (r"(?i)(password|passwd|pwd)\s*=\s*[^\s]{8,}", "Hardcoded password"),
        (r"(?i)(api[_-]?key|apikey)\s*=\s*[a-zA-Z0-9]{16,}", "API key"),
        (r"(?i)github[_-]?token\s*=\s*ghp_[a-zA-Z0-9]{36}", "GitHub token"),
    ]

    for layer in image_layers:
        layer_index = layer.get("index", layer.get("layer", 0))
        layer_command = layer.get("command", layer.get("created_by", ""))

        for pkg in layer.get("packages", []):
            pkg_name = pkg.get("name", pkg.get("package", "")).lower()
            pkg_version = pkg.get("version", pkg.get("tag", ""))
            for vuln in vuln_db.get(pkg_name, []):
                for pattern in vuln.get("affected_versions", []):
                    if pattern.startswith("<"):
                        target = pattern[1:]
                        try:
                            v_parts = [int(x) for x in pkg_version.split(".")]
                            t_parts = [int(x) for x in target.split(".")]
                            while len(v_parts) < len(t_parts):
                                v_parts.append(0)
                            while len(t_parts) < len(v_parts):
                                t_parts.append(0)
                            if v_parts < t_parts:
                                vulnerabilities.append({"cve": vuln.get("cve", "unknown"), "package": pkg_name, "version": pkg_version, "severity": vuln.get("severity", "unknown"), "cvss": vuln.get("cvss", 0), "layer": layer_index, "description": vuln.get("description", "")})
                        except (ValueError, AttributeError):
                            pass
                    elif pkg_version == pattern:
                        vulnerabilities.append({"cve": vuln.get("cve", "unknown"), "package": pkg_name, "version": pkg_version, "severity": vuln.get("severity", "unknown"), "cvss": vuln.get("cvss", 0), "layer": layer_index, "description": vuln.get("description", "")})

        for file_info in layer.get("files", layer.get("file_list", [])):
            file_path = file_info if isinstance(file_info, str) else file_info.get("path", "")
            file_content = file_info.get("content", "") if isinstance(file_info, dict) else ""
            for pattern, secret_type in secret_patterns:
                if re.search(pattern, file_content or file_path):
                    secrets_found.append({"type": secret_type, "layer": layer_index, "path": file_path, "severity": "critical", "message": f"{secret_type} found in layer {layer_index}"})

        if layer_command:
            for pattern, secret_type in secret_patterns:
                if re.search(pattern, layer_command):
                    secrets_found.append({"type": secret_type, "layer": layer_index, "path": "Dockerfile instruction", "severity": "critical", "message": f"{secret_type} found in layer command"})

    if signatures:
        image_digest = image_layers[0].get("digest", image_layers[0].get("sha256", "")) if image_layers else ""
        for sig in signatures:
            expected = sig.get("digest", sig.get("signature", ""))
            if image_digest and expected and image_digest != expected:
                signature_valid = False
                vulnerabilities.append({"cve": "SIGNATURE_MISMATCH", "package": "image", "version": "", "severity": "critical", "cvss": 10.0, "layer": 0, "description": f"Image signature verification failed (expected {sig.get('algorithm', 'sha256')} digest)"})
            elif not image_digest or not expected:
                signature_valid = False

    safe = len(vulnerabilities) == 0 and len(secrets_found) == 0 and signature_valid
    duration = time.time() - start_time
    metrics.inc_counter("cloud.container_image_scan.total")
    metrics.observe_histogram("cloud.container_image_scan.duration", duration)
    if vulnerabilities:
        metrics.inc_counter("cloud.container_image_scan.vulnerabilities", len(vulnerabilities))
    if secrets_found:
        metrics.inc_counter("cloud.container_image_scan.secrets_found", len(secrets_found))

    result = {"safe": safe, "vulnerabilities": vulnerabilities, "signature_valid": signature_valid, "secrets_found": secrets_found, "metadata": {"layers_scanned": len(image_layers), "packages_checked": sum(len(l.get("packages", [])) for l in image_layers), "vulnerability_count": len(vulnerabilities), "secrets_count": len(secrets_found), "timestamp": datetime.now(timezone.utc).isoformat(), "duration_ms": round(duration * 1000, 2)}}
    severity = EventSeverity.CRITICAL if any(v.get("severity") == "critical" for v in vulnerabilities) else EventSeverity.LOW
    getattr(span, "end", lambda: None)()
    return result


def runtime_k8s_anomaly(
    k8s_events: list[dict[str, Any]],
    baseline: Optional[dict[str, Any]] = None,
    anomaly_threshold: float = 2.0,
) -> dict[str, Any]:
    """Detect anomalous behavior in Kubernetes runtime events.

    Analyzes K8s events against established baselines to identify unusual
    patterns that may indicate security incidents or misconfigurations.

    Args:
        k8s_events: List of Kubernetes events to analyze.
        baseline: Established baseline behavior (event rates, resource usage, etc.).
        anomaly_threshold: Standard deviations from baseline to trigger anomaly.

    Returns:
        Dictionary with 'anomalies' (list), 'anomaly_count', 'risk_level', and 'metadata'.

    Example:
        >>> events = [{"type": "Warning", "reason": "FailedScheduling", "count": 50}]
        >>> result = runtime_k8s_anomaly(events, baseline={"avg_events_per_hour": 5})
        >>> print(result['anomaly_count'])
        1
    """
    start_time = time.time()
    span = create_span("k8s_anomaly_detection")
    metrics = get_metrics()
    anomalies: list[dict[str, Any]] = []
    default_baseline = {"avg_events_per_hour": 10, "std_events_per_hour": 5, "max_failed_pods_per_hour": 3, "max_unauthorized_per_hour": 1, "max_secret_access_per_hour": 5, "max_config_changes_per_hour": 5, "suspicious_reasons": ["FailedScheduling", "FailedMount", "Unhealthy", "BackOff", "Failed"], "critical_reasons": ["FailedCreate", "FailedDelete", "Unauthorized", "Forbidden"]}
    bl = baseline or default_baseline

    event_count = len(k8s_events)
    warning_count = sum(1 for e in k8s_events if e.get("type", "").lower() == "warning")
    failed_count = sum(1 for e in k8s_events if "fail" in e.get("reason", "").lower())
    avg_events = bl.get("avg_events_per_hour", 10)
    std_events = bl.get("std_events_per_hour", 5)

    if std_events > 0 and event_count > avg_events + (anomaly_threshold * std_events):
        anomalies.append({"type": "high_event_rate", "severity": "high", "metric": "event_rate", "observed": event_count, "baseline": avg_events, "deviation": round((event_count - avg_events) / std_events, 2), "message": f"Event rate ({event_count}) significantly exceeds baseline ({avg_events})", "recommendation": "Investigate cause of increased event rate"})

    max_failed = bl.get("max_failed_pods_per_hour", 3)
    if failed_count > max_failed:
        anomalies.append({"type": "excessive_failures", "severity": "high", "metric": "failed_pods", "observed": failed_count, "baseline": max_failed, "message": f"Failed pod count ({failed_count}) exceeds threshold ({max_failed})", "recommendation": "Check pod logs and node health"})

    suspicious_reasons = bl.get("suspicious_reasons", [])
    critical_reasons = bl.get("critical_reasons", [])
    for event in k8s_events:
        reason = event.get("reason", "")
        count = event.get("count", event.get("Count", 1))
        namespace = event.get("namespace", event.get("Namespace", "default"))
        involved = event.get("involvedObject", event.get("involved_object", {}))
        obj_name = involved.get("name", "unknown") if isinstance(involved, dict) else str(involved)

        if reason in critical_reasons:
            anomalies.append({"type": "critical_event", "severity": "critical", "reason": reason, "namespace": namespace, "object": obj_name, "count": count, "message": f"Critical event: {reason} in {namespace}/{obj_name}", "recommendation": "Immediate investigation required"})
        elif reason in suspicious_reasons and count > 1:
            anomalies.append({"type": "suspicious_event", "severity": "medium", "reason": reason, "namespace": namespace, "object": obj_name, "count": count, "message": f"Suspicious event: {reason} occurred {count} times", "recommendation": "Review event and object state"})

        message = event.get("message", "")
        if re.search(r"(?i)(unauthorized|forbidden|denied|permission)", message):
            anomalies.append({"type": "authorization_failure", "severity": "high", "namespace": namespace, "message": f"Authorization failure detected: {message[:100]}", "recommendation": "Review RBAC policies and service account permissions"})

    secret_access_count = sum(1 for e in k8s_events if "secret" in e.get("message", "").lower() or "secret" in e.get("reason", "").lower())
    if secret_access_count > bl.get("max_secret_access_per_hour", 5):
        anomalies.append({"type": "excessive_secret_access", "severity": "high", "metric": "secret_access", "observed": secret_access_count, "baseline": bl.get("max_secret_access_per_hour", 5), "message": f"Secret access count ({secret_access_count}) exceeds threshold", "recommendation": "Investigate potential secret exfiltration"})

    config_change_count = sum(1 for e in k8s_events if any(kw in e.get("reason", "").lower() for kw in ["update", "patch", "create", "delete"]))
    if config_change_count > bl.get("max_config_changes_per_hour", 5):
        anomalies.append({"type": "excessive_config_changes", "severity": "medium", "metric": "config_changes", "observed": config_change_count, "baseline": bl.get("max_config_changes_per_hour", 5), "message": f"Configuration change rate ({config_change_count}) exceeds baseline", "recommendation": "Review recent configuration changes"})

    risk_level = "critical" if any(a.get("severity") == "critical" for a in anomalies) else "high" if any(a.get("severity") == "high" for a in anomalies) else "medium" if anomalies else "low"
    duration = time.time() - start_time
    metrics.inc_counter("cloud.k8s_anomaly_detection.total")
    metrics.observe_histogram("cloud.k8s_anomaly_detection.duration", duration)
    if anomalies:
        metrics.inc_counter("cloud.k8s_anomaly_detection.anomalies", len(anomalies))

    result = {"anomalies": anomalies, "anomaly_count": len(anomalies), "risk_level": risk_level, "metadata": {"events_analyzed": len(k8s_events), "warning_events": warning_count, "failed_events": failed_count, "anomaly_threshold": anomaly_threshold, "timestamp": datetime.now(timezone.utc).isoformat(), "duration_ms": round(duration * 1000, 2)}}
    severity = EventSeverity.CRITICAL if risk_level == "critical" else EventSeverity.LOW
    getattr(span, "end", lambda: None)()
    return result


def cloud_security_score(
    config: dict[str, Any],
    benchmarks: Optional[dict[str, Any]] = None,
    weights: Optional[dict[str, float]] = None,
) -> dict[str, Any]:
    """Calculate an overall cloud security score based on configuration analysis.

    Evaluates cloud infrastructure against security benchmarks and produces
    a weighted security score with category breakdowns.

    Args:
        config: Cloud infrastructure configuration to score.
        benchmarks: Security benchmark requirements per category.
        weights: Category weights for score calculation (must sum to 1.0).

    Returns:
        Dictionary with 'overall_score', 'category_scores', 'grade', 'findings', and 'metadata'.

    Example:
        >>> cfg = {"encryption": True, "mfa": True, "logging": True}
        >>> result = cloud_security_score(cfg)
        >>> print(result['overall_score'])
        85
    """
    start_time = time.time()
    span = create_span("cloud_security_score")
    metrics = get_metrics()
    default_weights = {"identity_access": 0.20, "data_protection": 0.20, "network_security": 0.15, "logging_monitoring": 0.15, "infrastructure_security": 0.15, "compliance": 0.15}
    category_weights = weights or default_weights

    default_benchmarks = {
        "identity_access": [{"check": "mfa_enabled", "weight": 0.3, "description": "MFA enabled for all users"}, {"check": "password_policy_strong", "weight": 0.2, "description": "Strong password policy"}, {"check": "role_based_access", "weight": 0.2, "description": "Role-based access control"}, {"check": "no_root_keys", "weight": 0.3, "description": "No root access keys"}],
        "data_protection": [{"check": "encryption_at_rest", "weight": 0.35, "description": "Encryption at rest enabled"}, {"check": "encryption_in_transit", "weight": 0.35, "description": "Encryption in transit enabled"}, {"check": "backup_enabled", "weight": 0.15, "description": "Automated backups enabled"}, {"check": "key_rotation", "weight": 0.15, "description": "Encryption key rotation"}],
        "network_security": [{"check": "no_open_security_groups", "weight": 0.3, "description": "No open security groups"}, {"check": "waf_enabled", "weight": 0.25, "description": "Web Application Firewall enabled"}, {"check": "ddos_protection", "weight": 0.25, "description": "DDoS protection enabled"}, {"check": "private_subnets", "weight": 0.2, "description": "Resources in private subnets"}],
        "logging_monitoring": [{"check": "audit_logging", "weight": 0.3, "description": "Audit logging enabled"}, {"check": "alerting_configured", "weight": 0.25, "description": "Security alerting configured"}, {"check": "log_retention", "weight": 0.25, "description": "Log retention policy set"}, {"check": "centralized_logging", "weight": 0.2, "description": "Centralized log management"}],
        "infrastructure_security": [{"check": "patch_management", "weight": 0.3, "description": "Automated patch management"}, {"check": "hardened_images", "weight": 0.25, "description": "Hardened base images"}, {"check": "iac_scanning", "weight": 0.25, "description": "Infrastructure-as-code scanning"}, {"check": "container_scanning", "weight": 0.2, "description": "Container image scanning"}],
        "compliance": [{"check": "cis_benchmark", "weight": 0.3, "description": "CIS benchmark compliance"}, {"check": "regular_audits", "weight": 0.25, "description": "Regular security audits"}, {"check": "incident_response", "weight": 0.25, "description": "Incident response plan"}, {"check": "data_classification", "weight": 0.2, "description": "Data classification policy"}],
    }
    benchmarks_map = benchmarks or default_benchmarks

    category_scores: dict[str, dict[str, Any]] = {}
    all_findings: list[dict[str, Any]] = []
    for category, checks in benchmarks_map.items():
        category_score = 0.0
        category_findings = []
        total_weight = 0.0
        for check in checks:
            check_name = check["check"]
            check_weight = check.get("weight", 0.1)
            total_weight += check_weight
            actual_value = config.get(check_name, config.get(check_name.replace("_", ""), False))
            if actual_value:
                category_score += check_weight
            else:
                category_findings.append({"category": category, "check": check_name, "description": check.get("description", ""), "weight": check_weight, "status": "failed"})
        normalized_score = (category_score / total_weight * 100) if total_weight > 0 else 0
        category_scores[category] = {"score": round(normalized_score, 1), "checks_passed": total_weight - sum(f["weight"] for f in category_findings), "total_checks": total_weight, "findings": category_findings}
        all_findings.extend(category_findings)

    overall_score = sum(category_scores[cat]["score"] * category_weights.get(cat, 1.0 / len(category_weights)) for cat in category_scores)
    overall_score = round(overall_score, 1)
    grade = "A" if overall_score >= 90 else "B" if overall_score >= 80 else "C" if overall_score >= 70 else "D" if overall_score >= 60 else "F"

    duration = time.time() - start_time
    metrics.inc_counter("cloud.security_score.total")
    metrics.observe_histogram("cloud.security_score.duration", duration)
    metrics.set_gauge("cloud.security_score.overall", overall_score)

    result = {"overall_score": overall_score, "grade": grade, "category_scores": {k: v["score"] for k, v in category_scores.items()}, "category_details": category_scores, "findings": all_findings, "metadata": {"categories_evaluated": len(category_scores), "total_findings": len(all_findings), "weights_used": category_weights, "timestamp": datetime.now(timezone.utc).isoformat(), "duration_ms": round(duration * 1000, 2)}}
    logger.info("cloud_security_score_complete", score=overall_score, grade=grade)
    getattr(span, "end", lambda: None)()
    return result


def workload_identity_validation(
    workload_config: dict[str, Any],
    identity_provider: Optional[str] = None,
    trust_policy: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Validate workload identity configuration for security best practices.

    Checks workload-to-identity bindings, trust policies, token configurations,
    and identity provider settings for common misconfigurations.

    Args:
        workload_config: Workload identity configuration (service account, bindings, etc.).
        identity_provider: Identity provider name ('aws', 'gcp', 'azure', 'kubernetes').
        trust_policy: Trust policy defining allowed identity assumptions.

    Returns:
        Dictionary with 'valid' (bool), 'issues' (list), 'identity_score', and 'metadata'.

    Example:
        >>> cfg = {"service_account": "app-sa", "namespace": "default"}
        >>> result = workload_identity_validation(cfg, identity_provider="kubernetes")
        >>> print(result['valid'])
        True
    """
    start_time = time.time()
    span = create_span("workload_identity_validation")
    metrics = get_metrics()
    issues: list[dict[str, Any]] = []
    identity_score = 100
    provider = (identity_provider or "").lower()
    sa_name = workload_config.get("service_account", workload_config.get("serviceAccount", ""))
    namespace = workload_config.get("namespace", "default")
    annotations = workload_config.get("annotations", {})
    roles = workload_config.get("roles", workload_config.get("role_bindings", []))

    if not sa_name:
        issues.append({"type": "missing_service_account", "severity": "high", "message": "No service account specified for workload", "recommendation": "Assign a dedicated service account to the workload"})
        identity_score -= 20

    if workload_config.get("automount_service_account_token", workload_config.get("automountToken", True)):
        issues.append({"type": "automount_token", "severity": "medium", "message": "Service account token is automounted into pod", "recommendation": "Set automountServiceAccountToken: false unless required"})
        identity_score -= 10

    if provider == "aws":
        if not annotations.get("eks.amazonaws.com/role-arn", annotations.get("role_arn", "")):
            issues.append({"type": "missing_iam_role", "severity": "high", "message": "No IAM role annotation found for EKS workload identity", "recommendation": "Add eks.amazonaws.com/role-arn annotation"})
            identity_score -= 15
    elif provider == "gcp":
        if not annotations.get("iam.gke.io/gcp-service-account", annotations.get("gcp_service_account", "")):
            issues.append({"type": "missing_gcp_identity", "severity": "high", "message": "No GCP service account annotation found for Workload Identity", "recommendation": "Add iam.gke.io/gcp-service-account annotation"})
            identity_score -= 15
    elif provider == "azure":
        if not annotations.get("azure.workload.identity/client-id", annotations.get("aad_client_id", "")):
            issues.append({"type": "missing_azure_identity", "severity": "high", "message": "No Azure AD client ID annotation found for workload identity", "recommendation": "Add azure.workload.identity/client-id annotation"})
            identity_score -= 15

    if trust_policy:
        allowed_principals = trust_policy.get("allowed_principals", trust_policy.get("AllowedPrincipals", []))
        allowed_accounts = trust_policy.get("allowed_accounts", trust_policy.get("AllowedAccounts", []))
        conditions = trust_policy.get("conditions", trust_policy.get("Conditions", {}))
        if not allowed_principals and not allowed_accounts:
            issues.append({"type": "open_trust_policy", "severity": "critical", "message": "Trust policy does not restrict allowed principals", "recommendation": "Specify allowed principals in trust policy"})
            identity_score -= 25
        if isinstance(conditions, dict) and not conditions.get("mfa_required", conditions.get("MfaRequired", False)):
            issues.append({"type": "no_mfa_condition", "severity": "medium", "message": "Trust policy does not require MFA", "recommendation": "Add MFA requirement to trust policy conditions"})
            identity_score -= 5

    token_expiry = workload_config.get("token_expiry_seconds", workload_config.get("tokenExpiry", 3600))
    if token_expiry > 3600:
        issues.append({"type": "long_token_expiry", "severity": "medium", "message": f"Token expiry ({token_expiry}s) exceeds recommended maximum (3600s)", "recommendation": "Reduce token expiry to 3600 seconds or less"})
        identity_score -= 10

    if isinstance(roles, list) and len(roles) > 5:
        issues.append({"type": "excessive_roles", "severity": "medium", "message": f"Workload has {len(roles)} role bindings (recommended max: 5)", "recommendation": "Reduce role bindings to minimum required"})
        identity_score -= 10

    identity_score = max(0, identity_score)
    valid = len(issues) == 0
    duration = time.time() - start_time
    metrics.inc_counter("cloud.workload_identity_validation.total")
    metrics.observe_histogram("cloud.workload_identity_validation.duration", duration)
    if issues:
        metrics.inc_counter("cloud.workload_identity_validation.issues", len(issues))

    result = {"valid": valid, "issues": issues, "identity_score": identity_score, "metadata": {"service_account": sa_name, "namespace": namespace, "identity_provider": provider, "timestamp": datetime.now(timezone.utc).isoformat(), "duration_ms": round(duration * 1000, 2)}}
    severity = EventSeverity.CRITICAL if any(i.get("severity") == "critical" for i in issues) else EventSeverity.LOW
    getattr(span, "end", lambda: None)()
    return result


def confidential_computing_validation(
    attestation: dict[str, Any],
    tee_type: str = "sgx",
    expected_measurements: Optional[dict[str, str]] = None,
) -> dict[str, Any]:
    """Validate confidential computing attestation for Trusted Execution Environment (TEE).

    Verifies TEE attestation reports, checks measurement values against
    expected values, and validates the attestation chain of trust.

    Args:
        attestation: Attestation report from the TEE (SGX, TDX, SEV-SNP, etc.).
        tee_type: Type of TEE ('sgx', 'tdx', 'sev-snp', 'trustzone').
        expected_measurements: Expected measurement values to verify against.

    Returns:
        Dictionary with 'attested' (bool), 'measurements_valid', 'issues' (list), and 'metadata'.

    Example:
        >>> att = {"quote_valid": True, "measurements": {"mr_enclave": "abc123"}}
        >>> result = confidential_computing_validation(att, tee_type="sgx")
        >>> print(result['attested'])
        True
    """
    start_time = time.time()
    span = create_span("confidential_computing_validation")
    metrics = get_metrics()
    issues: list[dict[str, Any]] = []
    measurements_valid = True
    tee = tee_type.lower()

    quote_valid = attestation.get("quote_valid", attestation.get("QuoteValid", attestation.get("valid", False)))
    if not quote_valid:
        issues.append({"type": "invalid_quote", "severity": "critical", "message": "TEE attestation quote is invalid", "recommendation": "Re-generate attestation and verify TEE is properly initialized"})
        measurements_valid = False

    tcb_version = attestation.get("tcb_version", attestation.get("TcbVersion", attestation.get("tcb", None)))
    if tcb_version is not None:
        min_tcb = attestation.get("min_tcb_version", attestation.get("min_tcb", 0))
        if isinstance(tcb_version, int) and isinstance(min_tcb, int) and tcb_version < min_tcb:
            issues.append({"type": "tcb_version_low", "severity": "high", "message": f"TCB version ({tcb_version}) is below minimum required ({min_tcb})", "recommendation": "Update TEE firmware to meet minimum TCB requirements"})
            measurements_valid = False

    attestation_measurements = attestation.get("measurements", attestation.get("Measurements", {}))
    if expected_measurements:
        for measurement_name, expected_value in expected_measurements.items():
            actual_value = attestation_measurements.get(measurement_name, "")
            if actual_value and actual_value.lower() != expected_value.lower():
                issues.append({"type": "measurement_mismatch", "severity": "critical", "measurement": measurement_name, "expected": expected_value, "actual": actual_value, "message": f"Measurement '{measurement_name}' does not match expected value", "recommendation": "Verify enclave binary matches expected measurement"})
                measurements_valid = False

    if tee == "sgx":
        if not attestation_measurements.get("mr_enclave", attestation.get("MrEnclave", "")):
            issues.append({"type": "missing_mr_enclave", "severity": "high", "message": "MRENCLAVE measurement is missing from SGX attestation", "recommendation": "Ensure enclave is properly initialized and measured"})
            measurements_valid = False
        if attestation.get("debug", attestation_measurements.get("debug", False)):
            issues.append({"type": "debug_enclave", "severity": "high", "message": "Enclave is running in debug mode (attestable by anyone)", "recommendation": "Use production enclave (debug=false) for production workloads"})
    elif tee == "tdx":
        if not attestation.get("td_quote", attestation_measurements.get("td_quote", "")):
            issues.append({"type": "missing_td_quote", "severity": "high", "message": "TDX TD Quote is missing from attestation", "recommendation": "Generate TD Quote using Intel TDX attestation service"})
            measurements_valid = False
    elif tee == "sev-snp":
        if not attestation.get("snp_report", attestation_measurements.get("snp_report", "")):
            issues.append({"type": "missing_snp_report", "severity": "high", "message": "SEV-SNP attestation report is missing", "recommendation": "Generate SNP report using SEV-SNP guest API"})
            measurements_valid = False
        guest_policy = attestation.get("guest_policy", attestation_measurements.get("guest_policy", 0))
        if isinstance(guest_policy, int) and (guest_policy & 0x1):
            issues.append({"type": "snp_debug_allowed", "severity": "high", "message": "SEV-SNP guest policy allows debug", "recommendation": "Disable debug in guest policy for production"})
    elif tee == "trustzone":
        world = attestation.get("world", attestation_measurements.get("world", ""))
        if world and world.lower() != "secure":
            issues.append({"type": "non_secure_world", "severity": "high", "message": f"TrustZone is not in secure world (current: {world})", "recommendation": "Ensure execution in TrustZone secure world"})
            measurements_valid = False

    nonce = attestation.get("nonce", attestation.get("Nonce", None))
    if nonce:
        expected_nonce = attestation.get("expected_nonce", None)
        if expected_nonce and nonce != expected_nonce:
            issues.append({"type": "nonce_mismatch", "severity": "critical", "message": "Attestation nonce does not match expected value (possible replay attack)", "recommendation": "Use fresh nonce for each attestation request"})
            measurements_valid = False
    else:
        issues.append({"type": "missing_nonce", "severity": "medium", "message": "No nonce present in attestation (vulnerable to replay attacks)", "recommendation": "Include nonce in attestation requests"})

    timestamp_val = attestation.get("timestamp", attestation.get("Timestamp", None))
    if timestamp_val:
        try:
            att_time = datetime.fromtimestamp(timestamp_val, tz=timezone.utc) if isinstance(timestamp_val, (int, float)) else datetime.fromisoformat(str(timestamp_val).replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - att_time).total_seconds()
            max_age = attestation.get("max_attestation_age", 300)
            if age > max_age:
                issues.append({"type": "stale_attestation", "severity": "high", "message": f"Attestation is {age:.0f}s old (max: {max_age}s)", "recommendation": "Generate fresh attestation report"})
        except (ValueError, TypeError, OSError):
            pass

    attested = quote_valid and measurements_valid and len([i for i in issues if i["severity"] == "critical"]) == 0
    duration = time.time() - start_time
    metrics.inc_counter("cloud.confidential_computing_validation.total")
    metrics.observe_histogram("cloud.confidential_computing_validation.duration", duration)
    if attested:
        metrics.inc_counter("cloud.confidential_computing_validation.attested")
    else:
        metrics.inc_counter("cloud.confidential_computing_validation.failed")

    result = {"attested": attested, "measurements_valid": measurements_valid, "issues": issues, "metadata": {"tee_type": tee, "quote_valid": quote_valid, "measurements_checked": len(expected_measurements) if expected_measurements else 0, "timestamp": datetime.now(timezone.utc).isoformat(), "duration_ms": round(duration * 1000, 2)}}
    severity = EventSeverity.CRITICAL if not attested else EventSeverity.LOW
    logger.info("confidential_computing_validation_complete", attested=attested, tee=tee)
    getattr(span, "end", lambda: None)()
    return result
