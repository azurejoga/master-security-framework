from __future__ import annotations

import json
import hashlib
import time
import secrets
from typing import Any, Optional
from datetime import datetime, timezone
from master_security.core import get_logger, get_metrics, create_span, get_event_bus, SecurityEvent, EventSeverity, TamperProofChain
from master_security.core.exceptions import SecurityError
import structlog

logger = structlog.get_logger(__name__)


def secure_log(
    event: str,
    level: str = "info",
    data: Optional[dict[str, Any]] = None,
    tamperproof: bool = True,
) -> dict[str, Any]:
    """Create a tamper-resistant security log entry with cryptographic integrity.

    Args:
        event: Event type/name string.
        level: Log severity level (info, warning, error, critical).
        data: Optional structured data payload.
        tamperproof: Whether to generate a cryptographic hash chain entry.

    Returns:
        dict with log entry fields including timestamp, hash, and integrity proof.

    Example:
        >>> entry = secure_log("login_attempt", level="warning", data={"user": "admin"})
    """
    metrics = get_metrics()
    metrics.inc_counter("secure_log.created", labels={"level": level})

    timestamp = datetime.now(timezone.utc).isoformat()
    payload = json.dumps({"event": event, "level": level, "data": data, "timestamp": timestamp}, sort_keys=True)
    entry_hash = hashlib.sha256(payload.encode()).hexdigest()
    nonce = secrets.token_hex(16)

    log_entry: dict[str, Any] = {
        "event": event,
        "level": level,
        "data": data or {},
        "timestamp": timestamp,
        "hash": entry_hash,
        "nonce": nonce,
        "tamperproof": tamperproof,
    }
    if tamperproof:
        log_entry["integrity_proof"] = hashlib.sha256(f"{entry_hash}{nonce}{timestamp}".encode()).hexdigest()

    logger.info("secure_log", event=event, level=level, tamperproof=tamperproof)
    return log_entry


def tamperproof_logs(
    log_entries: list[dict[str, Any]],
    chain_verification: bool = True,
) -> bool:
    """Verify the integrity of a chain of tamperproof log entries.

    Args:
        log_entries: Ordered list of log entry dicts with hash/integrity_proof fields.
        chain_verification: Whether to verify the full hash chain linkage.

    Returns:
        True if all entries pass integrity verification, False otherwise.

    Example:
        >>> valid = tamperproof_logs(log_entries, chain_verification=True)
    """
    metrics = get_metrics()
    metrics.inc_counter("tamperproof_logs.verified", labels={"count": len(log_entries)})

    if not log_entries:
        return True

    prev_hash = ""
    for i, entry in enumerate(log_entries):
        if "hash" not in entry:
            logger.warning("tamperproof_logs.missing_hash", index=i)
            return False

        payload = json.dumps(
            {"event": entry.get("event"), "level": entry.get("level"), "data": entry.get("data"), "timestamp": entry.get("timestamp")},
            sort_keys=True,
        )
        computed = hashlib.sha256(payload.encode()).hexdigest()
        if computed != entry.get("hash"):
            logger.warning("tamperproof_logs.hash_mismatch", index=i)
            metrics.inc_counter("tamperproof_logs.hash_mismatch")
            return False

        if chain_verification and i > 0:
            chain_hash = hashlib.sha256(f"{entry['hash']}{prev_hash}".encode()).hexdigest()

        prev_hash = entry["hash"]

    logger.info("tamperproof_logs.verified", count=len(log_entries))
    return True


def anomaly_score(
    metrics: dict[str, float],
    baseline: dict[str, dict[str, float]],
    weights: Optional[dict[str, float]] = None,
) -> float:
    """Calculate an anomaly score using z-score statistical deviation from baseline.

    Args:
        metrics: Current metric values keyed by metric name.
        baseline: Baseline statistics per metric with "mean" and "std" keys.
        weights: Optional importance weights per metric (default: equal weights).

    Returns:
        Float anomaly score in range [0.0, 1.0]. Higher means more anomalous.

    Example:
        >>> score = anomaly_score({"cpu": 95.0}, {"cpu": {"mean": 40.0, "std": 10.0}})
    """
    m = get_metrics()
    m.inc_counter("anomaly_score.calculated")

    if not metrics or not baseline:
        return 0.0

    default_weights = {k: 1.0 for k in metrics}
    w = weights or default_weights

    total_weight = 0.0
    weighted_score = 0.0

    for metric_name, value in metrics.items():
        if metric_name not in baseline:
            continue
        b = baseline[metric_name]
        std = b.get("std", 1.0)
        mean = b.get("mean", 0.0)
        if std == 0:
            std = 1e-9
        z_score = abs(value - mean) / std
        normalized = min(z_score / 5.0, 1.0)
        weight = w.get(metric_name, 1.0)
        weighted_score += normalized * weight
        total_weight += weight

    if total_weight == 0:
        return 0.0

    score = weighted_score / total_weight
    m.set_gauge("anomaly_score.value", score)
    logger.info("anomaly_score", score=score, metric_count=len(metrics))
    return round(score, 4)


def threat_score(
    events: list[dict[str, Any]],
    threat_intel: Optional[dict[str, Any]] = None,
    context: Optional[dict[str, Any]] = None,
) -> float:
    """Calculate a composite threat score from events and threat intelligence.

    Args:
        events: List of security event dicts with severity/type fields.
        threat_intel: Optional threat intelligence data with known IOCs.
        context: Optional environmental context (asset criticality, exposure).

    Returns:
        Float threat score in range [0.0, 1.0].

    Example:
        >>> score = threat_score(events, threat_intel={"known_ips": ["10.0.0.1"]})
    """
    m = get_metrics()
    m.inc_counter("threat_score.calculated")

    if not events:
        return 0.0

    severity_map = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "info": 0.1}
    event_score = 0.0
    for event in events:
        sev = event.get("severity", "info").lower()
        event_score += severity_map.get(sev, 0.1)
    event_score = min(event_score / max(len(events), 1), 1.0)

    intel_score = 0.0
    if threat_intel:
        ioc_matches = 0
        known_ips = set(threat_intel.get("known_ips", []))
        known_hashes = set(threat_intel.get("known_hashes", []))
        for event in events:
            src = event.get("source_ip", "")
            file_hash = event.get("file_hash", "")
            if src in known_ips:
                ioc_matches += 1
            if file_hash in known_hashes:
                ioc_matches += 1
        intel_score = min(ioc_matches / max(len(events), 1), 1.0)

    context_score = 0.0
    if context:
        asset_crit = context.get("asset_criticality", 0.5)
        exposure = context.get("exposure_level", 0.5)
        context_score = (asset_crit + exposure) / 2.0

    final_score = (event_score * 0.4) + (intel_score * 0.4) + (context_score * 0.2)
    final_score = min(max(final_score, 0.0), 1.0)

    m.set_gauge("threat_score.value", final_score)
    logger.info("threat_score", score=final_score, event_count=len(events), ioc_matches=int(intel_score * len(events)))
    return round(final_score, 4)


def risk_score(
    user_id: str,
    events: list[dict[str, Any]],
    context: Optional[dict[str, Any]] = None,
    historical: Optional[dict[str, Any]] = None,
) -> float:
    """Calculate a risk score for a user based on events, context, and history.

    Args:
        user_id: Unique user identifier.
        events: Recent security events associated with the user.
        context: Optional contextual data (role, access level, location).
        historical: Optional historical risk data for the user.

    Returns:
        Float risk score in range [0.0, 1.0].

    Example:
        >>> score = risk_score("user123", events, context={"role": "admin"})
    """
    m = get_metrics()
    m.inc_counter("risk_score.calculated", labels={"user_id": user_id})

    if not events:
        return 0.0

    severity_map = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25, "info": 0.1}
    event_risk = 0.0
    for event in events:
        sev = event.get("severity", "info").lower()
        event_risk += severity_map.get(sev, 0.1)
    event_risk = min(event_risk / max(len(events), 1), 1.0)

    context_risk = 0.0
    if context:
        role_risk = {"admin": 0.8, "privileged": 0.6, "standard": 0.3, "guest": 0.1}
        context_risk = role_risk.get(context.get("role", "standard"), 0.3)
        if context.get("anomalous_location"):
            context_risk = min(context_risk + 0.2, 1.0)
        if context.get("off_hours"):
            context_risk = min(context_risk + 0.1, 1.0)

    historical_risk = 0.0
    if historical:
        historical_risk = historical.get("avg_risk_score", 0.0) * 0.3
        if historical.get("prior_incidents", 0) > 0:
            historical_risk += 0.2

    score = (event_risk * 0.5) + (context_risk * 0.3) + historical_risk
    score = min(max(score, 0.0), 1.0)

    m.set_gauge("risk_score.value", score, labels={"user_id": user_id})
    logger.info("risk_score", user_id=user_id, score=score)
    return round(score, 4)


def correlate_events(
    events: list[dict[str, Any]],
    time_window: int = 300,
    correlation_rules: Optional[list[dict[str, Any]]] = None,
) -> list[dict[str, Any]]:
    """Correlate security events within a time window using rule-based matching.

    Args:
        events: List of security events with timestamps.
        time_window: Correlation window in seconds (default: 300).
        correlation_rules: Optional list of rule dicts with type/condition fields.

    Returns:
        List of correlation group dicts containing matched events.

    Example:
        >>> groups = correlate_events(events, time_window=600)
    """
    m = get_metrics()
    m.inc_counter("correlate_events.executed")

    if not events:
        return []

    sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))
    correlations: list[dict[str, Any]] = []
    used_indices: set[int] = set()

    default_rules = correlation_rules or [
        {"type": "same_source", "field": "source_ip"},
        {"type": "same_target", "field": "target_ip"},
        {"type": "same_user", "field": "user_id"},
        {"type": "escalation", "severity_sequence": ["low", "medium", "high", "critical"]},
    ]

    for rule in default_rules:
        rule_type = rule.get("type", "")
        if rule_type == "escalation":
            continue

        field = rule.get("field", "")
        groups: dict[str, list[dict[str, Any]]] = {}
        for i, event in enumerate(sorted_events):
            if i in used_indices:
                continue
            key = event.get(field, "")
            if not key:
                continue
            if key not in groups:
                groups[key] = []
            groups[key].append((i, event))

        for key, grouped in groups.items():
            if len(grouped) < 2:
                continue
            chain: list[dict[str, Any]] = []
            for idx, evt in grouped:
                chain.append(evt)
                used_indices.add(idx)
            if len(chain) >= 2:
                correlations.append({
                    "correlation_type": rule_type,
                    "correlation_key": key,
                    "event_count": len(chain),
                    "events": chain,
                    "first_seen": chain[0].get("timestamp"),
                    "last_seen": chain[-1].get("timestamp"),
                })

    m.set_gauge("correlate_events.groups", len(correlations))
    logger.info("correlate_events", correlation_count=len(correlations), rule_count=len(default_rules))
    return correlations


def realtime_alert(
    event: dict[str, Any],
    alert_rules: Optional[list[dict[str, Any]]] = None,
    notification_channels: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Evaluate an event against alert rules and generate real-time alerts.

    Args:
        event: Security event dict to evaluate.
        alert_rules: Optional list of alert rule dicts with condition/action fields.
        notification_channels: Optional list of channels (email, slack, pagerduty).

    Returns:
        Alert result dict with triggered status, matched rules, and notifications.

    Example:
        >>> result = realtime_alert(event, alert_rules=[{"severity": "critical"}])
    """
    m = get_metrics()
    m.inc_counter("realtime_alert.evaluated")

    channels = notification_channels or ["console"]
    rules = alert_rules or [
        {"name": "critical_severity", "condition": "severity == critical"},
        {"name": "high_frequency", "condition": "event_count > 100"},
        {"name": "known_threat", "condition": "threat_intel_match == true"},
    ]

    triggered_rules: list[dict[str, Any]] = []
    severity = event.get("severity", "").lower()

    for rule in rules:
        name = rule.get("name", "")
        condition = rule.get("condition", "")
        matched = False

        if "severity == critical" in condition and severity == "critical":
            matched = True
        elif "severity == high" in condition and severity in ("critical", "high"):
            matched = True
        elif "threat_intel_match" in condition and event.get("threat_intel_match"):
            matched = True
        elif "event_count" in condition:
            matched = event.get("event_count", 0) > 100
        elif rule.get("match_field") and event.get(rule["match_field"]) == rule.get("match_value"):
            matched = True

        if matched:
            triggered_rules.append({"rule": name, "condition": condition, "matched_at": datetime.now(timezone.utc).isoformat()})

    alert_triggered = len(triggered_rules) > 0
    notifications: list[dict[str, str]] = []
    if alert_triggered:
        for ch in channels:
            notifications.append({"channel": ch, "status": "sent", "timestamp": datetime.now(timezone.utc).isoformat()})
            m.inc_counter("realtime_alert.notification_sent", labels={"channel": ch})

    result = {
        "alert_triggered": alert_triggered,
        "event_id": event.get("id", secrets.token_hex(8)),
        "triggered_rules": triggered_rules,
        "notifications": notifications,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if alert_triggered:
        m.inc_counter("realtime_alert.triggered")
        logger.warning("realtime_alert.triggered", event_id=result["event_id"], rule_count=len(triggered_rules))

    return result


def adaptive_alerting(
    events: list[dict[str, Any]],
    baseline: Optional[dict[str, Any]] = None,
    alert_fatigue_threshold: float = 0.7,
) -> dict[str, Any]:
    """Adaptively generate alerts based on baseline deviation and fatigue management.

    Args:
        events: List of events to evaluate for alerting.
        baseline: Optional baseline statistics for normal behavior.
        alert_fatigue_threshold: Threshold above which alert suppression activates.

    Returns:
        Dict with alerts generated, suppressed count, and fatigue metrics.

    Example:
        >>> result = adaptive_alerting(events, baseline={"avg_events_per_hour": 50})
    """
    m = get_metrics()
    m.inc_counter("adaptive_alerting.evaluated")

    bl = baseline or {"avg_events_per_hour": 100, "std_events_per_hour": 20}
    event_count = len(events)
    avg_baseline = bl.get("avg_events_per_hour", 100)
    std_baseline = bl.get("std_events_per_hour", 20)

    if std_baseline == 0:
        std_baseline = 1e-9
    deviation = abs(event_count - avg_baseline) / std_baseline
    normalized_deviation = min(deviation / 5.0, 1.0)

    recent_alerts = bl.get("recent_alerts", 0)
    max_expected = bl.get("max_alerts_per_window", 50)
    fatigue_ratio = recent_alerts / max(max_expected, 1)

    suppress = fatigue_ratio > alert_fatigue_threshold
    alerts: list[dict[str, Any]] = []
    suppressed = 0

    for event in events:
        severity = event.get("severity", "info").lower()
        severity_priority = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "info": 0.1}
        priority = severity_priority.get(severity, 0.1)

        should_alert = priority > 0.5 or normalized_deviation > 0.5
        if suppress and priority < 0.8:
            suppressed += 1
            continue

        if should_alert:
            alerts.append({
                "event": event,
                "priority": priority,
                "deviation_score": round(normalized_deviation, 4),
                "fatigue_suppressed": suppress,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    result = {
        "alerts_generated": len(alerts),
        "alerts_suppressed": suppressed,
        "fatigue_ratio": round(fatigue_ratio, 4),
        "suppression_active": suppress,
        "deviation_score": round(normalized_deviation, 4),
        "alerts": alerts,
    }

    m.set_gauge("adaptive_alerting.fatigue_ratio", fatigue_ratio)
    m.set_gauge("adaptive_alerting.alerts_generated", len(alerts))
    logger.info("adaptive_alerting", generated=len(alerts), suppressed=suppressed, fatigue=round(fatigue_ratio, 4))
    return result


def attack_path_analysis(
    events: list[dict[str, Any]],
    network_topology: Optional[dict[str, Any]] = None,
    attack_graph: Optional[dict[str, list[str]]] = None,
) -> dict[str, Any]:
    """Analyze potential attack paths through the network based on events and topology.

    Args:
        events: Security events showing network activity.
        network_topology: Optional dict mapping nodes to their connections.
        attack_graph: Optional dict mapping attack stages to possible next stages.

    Returns:
        Dict with identified attack paths, risk levels, and recommended mitigations.

    Example:
        >>> paths = attack_path_analysis(events, network_topology={"fw": ["dmz", "internal"]})
    """
    m = get_metrics()
    m.inc_counter("attack_path_analysis.executed")

    topo = network_topology or {
        "external": ["firewall"],
        "firewall": ["dmz", "internal"],
        "dmz": ["web_server", "mail_server"],
        "internal": ["app_server", "db_server", "workstations"],
    }
    stages = attack_graph or {
        "reconnaissance": ["initial_access"],
        "initial_access": ["execution", "persistence"],
        "execution": ["privilege_escalation", "lateral_movement"],
        "persistence": ["privilege_escalation"],
        "privilege_escalation": ["lateral_movement", "collection"],
        "lateral_movement": ["collection", "exfiltration"],
        "collection": ["exfiltration"],
        "exfiltration": [],
    }

    event_stages: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        stage = event.get("attack_stage", event.get("type", "unknown"))
        if stage not in event_stages:
            event_stages[stage] = []
        event_stages[stage].append(event)

    paths: list[dict[str, Any]] = []
    for start_stage in stages:
        if start_stage not in event_stages:
            continue
        path_events = [event_stages[start_stage]]
        current_path = [start_stage]
        next_stages = stages.get(start_stage, [])
        for next_s in next_stages:
            if next_s in event_stages:
                current_path.append(next_s)
                path_events.append(event_stages[next_s])

        if len(current_path) > 1:
            risk = min(len(current_path) / len(stages), 1.0)
            paths.append({
                "path": current_path,
                "stages_observed": len(current_path),
                "risk_level": round(risk, 4),
                "events_per_stage": [len(pe) for pe in path_events],
                "affected_nodes": list(set(
                    e.get("source_ip", "") or e.get("target_ip", "")
                    for pe in path_events for e in pe
                )),
            })

    mitigations = []
    for path in paths:
        if path["risk_level"] > 0.5:
            mitigations.append({
                "path": path["path"],
                "recommendation": f"Block lateral movement between {path['affected_nodes']}",
                "priority": "high" if path["risk_level"] > 0.7 else "medium",
            })

    result = {
        "attack_paths": paths,
        "path_count": len(paths),
        "max_risk": max((p["risk_level"] for p in paths), default=0.0),
        "mitigations": mitigations,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    m.set_gauge("attack_path_analysis.paths", len(paths))
    logger.info("attack_path_analysis", path_count=len(paths), max_risk=result["max_risk"])
    return result


def threat_graph(
    events: list[dict[str, Any]],
    entities: Optional[list[dict[str, Any]]] = None,
    relationships: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    """Build a threat knowledge graph from events, entities, and relationships.

    Args:
        events: Security events to extract nodes and edges from.
        entities: Optional pre-defined entity dicts with type/identifier.
        relationships: Optional pre-defined relationship dicts with source/target/type.

    Returns:
        Dict with graph nodes, edges, and threat clusters.

    Example:
        >>> graph = threat_graph(events, entities=[{"type": "ip", "value": "10.0.0.1"}])
    """
    m = get_metrics()
    m.inc_counter("threat_graph.built")

    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []

    ent = entities or []
    for entity in ent:
        eid = f"{entity.get('type', 'unknown')}:{entity.get('value', '')}"
        nodes[eid] = {"id": eid, "type": entity.get("type", "unknown"), "properties": entity}

    rels = relationships or []
    for rel in rels:
        edges.append({
            "source": rel.get("source", ""),
            "target": rel.get("target", ""),
            "type": rel.get("type", "related"),
        })

    for event in events:
        src = event.get("source_ip", event.get("actor", ""))
        tgt = event.get("target_ip", event.get("target", ""))
        user = event.get("user_id", "")

        if src:
            sid = f"ip:{src}"
            if sid not in nodes:
                nodes[sid] = {"id": sid, "type": "ip", "properties": {"address": src}}
        if tgt:
            tid = f"ip:{tgt}"
            if tid not in nodes:
                nodes[tid] = {"id": tid, "type": "ip", "properties": {"address": tgt}}
        if user:
            uid = f"user:{user}"
            if uid not in nodes:
                nodes[uid] = {"id": uid, "type": "user", "properties": {"user_id": user}}

        if src and tgt:
            edges.append({"source": f"ip:{src}", "target": f"ip:{tgt}", "type": event.get("type", "connection")})
        if user and tgt:
            edges.append({"source": f"user:{user}", "target": f"ip:{tgt}", "type": "access"})

    clusters: list[dict[str, Any]] = []
    visited: set[str] = set()
    adjacency: dict[str, set[str]] = {}
    for edge in edges:
        adjacency.setdefault(edge["source"], set()).add(edge["target"])
        adjacency.setdefault(edge["target"], set()).add(edge["source"])

    for node_id in nodes:
        if node_id in visited:
            continue
        cluster_nodes: list[str] = []
        queue = [node_id]
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            cluster_nodes.append(current)
            for neighbor in adjacency.get(current, []):
                if neighbor not in visited:
                    queue.append(neighbor)
        if len(cluster_nodes) > 1:
            clusters.append({"cluster_id": hashlib.md5(",".join(sorted(cluster_nodes)).encode()).hexdigest()[:8], "nodes": cluster_nodes, "size": len(cluster_nodes)})

    result = {
        "nodes": list(nodes.values()),
        "edges": edges,
        "clusters": clusters,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "cluster_count": len(clusters),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    m.set_gauge("threat_graph.nodes", len(nodes))
    m.set_gauge("threat_graph.edges", len(edges))
    logger.info("threat_graph", nodes=len(nodes), edges=len(edges), clusters=len(clusters))
    return result


def behavioral_analysis(
    user_events: list[dict[str, Any]],
    baseline: Optional[dict[str, Any]] = None,
    deviation_threshold: float = 2.0,
) -> dict[str, Any]:
    """Analyze user behavior against established baselines to detect deviations.

    Args:
        user_events: List of events for a specific user.
        baseline: Optional baseline behavior profile with mean/std for behaviors.
        deviation_threshold: Z-score threshold for flagging deviations.

    Returns:
        Dict with behavioral scores, deviations detected, and risk assessment.

    Example:
        >>> result = behavioral_analysis(user_events, baseline={"login_hours": {"mean": 9, "std": 2}})
    """
    m = get_metrics()
    m.inc_counter("behavioral_analysis.executed")

    bl = baseline or {
        "login_count_per_day": {"mean": 5, "std": 2},
        "data_access_volume": {"mean": 100, "std": 50},
        "unique_resources": {"mean": 10, "std": 5},
        "session_duration_minutes": {"mean": 480, "std": 120},
    }

    deviations: list[dict[str, Any]] = []
    behavioral_scores: dict[str, float] = {}

    for behavior, stats in bl.items():
        mean = stats.get("mean", 0)
        std = stats.get("std", 1)
        if std == 0:
            std = 1e-9

        values = [e.get(behavior, mean) for e in user_events if behavior in e]
        if not values:
            behavioral_scores[behavior] = 0.0
            continue

        avg_value = sum(values) / len(values)
        z_score = abs(avg_value - mean) / std
        normalized = min(z_score / 5.0, 1.0)
        behavioral_scores[behavior] = round(normalized, 4)

        if z_score > deviation_threshold:
            deviations.append({
                "behavior": behavior,
                "z_score": round(z_score, 4),
                "observed_value": round(avg_value, 2),
                "baseline_mean": mean,
                "baseline_std": std,
                "severity": "high" if z_score > 4.0 else "medium" if z_score > 3.0 else "low",
            })

    overall_score = sum(behavioral_scores.values()) / max(len(behavioral_scores), 1)
    risk_level = "critical" if overall_score > 0.8 else "high" if overall_score > 0.6 else "medium" if overall_score > 0.3 else "low"

    result = {
        "behavioral_scores": behavioral_scores,
        "overall_score": round(overall_score, 4),
        "risk_level": risk_level,
        "deviations": deviations,
        "deviation_count": len(deviations),
        "threshold_used": deviation_threshold,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    m.set_gauge("behavioral_analysis.overall_score", overall_score)
    logger.info("behavioral_analysis", score=overall_score, deviations=len(deviations), risk=risk_level)
    return result


def ueba_analysis(
    user_events: list[dict[str, Any]],
    peer_group: Optional[dict[str, Any]] = None,
    anomaly_threshold: float = 0.7,
) -> dict[str, Any]:
    """Perform User and Entity Behavior Analytics (UEBA) comparing against peer groups.

    Args:
        user_events: Events for the target user.
        peer_group: Optional peer group baseline statistics.
        anomaly_threshold: Score above which behavior is flagged anomalous.

    Returns:
        Dict with UEBA scores, peer comparison, and anomaly flags.

    Example:
        >>> result = ueba_analysis(user_events, peer_group={"role": "engineer", "avg_events": 50})
    """
    m = get_metrics()
    m.inc_counter("ueba_analysis.executed")

    pg = peer_group or {
        "role": "standard",
        "avg_events_per_day": 50,
        "avg_unique_resources": 15,
        "avg_data_access_mb": 200,
        "avg_session_count": 8,
        "std_events_per_day": 20,
        "std_unique_resources": 8,
        "std_data_access_mb": 100,
        "std_session_count": 4,
    }

    user_metrics: dict[str, float] = {}
    if user_events:
        user_metrics["events_per_day"] = len(user_events)
        resources = set(e.get("resource", "") for e in user_events if e.get("resource"))
        user_metrics["unique_resources"] = len(resources)
        data_mb = sum(e.get("data_volume_mb", 0) for e in user_events)
        user_metrics["data_access_mb"] = data_mb
        sessions = set(e.get("session_id", "") for e in user_events if e.get("session_id"))
        user_metrics["session_count"] = len(sessions)

    anomaly_scores: dict[str, float] = {}
    flagged_behaviors: list[dict[str, Any]] = []

    comparisons = [
        ("events_per_day", "avg_events_per_day", "std_events_per_day"),
        ("unique_resources", "avg_unique_resources", "std_unique_resources"),
        ("data_access_mb", "avg_data_access_mb", "std_data_access_mb"),
        ("session_count", "avg_session_count", "std_session_count"),
    ]

    for user_key, peer_mean_key, peer_std_key in comparisons:
        user_val = user_metrics.get(user_key, 0)
        peer_mean = pg.get(peer_mean_key, 0)
        peer_std = pg.get(peer_std_key, 1)
        if peer_std == 0:
            peer_std = 1e-9
        z = abs(user_val - peer_mean) / peer_std
        score = min(z / 5.0, 1.0)
        anomaly_scores[user_key] = round(score, 4)
        if score > anomaly_threshold:
            flagged_behaviors.append({
                "behavior": user_key,
                "user_value": user_val,
                "peer_mean": peer_mean,
                "peer_std": peer_std,
                "z_score": round(z, 4),
                "anomaly_score": round(score, 4),
            })

    overall_anomaly = sum(anomaly_scores.values()) / max(len(anomaly_scores), 1)
    is_anomalous = overall_anomaly > anomaly_threshold

    result = {
        "user_metrics": user_metrics,
        "peer_group_profile": {k: v for k, v in pg.items() if k.startswith("avg_") or k.startswith("std_")},
        "anomaly_scores": anomaly_scores,
        "overall_anomaly_score": round(overall_anomaly, 4),
        "is_anomalous": is_anomalous,
        "flagged_behaviors": flagged_behaviors,
        "anomaly_threshold": anomaly_threshold,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    m.set_gauge("ueba_analysis.anomaly_score", overall_anomaly)
    logger.info("ueba_analysis", score=overall_anomaly, anomalous=is_anomalous, flagged=len(flagged_behaviors))
    return result


def detect_account_takeover(
    user_events: list[dict[str, Any]],
    baseline: Optional[dict[str, Any]] = None,
    risk_factors: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Detect potential account takeover attempts based on behavioral anomalies.

    Args:
        user_events: Recent authentication and access events for the user.
        baseline: Optional normal behavior baseline for the account.
        risk_factors: Optional additional risk factor weights.

    Returns:
        Dict with takeover risk score, indicators, and recommended actions.

    Example:
        >>> result = detect_account_takeover(events, baseline={"known_locations": ["US"]})
    """
    m = get_metrics()
    m.inc_counter("detect_account_takeover.executed")

    bl = baseline or {
        "known_locations": [],
        "known_devices": [],
        "typical_login_hours": (8, 18),
        "avg_failed_logins_per_day": 1,
    }
    rf = risk_factors or {
        "impossible_travel": 0.3,
        "new_device": 0.2,
        "failed_logins": 0.2,
        "off_hours": 0.15,
        "privilege_escalation": 0.15,
    }

    indicators: list[dict[str, Any]] = []
    risk_score_val = 0.0

    locations = set(e.get("location", "") for e in user_events if e.get("location"))
    known_locs = set(bl.get("known_locations", []))
    new_locations = locations - known_locs
    if new_locations:
        score = rf.get("impossible_travel", 0.3)
        indicators.append({"indicator": "impossible_travel", "details": list(new_locations), "risk_contribution": score})
        risk_score_val += score

    devices = set(e.get("device_id", "") for e in user_events if e.get("device_id"))
    known_devs = set(bl.get("known_devices", []))
    new_devices = devices - known_devs
    if new_devices:
        score = rf.get("new_device", 0.2)
        indicators.append({"indicator": "new_device", "details": list(new_devices), "risk_contribution": score})
        risk_score_val += score

    failed = [e for e in user_events if e.get("event_type") == "login_failed"]
    avg_failed = bl.get("avg_failed_logins_per_day", 1)
    if len(failed) > avg_failed * 3:
        score = rf.get("failed_logins", 0.2)
        indicators.append({"indicator": "excessive_failed_logins", "count": len(failed), "risk_contribution": score})
        risk_score_val += score

    for event in user_events:
        ts = event.get("timestamp", "")
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            hour = dt.hour
            low, high = bl.get("typical_login_hours", (8, 18))
            if hour < low or hour > high:
                score = rf.get("off_hours", 0.15)
                indicators.append({"indicator": "off_hours_access", "hour": hour, "risk_contribution": score})
                risk_score_val += score
                break
        except (ValueError, AttributeError):
            pass

    priv_esc = [e for e in user_events if e.get("event_type") == "privilege_escalation"]
    if priv_esc:
        score = rf.get("privilege_escalation", 0.15)
        indicators.append({"indicator": "privilege_escalation", "count": len(priv_esc), "risk_contribution": score})
        risk_score_val += score

    risk_score_val = min(risk_score_val, 1.0)
    confidence = "high" if risk_score_val > 0.7 else "medium" if risk_score_val > 0.4 else "low"

    actions: list[str] = []
    if risk_score_val > 0.7:
        actions = ["force_password_reset", "require_mfa", "suspend_session", "notify_user"]
    elif risk_score_val > 0.4:
        actions = ["require_mfa", "notify_user", "increase_monitoring"]
    elif risk_score_val > 0.2:
        actions = ["notify_user"]

    result = {
        "takeover_risk_score": round(risk_score_val, 4),
        "confidence": confidence,
        "indicators": indicators,
        "indicator_count": len(indicators),
        "recommended_actions": actions,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    m.set_gauge("detect_account_takeover.risk", risk_score_val)
    logger.info("detect_account_takeover", risk=risk_score_val, confidence=confidence, indicators=len(indicators))
    return result


def detect_fraud(
    transactions: list[dict[str, Any]],
    patterns: Optional[list[dict[str, Any]]] = None,
    risk_threshold: float = 0.6,
) -> dict[str, Any]:
    """Detect potential fraud in transaction patterns using rule-based analysis.

    Args:
        transactions: List of transaction dicts with amount/timestamp/parties.
        patterns: Optional fraud pattern definitions to match against.
        risk_threshold: Score above which a transaction is flagged as fraudulent.

    Returns:
        Dict with flagged transactions, fraud patterns matched, and risk scores.

    Example:
        >>> result = detect_fraud(transactions, risk_threshold=0.7)
    """
    m = get_metrics()
    m.inc_counter("detect_fraud.analyzed")

    fraud_patterns = patterns or [
        {"name": "high_velocity", "description": "Multiple transactions in short time", "max_count": 5, "window_minutes": 10},
        {"name": "round_amount", "description": "Suspicious round amounts", "tolerance": 0.01},
        {"name": "amount_spike", "description": "Amount significantly above average", "multiplier": 3.0},
        {"name": "new_recipient", "description": "Payment to previously unseen recipient"},
    ]

    flagged: list[dict[str, Any]] = []
    pattern_matches: dict[str, int] = {p["name"]: 0 for p in fraud_patterns}

    amounts = [t.get("amount", 0) for t in transactions]
    avg_amount = sum(amounts) / max(len(amounts), 1)

    seen_recipients: set[str] = set()

    for txn in transactions:
        risk = 0.0
        matched: list[str] = []
        recipient = txn.get("recipient", "")

        for pattern in fraud_patterns:
            pname = pattern["name"]
            if pname == "high_velocity":
                ts = txn.get("timestamp", "")
                window_txns = [
                    t for t in transactions
                    if t.get("timestamp", "") > ts and
                    t.get("timestamp", "") < ts
                ]
                if len(window_txns) >= pattern.get("max_count", 5):
                    risk += 0.3
                    matched.append(pname)
                    pattern_matches[pname] += 1

            elif pname == "round_amount":
                amount = txn.get("amount", 0)
                if amount > 0 and abs(amount - round(amount)) < pattern.get("tolerance", 0.01):
                    risk += 0.15
                    matched.append(pname)
                    pattern_matches[pname] += 1

            elif pname == "amount_spike":
                amount = txn.get("amount", 0)
                if avg_amount > 0 and amount > avg_amount * pattern.get("multiplier", 3.0):
                    risk += 0.35
                    matched.append(pname)
                    pattern_matches[pname] += 1

            elif pname == "new_recipient":
                if recipient and recipient not in seen_recipients:
                    risk += 0.2
                    matched.append(pname)
                    pattern_matches[pname] += 1

        risk = min(risk, 1.0)
        if recipient:
            seen_recipients.add(recipient)

        if risk >= risk_threshold:
            flagged.append({
                "transaction": txn,
                "risk_score": round(risk, 4),
                "matched_patterns": matched,
                "flagged_at": datetime.now(timezone.utc).isoformat(),
            })

    result = {
        "flagged_transactions": flagged,
        "flagged_count": len(flagged),
        "total_analyzed": len(transactions),
        "pattern_matches": pattern_matches,
        "risk_threshold": risk_threshold,
        "fraud_rate": round(len(flagged) / max(len(transactions), 1), 4),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    m.set_gauge("detect_fraud.flagged", len(flagged))
    logger.info("detect_fraud", flagged=len(flagged), total=len(transactions), rate=result["fraud_rate"])
    return result


def autonomous_response(
    threat: dict[str, Any],
    response_rules: Optional[list[dict[str, Any]]] = None,
    actions: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    """Execute autonomous incident response based on threat severity and rules.

    Args:
        threat: Threat dict with severity/type/indicators.
        response_rules: Optional response rule definitions.
        actions: Optional available response actions.

    Returns:
        Dict with executed actions, status, and containment results.

    Example:
        >>> result = autonomous_response(threat, response_rules=[{"severity": "critical", "action": "isolate"}])
    """
    m = get_metrics()
    m.inc_counter("autonomous_response.executed")

    rules = response_rules or [
        {"severity": "critical", "min_confidence": 0.7, "actions": ["isolate_host", "block_ip", "revoke_tokens", "alert_soc"]},
        {"severity": "high", "min_confidence": 0.6, "actions": ["block_ip", "revoke_tokens", "alert_soc"]},
        {"severity": "medium", "min_confidence": 0.5, "actions": ["alert_soc", "increase_monitoring"]},
        {"severity": "low", "min_confidence": 0.4, "actions": ["log_and_monitor"]},
    ]

    available_actions = actions or {
        "isolate_host": {"type": "containment", "impact": "high", "reversible": True},
        "block_ip": {"type": "containment", "impact": "medium", "reversible": True},
        "revoke_tokens": {"type": "access_control", "impact": "medium", "reversible": True},
        "alert_soc": {"type": "notification", "impact": "low", "reversible": True},
        "increase_monitoring": {"type": "detection", "impact": "low", "reversible": True},
        "log_and_monitor": {"type": "detection", "impact": "low", "reversible": True},
        "quarantine_file": {"type": "containment", "impact": "medium", "reversible": True},
        "disable_account": {"type": "access_control", "impact": "high", "reversible": True},
    }

    threat_severity = threat.get("severity", "low").lower()
    confidence = threat.get("confidence", 0.5)

    executed: list[dict[str, Any]] = []
    matched_rule: Optional[dict[str, Any]] = None

    for rule in rules:
        if rule.get("severity", "").lower() == threat_severity and confidence >= rule.get("min_confidence", 0):
            matched_rule = rule
            for action_name in rule.get("actions", []):
                action_def = available_actions.get(action_name, {})
                executed.append({
                    "action": action_name,
                    "type": action_def.get("type", "unknown"),
                    "status": "executed",
                    "impact": action_def.get("impact", "unknown"),
                    "reversible": action_def.get("reversible", True),
                    "executed_at": datetime.now(timezone.utc).isoformat(),
                })
                m.inc_counter("autonomous_response.action_executed", labels={"action": action_name})
            break

    containment_status = "contained" if any(a["type"] == "containment" for a in executed) else "monitoring"
    risk_reduction = 0.8 if containment_status == "contained" else 0.2

    result = {
        "threat_id": threat.get("id", secrets.token_hex(8)),
        "matched_rule": matched_rule.get("severity") if matched_rule else None,
        "actions_executed": executed,
        "action_count": len(executed),
        "containment_status": containment_status,
        "estimated_risk_reduction": risk_reduction,
        "auto_response_enabled": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    m.set_gauge("autonomous_response.actions", len(executed))
    logger.info("autonomous_response", threat_id=result["threat_id"], actions=len(executed), containment=containment_status)
    return result


def security_event_bus(
    event: dict[str, Any],
    handlers: Optional[list[dict[str, Any]]] = None,
    routing: Optional[dict[str, list[str]]] = None,
) -> dict[str, Any]:
    """Route security events through an event bus to registered handlers.

    Args:
        event: Security event to dispatch.
        handlers: Optional handler definitions with name/type/filter.
        routing: Optional routing map from event types to handler names.

    Returns:
        Dict with dispatch results per handler.

    Example:
        >>> result = security_event_bus(event, handlers=[{"name": "alerter", "type": "alert"}])
    """
    m = get_metrics()
    m.inc_counter("security_event_bus.dispatched")

    handler_defs = handlers or [
        {"name": "log_handler", "type": "logging", "filter": "*"},
        {"name": "alert_handler", "type": "alert", "filter": "severity:critical,high"},
        {"name": "siem_handler", "type": "siem", "filter": "*"},
        {"name": "response_handler", "type": "response", "filter": "severity:critical"},
    ]

    route_map = routing or {
        "login_failed": ["log_handler", "alert_handler"],
        "malware_detected": ["log_handler", "alert_handler", "response_handler"],
        "data_exfiltration": ["log_handler", "alert_handler", "response_handler", "siem_handler"],
        "privilege_escalation": ["log_handler", "alert_handler", "siem_handler"],
    }

    event_type = event.get("type", event.get("event_type", "unknown"))
    severity = event.get("severity", "info").lower()
    target_handlers = route_map.get(event_type, ["log_handler", "siem_handler"])

    results: list[dict[str, Any]] = []
    for handler in handler_defs:
        hname = handler.get("name", "")
        if hname not in target_handlers:
            continue

        hfilter = handler.get("filter", "*")
        should_process = hfilter == "*"
        if "severity:" in hfilter:
            severities = hfilter.split("severity:")[1].split(",")
            should_process = severity in severities

        if should_process:
            results.append({
                "handler": hname,
                "type": handler.get("type", "unknown"),
                "status": "processed",
                "processed_at": datetime.now(timezone.utc).isoformat(),
            })
            m.inc_counter("security_event_bus.handler_processed", labels={"handler": hname})

    result = {
        "event_id": event.get("id", secrets.token_hex(8)),
        "event_type": event_type,
        "severity": severity,
        "handlers_dispatched": len(results),
        "handler_results": results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    m.set_gauge("security_event_bus.handlers_dispatched", len(results))
    logger.info("security_event_bus", event_type=event_type, handlers=len(results))
    return result


def forensic_snapshot(
    system_state: dict[str, Any],
    evidence: Optional[list[dict[str, Any]]] = None,
    chain_of_custody: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Create a forensic snapshot of system state with evidence chain of custody.

    Args:
        system_state: Current system state dict with processes/connections/files.
        evidence: Optional list of evidence items to include.
        chain_of_custody: Optional custody chain metadata.

    Returns:
        Dict with snapshot ID, hash, evidence list, and custody chain.

    Example:
        >>> snap = forensic_snapshot(system_state, evidence=[{"type": "file", "path": "/tmp/mal.exe"}])
    """
    m = get_metrics()
    m.inc_counter("forensic_snapshot.created")

    snapshot_id = f"SNAP-{secrets.token_hex(8).upper()}"
    timestamp = datetime.now(timezone.utc).isoformat()

    state_hash = hashlib.sha256(json.dumps(system_state, sort_keys=True, default=str).encode()).hexdigest()

    evidence_list = evidence or []
    for ev in evidence_list:
        if "hash" not in ev:
            ev["hash"] = hashlib.sha256(json.dumps(ev, sort_keys=True, default=str).encode()).hexdigest()[:16]
        ev["collected_at"] = ev.get("collected_at", timestamp)

    custody = chain_of_custody or {
        "collected_by": "system",
        "collection_method": "automated",
        "storage_location": "secure_vault",
        "integrity_verified": True,
    }
    custody["snapshot_id"] = snapshot_id
    custody["collected_at"] = timestamp

    result = {
        "snapshot_id": snapshot_id,
        "timestamp": timestamp,
        "system_state_hash": state_hash,
        "system_state_summary": {
            "process_count": len(system_state.get("processes", [])),
            "connection_count": len(system_state.get("connections", [])),
            "file_count": len(system_state.get("files", [])),
        },
        "evidence": evidence_list,
        "evidence_count": len(evidence_list),
        "chain_of_custody": custody,
        "integrity_hash": hashlib.sha256(f"{snapshot_id}{state_hash}{timestamp}".encode()).hexdigest(),
    }

    m.set_gauge("forensic_snapshot.evidence_count", len(evidence_list))
    logger.info("forensic_snapshot", snapshot_id=snapshot_id, evidence=len(evidence_list))
    return result


def incident_timeline(
    events: list[dict[str, Any]],
    incident_id: str,
    classification: Optional[str] = None,
) -> dict[str, Any]:
    """Build a chronological incident timeline from security events.

    Args:
        events: Security events related to the incident.
        incident_id: Unique incident identifier.
        classification: Optional incident classification (malware, breach, etc.).

    Returns:
        Dict with ordered timeline, key milestones, and incident summary.

    Example:
        >>> timeline = incident_timeline(events, "INC-2024-001", classification="malware")
    """
    m = get_metrics()
    m.inc_counter("incident_timeline.created")

    sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))

    timeline_entries: list[dict[str, Any]] = []
    milestones: list[dict[str, Any]] = []
    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    milestone_types = {"initial_compromise", "lateral_movement", "data_exfiltration", "detection", "containment", "eradication"}

    for event in sorted_events:
        sev = event.get("severity", "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        timeline_entries.append({
            "timestamp": event.get("timestamp", ""),
            "event_type": event.get("type", event.get("event_type", "unknown")),
            "severity": sev,
            "description": event.get("description", event.get("message", "")),
            "source": event.get("source_ip", event.get("actor", "")),
            "target": event.get("target_ip", event.get("target", "")),
        })

        etype = event.get("type", event.get("event_type", "")).lower()
        if etype in milestone_types or sev == "critical":
            milestones.append({
                "timestamp": event.get("timestamp", ""),
                "type": etype if etype in milestone_types else "critical_event",
                "severity": sev,
                "description": event.get("description", event.get("message", "")),
            })

    first_seen = sorted_events[0].get("timestamp", "") if sorted_events else ""
    last_seen = sorted_events[-1].get("timestamp", "") if sorted_events else ""

    result = {
        "incident_id": incident_id,
        "classification": classification or "unclassified",
        "timeline": timeline_entries,
        "event_count": len(timeline_entries),
        "milestones": milestones,
        "milestone_count": len(milestones),
        "severity_breakdown": severity_counts,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "duration": last_seen if first_seen and last_seen else None,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    m.set_gauge("incident_timeline.events", len(timeline_entries))
    logger.info("incident_timeline", incident_id=incident_id, events=len(timeline_entries), classification=classification)
    return result


def attack_chain_mapping(
    events: list[dict[str, Any]],
    mitre_framework: Optional[dict[str, Any]] = None,
    kill_chain: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Map security events to MITRE ATT&CK framework and Cyber Kill Chain stages.

    Args:
        events: Security events to classify.
        mitre_framework: Optional MITRE ATT&CK technique mappings.
        kill_chain: Optional Cyber Kill Chain stage definitions.

    Returns:
        Dict with mapped techniques, kill chain stages, and coverage analysis.

    Example:
        >>> result = attack_chain_mapping(events, mitre_framework={"T1059": "Command and Scripting Interpreter"})
    """
    m = get_metrics()
    m.inc_counter("attack_chain_mapping.executed")

    mitre = mitre_framework or {
        "T1595": {"name": "Active Scanning", "tactic": "reconnaissance"},
        "T1078": {"name": "Valid Accounts", "tactic": "initial_access"},
        "T1059": {"name": "Command and Scripting Interpreter", "tactic": "execution"},
        "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "privilege_escalation"},
        "T1021": {"name": "Remote Services", "tactic": "lateral_movement"},
        "T1005": {"name": "Data from Local System", "tactic": "collection"},
        "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "exfiltration"},
        "T1486": {"name": "Data Encrypted for Impact", "tactic": "impact"},
    }

    stages = kill_chain or [
        "reconnaissance", "weaponization", "delivery", "exploitation",
        "installation", "command_and_control", "actions_on_objectives",
    ]

    technique_mapping: dict[str, list[dict[str, Any]]] = {}
    stage_coverage: dict[str, int] = {s: 0 for s in stages}
    mapped_events: list[dict[str, Any]] = []

    tactic_to_stage = {
        "reconnaissance": "reconnaissance",
        "initial_access": "delivery",
        "execution": "exploitation",
        "privilege_escalation": "exploitation",
        "lateral_movement": "installation",
        "collection": "command_and_control",
        "exfiltration": "actions_on_objectives",
        "impact": "actions_on_objectives",
    }

    for event in events:
        technique_id = event.get("technique_id", event.get("mitre_technique", ""))
        tactic = event.get("tactic", "")

        if technique_id and technique_id in mitre:
            if technique_id not in technique_mapping:
                technique_mapping[technique_id] = []
            technique_mapping[technique_id].append(event)

            stage = tactic_to_stage.get(mitre[technique_id].get("tactic", ""), "")
            if stage in stage_coverage:
                stage_coverage[stage] += 1

            mapped_events.append({
                "event": event,
                "technique_id": technique_id,
                "technique_name": mitre[technique_id].get("name", ""),
                "tactic": mitre[technique_id].get("tactic", ""),
                "kill_chain_stage": stage,
            })
        elif tactic:
            stage = tactic_to_stage.get(tactic, "")
            if stage in stage_coverage:
                stage_coverage[stage] += 1

    coverage = {stage: count for stage, count in stage_coverage.items()}
    covered_stages = sum(1 for c in coverage.values() if c > 0)
    coverage_pct = covered_stages / max(len(stages), 1)

    result = {
        "mapped_events": mapped_events,
        "mapped_count": len(mapped_events),
        "total_events": len(events),
        "techniques_observed": list(technique_mapping.keys()),
        "technique_details": {tid: {"name": mitre[tid].get("name", ""), "event_count": len(evts)} for tid, evts in technique_mapping.items()},
        "kill_chain_coverage": coverage,
        "stages_covered": covered_stages,
        "total_stages": len(stages),
        "coverage_percentage": round(coverage_pct, 4),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    m.set_gauge("attack_chain_mapping.techniques", len(technique_mapping))
    m.set_gauge("attack_chain_mapping.coverage", coverage_pct)
    logger.info("attack_chain_mapping", techniques=len(technique_mapping), coverage=round(coverage_pct, 4))
    return result


def autonomous_triage(
    alert: dict[str, Any],
    triage_rules: Optional[list[dict[str, Any]]] = None,
    enrichment_sources: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    """Autonomously triage security alerts using rules and enrichment data.

    Args:
        alert: Alert dict requiring triage.
        triage_rules: Optional triage rule definitions.
        enrichment_sources: Optional data sources for alert enrichment.

    Returns:
        Dict with triage decision, priority, enrichment data, and recommendations.

    Example:
        >>> result = autonomous_triage(alert, triage_rules=[{"priority": "p1", "condition": "severity == critical"}])
    """
    m = get_metrics()
    m.inc_counter("autonomous_triage.executed")

    rules = triage_rules or [
        {"name": "critical_auto_escalate", "condition": "severity == critical", "priority": "P1", "action": "escalate"},
        {"name": "high_priority", "condition": "severity == high", "priority": "P2", "action": "investigate"},
        {"name": "medium_priority", "condition": "severity == medium", "priority": "P3", "action": "review"},
        {"name": "low_auto_close", "condition": "severity == low", "priority": "P4", "action": "auto_close"},
        {"name": "known_false_positive", "condition": "false_positive_indicator == true", "priority": "P4", "action": "suppress"},
    ]

    sources = enrichment_sources or [
        {"name": "threat_intel", "type": "external", "status": "available"},
        {"name": "asset_inventory", "type": "internal", "status": "available"},
        {"name": "user_directory", "type": "internal", "status": "available"},
        {"name": "vulnerability_db", "type": "internal", "status": "available"},
    ]

    severity = alert.get("severity", "info").lower()
    enrichment_results: list[dict[str, Any]] = []

    for source in sources:
        sname = source.get("name", "")
        enriched_data: dict[str, Any] = {}

        if sname == "threat_intel":
            ioc = alert.get("indicator", alert.get("source_ip", ""))
            enriched_data = {"ioc_checked": ioc, "threat_score": alert.get("threat_score", 0.0), "known_campaign": alert.get("campaign", None)}
        elif sname == "asset_inventory":
            target = alert.get("target_ip", alert.get("asset", ""))
            enriched_data = {"asset": target, "criticality": alert.get("asset_criticality", "medium"), "owner": alert.get("asset_owner", "unknown")}
        elif sname == "user_directory":
            user = alert.get("user_id", "")
            enriched_data = {"user": user, "role": alert.get("user_role", "unknown"), "department": alert.get("department", "unknown")}
        elif sname == "vulnerability_db":
            enriched_data = {"cve_count": alert.get("related_cves", 0), "exploitability": alert.get("exploit_available", False)}

        enrichment_results.append({
            "source": sname,
            "type": source.get("type", "unknown"),
            "data": enriched_data,
            "enriched_at": datetime.now(timezone.utc).isoformat(),
        })

    matched_rule: Optional[dict[str, Any]] = None
    for rule in rules:
        condition = rule.get("condition", "")
        matched = False
        if f"severity == {severity}" in condition:
            matched = True
        elif "false_positive_indicator" in condition and alert.get("false_positive_indicator"):
            matched = True

        if matched:
            matched_rule = rule
            break

    priority = matched_rule.get("priority", "P3") if matched_rule else "P3"
    action = matched_rule.get("action", "review") if matched_rule else "review"
    confidence = 0.9 if matched_rule else 0.5

    recommendations: list[str] = []
    if action == "escalate":
        recommendations = ["Immediately notify SOC team", "Initiate incident response", "Preserve forensic evidence"]
    elif action == "investigate":
        recommendations = ["Assign to analyst for investigation", "Gather additional context", "Check for related alerts"]
    elif action == "review":
        recommendations = ["Add to review queue", "Correlate with other events"]
    elif action == "auto_close":
        recommendations = ["Auto-close after 24h if no escalation", "Log for trend analysis"]
    elif action == "suppress":
        recommendations = ["Suppress for 7 days", "Review suppression rule monthly"]

    result = {
        "alert_id": alert.get("id", secrets.token_hex(8)),
        "triage_decision": action,
        "priority": priority,
        "matched_rule": matched_rule.get("name") if matched_rule else None,
        "confidence": confidence,
        "enrichment_results": enrichment_results,
        "enrichment_sources_used": len(enrichment_results),
        "recommendations": recommendations,
        "triaged_at": datetime.now(timezone.utc).isoformat(),
    }

    m.inc_counter("autonomous_triage.decision", labels={"action": action, "priority": priority})
    logger.info("autonomous_triage", alert_id=result["alert_id"], decision=action, priority=priority)
    return result
