from __future__ import annotations

import re
import ipaddress
import hashlib
import math
import time
import json
from typing import Any, Optional
from datetime import datetime, timezone
from master_security.core import get_logger, get_metrics, create_span, get_event_bus, SecurityEvent, EventSeverity
from master_security.core.exceptions import SecurityError
import structlog

logger = structlog.get_logger(__name__)


def detect_port_scan(
    source_ip: str,
    connections: list[dict[str, Any]],
    window: float = 60.0,
    threshold: int = 10,
) -> dict[str, Any]:
    """Detect port scanning activity from a source IP address.

    Analyzes connection patterns within a time window to identify potential
    port scanning behavior based on the number of unique destination ports
    contacted by a single source IP.

    Args:
        source_ip: The IP address to analyze for scanning behavior.
        connections: List of connection dicts with keys: 'dst_ip', 'dst_port',
                     'timestamp', 'protocol', 'status'.
        window: Time window in seconds to analyze. Defaults to 60.0.
        threshold: Number of unique ports that triggers a scan alert. Defaults to 10.

    Returns:
        A dictionary containing:
            - detected: Boolean indicating if a port scan was detected.
            - scan_type: Type of scan ('horizontal', 'vertical', 'stealth', 'none').
            - unique_ports: Number of unique destination ports contacted.
            - unique_hosts: Number of unique destination hosts contacted.
            - connection_count: Total connections in the window.
            - scan_rate: Connections per second.
            - ports_sample: Sample of targeted ports (up to 20).
            - severity: Risk severity level.
            - timestamp: Detection timestamp.

    Example:
        >>> connections = [
        ...     {'dst_ip': '10.0.0.1', 'dst_port': p, 'timestamp': time.time(), 'protocol': 'TCP', 'status': 'SYN'}
        ...     for p in range(1, 100)
        ... ]
        >>> result = detect_port_scan('192.168.1.100', connections, threshold=50)
        >>> result['detected']
        True
    """
    start = time.monotonic()
    span = create_span("network.detect_port_scan")
    metrics = get_metrics()

    try:
        now = time.time()
        window_start = now - window

        filtered = [
            c for c in connections
            if c.get("timestamp", 0) >= window_start
        ]

        unique_ports = set()
        unique_hosts = set()
        syn_count = 0
        rst_count = 0
        port_list = []

        for conn in filtered:
            dst_port = conn.get("dst_port")
            dst_ip = conn.get("dst_ip", "")
            protocol = conn.get("protocol", "").upper()
            status = conn.get("status", "").upper()

            if dst_port is not None:
                unique_ports.add(dst_port)
                port_list.append(dst_port)
            if dst_ip:
                unique_hosts.add(dst_ip)
            if status == "SYN":
                syn_count += 1
            if status in ("RST", "RESET"):
                rst_count += 1

        port_count = len(unique_ports)
        host_count = len(unique_hosts)
        conn_count = len(filtered)
        scan_rate = conn_count / window if window > 0 else 0

        scan_type = "none"
        detected = False
        severity = EventSeverity.INFO

        if port_count >= threshold:
            detected = True
            if host_count <= 3:
                scan_type = "vertical"
                severity = EventSeverity.HIGH
            elif port_count <= 5 and host_count > 10:
                scan_type = "horizontal"
                severity = EventSeverity.MEDIUM
            else:
                scan_type = "stealth"
                severity = EventSeverity.CRITICAL

            if syn_count > conn_count * 0.8:
                scan_type = f"syn_{scan_type}"

        ports_sample = sorted(list(unique_ports))[:20]

        result = {
            "detected": detected,
            "scan_type": scan_type,
            "unique_ports": port_count,
            "unique_hosts": host_count,
            "connection_count": conn_count,
            "scan_rate": round(scan_rate, 2),
            "ports_sample": ports_sample,
            "severity": severity.value if hasattr(severity, "value") else str(severity),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        elapsed = time.monotonic() - start
        metrics.observe_histogram("network.port_scan_duration_ms", elapsed * 1000)
        metrics.inc_counter("network.port_scan_check", labels={"detected": str(detected)})

        if detected:
            logger.warning(
                "port_scan_detected",
                source_ip=source_ip,
                scan_type=scan_type,
                unique_ports=port_count,
                severity=result["severity"],
            )
            event_bus = get_event_bus()
            event_bus.publish_sync(
                SecurityEvent(type="port_scan_detected",
                    severity=severity,
                    source=source_ip,
                    data=result,
                )
            )
        else:
            logger.debug("port_scan_check_clean", source_ip=source_ip)

        return result

    except Exception as e:
        metrics.inc_counter("network.port_scan_error")
        logger.error("port_scan_detection_failed", source_ip=source_ip, error=str(e))
        raise SecurityError(f"Port scan detection failed: {e}") from e
    finally:
        getattr(span, "end", lambda: None)()


def detect_dns_tunneling(
    dns_queries: list[dict[str, Any]],
    domain: str,
    threshold: float = 3.5,
) -> dict[str, Any]:
    """Detect DNS tunneling by analyzing query entropy and patterns.

    DNS tunneling encodes data in DNS queries. This function detects it by
    analyzing query length, subdomain entropy, query frequency, and unusual
    record types for a given domain.

    Args:
        dns_queries: List of DNS query dicts with keys: 'query_name', 'query_type',
                     'timestamp', 'response_size', 'source_ip'.
        domain: The base domain to analyze for tunneling activity.
        threshold: Shannon entropy threshold for flagging suspicious queries.
                   Defaults to 3.5.

    Returns:
        A dictionary containing:
            - detected: Boolean indicating if DNS tunneling was detected.
            - entropy_score: Average Shannon entropy of subdomain labels.
            - avg_query_length: Average length of query names.
            - max_query_length: Maximum query name length observed.
            - query_count: Total queries for the domain.
            - unusual_types: Count of unusual DNS record types (TXT, NULL, etc.).
            - high_entropy_queries: Number of queries exceeding entropy threshold.
            - severity: Risk severity level.
            - timestamp: Detection timestamp.

    Example:
        >>> queries = [
        ...     {'query_name': f'aGVsbG8gd29ybGQ{i}.evil.com', 'query_type': 'TXT', 'timestamp': time.time()}
        ...     for i in range(20)
        ... ]
        >>> result = detect_dns_tunneling(queries, 'evil.com')
        >>> result['detected']
        True
    """
    start = time.monotonic()
    span = create_span("network.detect_dns_tunneling")
    metrics = get_metrics()

    try:
        def shannon_entropy(data: str) -> float:
            if not data:
                return 0.0
            freq: dict[str, int] = {}
            for c in data:
                freq[c] = freq.get(c, 0) + 1
            length = len(data)
            entropy = 0.0
            for count in freq.values():
                p = count / length
                if p > 0:
                    entropy -= p * math.log2(p)
            return entropy

        domain_lower = domain.lower().rstrip(".")
        target_queries = []
        query_lengths = []
        entropies = []
        unusual_types = {"TXT", "NULL", "CNAME", "MX", "SRV"}
        unusual_type_count = 0
        high_entropy_count = 0

        for query in dns_queries:
            qname = query.get("query_name", "").lower().rstrip(".")
            if qname.endswith(domain_lower) or qname == domain_lower:
                target_queries.append(query)
                query_lengths.append(len(qname))

                parts = qname.split(".")
                subdomain_parts = parts[: max(0, len(parts) - len(domain_lower.split(".")))]
                subdomain = ".".join(subdomain_parts)

                if subdomain:
                    ent = shannon_entropy(subdomain)
                    entropies.append(ent)
                    if ent > threshold:
                        high_entropy_count += 1

                qtype = query.get("query_type", "").upper()
                if qtype in unusual_types:
                    unusual_type_count += 1

        query_count = len(target_queries)
        avg_length = sum(query_lengths) / query_count if query_count > 0 else 0
        max_length = max(query_lengths) if query_lengths else 0
        avg_entropy = sum(entropies) / len(entropies) if entropies else 0

        detected = False
        severity = EventSeverity.INFO

        indicators = 0
        if avg_entropy > threshold:
            indicators += 1
        if max_length > 100:
            indicators += 1
        if unusual_type_count > query_count * 0.3 and query_count > 5:
            indicators += 1
        if high_entropy_count > query_count * 0.5 and query_count > 5:
            indicators += 1
        if query_count > 50:
            indicators += 1

        if indicators >= 2 and query_count > 0:
            detected = True
            if indicators >= 4:
                severity = EventSeverity.CRITICAL
            elif indicators >= 3:
                severity = EventSeverity.HIGH
            else:
                severity = EventSeverity.MEDIUM

        result = {
            "detected": detected,
            "entropy_score": round(avg_entropy, 4),
            "avg_query_length": round(avg_length, 2),
            "max_query_length": max_length,
            "query_count": query_count,
            "unusual_types": unusual_type_count,
            "high_entropy_queries": high_entropy_count,
            "indicators": indicators,
            "severity": severity.value if hasattr(severity, "value") else str(severity),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        elapsed = time.monotonic() - start
        metrics.observe_histogram("network.dns_tunneling_duration_ms", elapsed * 1000)
        metrics.inc_counter("network.dns_tunneling_check", labels={"domain": domain, "detected": str(detected)})

        if detected:
            logger.warning(
                "dns_tunneling_detected",
                domain=domain,
                entropy_score=avg_entropy,
                query_count=query_count,
                severity=result["severity"],
            )
        else:
            logger.debug("dns_tunneling_check_clean", domain=domain)

        return result

    except Exception as e:
        metrics.inc_counter("network.dns_tunneling_error")
        logger.error("dns_tunneling_detection_failed", domain=domain, error=str(e))
        raise SecurityError(f"DNS tunneling detection failed: {e}") from e
    finally:
        getattr(span, "end", lambda: None)()


def detect_traffic_anomaly(
    traffic_data: list[dict[str, Any]],
    baseline: dict[str, float],
    deviation_threshold: float = 2.0,
) -> dict[str, Any]:
    """Detect anomalies in network traffic by comparing against a baseline.

    Uses statistical analysis (z-score) to identify traffic metrics that
    deviate significantly from established baselines.

    Args:
        traffic_data: List of traffic metric dicts with keys: 'bytes_in',
                      'bytes_out', 'packets_in', 'packets_out', 'connections',
                      'timestamp'.
        baseline: Dict of baseline statistics with keys matching traffic_data
                  metrics, each containing 'mean' and 'std' values.
                  Example: {'bytes_in': {'mean': 10000, 'std': 2000}}
        deviation_threshold: Number of standard deviations from mean to flag
                             as anomalous. Defaults to 2.0.

    Returns:
        A dictionary containing:
            - detected: Boolean indicating if anomalies were found.
            - anomalies: List of anomalous metrics with their z-scores.
            - anomaly_count: Number of anomalous metrics.
            - max_deviation: Maximum z-score observed.
            - traffic_summary: Summary statistics of the traffic data.
            - severity: Risk severity level.
            - timestamp: Detection timestamp.

    Example:
        >>> traffic = [{'bytes_in': 50000, 'bytes_out': 1000, 'packets_in': 500, 'packets_out': 10, 'connections': 50, 'timestamp': time.time()}]
        >>> baseline = {
        ...     'bytes_in': {'mean': 10000, 'std': 2000},
        ...     'bytes_out': {'mean': 5000, 'std': 1000},
        ... }
        >>> result = detect_traffic_anomaly(traffic, baseline)
        >>> result['detected']
        True
    """
    start = time.monotonic()
    span = create_span("network.detect_traffic_anomaly")
    metrics = get_metrics()

    try:
        metric_keys = ["bytes_in", "bytes_out", "packets_in", "packets_out", "connections"]
        current_values: dict[str, float] = {}

        if traffic_data:
            for key in metric_keys:
                values = [t.get(key, 0) for t in traffic_data if key in t]
                current_values[key] = sum(values) / len(values) if values else 0

        anomalies = []
        max_deviation = 0.0

        for key, value in current_values.items():
            if key in baseline:
                bl = baseline[key]
                mean = bl.get("mean", 0)
                std = bl.get("std", 1)

                if std > 0:
                    z_score = abs(value - mean) / std
                else:
                    z_score = abs(value - mean) if mean > 0 else 0

                if z_score > max_deviation:
                    max_deviation = z_score

                if z_score >= deviation_threshold:
                    direction = "above" if value > mean else "below"
                    anomalies.append({
                        "metric": key,
                        "current_value": round(value, 2),
                        "baseline_mean": mean,
                        "baseline_std": std,
                        "z_score": round(z_score, 4),
                        "direction": direction,
                    })

        detected = len(anomalies) > 0
        severity = EventSeverity.INFO

        if detected:
            if max_deviation >= 5.0:
                severity = EventSeverity.CRITICAL
            elif max_deviation >= 3.5:
                severity = EventSeverity.HIGH
            else:
                severity = EventSeverity.MEDIUM

        traffic_summary = {k: round(v, 2) for k, v in current_values.items()}

        result = {
            "detected": detected,
            "anomalies": anomalies,
            "anomaly_count": len(anomalies),
            "max_deviation": round(max_deviation, 4),
            "traffic_summary": traffic_summary,
            "severity": severity.value if hasattr(severity, "value") else str(severity),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        elapsed = time.monotonic() - start
        metrics.observe_histogram("network.traffic_anomaly_duration_ms", elapsed * 1000)
        metrics.inc_counter("network.traffic_anomaly_check", labels={"detected": str(detected)})

        if detected:
            logger.warning(
                "traffic_anomaly_detected",
                anomaly_count=len(anomalies),
                max_deviation=max_deviation,
                severity=result["severity"],
            )
        else:
            logger.debug("traffic_anomaly_check_clean")

        return result

    except Exception as e:
        metrics.inc_counter("network.traffic_anomaly_error")
        logger.error("traffic_anomaly_detection_failed", error=str(e))
        raise SecurityError(f"Traffic anomaly detection failed: {e}") from e
    finally:
        getattr(span, "end", lambda: None)()


def detect_proxy(
    ip: str,
    headers: dict[str, str],
    detection_methods: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Detect if a request is coming through a proxy server.

    Analyzes HTTP headers and IP characteristics to identify proxy usage
    including transparent, anonymous, and elite proxies.

    Args:
        ip: The source IP address to analyze.
        headers: HTTP request headers to inspect for proxy indicators.
        detection_methods: List of detection methods to use. Options:
                          'headers', 'ip_reputation', 'behavioral'.
                          Defaults to all methods.

    Returns:
        A dictionary containing:
            - detected: Boolean indicating if a proxy was detected.
            - proxy_type: Type of proxy ('transparent', 'anonymous', 'elite', 'unknown').
            - indicators: List of detected proxy indicators.
            - confidence: Confidence score (0.0 to 1.0).
            - headers_analyzed: Headers that indicated proxy usage.
            - timestamp: Detection timestamp.

    Example:
        >>> headers = {
        ...     'X-Forwarded-For': '203.0.113.50',
        ...     'Via': '1.1 proxy.example.com',
        ... }
        >>> result = detect_proxy('10.0.0.1', headers)
        >>> result['detected']
        True
    """
    start = time.monotonic()
    span = create_span("network.detect_proxy")
    metrics = get_metrics()

    try:
        if detection_methods is None:
            detection_methods = ["headers", "ip_reputation", "behavioral"]

        indicators = []
        headers_detected = []
        confidence = 0.0

        proxy_headers = {
            "x-forwarded-for": "transparent",
            "x-real-ip": "transparent",
            "via": "transparent",
            "x-forwarded-host": "anonymous",
            "x-forwarded-proto": "anonymous",
            "forwarded": "transparent",
            "x-proxy-user-ip": "anonymous",
            "x-client-ip": "transparent",
            "x-originating-ip": "transparent",
            "proxy-connection": "transparent",
            "x-proxy-id": "anonymous",
        }

        if "headers" in detection_methods:
            for header, ptype in proxy_headers.items():
                if header in {k.lower(): v for k, v in headers.items()}:
                    indicators.append(f"header:{header}")
                    headers_detected.append(header)
                    if ptype == "transparent":
                        confidence += 0.15
                    else:
                        confidence += 0.1

        if "ip_reputation" in detection_methods:
            known_proxy_ranges = [
                "45.0.0.0/8",
                "103.0.0.0/8",
                "185.0.0.0/8",
            ]
            try:
                ip_obj = ipaddress.ip_address(ip)
                for range_str in known_proxy_ranges:
                    if ip_obj in ipaddress.ip_network(range_str):
                        indicators.append(f"ip_range:{range_str}")
                        confidence += 0.2
                        break
            except ValueError:
                pass

        if "behavioral" in detection_methods:
            user_agent = headers.get("User-Agent", headers.get("user-agent", ""))
            if not user_agent:
                indicators.append("missing_user_agent")
                confidence += 0.1
            if "proxy" in user_agent.lower() or "bot" in user_agent.lower():
                indicators.append("suspicious_user_agent")
                confidence += 0.15

        confidence = min(confidence, 1.0)
        detected = confidence >= 0.3

        proxy_type = "unknown"
        if detected:
            if any("transparent" in i for i in indicators):
                proxy_type = "transparent"
            elif any("anonymous" in i for i in indicators):
                proxy_type = "anonymous"
            elif confidence >= 0.7:
                proxy_type = "elite"

        result = {
            "detected": detected,
            "proxy_type": proxy_type,
            "indicators": indicators,
            "confidence": round(confidence, 2),
            "headers_analyzed": headers_detected,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        elapsed = time.monotonic() - start
        metrics.observe_histogram("network.proxy_detection_duration_ms", elapsed * 1000)
        metrics.inc_counter("network.proxy_check", labels={"detected": str(detected), "ip": ip})

        if detected:
            logger.info("proxy_detected", ip=ip, proxy_type=proxy_type, confidence=confidence)
        else:
            logger.debug("proxy_check_clean", ip=ip)

        return result

    except Exception as e:
        metrics.inc_counter("network.proxy_detection_error")
        logger.error("proxy_detection_failed", ip=ip, error=str(e))
        raise SecurityError(f"Proxy detection failed: {e}") from e
    finally:
        getattr(span, "end", lambda: None)()


def detect_vpn(
    ip: str,
    headers: dict[str, str],
    vpn_db: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Detect if a connection originates from a VPN service.

    Checks IP against known VPN provider ranges, analyzes connection
    characteristics, and inspects headers for VPN indicators.

    Args:
        ip: The source IP address to check.
        headers: HTTP request headers for additional context.
        vpn_db: Optional database of known VPN IP ranges. Should contain
                'ip_ranges' (list of CIDR strings) and 'providers' (dict
                mapping range index to provider name).

    Returns:
        A dictionary containing:
            - detected: Boolean indicating if VPN usage was detected.
            - provider: Identified VPN provider name or 'unknown'.
            - confidence: Confidence score (0.0 to 1.0).
            - indicators: List of detection indicators.
            - timestamp: Detection timestamp.

    Example:
        >>> vpn_db = {
        ...     'ip_ranges': ['104.16.0.0/12'],
        ...     'providers': {0: 'example-vpn'},
        ... }
        >>> result = detect_vpn('104.16.0.1', {}, vpn_db)
        >>> result['detected']
        True
    """
    start = time.monotonic()
    span = create_span("network.detect_vpn")
    metrics = get_metrics()

    try:
        indicators = []
        confidence = 0.0
        provider = "unknown"

        if vpn_db and "ip_ranges" in vpn_db:
            try:
                ip_obj = ipaddress.ip_address(ip)
                for idx, cidr in enumerate(vpn_db["ip_ranges"]):
                    if ip_obj in ipaddress.ip_network(cidr, strict=False):
                        indicators.append(f"vpn_range:{cidr}")
                        confidence += 0.6
                        providers = vpn_db.get("providers", {})
                        provider = providers.get(idx, "unknown")
                        break
            except ValueError:
                pass

        user_agent = headers.get("User-Agent", headers.get("user-agent", ""))
        vpn_keywords = ["openvpn", "wireguard", "nordvpn", "expressvpn", "vpn"]
        for keyword in vpn_keywords:
            if keyword in user_agent.lower():
                indicators.append(f"ua_keyword:{keyword}")
                confidence += 0.2

        tls_fingerprint = headers.get("X-TLS-Fingerprint", headers.get("x-tls-fingerprint", ""))
        if tls_fingerprint:
            indicators.append("custom_tls_header")
            confidence += 0.1

        confidence = min(confidence, 1.0)
        detected = confidence >= 0.5

        result = {
            "detected": detected,
            "provider": provider,
            "confidence": round(confidence, 2),
            "indicators": indicators,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        elapsed = time.monotonic() - start
        metrics.observe_histogram("network.vpn_detection_duration_ms", elapsed * 1000)
        metrics.inc_counter("network.vpn_check", labels={"detected": str(detected), "ip": ip})

        if detected:
            logger.info("vpn_detected", ip=ip, provider=provider, confidence=confidence)
        else:
            logger.debug("vpn_check_clean", ip=ip)

        return result

    except Exception as e:
        metrics.inc_counter("network.vpn_detection_error")
        logger.error("vpn_detection_failed", ip=ip, error=str(e))
        raise SecurityError(f"VPN detection failed: {e}") from e
    finally:
        getattr(span, "end", lambda: None)()


def detect_tor(
    ip: str,
    tor_nodes: Optional[list[str]] = None,
    exit_nodes: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Detect if an IP address belongs to the Tor network.

    Checks the IP against known Tor relay and exit node lists to identify
    Tor network usage.

    Args:
        ip: The source IP address to check.
        tor_nodes: List of known Tor relay IP addresses.
        exit_nodes: List of known Tor exit node IP addresses.

    Returns:
        A dictionary containing:
            - detected: Boolean indicating if Tor usage was detected.
            - node_type: Type of Tor node ('exit', 'relay', 'bridge', 'unknown').
            - confidence: Confidence score (0.0 to 1.0).
            - timestamp: Detection timestamp.

    Example:
        >>> exit_nodes = ['185.220.101.1', '185.220.101.2']
        >>> result = detect_tor('185.220.101.1', exit_nodes=exit_nodes)
        >>> result['detected']
        True
        >>> result['node_type']
        'exit'
    """
    start = time.monotonic()
    span = create_span("network.detect_tor")
    metrics = get_metrics()

    try:
        detected = False
        node_type = "unknown"
        confidence = 0.0

        if exit_nodes and ip in exit_nodes:
            detected = True
            node_type = "exit"
            confidence = 0.95
        elif tor_nodes and ip in tor_nodes:
            detected = True
            node_type = "relay"
            confidence = 0.85

        if not detected:
            try:
                ip_obj = ipaddress.ip_address(ip)
                known_tor_subnets = [
                    "185.220.100.0/22",
                    "176.10.99.0/24",
                    "199.249.230.0/24",
                ]
                for subnet in known_tor_subnets:
                    if ip_obj in ipaddress.ip_network(subnet):
                        detected = True
                        node_type = "bridge"
                        confidence = 0.7
                        break
            except ValueError:
                pass

        result = {
            "detected": detected,
            "node_type": node_type,
            "confidence": confidence,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        elapsed = time.monotonic() - start
        metrics.observe_histogram("network.tor_detection_duration_ms", elapsed * 1000)
        metrics.inc_counter("network.tor_check", labels={"detected": str(detected), "ip": ip})

        if detected:
            logger.warning("tor_detected", ip=ip, node_type=node_type, confidence=confidence)
        else:
            logger.debug("tor_check_clean", ip=ip)

        return result

    except Exception as e:
        metrics.inc_counter("network.tor_detection_error")
        logger.error("tor_detection_failed", ip=ip, error=str(e))
        raise SecurityError(f"Tor detection failed: {e}") from e
    finally:
        getattr(span, "end", lambda: None)()


def detect_ddos(
    traffic_data: list[dict[str, Any]],
    baseline: dict[str, float],
    threshold: float = 3.0,
    window: float = 60.0,
) -> dict[str, Any]:
    """Detect Distributed Denial of Service (DDoS) attacks.

    Analyzes traffic patterns against baseline metrics to identify DDoS
    attack signatures including volumetric, protocol, and application layer attacks.

    Args:
        traffic_data: List of traffic data points with keys: 'bytes_in',
                      'bytes_out', 'packets_in', 'packets_out', 'connections',
                      'syn_count', 'icmp_count', 'udp_count', 'timestamp'.
        baseline: Baseline traffic statistics with 'mean' and 'std' for
                  each metric.
        threshold: Z-score threshold for anomaly detection. Defaults to 3.0.
        window: Time window in seconds for analysis. Defaults to 60.0.

    Returns:
        A dictionary containing:
            - detected: Boolean indicating if a DDoS attack was detected.
            - attack_type: Type of attack ('volumetric', 'syn_flood', 'udp_flood',
                          'icmp_flood', 'application', 'unknown').
            - severity: Attack severity level.
            - metrics_exceeded: List of metrics exceeding threshold.
            - peak_rate: Peak traffic rate observed.
            - mitigation_recommended: Whether mitigation is recommended.
            - timestamp: Detection timestamp.

    Example:
        >>> traffic = [
        ...     {'bytes_in': 1000000, 'packets_in': 100000, 'connections': 50000,
        ...      'syn_count': 45000, 'timestamp': time.time()}
        ... ]
        >>> baseline = {
        ...     'bytes_in': {'mean': 10000, 'std': 2000},
        ...     'packets_in': {'mean': 1000, 'std': 200},
        ...     'connections': {'mean': 100, 'std': 20},
        ... }
        >>> result = detect_ddos(traffic, baseline)
        >>> result['detected']
        True
    """
    start = time.monotonic()
    span = create_span("network.detect_ddos")
    metrics = get_metrics()

    try:
        now = time.time()
        window_start = now - window
        window_data = [t for t in traffic_data if t.get("timestamp", 0) >= window_start]

        if not window_data:
            window_data = traffic_data

        current: dict[str, float] = {}
        metric_keys = ["bytes_in", "bytes_out", "packets_in", "packets_out",
                       "connections", "syn_count", "icmp_count", "udp_count"]

        for key in metric_keys:
            values = [t.get(key, 0) for t in window_data if key in t]
            current[key] = sum(values) / len(values) if values else 0

        metrics_exceeded = []
        z_scores: dict[str, float] = {}
        peak_rate = 0.0

        for key, value in current.items():
            if key in baseline:
                mean = baseline.get(key, {}).get("mean", 0)
                std = baseline.get(key, {}).get("std", 1)
                if std > 0:
                    z = abs(value - mean) / std
                else:
                    z = abs(value - mean) if mean > 0 else 0
                z_scores[key] = z
                if z >= threshold:
                    metrics_exceeded.append({
                        "metric": key,
                        "current": round(value, 2),
                        "baseline_mean": mean,
                        "z_score": round(z, 4),
                    })
                if value > peak_rate:
                    peak_rate = value

        detected = len(metrics_exceeded) > 0
        attack_type = "unknown"
        severity = EventSeverity.INFO
        mitigation_recommended = False

        if detected:
            syn_z = z_scores.get("syn_count", 0)
            udp_z = z_scores.get("udp_count", 0)
            icmp_z = z_scores.get("icmp_count", 0)
            bytes_z = z_scores.get("bytes_in", 0)
            conn_z = z_scores.get("connections", 0)

            if syn_z >= threshold and syn_z >= udp_z and syn_z >= icmp_z:
                attack_type = "syn_flood"
            elif udp_z >= threshold and udp_z >= syn_z:
                attack_type = "udp_flood"
            elif icmp_z >= threshold and icmp_z >= syn_z:
                attack_type = "icmp_flood"
            elif bytes_z >= threshold and conn_z < threshold:
                attack_type = "volumetric"
            elif conn_z >= threshold and bytes_z < threshold:
                attack_type = "application"
            else:
                attack_type = "volumetric"

            max_z = max(z_scores.values()) if z_scores else 0
            if max_z >= 10:
                severity = EventSeverity.CRITICAL
                mitigation_recommended = True
            elif max_z >= 5:
                severity = EventSeverity.HIGH
                mitigation_recommended = True
            else:
                severity = EventSeverity.MEDIUM
                mitigation_recommended = len(metrics_exceeded) >= 3

        result = {
            "detected": detected,
            "attack_type": attack_type,
            "severity": severity.value if hasattr(severity, "value") else str(severity),
            "metrics_exceeded": metrics_exceeded,
            "peak_rate": round(peak_rate, 2),
            "mitigation_recommended": mitigation_recommended,
            "window_data_points": len(window_data),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        elapsed = time.monotonic() - start
        metrics.observe_histogram("network.ddos_detection_duration_ms", elapsed * 1000)
        metrics.inc_counter("network.ddos_check", labels={"detected": str(detected), "attack_type": attack_type})

        if detected:
            logger.critical(
                "ddos_attack_detected",
                attack_type=attack_type,
                severity=result["severity"],
                metrics_exceeded=len(metrics_exceeded),
            )
            event_bus = get_event_bus()
            event_bus.publish_sync(
                SecurityEvent(type="ddos_detected",
                    severity=severity,
                    data=result,
                )
            )
        else:
            logger.debug("ddos_check_clean")

        return result

    except Exception as e:
        metrics.inc_counter("network.ddos_detection_error")
        logger.error("ddos_detection_failed", error=str(e))
        raise SecurityError(f"DDoS detection failed: {e}") from e
    finally:
        getattr(span, "end", lambda: None)()


def validate_ip(
    ip: str,
    allowed_ranges: Optional[list[str]] = None,
    blocked_ranges: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Validate an IP address against allowed and blocked ranges.

    Checks if an IP address is valid, falls within allowed CIDR ranges,
    and is not in any blocked ranges.

    Args:
        ip: The IP address to validate.
        allowed_ranges: Optional list of allowed CIDR ranges. If provided,
                        IP must be within at least one range.
        blocked_ranges: Optional list of blocked CIDR ranges. IP must not
                        be in any of these ranges.

    Returns:
        A dictionary containing:
            - valid: Boolean indicating if the IP is valid and allowed.
            - ip_type: Type of IP ('ipv4', 'ipv6', 'invalid').
            - is_private: Whether the IP is in a private range.
            - is_loopback: Whether the IP is a loopback address.
            - is_reserved: Whether the IP is reserved.
            - in_allowed_range: Whether IP is in an allowed range.
            - in_blocked_range: Whether IP is in a blocked range.
            - matched_range: The specific range that matched (if any).
            - timestamp: Validation timestamp.

    Example:
        >>> result = validate_ip('192.168.1.1', allowed_ranges=['192.168.0.0/16'])
        >>> result['valid']
        True
        >>> result = validate_ip('10.0.0.1', blocked_ranges=['10.0.0.0/8'])
        >>> result['valid']
        False
    """
    start = time.monotonic()
    span = create_span("network.validate_ip")
    metrics = get_metrics()

    try:
        result = {
            "valid": False,
            "ip_type": "invalid",
            "is_private": False,
            "is_loopback": False,
            "is_reserved": False,
            "is_multicast": False,
            "in_allowed_range": False,
            "in_blocked_range": False,
            "matched_range": None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            logger.warning("invalid_ip_address", ip=ip)
            metrics.inc_counter("network.ip_validation_invalid")
            return result

        result["ip_type"] = "ipv6" if isinstance(ip_obj, ipaddress.IPv6Address) else "ipv4"
        result["is_private"] = ip_obj.is_private
        result["is_loopback"] = ip_obj.is_loopback
        result["is_reserved"] = ip_obj.is_reserved
        result["is_multicast"] = ip_obj.is_multicast

        valid = True

        if blocked_ranges:
            for cidr in blocked_ranges:
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                    if ip_obj in network:
                        result["in_blocked_range"] = True
                        result["matched_range"] = cidr
                        valid = False
                        logger.warning(
                            "ip_in_blocked_range",
                            ip=ip,
                            range=cidr,
                        )
                        break
                except ValueError:
                    continue

        if allowed_ranges and valid:
            in_allowed = False
            for cidr in allowed_ranges:
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                    if ip_obj in network:
                        in_allowed = True
                        result["in_allowed_range"] = True
                        result["matched_range"] = cidr
                        break
                except ValueError:
                    continue
            if not in_allowed:
                valid = False
                logger.warning("ip_not_in_allowed_range", ip=ip)

        result["valid"] = valid

        elapsed = time.monotonic() - start
        metrics.observe_histogram("network.ip_validation_duration_ms", elapsed * 1000)
        metrics.inc_counter("network.ip_validation", labels={"valid": str(valid), "ip_type": result["ip_type"]})

        return result

    except Exception as e:
        metrics.inc_counter("network.ip_validation_error")
        logger.error("ip_validation_failed", ip=ip, error=str(e))
        raise SecurityError(f"IP validation failed: {e}") from e
    finally:
        getattr(span, "end", lambda: None)()


def validate_domain(
    domain: str,
    allowed_tlds: Optional[list[str]] = None,
    blocked_domains: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Validate a domain name against allowed TLDs and blocked domain lists.

    Checks domain format, TLD allowlist, and domain blocklist to determine
    if a domain is safe to interact with.

    Args:
        domain: The domain name to validate.
        allowed_tlds: Optional list of allowed top-level domains (e.g., ['.com', '.org']).
        blocked_domains: Optional list of blocked domain names.

    Returns:
        A dictionary containing:
            - valid: Boolean indicating if the domain is valid and allowed.
            - domain: Normalized domain name.
            - tld: Extracted top-level domain.
            - is_blocked: Whether the domain is in the blocklist.
            - tld_allowed: Whether the TLD is in the allowlist.
            - format_valid: Whether the domain format is valid.
            - risk_indicators: List of risk indicators found.
            - timestamp: Validation timestamp.

    Example:
        >>> result = validate_domain('example.com', allowed_tlds=['.com', '.org'])
        >>> result['valid']
        True
        >>> result = validate_domain('malware.evil.com', blocked_domains=['evil.com'])
        >>> result['valid']
        False
    """
    start = time.monotonic()
    span = create_span("network.validate_domain")
    metrics = get_metrics()

    try:
        domain = domain.lower().rstrip(".")
        risk_indicators = []

        domain_pattern = re.compile(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        )
        format_valid = bool(domain_pattern.match(domain))

        parts = domain.split(".")
        tld = f".{parts[-1]}" if len(parts) > 1 else ""

        valid = format_valid

        if blocked_domains:
            blocked_set = {d.lower().rstrip(".") for d in blocked_domains}
            is_blocked = domain in blocked_set
            if not is_blocked:
                for bd in blocked_set:
                    if domain.endswith(f".{bd}"):
                        is_blocked = True
                        break
            if is_blocked:
                valid = False
                risk_indicators.append("domain_blocked")

        if allowed_tlds:
            allowed_set = {t.lower() for t in allowed_tlds}
            tld_allowed = tld in allowed_set
            if not tld_allowed and allowed_tlds:
                valid = False
                risk_indicators.append("tld_not_allowed")
        else:
            tld_allowed = True

        suspicious_patterns = [
            (r"\d{4,}", "numeric_domain"),
            (r"[^a-zA-Z0-9.\-]", "special_characters"),
            (r"(xn--)", "punycode"),
            (r"(\w{30,})", "excessive_length"),
        ]
        for pattern, indicator in suspicious_patterns:
            if re.search(pattern, domain):
                risk_indicators.append(indicator)

        result = {
            "valid": valid,
            "domain": domain,
            "tld": tld,
            "is_blocked": domain in {d.lower().rstrip(".") for d in (blocked_domains or [])} or any(
                domain.endswith(f".{d.lower().rstrip('.')}") for d in (blocked_domains or [])
            ),
            "tld_allowed": tld_allowed,
            "format_valid": format_valid,
            "risk_indicators": risk_indicators,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        elapsed = time.monotonic() - start
        metrics.observe_histogram("network.domain_validation_duration_ms", elapsed * 1000)
        metrics.inc_counter("network.domain_validation", labels={"valid": str(valid), "domain": domain})

        if not valid:
            logger.warning("domain_validation_failed", domain=domain, indicators=risk_indicators)
        else:
            logger.debug("domain_validation_passed", domain=domain)

        return result

    except Exception as e:
        metrics.inc_counter("network.domain_validation_error")
        logger.error("domain_validation_failed", domain=domain, error=str(e))
        raise SecurityError(f"Domain validation failed: {e}") from e
    finally:
        getattr(span, "end", lambda: None)()


def detect_spoofing(
    packet_data: dict[str, Any],
    expected_source: str,
    network_topology: dict[str, Any],
) -> dict[str, Any]:
    """Detect IP spoofing by analyzing packet data against expected sources.

    Compares packet source information with network topology and expected
    source addresses to identify potential IP spoofing attacks.

    Args:
        packet_data: Packet metadata with keys: 'source_ip', 'dest_ip',
                     'ttl', 'source_mac', 'interface', 'timestamp'.
        expected_source: The expected source IP address for legitimate traffic.
        network_topology: Network topology info with 'subnets', 'routers',
                          'expected_paths' mapping subnets to expected interfaces.

    Returns:
        A dictionary containing:
            - detected: Boolean indicating if spoofing was detected.
            - spoof_type: Type of spoofing ('source_ip', 'mac', 'path', 'ttl', 'none').
            - confidence: Confidence score (0.0 to 1.0).
            - indicators: List of spoofing indicators.
            - expected_interface: Expected network interface for the source.
            - actual_interface: Actual interface the packet arrived on.
            - timestamp: Detection timestamp.

    Example:
        >>> packet = {
        ...     'source_ip': '192.168.1.100',
        ...     'ttl': 64,
        ...     'interface': 'eth1',
        ...     'source_mac': 'aa:bb:cc:dd:ee:ff',
        ... }
        >>> topology = {
        ...     'subnets': {'192.168.1.0/24': {'expected_interface': 'eth0'}},
        ... }
        >>> result = detect_spoofing(packet, '192.168.1.100', topology)
        >>> result['detected']
        True
    """
    start = time.monotonic()
    span = create_span("network.detect_spoofing")
    metrics = get_metrics()

    try:
        indicators = []
        confidence = 0.0
        spoof_type = "none"

        packet_src = packet_data.get("source_ip", "")
        packet_ttl = packet_data.get("ttl", 0)
        packet_interface = packet_data.get("interface", "")
        packet_mac = packet_data.get("source_mac", "")

        if packet_src != expected_source:
            indicators.append("source_ip_mismatch")
            confidence += 0.4
            spoof_type = "source_ip"

        subnets = network_topology.get("subnets", {})
        expected_interface = None
        for cidr, info in subnets.items():
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                if ipaddress.ip_address(expected_source) in network:
                    expected_interface = info.get("expected_interface")
                    break
            except (ValueError, TypeError):
                continue

        if expected_interface and packet_interface and expected_interface != packet_interface:
            indicators.append("interface_mismatch")
            confidence += 0.3
            if spoof_type == "none":
                spoof_type = "path"

        expected_ttl = network_topology.get("expected_ttl", 64)
        if packet_ttl > 0 and abs(packet_ttl - expected_ttl) > 20:
            indicators.append("ttl_anomaly")
            confidence += 0.2
            if spoof_type == "none":
                spoof_type = "ttl"

        expected_macs = network_topology.get("mac_mappings", {})
        if expected_source in expected_macs:
            expected_mac = expected_macs[expected_source]
            if packet_mac and packet_mac.lower() != expected_mac.lower():
                indicators.append("mac_mismatch")
                confidence += 0.35
                if spoof_type == "none":
                    spoof_type = "mac"

        confidence = min(confidence, 1.0)
        detected = confidence >= 0.5

        if detected and spoof_type == "none":
            spoof_type = "source_ip"

        result = {
            "detected": detected,
            "spoof_type": spoof_type,
            "confidence": round(confidence, 2),
            "indicators": indicators,
            "expected_interface": expected_interface,
            "actual_interface": packet_interface,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        elapsed = time.monotonic() - start
        metrics.observe_histogram("network.spoofing_detection_duration_ms", elapsed * 1000)
        metrics.inc_counter("network.spoofing_check", labels={"detected": str(detected)})

        if detected:
            logger.warning(
                "spoofing_detected",
                expected_source=expected_source,
                actual_source=packet_src,
                spoof_type=spoof_type,
                confidence=confidence,
            )
        else:
            logger.debug("spoofing_check_clean", expected_source=expected_source)

        return result

    except Exception as e:
        metrics.inc_counter("network.spoofing_detection_error")
        logger.error("spoofing_detection_failed", error=str(e))
        raise SecurityError(f"Spoofing detection failed: {e}") from e
    finally:
        getattr(span, "end", lambda: None)()


def detect_arp_poisoning(
    arp_table: list[dict[str, Any]],
    expected_mappings: dict[str, str],
) -> dict[str, Any]:
    """Detect ARP poisoning attacks by comparing ARP table against expected mappings.

    Analyzes the current ARP table to identify inconsistencies with known
    IP-to-MAC address mappings that indicate ARP cache poisoning.

    Args:
        arp_table: Current ARP table entries as list of dicts with keys:
                   'ip', 'mac', 'interface', 'type' (dynamic/static).
        expected_mappings: Dictionary mapping IP addresses to expected MAC
                          addresses. Example: {'192.168.1.1': 'aa:bb:cc:dd:ee:01'}

    Returns:
        A dictionary containing:
            - detected: Boolean indicating if ARP poisoning was detected.
            - poisoned_entries: List of entries with mismatched MAC addresses.
            - duplicate_ips: IPs appearing with multiple MAC addresses.
            - anomaly_count: Total number of anomalies found.
            - severity: Risk severity level.
            - timestamp: Detection timestamp.

    Example:
        >>> arp = [
        ...     {'ip': '192.168.1.1', 'mac': 'aa:bb:cc:dd:ee:ff', 'interface': 'eth0'},
        ...     {'ip': '192.168.1.1', 'mac': '11:22:33:44:55:66', 'interface': 'eth0'},
        ... ]
        >>> expected = {'192.168.1.1': 'aa:bb:cc:dd:ee:ff'}
        >>> result = detect_arp_poisoning(arp, expected)
        >>> result['detected']
        True
    """
    start = time.monotonic()
    span = create_span("network.detect_arp_poisoning")
    metrics = get_metrics()

    try:
        poisoned_entries = []
        ip_mac_map: dict[str, list[str]] = {}
        severity = EventSeverity.INFO

        for entry in arp_table:
            ip = entry.get("ip", "")
            mac = entry.get("mac", "").lower()
            interface = entry.get("interface", "")

            if ip not in ip_mac_map:
                ip_mac_map[ip] = []
            if mac not in ip_mac_map[ip]:
                ip_mac_map[ip].append(mac)

            if ip in expected_mappings:
                expected_mac = expected_mappings[ip].lower()
                if mac != expected_mac:
                    poisoned_entries.append({
                        "ip": ip,
                        "expected_mac": expected_mac,
                        "actual_mac": mac,
                        "interface": interface,
                    })

        duplicate_ips = {ip: macs for ip, macs in ip_mac_map.items() if len(macs) > 1}

        anomaly_count = len(poisoned_entries) + len(duplicate_ips)
        detected = anomaly_count > 0

        if detected:
            if len(poisoned_entries) > 5 or len(duplicate_ips) > 3:
                severity = EventSeverity.CRITICAL
            elif len(poisoned_entries) > 2 or len(duplicate_ips) > 1:
                severity = EventSeverity.HIGH
            else:
                severity = EventSeverity.MEDIUM

        result = {
            "detected": detected,
            "poisoned_entries": poisoned_entries,
            "duplicate_ips": {ip: macs for ip, macs in duplicate_ips.items()},
            "anomaly_count": anomaly_count,
            "severity": severity.value if hasattr(severity, "value") else str(severity),
            "arp_table_size": len(arp_table),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        elapsed = time.monotonic() - start
        metrics.observe_histogram("network.arp_poisoning_duration_ms", elapsed * 1000)
        metrics.inc_counter("network.arp_poisoning_check", labels={"detected": str(detected)})

        if detected:
            logger.critical(
                "arp_poisoning_detected",
                poisoned_count=len(poisoned_entries),
                duplicate_count=len(duplicate_ips),
                severity=result["severity"],
            )
            event_bus = get_event_bus()
            event_bus.publish_sync(
                SecurityEvent(type="arp_poisoning_detected",
                    severity=severity,
                    data=result,
                )
            )
        else:
            logger.debug("arp_poisoning_check_clean")

        return result

    except Exception as e:
        metrics.inc_counter("network.arp_poisoning_error")
        logger.error("arp_poisoning_detection_failed", error=str(e))
        raise SecurityError(f"ARP poisoning detection failed: {e}") from e
    finally:
        getattr(span, "end", lambda: None)()


def tls_fingerprint(
    tls_handshake: dict[str, Any],
    ja3_database: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Generate and match TLS fingerprint from handshake data.

    Creates a JA3 fingerprint from the TLS ClientHello message and matches
    it against a database of known fingerprints to identify clients.

    Args:
        tls_handshake: TLS handshake data with keys: 'version', 'ciphers',
                       'extensions', 'elliptic_curves', 'ec_point_formats',
                       'compression_methods'.
        ja3_database: Optional database mapping JA3 hashes to client info.
                      Example: {'abc123...': {'client': 'Chrome 120', 'risk': 'low'}}

    Returns:
        A dictionary containing:
            - ja3_hash: The JA3 fingerprint hash.
            - ja3_string: The raw JA3 string representation.
            - matched: Whether the fingerprint matched the database.
            - client_info: Information about the matched client.
            - risk_level: Assessed risk level ('low', 'medium', 'high', 'unknown').
            - timestamp: Fingerprint timestamp.

    Example:
        >>> handshake = {
        ...     'version': 771,
        ...     'ciphers': [4865, 4866, 4867],
        ...     'extensions': [0, 23, 35, 13],
        ...     'elliptic_curves': [29, 23, 24],
        ...     'ec_point_formats': [0],
        ... }
        >>> result = tls_fingerprint(handshake)
        >>> 'ja3_hash' in result
        True
    """
    start = time.monotonic()
    span = create_span("network.tls_fingerprint")
    metrics = get_metrics()

    try:
        version = tls_handshake.get("version", 0)
        ciphers = tls_handshake.get("ciphers", [])
        extensions = tls_handshake.get("extensions", [])
        curves = tls_handshake.get("elliptic_curves", [])
        point_formats = tls_handshake.get("ec_point_formats", [])

        cipher_str = "-".join(str(c) for c in ciphers)
        ext_str = "-".join(str(e) for e in extensions)
        curve_str = "-".join(str(c) for c in curves)
        point_str = "-".join(str(p) for p in point_formats)

        ja3_string = f"{version},{cipher_str},{ext_str},{curve_str},{point_str}"
        ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()

        matched = False
        client_info: dict[str, Any] = {}
        risk_level = "unknown"

        if ja3_database and ja3_hash in ja3_database:
            matched = True
            client_info = ja3_database[ja3_hash]
            risk_level = client_info.get("risk", "unknown")

        result = {
            "ja3_hash": ja3_hash,
            "ja3_string": ja3_string,
            "matched": matched,
            "client_info": client_info,
            "risk_level": risk_level,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        elapsed = time.monotonic() - start
        metrics.observe_histogram("network.tls_fingerprint_duration_ms", elapsed * 1000)
        metrics.inc_counter("network.tls_fingerprint", labels={"matched": str(matched)})

        if matched:
            logger.info(
                "tls_fingerprint_matched",
                ja3_hash=ja3_hash,
                client=client_info.get("client", "unknown"),
                risk=risk_level,
            )
        else:
            logger.debug("tls_fingerprint_unknown", ja3_hash=ja3_hash)

        return result

    except Exception as e:
        metrics.inc_counter("network.tls_fingerprint_error")
        logger.error("tls_fingerprint_failed", error=str(e))
        raise SecurityError(f"TLS fingerprinting failed: {e}") from e
    finally:
        getattr(span, "end", lambda: None)()


def ja3_fingerprint(tls_client_hello: dict[str, Any]) -> str:
    """Generate a JA3 fingerprint hash from a TLS ClientHello message.

    JA3 is a method for creating SSL/TLS client fingerprints that can be
    used for client identification and threat detection. The fingerprint
    is an MD5 hash of a string derived from the ClientHello message.

    Args:
        tls_client_hello: TLS ClientHello data with keys: 'version' (TLS version
                          as integer), 'ciphers' (list of cipher suite integers),
                          'extensions' (list of extension type integers),
                          'elliptic_curves' (list of curve integers),
                          'ec_point_formats' (list of point format integers).

    Returns:
        The JA3 fingerprint as a 32-character hexadecimal MD5 hash string.

    Example:
        >>> hello = {
        ...     'version': 771,
        ...     'ciphers': [4865, 4866],
        ...     'extensions': [0, 23, 35],
        ...     'elliptic_curves': [29, 23],
        ...     'ec_point_formats': [0],
        ... }
        >>> ja3 = ja3_fingerprint(hello)
        >>> len(ja3) == 32
        True
    """
    start = time.monotonic()
    span = create_span("network.ja3_fingerprint")
    metrics = get_metrics()

    try:
        version = tls_client_hello.get("version", 0)
        ciphers = tls_client_hello.get("ciphers", [])
        extensions = tls_client_hello.get("extensions", [])
        curves = tls_client_hello.get("elliptic_curves", [])
        point_formats = tls_client_hello.get("ec_point_formats", [])

        cipher_str = "-".join(str(c) for c in ciphers)
        ext_str = "-".join(str(e) for e in extensions)
        curve_str = "-".join(str(c) for c in curves)
        point_str = "-".join(str(p) for p in point_formats)

        ja3_string = f"{version},{cipher_str},{ext_str},{curve_str},{point_str}"
        ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()

        elapsed = time.monotonic() - start
        metrics.observe_histogram("network.ja3_fingerprint_duration_ms", elapsed * 1000)
        metrics.inc_counter("network.ja3_fingerprint_count")
        logger.debug("ja3_generated", ja3_hash=ja3_hash)

        return ja3_hash

    except Exception as e:
        metrics.inc_counter("network.ja3_fingerprint_error")
        logger.error("ja3_fingerprint_failed", error=str(e))
        raise SecurityError(f"JA3 fingerprint generation failed: {e}") from e
    finally:
        getattr(span, "end", lambda: None)()


def suspicious_dns_detection(
    dns_queries: list[dict[str, Any]],
    threat_intel: Optional[dict[str, Any]] = None,
    patterns: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Detect suspicious DNS activity using threat intelligence and pattern matching.

    Analyzes DNS queries against known malicious domains, suspicious patterns,
    and behavioral indicators to identify potential DNS-based threats.

    Args:
        dns_queries: List of DNS query dicts with keys: 'query_name', 'query_type',
                     'response', 'timestamp', 'source_ip'.
        threat_intel: Threat intelligence data with 'malicious_domains' (set/list),
                      'suspicious_tlds' (list), 'known_c2_domains' (list).
        patterns: List of regex patterns to match against query names.

    Returns:
        A dictionary containing:
            - detected: Boolean indicating suspicious activity was found.
            - suspicious_queries: List of suspicious query details.
            - threat_matches: Queries matching threat intelligence.
            - pattern_matches: Queries matching suspicious patterns.
            - total_analyzed: Total number of queries analyzed.
            - severity: Risk severity level.
            - timestamp: Detection timestamp.

    Example:
        >>> queries = [
        ...     {'query_name': 'malware.evil.com', 'query_type': 'A', 'timestamp': time.time()},
        ...     {'query_name': 'safe.example.com', 'query_type': 'A', 'timestamp': time.time()},
        ... ]
        >>> intel = {'malicious_domains': ['evil.com', 'malware.evil.com']}
        >>> result = suspicious_dns_detection(queries, threat_intel=intel)
        >>> result['detected']
        True
    """
    start = time.monotonic()
    span = create_span("network.suspicious_dns_detection")
    metrics = get_metrics()

    try:
        suspicious_queries = []
        threat_matches = []
        pattern_matches = []
        severity = EventSeverity.INFO

        malicious_domains = set()
        suspicious_tlds = set()
        known_c2 = set()

        if threat_intel:
            malicious_domains = {d.lower() for d in threat_intel.get("malicious_domains", [])}
            suspicious_tlds = {t.lower() for t in threat_intel.get("suspicious_tlds", [])}
            known_c2 = {d.lower() for d in threat_intel.get("known_c2_domains", [])}

        compiled_patterns = []
        if patterns:
            for p in patterns:
                try:
                    compiled_patterns.append(re.compile(p, re.IGNORECASE))
                except re.error:
                    continue

        for query in dns_queries:
            qname = query.get("query_name", "").lower().rstrip(".")
            qtype = query.get("query_type", "A")
            is_suspicious = False
            reasons = []

            if qname in malicious_domains:
                is_suspicious = True
                reasons.append("malicious_domain")
                threat_matches.append({"query": qname, "reason": "malicious_domain"})

            for md in malicious_domains:
                if qname.endswith(f".{md}"):
                    is_suspicious = True
                    if "malicious_domain" not in reasons:
                        reasons.append("malicious_domain_subdomain")
                        threat_matches.append({"query": qname, "reason": "malicious_domain_subdomain"})
                    break

            if qname in known_c2:
                is_suspicious = True
                reasons.append("known_c2")
                threat_matches.append({"query": qname, "reason": "known_c2"})

            parts = qname.split(".")
            if parts:
                tld = f".{parts[-1]}"
                if tld in suspicious_tlds:
                    is_suspicious = True
                    reasons.append("suspicious_tld")

            for pattern in compiled_patterns:
                if pattern.search(qname):
                    is_suspicious = True
                    reasons.append(f"pattern:{pattern.pattern}")
                    pattern_matches.append({"query": qname, "pattern": pattern.pattern})
                    break

            if qtype in ("TXT", "NULL", "CNAME") and len(qname) > 50:
                is_suspicious = True
                reasons.append("long_suspicious_query")

            if is_suspicious:
                suspicious_queries.append({
                    "query_name": qname,
                    "query_type": qtype,
                    "reasons": reasons,
                    "timestamp": query.get("timestamp"),
                })

        detected = len(suspicious_queries) > 0

        if detected:
            threat_ratio = len(threat_matches) / len(suspicious_queries) if suspicious_queries else 0
            if threat_ratio > 0.5 or len(threat_matches) > 10:
                severity = EventSeverity.CRITICAL
            elif len(suspicious_queries) > 5:
                severity = EventSeverity.HIGH
            else:
                severity = EventSeverity.MEDIUM

        result = {
            "detected": detected,
            "suspicious_queries": suspicious_queries[:50],
            "threat_matches": threat_matches,
            "pattern_matches": pattern_matches,
            "total_analyzed": len(dns_queries),
            "suspicious_count": len(suspicious_queries),
            "severity": severity.value if hasattr(severity, "value") else str(severity),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        elapsed = time.monotonic() - start
        metrics.observe_histogram("network.suspicious_dns_duration_ms", elapsed * 1000)
        metrics.inc_counter("network.suspicious_dns_check", labels={"detected": str(detected)})

        if detected:
            logger.warning(
                "suspicious_dns_detected",
                suspicious_count=len(suspicious_queries),
                threat_matches=len(threat_matches),
                severity=result["severity"],
            )
        else:
            logger.debug("suspicious_dns_check_clean", analyzed=len(dns_queries))

        return result

    except Exception as e:
        metrics.inc_counter("network.suspicious_dns_error")
        logger.error("suspicious_dns_detection_failed", error=str(e))
        raise SecurityError(f"Suspicious DNS detection failed: {e}") from e
    finally:
        getattr(span, "end", lambda: None)()


def beaconing_detection(
    connections: list[dict[str, Any]],
    interval_threshold: float = 0.15,
    jitter_threshold: float = 0.3,
) -> dict[str, Any]:
    """Detect beaconing behavior indicative of command-and-control communication.

    Analyzes connection timing patterns to identify regular, periodic connections
    that suggest automated beaconing to a C2 server.

    Args:
        connections: List of connection dicts with keys: 'destination', 'timestamp',
                     'duration', 'bytes_sent', 'bytes_received', 'source_ip'.
        interval_threshold: Maximum coefficient of variation (std/mean) for
                            intervals to be considered regular. Defaults to 0.15.
        jitter_threshold: Maximum allowed jitter ratio for beaconing detection.
                          Defaults to 0.3.

    Returns:
        A dictionary containing:
            - detected: Boolean indicating beaconing was detected.
            - beacons: List of detected beacon patterns with destination,
                       interval, regularity score, and connection count.
            - beacon_count: Number of unique beacon destinations found.
            - severity: Risk severity level.
            - timestamp: Detection timestamp.

    Example:
        >>> import time
        >>> base = time.time()
        >>> conns = [
        ...     {'destination': 'c2.evil.com', 'timestamp': base + i * 60,
        ...      'bytes_sent': 100, 'bytes_received': 200}
        ...     for i in range(20)
        ... ]
        >>> result = beaconing_detection(conns)
        >>> result['detected']
        True
    """
    start = time.monotonic()
    span = create_span("network.beaconing_detection")
    metrics = get_metrics()

    try:
        dest_connections: dict[str, list[float]] = {}
        dest_data: dict[str, list[dict[str, Any]]] = {}

        for conn in connections:
            dest = conn.get("destination", "unknown")
            ts = conn.get("timestamp", 0)
            if dest not in dest_connections:
                dest_connections[dest] = []
                dest_data[dest] = []
            dest_connections[dest].append(ts)
            dest_data[dest].append(conn)

        beacons = []

        for dest, timestamps in dest_connections.items():
            if len(timestamps) < 4:
                continue

            timestamps.sort()
            intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]

            if not intervals:
                continue

            mean_interval = sum(intervals) / len(intervals)
            if mean_interval <= 0:
                continue

            variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
            std_interval = math.sqrt(variance)
            cv = std_interval / mean_interval if mean_interval > 0 else float("inf")

            max_interval = max(intervals)
            min_interval = min(intervals)
            jitter = (max_interval - min_interval) / mean_interval if mean_interval > 0 else float("inf")

            is_beacon = cv <= interval_threshold and jitter <= jitter_threshold

            if is_beacon:
                beacons.append({
                    "destination": dest,
                    "interval_mean": round(mean_interval, 2),
                    "interval_std": round(std_interval, 2),
                    "coefficient_of_variation": round(cv, 4),
                    "jitter": round(jitter, 4),
                    "connection_count": len(timestamps),
                    "regularity_score": round(1.0 - cv, 4),
                    "first_seen": datetime.fromtimestamp(timestamps[0], tz=timezone.utc).isoformat(),
                    "last_seen": datetime.fromtimestamp(timestamps[-1], tz=timezone.utc).isoformat(),
                })

        detected = len(beacons) > 0
        severity = EventSeverity.INFO

        if detected:
            max_connections = max(b["connection_count"] for b in beacons)
            if max_connections > 50:
                severity = EventSeverity.CRITICAL
            elif max_connections > 20:
                severity = EventSeverity.HIGH
            else:
                severity = EventSeverity.MEDIUM

        result = {
            "detected": detected,
            "beacons": beacons,
            "beacon_count": len(beacons),
            "total_destinations": len(dest_connections),
            "severity": severity.value if hasattr(severity, "value") else str(severity),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        elapsed = time.monotonic() - start
        metrics.observe_histogram("network.beaconing_detection_duration_ms", elapsed * 1000)
        metrics.inc_counter("network.beaconing_check", labels={"detected": str(detected)})

        if detected:
            logger.critical(
                "beaconing_detected",
                beacon_count=len(beacons),
                destinations=[b["destination"] for b in beacons],
                severity=result["severity"],
            )
            event_bus = get_event_bus()
            event_bus.publish_sync(
                SecurityEvent(type="beaconing_detected",
                    severity=severity,
                    data=result,
                )
            )
        else:
            logger.debug("beaconing_check_clean", destinations=len(dest_connections))

        return result

    except Exception as e:
        metrics.inc_counter("network.beaconing_error")
        logger.error("beaconing_detection_failed", error=str(e))
        raise SecurityError(f"Beaconing detection failed: {e}") from e
    finally:
        getattr(span, "end", lambda: None)()


def lateral_movement_detection(
    events: list[dict[str, Any]],
    network_topology: dict[str, Any],
    user_behavior: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Detect lateral movement within a network.

    Analyzes security events and network topology to identify patterns
    consistent with an attacker moving laterally through the network.

    Args:
        events: List of security events with keys: 'source_ip', 'dest_ip',
                'event_type', 'timestamp', 'user', 'protocol', 'port',
                'success', 'auth_method'.
        network_topology: Network structure with 'segments', 'critical_assets',
                          'normal_paths' describing expected traffic flows.
        user_behavior: Optional user behavior baselines with 'normal_hours',
                       'typical_sources', 'usual_protocols' per user.

    Returns:
        A dictionary containing:
            - detected: Boolean indicating lateral movement was detected.
            - indicators: List of lateral movement indicators.
            - affected_hosts: Set of hosts involved in suspicious activity.
            - affected_users: Set of users involved in suspicious activity.
            - movement_chain: Sequence of hops suggesting lateral movement.
            - severity: Risk severity level.
            - timestamp: Detection timestamp.

    Example:
        >>> events = [
        ...     {'source_ip': '10.0.1.5', 'dest_ip': '10.0.2.10', 'event_type': 'auth',
        ...      'user': 'admin', 'protocol': 'SMB', 'port': 445, 'success': True,
        ...      'timestamp': time.time()},
        ...     {'source_ip': '10.0.2.10', 'dest_ip': '10.0.3.20', 'event_type': 'auth',
        ...      'user': 'admin', 'protocol': 'RDP', 'port': 3389, 'success': True,
        ...      'timestamp': time.time() + 60},
        ... ]
        >>> topology = {'segments': {'10.0.1.0/24': 'workstation', '10.0.2.0/24': 'server'}}
        >>> result = lateral_movement_detection(events, topology)
        >>> result['detected']
        True
    """
    start = time.monotonic()
    span = create_span("network.lateral_movement_detection")
    metrics = get_metrics()

    try:
        indicators = []
        affected_hosts = set()
        affected_users = set()
        movement_chain = []
        severity = EventSeverity.INFO

        lateral_protocols = {"SMB", "RDP", "SSH", "WMI", "WinRM", "PSExec", "DCOM"}
        lateral_ports = {445, 3389, 22, 135, 5985, 5986}

        user_sources: dict[str, set[str]] = {}
        user_destinations: dict[str, set[str]] = {}
        user_protocols: dict[str, set[str]] = {}
        host_connections: dict[str, set[str]] = {}

        for event in events:
            src = event.get("source_ip", "")
            dst = event.get("dest_ip", "")
            user = event.get("user", "")
            protocol = event.get("protocol", "").upper()
            port = event.get("port", 0)
            success = event.get("success", False)
            event_type = event.get("event_type", "")

            if user:
                user_sources.setdefault(user, set()).add(src)
                user_destinations.setdefault(user, set()).add(dst)
                user_protocols.setdefault(user, set()).add(protocol)

            if src:
                host_connections.setdefault(src, set()).add(dst)

            if protocol in lateral_protocols or port in lateral_ports:
                if success:
                    affected_hosts.add(src)
                    affected_hosts.add(dst)
                    if user:
                        affected_users.add(user)

        for user, sources in user_sources.items():
            if len(sources) > 3:
                indicators.append({
                    "type": "multiple_source_ips",
                    "user": user,
                    "source_count": len(sources),
                    "sources": list(sources),
                })

        for user, destinations in user_destinations.items():
            if len(destinations) > 5:
                indicators.append({
                    "type": "multiple_destination_ips",
                    "user": user,
                    "destination_count": len(destinations),
                    "destinations": list(destinations),
                })

        lateral_events = [
            e for e in events
            if e.get("protocol", "").upper() in lateral_protocols
            or e.get("port", 0) in lateral_ports
        ]

        if len(lateral_events) > 10:
            indicators.append({
                "type": "high_lateral_protocol_count",
                "count": len(lateral_events),
            })

        failed_auths = [e for e in events if not e.get("success", True) and e.get("event_type") == "auth"]
        if len(failed_auths) > 5:
            indicators.append({
                "type": "multiple_auth_failures",
                "count": len(failed_auths),
            })

        chain: list[dict[str, Any]] = []
        seen = set()
        for event in sorted(events, key=lambda x: x.get("timestamp", 0)):
            src = event.get("source_ip", "")
            dst = event.get("dest_ip", "")
            if src and dst and src not in seen:
                chain.append({
                    "hop": len(chain) + 1,
                    "source": src,
                    "destination": dst,
                    "protocol": event.get("protocol", ""),
                    "user": event.get("user", ""),
                    "timestamp": event.get("timestamp"),
                })
                seen.add(src)
                seen.add(dst)

        movement_chain = chain[-10:] if len(chain) > 10 else chain

        detected = len(indicators) >= 2 or (len(lateral_events) > 10 and len(affected_hosts) > 3)

        if detected:
            if len(affected_hosts) > 10 or len(indicators) > 5:
                severity = EventSeverity.CRITICAL
            elif len(affected_hosts) > 5 or len(indicators) > 3:
                severity = EventSeverity.HIGH
            else:
                severity = EventSeverity.MEDIUM

        result = {
            "detected": detected,
            "indicators": indicators,
            "affected_hosts": list(affected_hosts),
            "affected_users": list(affected_users),
            "movement_chain": movement_chain,
            "lateral_event_count": len(lateral_events),
            "severity": severity.value if hasattr(severity, "value") else str(severity),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        elapsed = time.monotonic() - start
        metrics.observe_histogram("network.lateral_movement_duration_ms", elapsed * 1000)
        metrics.inc_counter("network.lateral_movement_check", labels={"detected": str(detected)})

        if detected:
            logger.critical(
                "lateral_movement_detected",
                affected_hosts=len(affected_hosts),
                indicators=len(indicators),
                severity=result["severity"],
            )
            event_bus = get_event_bus()
            event_bus.publish_sync(
                SecurityEvent(type="lateral_movement_detected",
                    severity=severity,
                    data=result,
                )
            )
        else:
            logger.debug("lateral_movement_check_clean")

        return result

    except Exception as e:
        metrics.inc_counter("network.lateral_movement_error")
        logger.error("lateral_movement_detection_failed", error=str(e))
        raise SecurityError(f"Lateral movement detection failed: {e}") from e
    finally:
        getattr(span, "end", lambda: None)()


def command_and_control_detection(
    traffic_patterns: list[dict[str, Any]],
    known_c2: Optional[dict[str, Any]] = None,
    behavioral_analysis: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Detect command-and-control (C2) communication patterns.

    Analyzes network traffic for patterns consistent with C2 communication
    including beaconing, data exfiltration, and known C2 infrastructure.

    Args:
        traffic_patterns: List of traffic pattern dicts with keys: 'destination',
                          'interval', 'bytes_sent', 'bytes_received', 'protocol',
                          'port', 'timestamp', 'duration'.
        known_c2: Known C2 infrastructure data with 'ip_addresses', 'domains',
                  'ports', 'protocols', 'signatures'.
        behavioral_analysis: Behavioral baselines with 'normal_destinations',
                             'normal_protocols', 'normal_data_volumes'.

    Returns:
        A dictionary containing:
            - detected: Boolean indicating C2 communication was detected.
            - indicators: List of C2 indicators found.
            - c2_type: Type of C2 communication detected.
            - confidence: Confidence score (0.0 to 1.0).
            - suspicious_destinations: List of suspicious destination addresses.
            - severity: Risk severity level.
            - timestamp: Detection timestamp.

    Example:
        >>> patterns = [
        ...     {'destination': 'c2.evil.com', 'interval': 60, 'bytes_sent': 256,
        ...      'bytes_received': 1024, 'protocol': 'HTTPS', 'timestamp': time.time()}
        ...     for _ in range(10)
        ... ]
        >>> known = {'domains': ['c2.evil.com']}
        >>> result = command_and_control_detection(patterns, known_c2=known)
        >>> result['detected']
        True
    """
    start = time.monotonic()
    span = create_span("network.command_and_control_detection")
    metrics = get_metrics()

    try:
        indicators = []
        suspicious_destinations = set()
        confidence = 0.0
        c2_type = "unknown"
        severity = EventSeverity.INFO

        known_ips = set(known_c2.get("ip_addresses", [])) if known_c2 else set()
        known_domains = set(d.lower() for d in known_c2.get("domains", [])) if known_c2 else set()
        known_ports = set(known_c2.get("ports", [])) if known_c2 else set()
        known_signatures = known_c2.get("signatures", []) if known_c2 else []

        normal_destinations = set(behavioral_analysis.get("normal_destinations", [])) if behavioral_analysis else set()
        normal_protocols = set(p.upper() for p in behavioral_analysis.get("normal_protocols", [])) if behavioral_analysis else set()

        dest_counts: dict[str, int] = {}
        dest_bytes: dict[str, int] = {}
        dest_intervals: dict[str, list[float]] = {}

        for pattern in traffic_patterns:
            dest = pattern.get("destination", "")
            protocol = pattern.get("protocol", "").upper()
            port = pattern.get("port", 0)
            bytes_sent = pattern.get("bytes_sent", 0)
            bytes_received = pattern.get("bytes_received", 0)
            interval = pattern.get("interval", 0)

            dest_counts[dest] = dest_counts.get(dest, 0) + 1
            dest_bytes[dest] = dest_bytes.get(dest, 0) + bytes_sent + bytes_received
            dest_intervals.setdefault(dest, []).append(interval)

            if dest in known_ips or dest.lower() in known_domains:
                indicators.append({
                    "type": "known_c2_destination",
                    "destination": dest,
                })
                suspicious_destinations.add(dest)
                confidence += 0.3

            if port in known_ports:
                indicators.append({
                    "type": "known_c2_port",
                    "destination": dest,
                    "port": port,
                })
                suspicious_destinations.add(dest)
                confidence += 0.15

            if dest not in normal_destinations and normal_destinations:
                indicators.append({
                    "type": "unusual_destination",
                    "destination": dest,
                })
                suspicious_destinations.add(dest)
                confidence += 0.1

            if protocol and protocol not in normal_protocols and normal_protocols:
                indicators.append({
                    "type": "unusual_protocol",
                    "destination": dest,
                    "protocol": protocol,
                })
                confidence += 0.1

            if bytes_sent > 0 and bytes_received > 0:
                ratio = bytes_sent / bytes_received if bytes_received > 0 else float("inf")
                if ratio > 10 or ratio < 0.1:
                    indicators.append({
                        "type": "asymmetric_traffic",
                        "destination": dest,
                        "ratio": round(ratio, 2),
                    })
                    confidence += 0.1

        for dest, intervals in dest_intervals.items():
            if len(intervals) >= 3:
                mean = sum(intervals) / len(intervals)
                if mean > 0:
                    variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
                    std = math.sqrt(variance)
                    cv = std / mean
                    if cv < 0.2:
                        indicators.append({
                            "type": "regular_beaconing",
                            "destination": dest,
                            "interval": round(mean, 2),
                            "cv": round(cv, 4),
                        })
                        confidence += 0.2

        confidence = min(confidence, 1.0)
        detected = confidence >= 0.4

        if detected:
            indicator_types = {i["type"] for i in indicators}
            if "known_c2_destination" in indicator_types:
                c2_type = "known_infrastructure"
            elif "regular_beaconing" in indicator_types:
                c2_type = "beaconing"
            elif "asymmetric_traffic" in indicator_types:
                c2_type = "data_exfiltration"
            else:
                c2_type = "suspicious_communication"

            if confidence >= 0.8:
                severity = EventSeverity.CRITICAL
            elif confidence >= 0.6:
                severity = EventSeverity.HIGH
            else:
                severity = EventSeverity.MEDIUM

        result = {
            "detected": detected,
            "indicators": indicators[:50],
            "c2_type": c2_type,
            "confidence": round(confidence, 2),
            "suspicious_destinations": list(suspicious_destinations),
            "total_patterns_analyzed": len(traffic_patterns),
            "severity": severity.value if hasattr(severity, "value") else str(severity),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        elapsed = time.monotonic() - start
        metrics.observe_histogram("network.c2_detection_duration_ms", elapsed * 1000)
        metrics.inc_counter("network.c2_check", labels={"detected": str(detected)})

        if detected:
            logger.critical(
                "c2_communication_detected",
                c2_type=c2_type,
                confidence=confidence,
                indicators=len(indicators),
                severity=result["severity"],
            )
            event_bus = get_event_bus()
            event_bus.publish_sync(
                SecurityEvent(type="c2_detected",
                    severity=severity,
                    data=result,
                )
            )
        else:
            logger.debug("c2_check_clean", patterns=len(traffic_patterns))

        return result

    except Exception as e:
        metrics.inc_counter("network.c2_detection_error")
        logger.error("c2_detection_failed", error=str(e))
        raise SecurityError(f"C2 detection failed: {e}") from e
    finally:
        getattr(span, "end", lambda: None)()


def network_entropy_analysis(
    packets: list[dict[str, Any]],
    block_size: int = 16,
    threshold: float = 7.5,
) -> dict[str, Any]:
    """Analyze network packet entropy to detect encrypted or encoded traffic.

    Calculates Shannon entropy of packet payloads to identify anomalous
    data patterns that may indicate encryption, encoding, or data exfiltration.

    Args:
        packets: List of packet dicts with keys: 'payload' (bytes or hex string),
                 'source_ip', 'dest_ip', 'protocol', 'timestamp', 'length'.
        block_size: Size of data blocks for entropy calculation. Defaults to 16.
        threshold: Entropy threshold for flagging high-entropy packets.
                   Defaults to 7.5 (near-random data).

    Returns:
        A dictionary containing:
            - high_entropy_packets: List of packets exceeding entropy threshold.
            - average_entropy: Mean entropy across all packets.
            - max_entropy: Maximum entropy observed.
            - min_entropy: Minimum entropy observed.
            - entropy_distribution: Histogram of entropy values.
            - encrypted_likelihood: Estimated likelihood of encryption (0.0-1.0).
            - severity: Risk severity level.
            - timestamp: Analysis timestamp.

    Example:
        >>> import os
        >>> packets = [
        ...     {'payload': os.urandom(100).hex(), 'source_ip': '10.0.0.1',
        ...      'dest_ip': '10.0.0.2', 'protocol': 'TCP', 'timestamp': time.time()}
        ...     for _ in range(10)
        ... ]
        >>> result = network_entropy_analysis(packets)
        >>> result['average_entropy'] > 7.0
        True
    """
    start = time.monotonic()
    span = create_span("network.network_entropy_analysis")
    metrics = get_metrics()

    try:
        def shannon_entropy(data: bytes) -> float:
            if not data:
                return 0.0
            freq: dict[int, int] = {}
            for byte in data:
                freq[byte] = freq.get(byte, 0) + 1
            length = len(data)
            entropy = 0.0
            for count in freq.values():
                p = count / length
                if p > 0:
                    entropy -= p * math.log2(p)
            return entropy

        def block_entropy(data: bytes, size: int) -> list[float]:
            entropies = []
            for i in range(0, len(data), size):
                block = data[i : i + size]
                if len(block) >= size // 2:
                    entropies.append(shannon_entropy(block))
            return entropies if entropies else [0.0]

        packet_entropies = []
        high_entropy_packets = []
        all_entropies = []

        for packet in packets:
            payload = packet.get("payload", b"")
            if isinstance(payload, str):
                try:
                    payload = bytes.fromhex(payload)
                except ValueError:
                    payload = payload.encode("utf-8", errors="ignore")

            if not isinstance(payload, bytes):
                payload = b""

            entropies = block_entropy(payload, block_size)
            avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0
            packet_entropies.append(avg_entropy)
            all_entropies.extend(entropies)

            if avg_entropy > threshold:
                high_entropy_packets.append({
                    "source_ip": packet.get("source_ip", ""),
                    "dest_ip": packet.get("dest_ip", ""),
                    "protocol": packet.get("protocol", ""),
                    "entropy": round(avg_entropy, 4),
                    "length": packet.get("length", len(payload)),
                    "timestamp": packet.get("timestamp"),
                })

        avg_entropy = sum(packet_entropies) / len(packet_entropies) if packet_entropies else 0.0
        max_entropy = max(packet_entropies) if packet_entropies else 0.0
        min_entropy = min(packet_entropies) if packet_entropies else 0.0

        high_entropy_ratio = len(high_entropy_packets) / len(packets) if packets else 0.0
        encrypted_likelihood = min(high_entropy_ratio * 2, 1.0)

        severity = EventSeverity.INFO
        if encrypted_likelihood > 0.7:
            severity = EventSeverity.HIGH
        elif encrypted_likelihood > 0.4:
            severity = EventSeverity.MEDIUM

        entropy_buckets = {"0-2": 0, "2-4": 0, "4-6": 0, "6-7": 0, "7-7.5": 0, "7.5-8": 0}
        for e in all_entropies:
            if e < 2:
                entropy_buckets["0-2"] += 1
            elif e < 4:
                entropy_buckets["2-4"] += 1
            elif e < 6:
                entropy_buckets["4-6"] += 1
            elif e < 7:
                entropy_buckets["6-7"] += 1
            elif e < 7.5:
                entropy_buckets["7-7.5"] += 1
            else:
                entropy_buckets["7.5-8"] += 1

        result = {
            "high_entropy_packets": high_entropy_packets[:50],
            "average_entropy": round(avg_entropy, 4),
            "max_entropy": round(max_entropy, 4),
            "min_entropy": round(min_entropy, 4),
            "entropy_distribution": entropy_buckets,
            "encrypted_likelihood": round(encrypted_likelihood, 4),
            "high_entropy_count": len(high_entropy_packets),
            "total_packets": len(packets),
            "severity": severity.value if hasattr(severity, "value") else str(severity),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        elapsed = time.monotonic() - start
        metrics.observe_histogram("network.entropy_analysis_duration_ms", elapsed * 1000)
        metrics.inc_counter("network.entropy_analysis", labels={"high_entropy": str(len(high_entropy_packets))})

        if len(high_entropy_packets) > 0:
            logger.info(
                "high_entropy_detected",
                count=len(high_entropy_packets),
                avg_entropy=avg_entropy,
                encrypted_likelihood=encrypted_likelihood,
            )
        else:
            logger.debug("entropy_analysis_clean", avg_entropy=avg_entropy)

        return result

    except Exception as e:
        metrics.inc_counter("network.entropy_analysis_error")
        logger.error("entropy_analysis_failed", error=str(e))
        raise SecurityError(f"Network entropy analysis failed: {e}") from e
    finally:
        getattr(span, "end", lambda: None)()


def traffic_behavior_analysis(
    traffic_data: list[dict[str, Any]],
    baseline: dict[str, Any],
    time_window: float = 3600.0,
) -> dict[str, Any]:
    """Analyze network traffic behavior against established baselines.

    Performs comprehensive behavioral analysis of network traffic including
    volume, protocol distribution, temporal patterns, and connection behavior.

    Args:
        traffic_data: List of traffic data points with keys: 'bytes_in',
                      'bytes_out', 'packets', 'connections', 'protocol',
                      'source_ip', 'dest_ip', 'timestamp', 'duration'.
        baseline: Behavioral baseline with 'hourly_volumes', 'protocol_ratios',
                  'connection_patterns', 'typical_sources', 'typical_destinations'.
        time_window: Analysis time window in seconds. Defaults to 3600.0 (1 hour).

    Returns:
        A dictionary containing:
            - anomalies: List of behavioral anomalies detected.
            - anomaly_count: Number of anomalies found.
            - behavior_score: Overall behavior score (0.0-1.0, higher is more normal).
            - volume_analysis: Analysis of traffic volume deviations.
            - protocol_analysis: Analysis of protocol distribution changes.
            - temporal_analysis: Analysis of temporal pattern changes.
            - severity: Risk severity level.
            - timestamp: Analysis timestamp.

    Example:
        >>> traffic = [
        ...     {'bytes_in': 50000, 'bytes_out': 10000, 'protocol': 'HTTPS',
        ...      'timestamp': time.time(), 'source_ip': '10.0.0.1', 'dest_ip': '8.8.8.8'}
        ...     for _ in range(100)
        ... ]
        >>> baseline = {
        ...     'hourly_volumes': {'mean_bytes_in': 10000, 'std_bytes_in': 2000},
        ...     'protocol_ratios': {'HTTPS': 0.8, 'HTTP': 0.15, 'DNS': 0.05},
        ... }
        >>> result = traffic_behavior_analysis(traffic, baseline)
        >>> 'anomalies' in result
        True
    """
    start = time.monotonic()
    span = create_span("network.traffic_behavior_analysis")
    metrics = get_metrics()

    try:
        now = time.time()
        window_start = now - time_window
        window_data = [t for t in traffic_data if t.get("timestamp", 0) >= window_start]

        if not window_data:
            window_data = traffic_data

        anomalies = []
        behavior_score = 1.0

        bytes_in_values = [t.get("bytes_in", 0) for t in window_data]
        bytes_out_values = [t.get("bytes_out", 0) for t in window_data]
        total_bytes_in = sum(bytes_in_values)
        total_bytes_out = sum(bytes_out_values)

        hourly_volumes = baseline.get("hourly_volumes", {})
        if hourly_volumes:
            mean_in = hourly_volumes.get("mean_bytes_in", 0)
            std_in = hourly_volumes.get("std_bytes_in", 1)
            if std_in > 0 and total_bytes_in > 0:
                z_in = abs(total_bytes_in - mean_in) / std_in
                if z_in > 2.0:
                    anomalies.append({
                        "type": "volume_anomaly",
                        "metric": "bytes_in",
                        "current": total_bytes_in,
                        "baseline_mean": mean_in,
                        "z_score": round(z_in, 4),
                    })
                    behavior_score -= 0.2

            mean_out = hourly_volumes.get("mean_bytes_out", 0)
            std_out = hourly_volumes.get("std_bytes_out", 1)
            if std_out > 0 and total_bytes_out > 0:
                z_out = abs(total_bytes_out - mean_out) / std_out
                if z_out > 2.0:
                    anomalies.append({
                        "type": "volume_anomaly",
                        "metric": "bytes_out",
                        "current": total_bytes_out,
                        "baseline_mean": mean_out,
                        "z_score": round(z_out, 4),
                    })
                    behavior_score -= 0.2

        protocol_ratios = baseline.get("protocol_ratios", {})
        if protocol_ratios and window_data:
            protocol_counts: dict[str, int] = {}
            for t in window_data:
                proto = t.get("protocol", "unknown").upper()
                protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

            total = sum(protocol_counts.values())
            if total > 0:
                for proto, expected_ratio in protocol_ratios.items():
                    actual_ratio = protocol_counts.get(proto, 0) / total
                    deviation = abs(actual_ratio - expected_ratio)
                    if deviation > 0.2:
                        anomalies.append({
                            "type": "protocol_anomaly",
                            "protocol": proto,
                            "expected_ratio": expected_ratio,
                            "actual_ratio": round(actual_ratio, 4),
                            "deviation": round(deviation, 4),
                        })
                        behavior_score -= 0.15

        typical_sources = set(baseline.get("typical_sources", []))
        if typical_sources and window_data:
            unusual_sources = set()
            for t in window_data:
                src = t.get("source_ip", "")
                if src and src not in typical_sources:
                    unusual_sources.add(src)
            if len(unusual_sources) > 3:
                anomalies.append({
                    "type": "unusual_sources",
                    "count": len(unusual_sources),
                    "sources": list(unusual_sources)[:10],
                })
                behavior_score -= 0.15

        typical_destinations = set(baseline.get("typical_destinations", []))
        if typical_destinations and window_data:
            unusual_destinations = set()
            for t in window_data:
                dst = t.get("dest_ip", "")
                if dst and dst not in typical_destinations:
                    unusual_destinations.add(dst)
            if len(unusual_destinations) > 5:
                anomalies.append({
                    "type": "unusual_destinations",
                    "count": len(unusual_destinations),
                    "destinations": list(unusual_destinations)[:10],
                })
                behavior_score -= 0.15

        behavior_score = max(behavior_score, 0.0)
        anomaly_count = len(anomalies)

        severity = EventSeverity.INFO
        if behavior_score < 0.3:
            severity = EventSeverity.CRITICAL
        elif behavior_score < 0.5:
            severity = EventSeverity.HIGH
        elif behavior_score < 0.7:
            severity = EventSeverity.MEDIUM

        volume_analysis = {
            "total_bytes_in": total_bytes_in,
            "total_bytes_out": total_bytes_out,
            "total_packets": sum(t.get("packets", 0) for t in window_data),
            "total_connections": sum(t.get("connections", 0) for t in window_data),
        }

        protocol_analysis = {
            "protocol_counts": {k: v for k, v in protocol_counts.items()},
            "deviations": [a for a in anomalies if a["type"] == "protocol_anomaly"],
        }

        temporal_analysis = {
            "window_start": datetime.fromtimestamp(window_start, tz=timezone.utc).isoformat(),
            "window_end": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
            "data_points": len(window_data),
        }

        result = {
            "anomalies": anomalies,
            "anomaly_count": anomaly_count,
            "behavior_score": round(behavior_score, 4),
            "volume_analysis": volume_analysis,
            "protocol_analysis": protocol_analysis,
            "temporal_analysis": temporal_analysis,
            "severity": severity.value if hasattr(severity, "value") else str(severity),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        elapsed = time.monotonic() - start
        metrics.observe_histogram("network.behavior_analysis_duration_ms", elapsed * 1000)
        metrics.inc_counter("network.behavior_analysis", labels={"anomaly_count": str(anomaly_count)})

        if anomaly_count > 0:
            logger.warning(
                "traffic_behavior_anomalies",
                anomaly_count=anomaly_count,
                behavior_score=behavior_score,
                severity=result["severity"],
            )
        else:
            logger.debug("traffic_behavior_normal", behavior_score=behavior_score)

        return result

    except Exception as e:
        metrics.inc_counter("network.behavior_analysis_error")
        logger.error("traffic_behavior_analysis_failed", error=str(e))
        raise SecurityError(f"Traffic behavior analysis failed: {e}") from e
    finally:
        getattr(span, "end", lambda: None)()


def protocol_anomaly_detection(
    protocol_data: list[dict[str, Any]],
    protocol_spec: dict[str, Any],
    deviation_threshold: float = 2.0,
) -> dict[str, Any]:
    """Detect anomalies in protocol behavior against protocol specifications.

    Analyzes network protocol data to identify deviations from expected
    protocol behavior, including malformed packets, unexpected sequences,
    and protocol violations.

    Args:
        protocol_data: List of protocol event dicts with keys: 'protocol',
                       'message_type', 'fields', 'payload_length', 'flags',
                       'sequence_number', 'timestamp', 'source_ip', 'dest_ip'.
        protocol_spec: Protocol specification with 'allowed_message_types',
                       'required_fields', 'field_constraints', 'max_payload_length',
                       'valid_flags', 'expected_sequence'.
        deviation_threshold: Number of standard deviations for anomaly detection.
                             Defaults to 2.0.

    Returns:
        A dictionary containing:
            - detected: Boolean indicating protocol anomalies were found.
            - anomalies: List of protocol anomalies with details.
            - anomaly_count: Number of anomalies detected.
            - protocol_violations: List of protocol specification violations.
            - severity: Risk severity level.
            - timestamp: Detection timestamp.

    Example:
        >>> data = [
        ...     {'protocol': 'HTTP', 'message_type': 'REQUEST', 'fields': {'method': 'GET'},
        ...      'payload_length': 100, 'timestamp': time.time()}
        ... ]
        >>> spec = {
        ...     'allowed_message_types': ['REQUEST', 'RESPONSE'],
        ...     'max_payload_length': 10000,
        ...     'required_fields': ['method'],
        ... }
        >>> result = protocol_anomaly_detection(data, spec)
        >>> 'anomalies' in result
        True
    """
    start = time.monotonic()
    span = create_span("network.protocol_anomaly_detection")
    metrics = get_metrics()

    try:
        anomalies = []
        protocol_violations = []

        allowed_types = set(protocol_spec.get("allowed_message_types", []))
        required_fields = set(protocol_spec.get("required_fields", []))
        field_constraints = protocol_spec.get("field_constraints", {})
        max_payload = protocol_spec.get("max_payload_length", float("inf"))
        valid_flags = set(protocol_spec.get("valid_flags", []))
        expected_sequence = protocol_spec.get("expected_sequence", [])

        payload_lengths = []
        sequence_numbers = []

        for idx, data in enumerate(protocol_data):
            entry_anomalies = []
            protocol = data.get("protocol", "unknown")
            msg_type = data.get("message_type", "")
            fields = data.get("fields", {})
            payload_len = data.get("payload_length", 0)
            flags = data.get("flags", [])
            seq_num = data.get("sequence_number")

            if allowed_types and msg_type not in allowed_types:
                anomaly = {
                    "type": "invalid_message_type",
                    "protocol": protocol,
                    "message_type": msg_type,
                    "allowed": list(allowed_types),
                    "index": idx,
                }
                entry_anomalies.append(anomaly)
                protocol_violations.append(anomaly)

            for field in required_fields:
                if field not in fields:
                    anomaly = {
                        "type": "missing_required_field",
                        "protocol": protocol,
                        "field": field,
                        "index": idx,
                    }
                    entry_anomalies.append(anomaly)
                    protocol_violations.append(anomaly)

            for field_name, constraint in field_constraints.items():
                if field_name in fields:
                    value = fields[field_name]
                    if isinstance(constraint, dict):
                        allowed_values = constraint.get("allowed_values", [])
                        if allowed_values and value not in allowed_values:
                            anomaly = {
                                "type": "invalid_field_value",
                                "protocol": protocol,
                                "field": field_name,
                                "value": value,
                                "allowed": allowed_values,
                                "index": idx,
                            }
                            entry_anomalies.append(anomaly)

                        max_val = constraint.get("max")
                        min_val = constraint.get("min")
                        if max_val is not None and isinstance(value, (int, float)) and value > max_val:
                            anomaly = {
                                "type": "field_value_exceeded_max",
                                "protocol": protocol,
                                "field": field_name,
                                "value": value,
                                "max": max_val,
                                "index": idx,
                            }
                            entry_anomalies.append(anomaly)

            if payload_len > max_payload:
                anomaly = {
                    "type": "payload_overflow",
                    "protocol": protocol,
                    "payload_length": payload_len,
                    "max_allowed": max_payload,
                    "index": idx,
                }
                entry_anomalies.append(anomaly)

            if valid_flags and flags:
                for flag in flags:
                    if flag not in valid_flags:
                        anomaly = {
                            "type": "invalid_flag",
                            "protocol": protocol,
                            "flag": flag,
                            "valid_flags": list(valid_flags),
                            "index": idx,
                        }
                        entry_anomalies.append(anomaly)

            if payload_len > 0:
                payload_lengths.append(payload_len)
            if seq_num is not None:
                sequence_numbers.append(seq_num)

            if entry_anomalies:
                anomalies.extend(entry_anomalies)

        if payload_lengths:
            mean_len = sum(payload_lengths) / len(payload_lengths)
            if len(payload_lengths) > 1:
                variance = sum((x - mean_len) ** 2 for x in payload_lengths) / len(payload_lengths)
                std_len = math.sqrt(variance)
                if std_len > 0:
                    for idx, length in enumerate(payload_lengths):
                        z = abs(length - mean_len) / std_len
                        if z > deviation_threshold:
                            anomalies.append({
                                "type": "payload_length_anomaly",
                                "payload_length": length,
                                "mean": round(mean_len, 2),
                                "std": round(std_len, 2),
                                "z_score": round(z, 4),
                            })

        if sequence_numbers and len(sequence_numbers) > 1:
            for i in range(1, len(sequence_numbers)):
                if sequence_numbers[i] <= sequence_numbers[i - 1]:
                    anomalies.append({
                        "type": "sequence_anomaly",
                        "previous": sequence_numbers[i - 1],
                        "current": sequence_numbers[i],
                    })

        detected = len(anomalies) > 0
        severity = EventSeverity.INFO

        if detected:
            violation_count = len(protocol_violations)
            if violation_count > 10 or len(anomalies) > 20:
                severity = EventSeverity.CRITICAL
            elif violation_count > 5 or len(anomalies) > 10:
                severity = EventSeverity.HIGH
            else:
                severity = EventSeverity.MEDIUM

        result = {
            "detected": detected,
            "anomalies": anomalies[:100],
            "anomaly_count": len(anomalies),
            "protocol_violations": protocol_violations[:50],
            "violation_count": len(protocol_violations),
            "total_entries_analyzed": len(protocol_data),
            "severity": severity.value if hasattr(severity, "value") else str(severity),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        elapsed = time.monotonic() - start
        metrics.observe_histogram("network.protocol_anomaly_duration_ms", elapsed * 1000)
        metrics.inc_counter("network.protocol_anomaly_check", labels={"detected": str(detected)})

        if detected:
            logger.warning(
                "protocol_anomalies_detected",
                anomaly_count=len(anomalies),
                violation_count=len(protocol_violations),
                severity=result["severity"],
            )
        else:
            logger.debug("protocol_anomaly_check_clean", entries=len(protocol_data))

        return result

    except Exception as e:
        metrics.inc_counter("network.protocol_anomaly_error")
        logger.error("protocol_anomaly_detection_failed", error=str(e))
        raise SecurityError(f"Protocol anomaly detection failed: {e}") from e
    finally:
        getattr(span, "end", lambda: None)()
