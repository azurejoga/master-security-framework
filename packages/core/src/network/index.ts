import { createHash } from 'crypto';
import { sha3_256 } from '@noble/hashes/sha3';
import { getLogger, getMetrics, createSpan, getEventBus, SecurityEvent, EventSeverity } from '../core/index.js';
import { SecurityError } from '../core/exceptions.js';
import pino from 'pino';

const logger = pino().child({ module: 'msf.network' });

// --- Type Definitions -------------------------------------------------------

export interface DetectionResult {
  detected: boolean;
  confidence: number;
  severity: EventSeverity;
  details: Record<string, unknown>;
  timestamp: string;
  metrics: Record<string, number>;
}

export interface IpValidationResult {
  valid: boolean;
  ip: string;
  inAllowedRange: boolean;
  inBlockedRange: boolean;
  riskScore: number;
  details: Record<string, unknown>;
  timestamp: string;
}

export interface DomainValidationResult {
  valid: boolean;
  domain: string;
  tldAllowed: boolean;
  domainBlocked: boolean;
  riskScore: number;
  details: Record<string, unknown>;
  timestamp: string;
}

export interface FingerprintResult {
  fingerprint: string;
  ja3Hash: string;
  matched: boolean;
  matchedProfile?: string;
  riskScore: number;
  details: Record<string, unknown>;
  timestamp: string;
}

export interface EntropyResult {
  entropy: number;
  blockSize: number;
  threshold: number;
  isAnomalous: boolean;
  distribution: Record<string, number>;
  metrics: Record<string, number>;
  timestamp: string;
}

export interface BehaviorResult {
  baseline: Record<string, number>;
  current: Record<string, number>;
  deviations: Record<string, number>;
  anomalies: string[];
  riskScore: number;
  metrics: Record<string, number>;
  timestamp: string;
}

export interface ConnectionRecord {
  sourceIp: string;
  destinationIp: string;
  destinationPort: number;
  protocol: string;
  timestamp: number;
  bytesSent: number;
  bytesReceived: number;
}

export interface DnsQuery {
  domain: string;
  queryType: string;
  sourceIp: string;
  timestamp: number;
  responseSize?: number;
}

export interface TrafficData {
  bytesPerSecond: number;
  packetsPerSecond: number;
  connectionsPerSecond: number;
  protocolDistribution: Record<string, number>;
  sourceDistribution: Record<string, number>;
  timestamp: number;
}

export interface PacketData {
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: string;
  ttl: number;
  flags: string[];
  payload: string;
  timestamp: number;
}

export interface ArpEntry {
  ip: string;
  mac: string;
  interface: string;
  timestamp: number;
}

export interface TlsHandshake {
  version: string;
  cipherSuites: string[];
  extensions: string[];
  supportedGroups: string[];
  keyExchange: string;
  signatureAlgorithms: string[];
  timestamp: number;
}

export interface TlsClientHello {
  version: string;
  random: string;
  sessionId: string;
  cipherSuites: string[];
  compressionMethods: string[];
  extensions: Array<{ type: number; data: string }>;
}

export interface NetworkTopology {
  subnets: string[];
  gateways: string[];
  trustedHosts: string[];
  dmzHosts: string[];
}

export interface UserBehavior {
  userId: string;
  normalSubnets: string[];
  normalHours: number[];
  normalProtocols: string[];
  riskProfile: 'low' | 'medium' | 'high';
}

export interface SecurityEventRecord {
  eventType: string;
  sourceIp: string;
  destinationIp: string;
  protocol: string;
  timestamp: number;
  userId?: string;
  details?: Record<string, unknown>;
}

// --- Helper Functions -------------------------------------------------------

function ipToNumber(ip: string): number {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function ipInRange(ip: string, cidr: string): boolean {
  const [range, bits] = cidr.split('/');
  const mask = bits ? (~0 << (32 - parseInt(bits, 10))) >>> 0 : 0xffffffff;
  return (ipToNumber(ip) & mask) === (ipToNumber(range) & mask);
}

function calculateShannonEntropy(data: number[]): number {
  if (data.length === 0) return 0;
  const freq: Record<number, number> = {};
  for (const byte of data) {
    freq[byte] = (freq[byte] || 0) + 1;
  }
  let entropy = 0;
  const len = data.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return entropy;
}

function getSeverityFromConfidence(confidence: number): EventSeverity {
  if (confidence >= 0.9) return EventSeverity.CRITICAL;
  if (confidence >= 0.7) return EventSeverity.HIGH;
  if (confidence >= 0.4) return EventSeverity.MEDIUM;
  if (confidence >= 0.2) return EventSeverity.LOW;
  return EventSeverity.INFO;
}

// --- 1. detectPortScan ------------------------------------------------------

/**
 * Detects port scanning activity from a source IP within a time window.
 * @param sourceIp - The IP address to analyze
 * @param connections - Array of connection records
 * @param window - Time window in seconds (default: 60)
 * @param threshold - Number of unique ports to trigger detection (default: 20)
 * @returns DetectionResult with scan detection status and confidence
 */
export function detectPortScan(
  sourceIp: string,
  connections: ConnectionRecord[],
  window: number = 60,
  threshold: number = 20
): DetectionResult {
  const span = createSpan('network.detectPortScan', { sourceIp, window, threshold });
  const metrics = getMetrics();

  const now = Date.now();
  const windowStart = now - window * 1000;
  const recentConnections = connections.filter(
    (c) => c.sourceIp === sourceIp && c.timestamp >= windowStart
  );

  const uniquePorts = new Set(recentConnections.map((c) => c.destinationPort));
  const uniqueDestinations = new Set(recentConnections.map((c) => c.destinationIp));
  const confidence = Math.min(uniquePorts.size / threshold, 1);
  const detected = uniquePorts.size >= threshold;

  const result: DetectionResult = {
    detected,
    confidence,
    severity: getSeverityFromConfidence(confidence),
    details: {
      sourceIp,
      uniquePortsScanned: uniquePorts.size,
      uniqueDestinations: uniqueDestinations.size,
      totalConnections: recentConnections.length,
      windowSeconds: window,
      threshold,
    },
    timestamp: new Date().toISOString(),
    metrics: {
      'network.port_scan.connections': recentConnections.length,
      'network.port_scan.unique_ports': uniquePorts.size,
      'network.port_scan.unique_destinations': uniqueDestinations.size,
    },
  };

  metrics.incCounter('network.port_scan.checks');
  if (detected) metrics.incCounter('network.port_scan.detections');

  logger.warn({ sourceIp, ports: uniquePorts.size, detected }, 'Port scan detection');

  if (detected) {
    const eventBus = getEventBus();
    eventBus.publish('security:detection', {
      type: 'PORT_SCAN',
      severity: result.severity,
      sourceIp,
      details: result.details,
    } as SecurityEvent);
  }

  span.end({ detected });
  return result;
}

// --- 2. detectDnsTunneling --------------------------------------------------

/**
 * Detects DNS tunneling by analyzing query patterns for a specific domain.
 * @param dnsQueries - Array of DNS query records
 * @param domain - The domain to analyze for tunneling
 * @param threshold - Query count threshold for detection (default: 50)
 * @returns DetectionResult with tunneling detection status
 */
export function detectDnsTunneling(
  dnsQueries: DnsQuery[],
  domain: string,
  threshold: number = 50
): DetectionResult {
  const span = createSpan('network.detectDnsTunneling', { domain, threshold });
  const metrics = getMetrics();

  const domainQueries = dnsQueries.filter((q) => q.domain.endsWith(domain));
  const avgQueryLength =
    domainQueries.reduce((sum, q) => sum + q.domain.length, 0) / (domainQueries.length || 1);
  const avgResponseSize =
    domainQueries.reduce((sum, q) => sum + (q.responseSize || 0), 0) / (domainQueries.length || 1);

  const subdomainLabels = domainQueries.map((q) => {
    const prefix = q.domain.replace(new RegExp(`\\.?${domain.replace(/\./g, '\\.')}$`), '');
    return prefix.split('.');
  });
  const avgLabelCount =
    subdomainLabels.reduce((sum, labels) => sum + labels.length, 0) / (subdomainLabels.length || 1);
  const avgLabelLength =
    subdomainLabels.reduce(
      (sum, labels) => sum + labels.reduce((s, l) => s + l.length, 0) / (labels.length || 1),
      0
    ) / (subdomainLabels.length || 1);

  let confidence = 0;
  if (domainQueries.length >= threshold) confidence += 0.3;
  if (avgQueryLength > 50) confidence += 0.25;
  if (avgResponseSize > 512) confidence += 0.2;
  if (avgLabelLength > 20) confidence += 0.15;
  if (avgLabelCount > 3) confidence += 0.1;
  confidence = Math.min(confidence, 1);

  const detected = confidence >= 0.5;

  const result: DetectionResult = {
    detected,
    confidence,
    severity: getSeverityFromConfidence(confidence),
    details: {
      domain,
      queryCount: domainQueries.length,
      avgQueryLength,
      avgResponseSize,
      avgLabelCount,
      avgLabelLength,
      threshold,
    },
    timestamp: new Date().toISOString(),
    metrics: {
      'network.dns_tunnel.queries': domainQueries.length,
      'network.dns_tunnel.avg_length': avgQueryLength,
      'network.dns_tunnel.avg_response': avgResponseSize,
    },
  };

  metrics.incCounter('network.dns_tunnel.checks');
  if (detected) metrics.incCounter('network.dns_tunnel.detections');

  logger.warn({ domain, queries: domainQueries.length, confidence }, 'DNS tunneling detection');

  if (detected) {
    const eventBus = getEventBus();
    eventBus.publish('security:detection', {
      type: 'DNS_TUNNELING',
      severity: result.severity,
      details: result.details,
    } as SecurityEvent);
  }

  span.end({ detected });
  return result;
}

// --- 3. detectTrafficAnomaly ------------------------------------------------

/**
 * Detects anomalies in network traffic by comparing against baseline metrics.
 * @param trafficData - Current traffic data snapshot
 * @param baseline - Baseline traffic metrics
 * @param deviationThreshold - Standard deviation multiplier for anomaly (default: 2.0)
 * @returns DetectionResult with anomaly detection status
 */
export function detectTrafficAnomaly(
  trafficData: TrafficData,
  baseline: Record<string, number>,
  deviationThreshold: number = 2.0
): DetectionResult {
  const span = createSpan('network.detectTrafficAnomaly', { deviationThreshold });
  const metrics = getMetrics();

  const deviations: Record<string, number> = {};
  const anomalies: string[] = [];
  let maxDeviation = 0;

  for (const [key, baselineValue] of Object.entries(baseline)) {
    const currentValue = (trafficData as Record<string, unknown>)[key] as number | undefined;
    if (currentValue !== undefined && baselineValue > 0) {
      const deviation = Math.abs(currentValue - baselineValue) / baselineValue;
      deviations[key] = deviation;
      if (deviation > maxDeviation) maxDeviation = deviation;
      if (deviation >= deviationThreshold) {
        anomalies.push(key);
      }
    }
  }

  const confidence = Math.min(maxDeviation / (deviationThreshold * 2), 1);
  const detected = anomalies.length > 0;

  const result: DetectionResult = {
    detected,
    confidence,
    severity: getSeverityFromConfidence(confidence),
    details: {
      deviations,
      anomalies,
      maxDeviation,
      deviationThreshold,
    },
    timestamp: new Date().toISOString(),
    metrics: {
      'network.traffic_anomaly.max_deviation': maxDeviation,
      'network.traffic_anomaly.anomaly_count': anomalies.length,
    },
  };

  metrics.incCounter('network.traffic_anomaly.checks');
  if (detected) metrics.incCounter('network.traffic_anomaly.detections');

  logger.warn({ anomalies, maxDeviation, detected }, 'Traffic anomaly detection');

  if (detected) {
    const eventBus = getEventBus();
    eventBus.publish('security:detection', {
      type: 'TRAFFIC_ANOMALY',
      severity: result.severity,
      details: result.details,
    } as SecurityEvent);
  }

  span.end({ detected });
  return result;
}

// --- 4. detectProxy ---------------------------------------------------------

/**
 * Detects proxy usage by analyzing HTTP headers and behavior patterns.
 * @param ip - The IP address to analyze
 * @param headers - HTTP request headers
 * @param detectionMethods - Methods to use: header, behavior, database (default: all)
 * @returns DetectionResult with proxy detection status
 */
export function detectProxy(
  ip: string,
  headers: Record<string, string>,
  detectionMethods: string[] = ['header', 'behavior', 'database']
): DetectionResult {
  const span = createSpan('network.detectProxy', { ip, methods: detectionMethods });
  const metrics = getMetrics();

  let confidence = 0;
  const indicators: string[] = [];

  if (detectionMethods.includes('header')) {
    const proxyHeaders = [
      'x-forwarded-for',
      'via',
      'x-real-ip',
      'forwarded',
      'x-proxy-id',
      'x-forwarded-host',
    ];
    for (const header of proxyHeaders) {
      if (headers[header.toLowerCase()] || headers[header]) {
        confidence += 0.2;
        indicators.push(`header:${header}`);
      }
    }
  }

  if (detectionMethods.includes('behavior')) {
    const ttl = parseInt(headers['x-ttl'] || '0', 10);
    if (ttl > 0 && ttl < 32) {
      confidence += 0.15;
      indicators.push('low_ttl');
    }
  }

  if (detectionMethods.includes('database')) {
    const proxyDb = (globalThis as Record<string, unknown>).__proxyDb as
      | Set<string>
      | undefined;
    if (proxyDb?.has(ip)) {
      confidence += 0.4;
      indicators.push('database_match');
    }
  }

  confidence = Math.min(confidence, 1);
  const detected = confidence >= 0.5;

  const result: DetectionResult = {
    detected,
    confidence,
    severity: getSeverityFromConfidence(confidence),
    details: {
      ip,
      indicators,
      methodsUsed: detectionMethods,
      proxyHeadersFound: indicators.filter((i) => i.startsWith('header:')),
    },
    timestamp: new Date().toISOString(),
    metrics: {
      'network.proxy.indicators': indicators.length,
      'network.proxy.confidence': confidence,
    },
  };

  metrics.incCounter('network.proxy.checks');
  if (detected) metrics.incCounter('network.proxy.detections');

  logger.info({ ip, detected, confidence, indicators }, 'Proxy detection');

  span.end({ detected });
  return result;
}

// --- 5. detectVpn -----------------------------------------------------------

/**
 * Detects VPN usage by checking against known VPN databases and port analysis.
 * @param ip - The IP address to analyze
 * @param headers - HTTP request headers
 * @param vpnDb - Set of known VPN IP addresses
 * @returns DetectionResult with VPN detection status
 */
export function detectVpn(
  ip: string,
  headers: Record<string, string>,
  vpnDb: Set<string> = new Set()
): DetectionResult {
  const span = createSpan('network.detectVpn', { ip });
  const metrics = getMetrics();

  let confidence = 0;
  const indicators: string[] = [];

  if (vpnDb.has(ip)) {
    confidence += 0.6;
    indicators.push('vpn_database_match');
  }

  const knownVpnPorts = [1194, 500, 4500, 1701, 1723];
  const userPort = parseInt(headers['x-source-port'] || '0', 10);
  if (knownVpnPorts.includes(userPort)) {
    confidence += 0.2;
    indicators.push('vpn_port');
  }

  if (headers['x-vpn-protocol']) {
    confidence += 0.15;
    indicators.push('vpn_protocol_header');
  }

  confidence = Math.min(confidence, 1);
  const detected = confidence >= 0.5;

  const result: DetectionResult = {
    detected,
    confidence,
    severity: getSeverityFromConfidence(confidence),
    details: {
      ip,
      indicators,
      vpnDbSize: vpnDb.size,
    },
    timestamp: new Date().toISOString(),
    metrics: {
      'network.vpn.confidence': confidence,
      'network.vpn.indicators': indicators.length,
    },
  };

  metrics.incCounter('network.vpn.checks');
  if (detected) metrics.incCounter('network.vpn.detections');

  logger.info({ ip, detected, confidence }, 'VPN detection');

  span.end({ detected });
  return result;
}

// --- 6. detectTor -----------------------------------------------------------

/**
 * Detects Tor network usage by checking against known Tor node lists.
 * @param ip - The IP address to analyze
 * @param torNodes - Set of known Tor relay node IPs
 * @param exitNodes - Set of known Tor exit node IPs
 * @returns DetectionResult with Tor detection status and node role
 */
export function detectTor(
  ip: string,
  torNodes: Set<string> = new Set(),
  exitNodes: Set<string> = new Set()
): DetectionResult {
  const span = createSpan('network.detectTor', { ip });
  const metrics = getMetrics();

  let confidence = 0;
  const role: string[] = [];

  if (exitNodes.has(ip)) {
    confidence += 0.8;
    role.push('exit_node');
  } else if (torNodes.has(ip)) {
    confidence += 0.6;
    role.push('relay_node');
  }

  const isTor = confidence >= 0.5;

  const result: DetectionResult = {
    detected: isTor,
    confidence,
    severity: isTor ? EventSeverity.HIGH : EventSeverity.INFO,
    details: {
      ip,
      role,
      isExitNode: exitNodes.has(ip),
      isRelayNode: torNodes.has(ip) && !exitNodes.has(ip),
      torNodeCount: torNodes.size,
      exitNodeCount: exitNodes.size,
    },
    timestamp: new Date().toISOString(),
    metrics: {
      'network.tor.confidence': confidence,
      'network.tor.is_exit': exitNodes.has(ip) ? 1 : 0,
    },
  };

  metrics.incCounter('network.tor.checks');
  if (isTor) metrics.incCounter('network.tor.detections');

  logger.info({ ip, detected: isTor, role }, 'Tor detection');

  span.end({ detected: isTor });
  return result;
}

// --- 7. detectDdos ----------------------------------------------------------

/**
 * Detects DDoS attacks by analyzing traffic spikes against baseline.
 * @param trafficData - Current traffic data snapshot
 * @param baseline - Baseline traffic metrics
 * @param threshold - Multiplier over baseline to trigger detection (default: 5.0)
 * @param window - Analysis window in seconds (default: 60)
 * @returns DetectionResult with DDoS detection status and attack type
 */
export function detectDdos(
  trafficData: TrafficData,
  baseline: Record<string, number>,
  threshold: number = 5.0,
  window: number = 60
): DetectionResult {
  const span = createSpan('network.detectDdos', { threshold, window });
  const metrics = getMetrics();

  const bpsRatio = baseline.bytesPerSecond
    ? trafficData.bytesPerSecond / baseline.bytesPerSecond
    : 1;
  const ppsRatio = baseline.packetsPerSecond
    ? trafficData.packetsPerSecond / baseline.packetsPerSecond
    : 1;
  const cpsRatio = baseline.connectionsPerSecond
    ? trafficData.connectionsPerSecond / baseline.connectionsPerSecond
    : 1;

  const maxRatio = Math.max(bpsRatio, ppsRatio, cpsRatio);
  const detected = maxRatio >= threshold;
  const confidence = Math.min(maxRatio / (threshold * 2), 1);

  const sourceConcentration = Object.values(trafficData.sourceDistribution);
  const totalSources = sourceConcentration.length;
  const topSourceShare =
    sourceConcentration.length > 0
      ? Math.max(...sourceConcentration) /
        sourceConcentration.reduce((a, b) => a + b, 0)
      : 0;

  const attackType =
    ppsRatio > bpsRatio && ppsRatio >= threshold
      ? 'VOLUMETRIC'
      : cpsRatio >= threshold
        ? 'FLOOD'
        : 'APPLICATION_LAYER';

  const result: DetectionResult = {
    detected,
    confidence,
    severity: getSeverityFromConfidence(confidence),
    details: {
      bpsRatio,
      ppsRatio,
      cpsRatio,
      maxRatio,
      threshold,
      attackType,
      totalSources,
      topSourceShare,
      windowSeconds: window,
    },
    timestamp: new Date().toISOString(),
    metrics: {
      'network.ddos.bps_ratio': bpsRatio,
      'network.ddos.pps_ratio': ppsRatio,
      'network.ddos.cps_ratio': cpsRatio,
      'network.ddos.max_ratio': maxRatio,
    },
  };

  metrics.incCounter('network.ddos.checks');
  if (detected) metrics.incCounter('network.ddos.detections');

  logger.error(
    { detected, attackType, maxRatio, threshold },
    'DDoS detection'
  );

  if (detected) {
    const eventBus = getEventBus();
    eventBus.publish('security:detection', {
      type: 'DDOS',
      severity: result.severity,
      details: result.details,
    } as SecurityEvent);
  }

  span.end({ detected });
  return result;
}

// --- 8. validateIp ----------------------------------------------------------

/**
 * Validates an IP address against allowed and blocked ranges.
 * @param ip - The IP address to validate
 * @param allowedRanges - CIDR ranges that are allowed (empty = all allowed)
 * @param blockedRanges - CIDR ranges that are blocked
 * @returns IpValidationResult with validation status and risk score
 */
export function validateIp(
  ip: string,
  allowedRanges: string[] = [],
  blockedRanges: string[] = []
): IpValidationResult {
  const span = createSpan('network.validateIp', { ip });
  const metrics = getMetrics();

  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const isValidFormat = ipv4Regex.test(ip) && ip.split('.').every((o) => parseInt(o, 10) <= 255);

  if (!isValidFormat) {
    logger.warn({ ip }, 'Invalid IP format');
    span.end({ valid: false, reason: 'invalid_format' });
    return {
      valid: false,
      ip,
      inAllowedRange: false,
      inBlockedRange: false,
      riskScore: 1,
      details: { reason: 'invalid_format' },
      timestamp: new Date().toISOString(),
    };
  }

  const inAllowedRange =
    allowedRanges.length === 0 || allowedRanges.some((range) => ipInRange(ip, range));
  const inBlockedRange = blockedRanges.some((range) => ipInRange(ip, range));

  let riskScore = 0;
  if (!inAllowedRange && allowedRanges.length > 0) riskScore += 0.4;
  if (inBlockedRange) riskScore += 0.5;

  const privateRanges = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];
  const isPrivate = privateRanges.some((r) => ipInRange(ip, r));
  if (isPrivate) riskScore -= 0.1;

  riskScore = Math.max(0, Math.min(1, riskScore));

  const result: IpValidationResult = {
    valid: !inBlockedRange && (inAllowedRange || allowedRanges.length === 0),
    ip,
    inAllowedRange,
    inBlockedRange,
    riskScore,
    details: { isPrivate, allowedRangesCount: allowedRanges.length, blockedRangesCount: blockedRanges.length },
    timestamp: new Date().toISOString(),
  };

  metrics.incCounter('network.ip_validation.checks');
  if (!result.valid) metrics.incCounter('network.ip_validation.failures');

  logger.debug({ ip, valid: result.valid, riskScore }, 'IP validation');

  span.end({ valid: result.valid });
  return result;
}

// --- 9. validateDomain ------------------------------------------------------

/**
 * Validates a domain against allowed TLDs and blocked domains list.
 * @param domain - The domain to validate
 * @param allowedTlds - Allowed TLDs (empty = all allowed)
 * @param blockedDomains - Blocked domains and parent domains
 * @returns DomainValidationResult with validation status and risk score
 */
export function validateDomain(
  domain: string,
  allowedTlds: string[] = [],
  blockedDomains: string[] = []
): DomainValidationResult {
  const span = createSpan('network.validateDomain', { domain });
  const metrics = getMetrics();

  const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/;
  const isValidFormat = domainRegex.test(domain);

  if (!isValidFormat) {
    logger.warn({ domain }, 'Invalid domain format');
    span.end({ valid: false, reason: 'invalid_format' });
    return {
      valid: false,
      domain,
      tldAllowed: false,
      domainBlocked: false,
      riskScore: 1,
      details: { reason: 'invalid_format' },
      timestamp: new Date().toISOString(),
    };
  }

  const parts = domain.split('.');
  const tld = '.' + parts[parts.length - 1].toLowerCase();
  const tldAllowed = allowedTlds.length === 0 || allowedTlds.includes(tld);
  const domainBlocked =
    blockedDomains.some((bd) => domain === bd || domain.endsWith('.' + bd));

  let riskScore = 0;
  if (!tldAllowed && allowedTlds.length > 0) riskScore += 0.3;
  if (domainBlocked) riskScore += 0.5;
  if (domain.length > 50) riskScore += 0.1;
  if (parts.some((p) => p.length > 30)) riskScore += 0.1;

  riskScore = Math.max(0, Math.min(1, riskScore));

  const result: DomainValidationResult = {
    valid: !domainBlocked && (tldAllowed || allowedTlds.length === 0),
    domain,
    tldAllowed,
    domainBlocked,
    riskScore,
    details: { tld, partsCount: parts.length, maxLength: Math.max(...parts.map((p) => p.length)) },
    timestamp: new Date().toISOString(),
  };

  metrics.incCounter('network.domain_validation.checks');
  if (!result.valid) metrics.incCounter('network.domain_validation.failures');

  logger.debug({ domain, valid: result.valid, riskScore }, 'Domain validation');

  span.end({ valid: result.valid });
  return result;
}

// --- 10. detectSpoofing -----------------------------------------------------

/**
 * Detects IP spoofing by analyzing packet data against expected sources and network topology.
 * @param packetData - Packet data to analyze
 * @param expectedSource - Expected source IP address
 * @param networkTopology - Network topology with trusted hosts and subnets
 * @returns DetectionResult with spoofing detection status
 */
export function detectSpoofing(
  packetData: PacketData,
  expectedSource: string,
  networkTopology: NetworkTopology
): DetectionResult {
  const span = createSpan('network.detectSpoofing', { sourceIp: packetData.sourceIp });
  const metrics = getMetrics();

  let confidence = 0;
  const indicators: string[] = [];

  if (packetData.sourceIp !== expectedSource) {
    confidence += 0.3;
    indicators.push('source_mismatch');
  }

  const isTrusted = networkTopology.trustedHosts.includes(packetData.sourceIp);
  const isInSubnet = networkTopology.subnets.some((subnet) =>
    ipInRange(packetData.sourceIp, subnet)
  );

  if (!isTrusted && !isInSubnet) {
    confidence += 0.25;
    indicators.push('outside_trusted_network');
  }

  if (packetData.ttl <= 1) {
    confidence += 0.2;
    indicators.push('suspicious_ttl');
  }

  if (packetData.flags.includes('SYN') && packetData.flags.includes('FIN')) {
    confidence += 0.3;
    indicators.push('invalid_flag_combination');
  }

  if (packetData.flags.includes('SYN') && packetData.flags.includes('RST')) {
    confidence += 0.25;
    indicators.push('syn_rst_combination');
  }

  confidence = Math.min(confidence, 1);
  const detected = confidence >= 0.5;

  const result: DetectionResult = {
    detected,
    confidence,
    severity: getSeverityFromConfidence(confidence),
    details: {
      sourceIp: packetData.sourceIp,
      expectedSource,
      indicators,
      ttl: packetData.ttl,
      flags: packetData.flags,
      isTrusted,
      isInSubnet,
    },
    timestamp: new Date().toISOString(),
    metrics: {
      'network.spoofing.confidence': confidence,
      'network.spoofing.indicators': indicators.length,
    },
  };

  metrics.incCounter('network.spoofing.checks');
  if (detected) metrics.incCounter('network.spoofing.detections');

  logger.warn({ sourceIp: packetData.sourceIp, detected, indicators }, 'Spoofing detection');

  if (detected) {
    const eventBus = getEventBus();
    eventBus.publish('security:detection', {
      type: 'SPOOFING',
      severity: result.severity,
      details: result.details,
    } as SecurityEvent);
  }

  span.end({ detected });
  return result;
}

// --- 11. detectArpPoisoning -------------------------------------------------

/**
 * Detects ARP poisoning by analyzing ARP table for conflicting MAC mappings.
 * @param arpTable - Current ARP table entries
 * @param expectedMappings - Expected IP-to-MAC mappings
 * @returns DetectionResult with ARP poisoning detection status
 */
export function detectArpPoisoning(
  arpTable: ArpEntry[],
  expectedMappings: Record<string, string> = {}
): DetectionResult {
  const span = createSpan('network.detectArpPoisoning');
  const metrics = getMetrics();

  const ipToMac: Record<string, string[]> = {};
  for (const entry of arpTable) {
    if (!ipToMac[entry.ip]) ipToMac[entry.ip] = [];
    if (!ipToMac[entry.ip].includes(entry.mac)) {
      ipToMac[entry.ip].push(entry.mac);
    }
  }

  const conflictingIps = Object.entries(ipToMac).filter(([, macs]) => macs.length > 1);
  const expectedViolations: Array<{ ip: string; expected: string; actual: string }> = [];

  for (const [ip, expectedMac] of Object.entries(expectedMappings)) {
    const actualMacs = ipToMac[ip];
    if (actualMacs && !actualMacs.includes(expectedMac)) {
      expectedViolations.push({ ip, expected: expectedMac, actual: actualMacs.join(', ') });
    }
  }

  const macToIps: Record<string, string[]> = {};
  for (const entry of arpTable) {
    if (!macToIps[entry.mac]) macToIps[entry.mac] = [];
    if (!macToIps[entry.mac].includes(entry.ip)) {
      macToIps[entry.mac].push(entry.ip);
    }
  }
  const suspiciousMacs = Object.entries(macToIps).filter(([, ips]) => ips.length > 2);

  let confidence = 0;
  const indicators: string[] = [];

  if (conflictingIps.length > 0) {
    confidence += 0.3 * Math.min(conflictingIps.length / 3, 1);
    indicators.push('multiple_macs_per_ip');
  }
  if (expectedViolations.length > 0) {
    confidence += 0.4;
    indicators.push('expected_mapping_violation');
  }
  if (suspiciousMacs.length > 0) {
    confidence += 0.2;
    indicators.push('single_mac_multiple_ips');
  }

  confidence = Math.min(confidence, 1);
  const detected = confidence >= 0.4;

  const result: DetectionResult = {
    detected,
    confidence,
    severity: getSeverityFromConfidence(confidence),
    details: {
      conflictingIps: conflictingIps.map(([ip, macs]) => ({ ip, macs })),
      expectedViolations,
      suspiciousMacs: suspiciousMacs.map(([mac, ips]) => ({ mac, ips })),
      totalEntries: arpTable.length,
    },
    timestamp: new Date().toISOString(),
    metrics: {
      'network.arp_poisoning.conflicts': conflictingIps.length,
      'network.arp_poisoning.violations': expectedViolations.length,
      'network.arp_poisoning.suspicious_macs': suspiciousMacs.length,
    },
  };

  metrics.incCounter('network.arp_poisoning.checks');
  if (detected) metrics.incCounter('network.arp_poisoning.detections');

  logger.warn({ detected, confidence, conflicts: conflictingIps.length }, 'ARP poisoning detection');

  if (detected) {
    const eventBus = getEventBus();
    eventBus.publish('security:detection', {
      type: 'ARP_POISONING',
      severity: result.severity,
      details: result.details,
    } as SecurityEvent);
  }

  span.end({ detected });
  return result;
}

// --- 12. tlsFingerprint -----------------------------------------------------

/**
 * Analyzes TLS handshake to generate fingerprint and match against known profiles.
 * @param tlsHandshake - TLS handshake data
 * @param ja3Database - Database of known JA3 fingerprints mapped to profiles
 * @returns FingerprintResult with JA3 hash and profile match status
 */
export function tlsFingerprint(
  tlsHandshake: TlsHandshake,
  ja3Database: Record<string, string> = {}
): FingerprintResult {
  const span = createSpan('network.tlsFingerprint');
  const metrics = getMetrics();

  const ja3 = ja3Fingerprint({
    version: tlsHandshake.version,
    random: '',
    sessionId: '',
    cipherSuites: tlsHandshake.cipherSuites,
    compressionMethods: [],
    extensions: tlsHandshake.extensions.map((ext, i) => ({ type: i, data: ext })),
  });

  const matchedProfile = ja3Database[ja3];
  const matched = matchedProfile !== undefined;

  let riskScore = 0;
  if (!matched) riskScore += 0.3;
  if (tlsHandshake.cipherSuites.length < 3) riskScore += 0.2;
  if (tlsHandshake.version === 'TLSv1.0' || tlsHandshake.version === 'TLSv1.1') {
    riskScore += 0.3;
  }
  if (tlsHandshake.extensions.length < 5) riskScore += 0.1;

  riskScore = Math.max(0, Math.min(1, riskScore));

  const result: FingerprintResult = {
    fingerprint: ja3,
    ja3Hash: createHash('md5').update(ja3).digest('hex'),
    matched,
    matchedProfile,
    riskScore,
    details: {
      version: tlsHandshake.version,
      cipherCount: tlsHandshake.cipherSuites.length,
      extensionCount: tlsHandshake.extensions.length,
      keyExchange: tlsHandshake.keyExchange,
    },
    timestamp: new Date().toISOString(),
  };

  metrics.incCounter('network.tls_fingerprint.checks');
  if (!matched) metrics.incCounter('network.tls_fingerprint.unknown');

  logger.debug({ ja3, matched, riskScore }, 'TLS fingerprint analysis');

  span.end({ matched });
  return result;
}

// --- 13. ja3Fingerprint -----------------------------------------------------

/**
 * Generates a JA3 fingerprint hash from a TLS Client Hello message.
 * JA3 fingerprints uniquely identify TLS client configurations.
 * @param tlsClientHello - TLS Client Hello message data
 * @returns MD5 hash string representing the JA3 fingerprint
 */
export function ja3Fingerprint(tlsClientHello: TlsClientHello): string {
  const span = createSpan('network.ja3Fingerprint');
  const metrics = getMetrics();

  const version = tlsClientHello.version || '';
  const ciphers = tlsClientHello.cipherSuites.join('-');
  const extensions = tlsClientHello.extensions.map((e) => e.type.toString()).join('-');
  const curves = tlsClientHello.extensions
    .filter((e) => e.type === 10)
    .map((e) => e.data)
    .join('-');
  const ecPointFormats = tlsClientHello.extensions
    .filter((e) => e.type === 11)
    .map((e) => e.data)
    .join('-');

  const ja3String = `${version},${ciphers},${extensions},${curves},${ecPointFormats}`;
  const hash = createHash('md5').update(ja3String).digest('hex');

  metrics.incCounter('network.ja3.fingerprints');

  logger.debug({ ja3String, hash }, 'JA3 fingerprint generated');

  span.end({ hash });
  return hash;
}

// --- 14. suspiciousDnsDetection ---------------------------------------------

/**
 * Detects suspicious DNS queries using threat intelligence and pattern matching.
 * @param dnsQueries - Array of DNS queries to analyze
 * @param threatIntel - Set of known malicious domains
 * @param patterns - Regex patterns for suspicious domain detection
 * @returns DetectionResult with suspicious DNS detection status
 */
export function suspiciousDnsDetection(
  dnsQueries: DnsQuery[],
  threatIntel: Set<string> = new Set(),
  patterns: RegExp[] = []
): DetectionResult {
  const span = createSpan('network.suspiciousDnsDetection');
  const metrics = getMetrics();

  const suspiciousQueries: Array<DnsQuery & { reason: string }> = [];

  for (const query of dnsQueries) {
    if (threatIntel.has(query.domain)) {
      suspiciousQueries.push({ ...query, reason: 'threat_intel_match' });
      continue;
    }

    for (const pattern of patterns) {
      if (pattern.test(query.domain)) {
        suspiciousQueries.push({ ...query, reason: `pattern_match:${pattern.source}` });
        break;
      }
    }

    const labels = query.domain.split('.');
    const hasLongLabel = labels.some((l) => l.length > 30);
    const hasHighEntropy = calculateShannonEntropy(
      query.domain.split('').map((c) => c.charCodeAt(0))
    ) > 3.5;

    if (hasLongLabel) {
      suspiciousQueries.push({ ...query, reason: 'long_label' });
    } else if (hasHighEntropy && labels.length > 2) {
      suspiciousQueries.push({ ...query, reason: 'high_entropy_subdomain' });
    }
  }

  const confidence =
    dnsQueries.length > 0 ? suspiciousQueries.length / dnsQueries.length : 0;
  const detected = suspiciousQueries.length > 0;

  const result: DetectionResult = {
    detected,
    confidence,
    severity: getSeverityFromConfidence(confidence),
    details: {
      totalQueries: dnsQueries.length,
      suspiciousCount: suspiciousQueries.length,
      suspiciousQueries: suspiciousQueries.slice(0, 20).map((q) => ({
        domain: q.domain,
        reason: q.reason,
      })),
      threatIntelSize: threatIntel.size,
      patternCount: patterns.length,
    },
    timestamp: new Date().toISOString(),
    metrics: {
      'network.suspicious_dns.total': dnsQueries.length,
      'network.suspicious_dns.suspicious': suspiciousQueries.length,
      'network.suspicious_dns.confidence': confidence,
    },
  };

  metrics.incCounter('network.suspicious_dns.checks');
  if (detected) metrics.incCounter('network.suspicious_dns.detections');

  logger.warn({ suspicious: suspiciousQueries.length, total: dnsQueries.length }, 'Suspicious DNS detection');

  if (detected) {
    const eventBus = getEventBus();
    eventBus.publish('security:detection', {
      type: 'SUSPICIOUS_DNS',
      severity: result.severity,
      details: result.details,
    } as SecurityEvent);
  }

  span.end({ detected });
  return result;
}

// --- 15. beaconingDetection -------------------------------------------------

/**
 * Detects beaconing behavior by analyzing connection timing regularity.
 * @param connections - Array of connection records to analyze
 * @param intervalThreshold - Minimum regularity score for detection (default: 0.8)
 * @param jitterThreshold - Maximum acceptable jitter ratio (default: 0.15)
 * @returns DetectionResult with beaconing detection status
 */
export function beaconingDetection(
  connections: ConnectionRecord[],
  intervalThreshold: number = 0.8,
  jitterThreshold: number = 0.15
): DetectionResult {
  const span = createSpan('network.beaconingDetection', { intervalThreshold, jitterThreshold });
  const metrics = getMetrics();

  const groupedByDestination: Record<string, ConnectionRecord[]> = {};
  for (const conn of connections) {
    const key = `${conn.sourceIp}->${conn.destinationIp}:${conn.destinationPort}`;
    if (!groupedByDestination[key]) groupedByDestination[key] = [];
    groupedByDestination[key].push(conn);
  }

  const beacons: Array<{
    destination: string;
    interval: number;
    regularity: number;
    jitter: number;
    connectionCount: number;
  }> = [];

  for (const [destination, conns] of Object.entries(groupedByDestination)) {
    if (conns.length < 3) continue;

    const sorted = [...conns].sort((a, b) => a.timestamp - b.timestamp);
    const intervals: number[] = [];
    for (let i = 1; i < sorted.length; i++) {
      intervals.push(sorted[i].timestamp - sorted[i - 1].timestamp);
    }

    if (intervals.length < 2) continue;

    const meanInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    if (meanInterval === 0) continue;

    const variance =
      intervals.reduce((sum, interval) => sum + Math.pow(interval - meanInterval, 2), 0) /
      intervals.length;
    const stdDev = Math.sqrt(variance);
    const jitter = stdDev / meanInterval;

    const regularity = 1 - jitter;

    if (regularity >= intervalThreshold && jitter <= jitterThreshold) {
      beacons.push({
        destination,
        interval: meanInterval,
        regularity,
        jitter,
        connectionCount: conns.length,
      });
    }
  }

  const confidence = beacons.length > 0 ? Math.min(beacons.length / 3, 1) : 0;
  const detected = beacons.length > 0;

  const result: DetectionResult = {
    detected,
    confidence,
    severity: getSeverityFromConfidence(confidence),
    details: {
      beacons: beacons.slice(0, 10),
      totalDestinations: Object.keys(groupedByDestination).length,
      beaconCount: beacons.length,
      intervalThreshold,
      jitterThreshold,
    },
    timestamp: new Date().toISOString(),
    metrics: {
      'network.beaconing.destinations': Object.keys(groupedByDestination).length,
      'network.beaconing.beacons': beacons.length,
      'network.beaconing.confidence': confidence,
    },
  };

  metrics.incCounter('network.beaconing.checks');
  if (detected) metrics.incCounter('network.beaconing.detections');

  logger.warn({ beacons: beacons.length, detected }, 'Beaconing detection');

  if (detected) {
    const eventBus = getEventBus();
    eventBus.publish('security:detection', {
      type: 'BEACONING',
      severity: result.severity,
      details: result.details,
    } as SecurityEvent);
  }

  span.end({ detected });
  return result;
}

// --- 16. lateralMovementDetection -------------------------------------------

/**
 * Detects lateral movement by analyzing user behavior across network segments.
 * @param events - Security events to analyze
 * @param networkTopology - Network topology with subnets and trusted hosts
 * @param userBehavior - User behavior baseline profile
 * @returns DetectionResult with lateral movement detection status
 */
export function lateralMovementDetection(
  events: SecurityEventRecord[],
  networkTopology: NetworkTopology,
  userBehavior: UserBehavior
): DetectionResult {
  const span = createSpan('network.lateralMovementDetection', { userId: userBehavior.userId });
  const metrics = getMetrics();

  const indicators: string[] = [];
  let confidence = 0;

  const uniqueSubnets = new Set<string>();
  const uniqueHosts = new Set<string>();
  const unusualProtocols: string[] = [];

  for (const event of events) {
    for (const subnet of networkTopology.subnets) {
      if (ipInRange(event.sourceIp, subnet) || ipInRange(event.destinationIp, subnet)) {
        uniqueSubnets.add(subnet);
      }
    }
    uniqueHosts.add(event.destinationIp);

    if (!userBehavior.normalProtocols.includes(event.protocol)) {
      unusualProtocols.push(event.protocol);
    }
  }

  const unusualSubnets = [...uniqueSubnets].filter(
    (s) => !userBehavior.normalSubnets.includes(s)
  );

  if (unusualSubnets.length > 0) {
    confidence += 0.25 * Math.min(unusualSubnets.length / 2, 1);
    indicators.push('unusual_subnets');
  }

  if (uniqueHosts.size > 5) {
    confidence += 0.2;
    indicators.push('multiple_hosts');
  }

  if (unusualProtocols.length > 0) {
    confidence += 0.2;
    indicators.push('unusual_protocols');
  }

  if (userBehavior.riskProfile === 'high') {
    confidence += 0.15;
    indicators.push('high_risk_user');
  }

  const adminPorts = [22, 3389, 445, 135, 5985, 5986];
  const adminPortConnections = events.filter((e) =>
    adminPorts.includes(e.destinationPort as number)
  );
  if (adminPortConnections.length > 0) {
    confidence += 0.2;
    indicators.push('admin_port_access');
  }

  confidence = Math.min(confidence, 1);
  const detected = confidence >= 0.5;

  const result: DetectionResult = {
    detected,
    confidence,
    severity: getSeverityFromConfidence(confidence),
    details: {
      userId: userBehavior.userId,
      unusualSubnets,
      uniqueHosts: uniqueHosts.size,
      unusualProtocols: [...new Set(unusualProtocols)],
      adminPortAccess: adminPortConnections.length,
      indicators,
      totalEvents: events.length,
    },
    timestamp: new Date().toISOString(),
    metrics: {
      'network.lateral_movement.subnets': uniqueSubnets.size,
      'network.lateral_movement.hosts': uniqueHosts.size,
      'network.lateral_movement.confidence': confidence,
    },
  };

  metrics.incCounter('network.lateral_movement.checks');
  if (detected) metrics.incCounter('network.lateral_movement.detections');

  logger.warn({ userId: userBehavior.userId, detected, indicators }, 'Lateral movement detection');

  if (detected) {
    const eventBus = getEventBus();
    eventBus.publish('security:detection', {
      type: 'LATERAL_MOVEMENT',
      severity: result.severity,
      details: result.details,
    } as SecurityEvent);
  }

  span.end({ detected });
  return result;
}

// --- 17. commandAndControlDetection -----------------------------------------

/**
 * Detects command and control (C2) communication patterns in network traffic.
 * @param trafficPatterns - Array of traffic data snapshots to analyze
 * @param knownC2 - Set of known C2 server addresses
 * @param behavioralAnalysis - Additional behavioral analysis parameters
 * @returns DetectionResult with C2 detection status
 */
export function commandAndControlDetection(
  trafficPatterns: TrafficData[],
  knownC2: Set<string> = new Set(),
  behavioralAnalysis: Record<string, unknown> = {}
): DetectionResult {
  const span = createSpan('network.commandAndControlDetection');
  const metrics = getMetrics();

  const indicators: string[] = [];
  let confidence = 0;

  const c2Matches: string[] = [];
  for (const pattern of trafficPatterns) {
    for (const [source] of Object.entries(pattern.sourceDistribution)) {
      if (knownC2.has(source)) {
        c2Matches.push(source);
      }
    }
  }

  if (c2Matches.length > 0) {
    confidence += 0.5;
    indicators.push('known_c2_match');
  }

  const beaconResult = beaconingDetection(
    trafficPatterns.flatMap((p, i) =>
      Object.entries(p.sourceDistribution).map(([ip, bytes]) => ({
        sourceIp: ip,
        destinationIp: '0.0.0.0',
        destinationPort: 0,
        protocol: 'TCP',
        timestamp: p.timestamp + i * 1000,
        bytesSent: bytes,
        bytesReceived: 0,
      }))
    ),
    0.7,
    0.2
  );

  if (beaconResult.detected) {
    confidence += 0.25;
    indicators.push('beaconing_pattern');
  }

  const avgBytes =
    trafficPatterns.reduce((sum, p) => sum + p.bytesPerSecond, 0) /
    (trafficPatterns.length || 1);
  const byteVariance =
    trafficPatterns.reduce(
      (sum, p) => sum + Math.pow(p.bytesPerSecond - avgBytes, 2),
      0
    ) / (trafficPatterns.length || 1);
  const byteStdDev = Math.sqrt(byteVariance);
  const byteCoefficientVariation = avgBytes > 0 ? byteStdDev / avgBytes : 0;

  if (byteCoefficientVariation < 0.2 && trafficPatterns.length > 5) {
    confidence += 0.15;
    indicators.push('consistent_data_volume');
  }

  if (
    (behavioralAnalysis.encryptedRatio as number) > 0.9 &&
    (behavioralAnalysis.expectedEncryptedRatio as number) < 0.5
  ) {
    confidence += 0.1;
    indicators.push('unexpected_encryption');
  }

  confidence = Math.min(confidence, 1);
  const detected = confidence >= 0.5;

  const result: DetectionResult = {
    detected,
    confidence,
    severity: getSeverityFromConfidence(confidence),
    details: {
      c2Matches,
      beaconingDetected: beaconResult.detected,
      byteCoefficientVariation,
      indicators,
      patternsAnalyzed: trafficPatterns.length,
    },
    timestamp: new Date().toISOString(),
    metrics: {
      'network.c2.matches': c2Matches.length,
      'network.c2.beaconing': beaconResult.detected ? 1 : 0,
      'network.c2.confidence': confidence,
    },
  };

  metrics.incCounter('network.c2.checks');
  if (detected) metrics.incCounter('network.c2.detections');

  logger.error({ detected, c2Matches, indicators }, 'C2 detection');

  if (detected) {
    const eventBus = getEventBus();
    eventBus.publish('security:detection', {
      type: 'COMMAND_AND_CONTROL',
      severity: result.severity,
      details: result.details,
    } as SecurityEvent);
  }

  span.end({ detected });
  return result;
}

// --- 18. networkEntropyAnalysis ---------------------------------------------

/**
 * Analyzes network packet entropy to detect encrypted or encoded payloads.
 * High entropy may indicate encryption, compression, or encoded data exfiltration.
 * @param packets - Array of packet data to analyze
 * @param blockSize - Size of blocks for entropy calculation (default: 256)
 * @param threshold - Entropy threshold for anomaly detection (default: 7.5)
 * @returns EntropyResult with entropy metrics and anomaly status
 */
export function networkEntropyAnalysis(
  packets: PacketData[],
  blockSize: number = 256,
  threshold: number = 7.5
): EntropyResult {
  const span = createSpan('network.networkEntropyAnalysis', { blockSize, threshold });
  const metrics = getMetrics();

  const allBytes: number[] = [];
  for (const packet of packets) {
    const payloadBytes = Buffer.from(packet.payload, 'hex');
    for (let i = 0; i < payloadBytes.length; i++) {
      allBytes.push(payloadBytes[i]);
    }
  }

  const blocks: number[][] = [];
  for (let i = 0; i < allBytes.length; i += blockSize) {
    blocks.push(allBytes.slice(i, i + blockSize));
  }

  const blockEntropies = blocks.map((block) => calculateShannonEntropy(block));
  const overallEntropy = calculateShannonEntropy(allBytes);

  const distribution: Record<string, number> = {};
  for (const byte of allBytes) {
    const key = byte.toString(16).padStart(2, '0');
    distribution[key] = (distribution[key] || 0) + 1;
  }

  const totalBytes = allBytes.length;
  for (const key of Object.keys(distribution)) {
    distribution[key] = distribution[key] / totalBytes;
  }

  const anomalousBlocks = blockEntropies.filter((e) => e > threshold).length;
  const isAnomalous = overallEntropy > threshold || anomalousBlocks > blocks.length * 0.3;

  const result: EntropyResult = {
    entropy: overallEntropy,
    blockSize,
    threshold,
    isAnomalous,
    distribution: Object.fromEntries(
      Object.entries(distribution)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 16)
    ),
    metrics: {
      'network.entropy.overall': overallEntropy,
      'network.entropy.max_block': Math.max(...blockEntropies, 0),
      'network.entropy.min_block': Math.min(...blockEntropies, 0),
      'network.entropy.anomalous_blocks': anomalousBlocks,
      'network.entropy.total_blocks': blocks.length,
    },
    timestamp: new Date().toISOString(),
  };

  metrics.incCounter('network.entropy.checks');
  if (isAnomalous) metrics.incCounter('network.entropy.anomalies');

  logger.debug({ entropy: overallEntropy, isAnomalous, blocks: blocks.length }, 'Network entropy analysis');

  span.end({ isAnomalous });
  return result;
}

// --- 19. trafficBehaviorAnalysis --------------------------------------------

/**
 * Analyzes traffic behavior by comparing current metrics against baseline.
 * @param trafficData - Current traffic data snapshot
 * @param baseline - Baseline traffic behavior metrics
 * @param timeWindow - Analysis time window in seconds (default: 3600)
 * @returns BehaviorResult with deviation analysis and anomaly list
 */
export function trafficBehaviorAnalysis(
  trafficData: TrafficData,
  baseline: Record<string, number>,
  timeWindow: number = 3600
): BehaviorResult {
  const span = createSpan('network.trafficBehaviorAnalysis', { timeWindow });
  const metrics = getMetrics();

  const current: Record<string, number> = {
    bytesPerSecond: trafficData.bytesPerSecond,
    packetsPerSecond: trafficData.packetsPerSecond,
    connectionsPerSecond: trafficData.connectionsPerSecond,
    uniqueSources: Object.keys(trafficData.sourceDistribution).length,
    protocolDiversity: Object.keys(trafficData.protocolDistribution).length,
  };

  const deviations: Record<string, number> = {};
  const anomalies: string[] = [];

  for (const [key, currentValue] of Object.entries(current)) {
    const baselineValue = baseline[key] ?? 0;
    if (baselineValue > 0) {
      const deviation = Math.abs(currentValue - baselineValue) / baselineValue;
      deviations[key] = deviation;
      if (deviation > 1.0) {
        anomalies.push(key);
      }
    } else if (currentValue > 0) {
      deviations[key] = 1;
      anomalies.push(key);
    }
  }

  const protocolDeviation = calculateProtocolDeviation(
    trafficData.protocolDistribution,
    baseline.protocolDistribution as Record<string, number> | undefined
  );

  if (protocolDeviation > 0.3) {
    anomalies.push('protocol_distribution');
    deviations.protocol_distribution = protocolDeviation;
  }

  const riskScore = Math.min(
    Object.values(deviations).reduce((sum, d) => sum + d, 0) /
      (Object.keys(deviations).length || 1),
    1
  );

  const result: BehaviorResult = {
    baseline,
    current,
    deviations,
    anomalies,
    riskScore,
    metrics: {
      'network.behavior.risk_score': riskScore,
      'network.behavior.anomaly_count': anomalies.length,
      'network.behavior.protocol_deviation': protocolDeviation,
    },
    timestamp: new Date().toISOString(),
  };

  metrics.incCounter('network.behavior.checks');
  if (anomalies.length > 0) metrics.incCounter('network.behavior.anomalies');

  logger.info({ anomalies, riskScore }, 'Traffic behavior analysis');

  span.end({ anomalies: anomalies.length });
  return result;
}

function calculateProtocolDeviation(
  current: Record<string, number>,
  baseline?: Record<string, number>
): number {
  if (!baseline) return 0;

  const allProtocols = new Set([...Object.keys(current), ...Object.keys(baseline)]);
  let totalDeviation = 0;

  for (const protocol of allProtocols) {
    const currentVal = current[protocol] || 0;
    const baselineVal = baseline[protocol] || 0;
    const max = Math.max(currentVal, baselineVal, 1);
    totalDeviation += Math.abs(currentVal - baselineVal) / max;
  }

  return totalDeviation / allProtocols.size;
}

// --- 20. protocolAnomalyDetection -------------------------------------------

/**
 * Detects protocol anomalies by comparing actual protocol data against specification.
 * @param protocolData - Actual protocol data observed
 * @param protocolSpec - Expected protocol specification
 * @param deviationThreshold - Threshold for anomaly detection (default: 0.3)
 * @returns DetectionResult with protocol anomaly detection status
 */
export function protocolAnomalyDetection(
  protocolData: Record<string, unknown>,
  protocolSpec: Record<string, unknown>,
  deviationThreshold: number = 0.3
): DetectionResult {
  const span = createSpan('network.protocolAnomalyDetection');
  const metrics = getMetrics();

  const anomalies: string[] = [];
  const deviations: Record<string, number> = {};
  let confidence = 0;

  for (const [key, specValue] of Object.entries(protocolSpec)) {
    const actualValue = protocolData[key];

    if (actualValue === undefined && specValue !== undefined) {
      anomalies.push(`missing_field:${key}`);
      deviations[key] = 1;
      confidence += 0.15;
      continue;
    }

    if (typeof specValue === 'number' && typeof actualValue === 'number') {
      if (specValue > 0) {
        const deviation = Math.abs(actualValue - specValue) / specValue;
        deviations[key] = deviation;
        if (deviation > deviationThreshold) {
          anomalies.push(`value_deviation:${key}`);
          confidence += 0.1 * Math.min(deviation, 1);
        }
      }
    } else if (typeof specValue === 'string' && typeof actualValue === 'string') {
      if (actualValue !== specValue) {
        anomalies.push(`value_mismatch:${key}`);
        confidence += 0.2;
      }
    } else if (Array.isArray(specValue) && Array.isArray(actualValue)) {
      const specSet = new Set(specValue);
      const unexpected = actualValue.filter((v) => !specSet.has(v));
      if (unexpected.length > 0) {
        anomalies.push(`unexpected_values:${key}`);
        confidence += 0.1 * Math.min(unexpected.length / specValue.length, 1);
      }
    }
  }

  confidence = Math.min(confidence, 1);
  const detected = confidence >= deviationThreshold;

  const result: DetectionResult = {
    detected,
    confidence,
    severity: getSeverityFromConfidence(confidence),
    details: {
      anomalies,
      deviations,
      fieldsChecked: Object.keys(protocolSpec).length,
      anomalyCount: anomalies.length,
      deviationThreshold,
    },
    timestamp: new Date().toISOString(),
    metrics: {
      'network.protocol_anomaly.anomalies': anomalies.length,
      'network.protocol_anomaly.confidence': confidence,
      'network.protocol_anomaly.fields_checked': Object.keys(protocolSpec).length,
    },
  };

  metrics.incCounter('network.protocol_anomaly.checks');
  if (detected) metrics.incCounter('network.protocol_anomaly.detections');

  logger.warn({ detected, anomalies, confidence }, 'Protocol anomaly detection');

  if (detected) {
    const eventBus = getEventBus();
    eventBus.publish('security:detection', {
      type: 'PROTOCOL_ANOMALY',
      severity: result.severity,
      details: result.details,
    } as SecurityEvent);
  }

  span.end({ detected });
  return result;
}
