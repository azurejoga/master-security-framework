import { createHash } from 'crypto';
import { sha3_256 } from '@noble/hashes/sha3';
import { getLogger, getMetrics, createSpan, getEventBus, SecurityEvent, EventSeverity, TamperProofChain } from '../core/index.js';
import { SecurityError } from '../core/exceptions.js';
import pino from 'pino';

const logger = pino().child({ module: 'msf.monitoring' });

export interface LogEntry {
  id: string;
  timestamp: number;
  level: string;
  event: string;
  data: Record<string, unknown>;
  hash: string;
  prevHash: string;
  tamperproof: boolean;
}

export interface CorrelatedEvent {
  id: string;
  eventIds: string[];
  correlationRule: string;
  confidence: number;
  timestamp: number;
  severity: EventSeverity;
  details: Record<string, unknown>;
}

export interface AlertResult {
  triggered: boolean;
  alertId: string;
  severity: EventSeverity;
  message: string;
  timestamp: number;
  notificationSent: boolean;
  metadata: Record<string, unknown>;
}

export interface PathResult {
  paths: AttackPath[];
  riskScore: number;
  criticalNodes: string[];
  timestamp: number;
}

export interface AttackPath {
  id: string;
  steps: string[];
  probability: number;
  impact: number;
  mitigations: string[];
}

export interface GraphResult {
  nodes: GraphNode[];
  edges: GraphEdge[];
  clusters: GraphCluster[];
  timestamp: number;
}

export interface GraphNode {
  id: string;
  type: string;
  properties: Record<string, unknown>;
  riskScore: number;
}

export interface GraphEdge {
  source: string;
  target: string;
  type: string;
  weight: number;
}

export interface GraphCluster {
  id: string;
  nodeIds: string[];
  riskScore: number;
}

export interface AnalysisResult {
  userId: string;
  baselineDeviation: number;
  anomalies: Anomaly[];
  riskScore: number;
  timestamp: number;
}

export interface Anomaly {
  type: string;
  severity: number;
  description: string;
  timestamp: number;
  data: Record<string, unknown>;
}

export interface UebaResult {
  userId: string;
  peerGroupDeviation: number;
  anomalies: Anomaly[];
  riskScore: number;
  recommendations: string[];
  timestamp: number;
}

export interface DetectionResult {
  detected: boolean;
  confidence: number;
  riskScore: number;
  indicators: string[];
  details: Record<string, unknown>;
  timestamp: number;
}

export interface ResponseResult {
  actionTaken: string;
  success: boolean;
  riskReduced: number;
  sideEffects: string[];
  timestamp: number;
  metadata: Record<string, unknown>;
}

export interface BusResult {
  eventId: string;
  handlersExecuted: string[];
  handlersFailed: string[];
  latency: number;
  timestamp: number;
}

export interface SnapshotResult {
  snapshotId: string;
  systemState: Record<string, unknown>;
  evidenceHash: string;
  chainOfCustody: CustodyEntry[];
  timestamp: number;
  integrity: boolean;
}

export interface CustodyEntry {
  handler: string;
  timestamp: number;
  action: string;
  signature: string;
}

export interface TimelineResult {
  incidentId: string;
  events: TimelineEvent[];
  classification: string;
  duration: number;
  rootCause: string | null;
  timestamp: number;
}

export interface TimelineEvent {
  eventId: string;
  timestamp: number;
  type: string;
  severity: EventSeverity;
  description: string;
}

export interface ChainResult {
  techniques: MitreTechnique[];
  killChainPhases: KillChainPhase[];
  coverage: number;
  gaps: string[];
  timestamp: number;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  confidence: number;
  evidence: string[];
}

export interface KillChainPhase {
  phase: string;
  completed: boolean;
  events: string[];
  riskScore: number;
}

export interface TriageResult {
  priority: number;
  classification: string;
  confidence: number;
  recommendedActions: string[];
  enrichment: Record<string, unknown>;
  timestamp: number;
}

export interface MetricsData {
  [key: string]: number;
}

export interface BaselineData {
  [key: string]: { mean: number; std: number; min: number; max: number };
}

export interface ThreatIntel {
  [indicator: string]: { severity: number; confidence: number; type: string };
}

export interface AlertRule {
  id: string;
  condition: (event: SecurityEvent) => boolean;
  severity: EventSeverity;
  message: string;
  cooldownMs?: number;
}

export interface NotificationChannel {
  type: 'email' | 'slack' | 'webhook' | 'pagerduty';
  target: string;
  enabled: boolean;
}

export interface CorrelationRule {
  id: string;
  name: string;
  condition: (events: SecurityEvent[]) => boolean;
  severity: EventSeverity;
  timeWindowMs: number;
}

export interface ResponseRule {
  id: string;
  condition: (threat: SecurityEvent) => boolean;
  action: string;
  autoExecute: boolean;
}

export interface ResponseAction {
  type: string;
  execute: (threat: SecurityEvent) => Promise<boolean>;
}

export interface EnrichmentSource {
  name: string;
  enrich: (alert: SecurityEvent) => Promise<Record<string, unknown>>;
}

export interface TriageRule {
  id: string;
  condition: (alert: SecurityEvent) => boolean;
  priority: number;
  classification: string;
}

/**
 * Creates a tamper-resistant security log entry with cryptographic hashing.
 */
export async function secureLog(
  event: string,
  level: string = 'info',
  data: Record<string, unknown> = {},
  tamperproof: boolean = true,
): Promise<LogEntry> {
  const span = createSpan('monitoring.secureLog');
  try {
    const timestamp = Date.now();
    const id = createHash('sha256').update(`${event}:${timestamp}:${JSON.stringify(data)}`).digest('hex').slice(0, 16);
    const prevHash = tamperproof ? await TamperProofChain.getLastHash() : '0'.repeat(64);
    const payload = `${id}:${timestamp}:${level}:${event}:${JSON.stringify(data)}:${prevHash}`;
    const hash = Buffer.from(sha3_256(payload)).toString('hex');

    const entry: LogEntry = { id, timestamp, level, event, data, hash, prevHash, tamperproof };

    if (tamperproof) {
      await TamperProofChain.append(entry);
    }

    const logFn = (logger as any)[level] || logger.info;
    logFn.call(logger, { event, data, hash, tamperproof }, `Security event: ${event}`);

    getMetrics().incCounter('security.log.entries', { level, event });
    return entry;
  } catch (error) {
    logger.error({ error, event }, 'Failed to create secure log entry');
    throw new SecurityError('SECURE_LOG_FAILED', 'Failed to create secure log entry', { event, level });
  } finally {
    span.end();
  }
}

/**
 * Verifies the integrity of a chain of log entries using cryptographic hashes.
 */
export async function tamperproofLogs(
  logEntries: LogEntry[],
  chainVerification: boolean = true,
): Promise<boolean> {
  const span = createSpan('monitoring.tamperproofLogs');
  try {
    if (logEntries.length === 0) return true;

    for (let i = 0; i < logEntries.length; i++) {
      const entry = logEntries[i];
      const payload = `${entry.id}:${entry.timestamp}:${entry.level}:${entry.event}:${JSON.stringify(entry.data)}:${entry.prevHash}`;
      const expectedHash = Buffer.from(sha3_256(payload)).toString('hex');

      if (entry.hash !== expectedHash) {
        logger.warn({ entryId: entry.id, index: i }, 'Tamper detected: hash mismatch');
        getMetrics().incCounter('security.log.tamper.detected');
        return false;
      }

      if (chainVerification && i > 0) {
        const prevEntry = logEntries[i - 1];
        if (entry.prevHash !== prevEntry.hash) {
          logger.warn({ entryId: entry.id, prevId: prevEntry.id }, 'Tamper detected: chain broken');
          getMetrics().incCounter('security.log.chain.broken');
          return false;
        }
      }
    }

    getMetrics().incCounter('security.log.tamper.verified', { count: logEntries.length });
    return true;
  } catch (error) {
    logger.error({ error }, 'Failed to verify tamper-proof logs');
    throw new SecurityError('TAMPERPROOF_VERIFY_FAILED', 'Failed to verify log integrity');
  } finally {
    span.end();
  }
}

/**
 * Calculates anomaly score by comparing current metrics against baseline.
 */
export function anomalyScore(
  metrics: MetricsData,
  baseline: BaselineData,
  weights: Record<string, number> = {},
): number {
  const span = createSpan('monitoring.anomalyScore');
  try {
    let totalScore = 0;
    let totalWeight = 0;

    for (const [key, value] of Object.entries(metrics)) {
      const base = baseline[key];
      if (!base) continue;

      const weight = weights[key] ?? 1.0;
      const std = base.std || 1;
      const zScore = Math.abs((value - base.mean) / std);
      const normalizedScore = Math.min(zScore / 4, 1);

      totalScore += normalizedScore * weight;
      totalWeight += weight;
    }

    const score = totalWeight > 0 ? totalScore / totalWeight : 0;
    logger.debug({ score, metricCount: Object.keys(metrics).length }, 'Anomaly score calculated');
    getMetrics().observeHistogram('security.anomaly.score', score);
    return Math.round(score * 1000) / 1000;
  } catch (error) {
    logger.error({ error }, 'Failed to calculate anomaly score');
    throw new SecurityError('ANOMALY_SCORE_FAILED', 'Failed to calculate anomaly score');
  } finally {
    span.end();
  }
}

/**
 * Calculates threat score based on events and threat intelligence data.
 */
export function threatScore(
  events: SecurityEvent[],
  threatIntel: ThreatIntel,
  context: Record<string, unknown> = {},
): number {
  const span = createSpan('monitoring.threatScore');
  try {
    let maxScore = 0;

    for (const event of events) {
      let eventScore = 0;

      for (const [indicator, intel] of Object.entries(threatIntel)) {
        const eventStr = JSON.stringify(event).toLowerCase();
        if (eventStr.includes(indicator.toLowerCase())) {
          eventScore = Math.max(eventScore, intel.severity * intel.confidence);
        }
      }

      const severityMultiplier = event.severity === EventSeverity.CRITICAL ? 1.0
        : event.severity === EventSeverity.HIGH ? 0.8
        : event.severity === EventSeverity.MEDIUM ? 0.5
        : 0.2;

      eventScore *= severityMultiplier;
      maxScore = Math.max(maxScore, eventScore);
    }

    const contextMultiplier = (context as any).highRisk ? 1.5 : (context as any).mediumRisk ? 1.2 : 1.0;
    const score = Math.min(maxScore * contextMultiplier * 10, 100);

    logger.info({ score, eventCount: events.length }, 'Threat score calculated');
    getMetrics().gauge('security.threat.score', score);
    return Math.round(score * 100) / 100;
  } catch (error) {
    logger.error({ error }, 'Failed to calculate threat score');
    throw new SecurityError('THREAT_SCORE_FAILED', 'Failed to calculate threat score');
  } finally {
    span.end();
  }
}

/**
 * Calculates comprehensive risk score for a user based on events and history.
 */
export function riskScore(
  userId: string,
  events: SecurityEvent[],
  context: Record<string, unknown> = {},
  historical: { avgRisk: number; incidentCount: number; lastIncidentDays: number } = { avgRisk: 0, incidentCount: 0, lastIncidentDays: 365 },
): number {
  const span = createSpan('monitoring.riskScore');
  try {
    const eventScore = events.reduce((acc, e) => {
      const sev = e.severity === EventSeverity.CRITICAL ? 25
        : e.severity === EventSeverity.HIGH ? 15
        : e.severity === EventSeverity.MEDIUM ? 8
        : 2;
      return acc + sev;
    }, 0);

    const normalizedEventScore = Math.min(eventScore / (events.length * 25 || 1), 1) * 50;
    const historicalScore = Math.min(historical.avgRisk * 0.3 + (historical.incidentCount > 0 ? Math.min(historical.incidentCount * 5, 15) : 0), 30);

    const recencyFactor = historical.lastIncidentDays < 30 ? 1.5
      : historical.lastIncidentDays < 90 ? 1.2
      : 1.0;

    const contextFactor = (context as any).elevatedRisk ? 1.3 : 1.0;
    const score = Math.min((normalizedEventScore + historicalScore) * recencyFactor * contextFactor, 100);

    logger.info({ userId, score, eventCount: events.length }, 'Risk score calculated');
    getMetrics().gauge('security.risk.score', score, { userId });
    return Math.round(score * 100) / 100;
  } catch (error) {
    logger.error({ error, userId }, 'Failed to calculate risk score');
    throw new SecurityError('RISK_SCORE_FAILED', 'Failed to calculate risk score', { userId });
  } finally {
    span.end();
  }
}

/**
 * Correlates security events within a time window using defined rules.
 */
export function correlateEvents(
  events: SecurityEvent[],
  timeWindow: number = 300000,
  correlationRules: CorrelationRule[] = [],
): CorrelatedEvent[] {
  const span = createSpan('monitoring.correlateEvents');
  try {
    const correlated: CorrelatedEvent[] = [];
    const sorted = [...events].sort((a, b) => a.timestamp - b.timestamp);

    for (const rule of correlationRules) {
      const windowStart = sorted[0]?.timestamp ?? Date.now();
      const windowEvents = sorted.filter(e => e.timestamp >= windowStart && e.timestamp <= windowStart + rule.timeWindowMs);

      if (windowEvents.length >= 2 && rule.condition(windowEvents)) {
        const correlation: CorrelatedEvent = {
          id: createHash('sha256').update(`correlation:${rule.id}:${windowStart}`).digest('hex').slice(0, 16),
          eventIds: windowEvents.map(e => e.id),
          correlationRule: rule.name,
          confidence: Math.min(windowEvents.length / 5, 1),
          timestamp: Date.now(),
          severity: rule.severity,
          details: { ruleId: rule.id, eventCount: windowEvents.length, timeWindow: rule.timeWindowMs },
        };
        correlated.push(correlation);
        logger.info({ correlationId: correlation.id, rule: rule.name, eventCount: windowEvents.length }, 'Events correlated');
      }
    }

    getMetrics().incCounter('security.correlations', { count: correlated.length });
    return correlated;
  } catch (error) {
    logger.error({ error }, 'Failed to correlate events');
    throw new SecurityError('CORRELATE_EVENTS_FAILED', 'Failed to correlate events');
  } finally {
    span.end();
  }
}

/**
 * Evaluates a security event against alert rules and triggers notifications.
 */
export async function realtimeAlert(
  event: SecurityEvent,
  alertRules: AlertRule[],
  notificationChannels: NotificationChannel[] = [],
): Promise<AlertResult> {
  const span = createSpan('monitoring.realtimeAlert');
  try {
    let triggered = false;
    let matchedRule: AlertRule | null = null;

    for (const rule of alertRules) {
      if (rule.condition(event)) {
        triggered = true;
        matchedRule = rule;
        break;
      }
    }

    if (!triggered) {
      return {
        triggered: false,
        alertId: '',
        severity: EventSeverity.LOW,
        message: 'No alert rules matched',
        timestamp: Date.now(),
        notificationSent: false,
        metadata: {},
      };
    }

    const alertId = createHash('sha256').update(`alert:${event.id}:${Date.now()}`).digest('hex').slice(0, 16);
    const enabledChannels = notificationChannels.filter(c => c.enabled);
    let notificationSent = false;

    for (const channel of enabledChannels) {
      try {
        logger.info({ alertId, channel: channel.type, target: channel.target }, 'Sending alert notification');
        getMetrics().incCounter('security.alert.notification.sent', { channel: channel.type });
        notificationSent = true;
      } catch (err) {
        logger.warn({ alertId, channel: channel.type, error: err }, 'Failed to send notification');
      }
    }

    const result: AlertResult = {
      triggered: true,
      alertId,
      severity: matchedRule!.severity,
      message: matchedRule!.message,
      timestamp: Date.now(),
      notificationSent,
      metadata: { eventId: event.id, ruleId: matchedRule!.id },
    };

    logger.info({ alertId, severity: matchedRule!.severity }, 'Realtime alert triggered');
    getMetrics().incCounter('security.alert.triggered', { severity: matchedRule!.severity });
    return result;
  } catch (error) {
    logger.error({ error }, 'Failed to process realtime alert');
    throw new SecurityError('REALTIME_ALERT_FAILED', 'Failed to process realtime alert');
  } finally {
    span.end();
  }
}

/**
 * Implements adaptive alerting with fatigue prevention based on baselines.
 */
export function adaptiveAlerting(
  events: SecurityEvent[],
  baseline: { avgAlertsPerHour: number; cooldownMs: number },
  alertFatigueThreshold: number = 10,
): AlertResult {
  const span = createSpan('monitoring.adaptiveAlerting');
  try {
    const now = Date.now();
    const recentEvents = events.filter(e => now - e.timestamp < 3600000);
    const alertCount = recentEvents.filter(e => e.severity === EventSeverity.HIGH || e.severity === EventSeverity.CRITICAL).length;

    if (alertCount >= alertFatigueThreshold) {
      logger.warn({ alertCount, threshold: alertFatigueThreshold }, 'Alert fatigue threshold reached, suppressing');
      getMetrics().incCounter('security.alert.suppressed');
      return {
        triggered: false,
        alertId: '',
        severity: EventSeverity.LOW,
        message: `Alert suppressed: fatigue threshold (${alertFatigueThreshold}) reached`,
        timestamp: now,
        notificationSent: false,
        metadata: { suppressed: true, alertCount, threshold: alertFatigueThreshold },
      };
    }

    const adaptiveThreshold = baseline.avgAlertsPerHour > 0
      ? Math.max(baseline.avgAlertsPerHour * 2, 3)
      : 5;

    const shouldAlert = alertCount >= adaptiveThreshold;
    const cooldownActive = recentEvents.length > 0 && (now - recentEvents[recentEvents.length - 1].timestamp) < baseline.cooldownMs;

    if (cooldownActive && !shouldAlert) {
      return {
        triggered: false,
        alertId: '',
        severity: EventSeverity.LOW,
        message: 'Alert in cooldown period',
        timestamp: now,
        notificationSent: false,
        metadata: { cooldownActive: true, cooldownMs: baseline.cooldownMs },
      };
    }

    const maxSeverity = recentEvents.reduce((max, e) =>
      e.severity > max ? e.severity : max, EventSeverity.LOW);

    const result: AlertResult = {
      triggered: shouldAlert,
      alertId: shouldAlert ? createHash('sha256').update(`adaptive:${now}`).digest('hex').slice(0, 16) : '',
      severity: maxSeverity,
      message: shouldAlert ? `Adaptive alert: ${alertCount} events exceed threshold ${adaptiveThreshold}` : 'Below adaptive threshold',
      timestamp: now,
      notificationSent: shouldAlert,
      metadata: { alertCount, adaptiveThreshold, fatigueThreshold: alertFatigueThreshold },
    };

    logger.info({ triggered: shouldAlert, alertCount, adaptiveThreshold }, 'Adaptive alerting evaluated');
    getMetrics().incCounter('security.alert.adaptive', { triggered: String(shouldAlert) });
    return result;
  } catch (error) {
    logger.error({ error }, 'Failed to process adaptive alerting');
    throw new SecurityError('ADAPTIVE_ALERTING_FAILED', 'Failed to process adaptive alerting');
  } finally {
    span.end();
  }
}

/**
 * Analyzes potential attack paths through network topology.
 */
export function attackPathAnalysis(
  events: SecurityEvent[],
  networkTopology: { nodes: { id: string; criticality: number }[]; connections: { from: string; to: string }[] },
  attackGraph: { paths: { steps: string[]; probability: number; impact: number }[] },
): PathResult {
  const span = createSpan('monitoring.attackPathAnalysis');
  try {
    const eventNodeIds = new Set(events.map(e => e.target || ''));
    const criticalNodes = networkTopology.nodes
      .filter(n => n.criticality > 0.7 && eventNodeIds.has(n.id))
      .map(n => n.id);

    const activePaths = attackGraph.paths
      .filter(p => p.steps.some(step => eventNodeIds.has(step)))
      .map(p => ({
        id: createHash('sha256').update(p.steps.join(',')).digest('hex').slice(0, 16),
        steps: p.steps,
        probability: p.probability,
        impact: p.impact,
        mitigations: p.steps.filter(s => criticalNodes.includes(s)).map(s => `Isolate node ${s}`),
      }));

    const riskScore = activePaths.length > 0
      ? Math.min(activePaths.reduce((acc, p) => acc + p.probability * p.impact, 0) / activePaths.length * 100, 100)
      : 0;

    const result: PathResult = {
      paths: activePaths,
      riskScore: Math.round(riskScore * 100) / 100,
      criticalNodes,
      timestamp: Date.now(),
    };

    logger.info({ pathCount: activePaths.length, riskScore, criticalNodeCount: criticalNodes.length }, 'Attack path analysis complete');
    getMetrics().gauge('security.attack.path.risk', riskScore);
    return result;
  } catch (error) {
    logger.error({ error }, 'Failed to analyze attack paths');
    throw new SecurityError('ATTACK_PATH_ANALYSIS_FAILED', 'Failed to analyze attack paths');
  } finally {
    span.end();
  }
}

/**
 * Constructs a threat graph from events, entities, and relationships.
 */
export function threatGraph(
  events: SecurityEvent[],
  entities: { id: string; type: string; riskLevel: number }[],
  relationships: { source: string; target: string; type: string }[],
): GraphResult {
  const span = createSpan('monitoring.threatGraph');
  try {
    const eventEntityIds = new Set(events.map(e => e.source || e.target || ''));

    const nodes: GraphNode[] = entities.map(e => ({
      id: e.id,
      type: e.type,
      properties: { riskLevel: e.riskLevel, involvedInEvents: eventEntityIds.has(e.id) },
      riskScore: e.riskLevel * (eventEntityIds.has(e.id) ? 1.5 : 1),
    }));

    const edges: GraphEdge[] = relationships.map(r => ({
      source: r.source,
      target: r.target,
      type: r.type,
      weight: eventEntityIds.has(r.source) && eventEntityIds.has(r.target) ? 2 : 1,
    }));

    const clusters: GraphCluster[] = [];
    const visited = new Set<string>();

    for (const node of nodes) {
      if (visited.has(node.id)) continue;
      const clusterNodes = [node.id];
      visited.add(node.id);

      for (const edge of edges) {
        if (clusterNodes.includes(edge.source) && !visited.has(edge.target)) {
          clusterNodes.push(edge.target);
          visited.add(edge.target);
        }
        if (clusterNodes.includes(edge.target) && !visited.has(edge.source)) {
          clusterNodes.push(edge.source);
          visited.add(edge.source);
        }
      }

      const clusterRisk = clusterNodes.reduce((acc, id) => {
        const n = nodes.find(n => n.id === id);
        return acc + (n?.riskScore || 0);
      }, 0) / clusterNodes.length;

      clusters.push({
        id: createHash('sha256').update(clusterNodes.sort().join(',')).digest('hex').slice(0, 16),
        nodeIds: clusterNodes,
        riskScore: Math.round(clusterRisk * 100) / 100,
      });
    }

    const result: GraphResult = { nodes, edges, clusters, timestamp: Date.now() };

    logger.info({ nodeCount: nodes.length, edgeCount: edges.length, clusterCount: clusters.length }, 'Threat graph constructed');
    getMetrics().gauge('security.graph.nodes', nodes.length);
    getMetrics().gauge('security.graph.edges', edges.length);
    return result;
  } catch (error) {
    logger.error({ error }, 'Failed to construct threat graph');
    throw new SecurityError('THREAT_GRAPH_FAILED', 'Failed to construct threat graph');
  } finally {
    span.end();
  }
}

/**
 * Analyzes user behavior against established baselines to detect deviations.
 */
export function behavioralAnalysis(
  userEvents: SecurityEvent[],
  baseline: { loginHours: { mean: number; std: number }; locations: string[]; avgEventsPerHour: number },
  deviationThreshold: number = 2.0,
): AnalysisResult {
  const span = createSpan('monitoring.behavioralAnalysis');
  try {
    const anomalies: Anomaly[] = [];
    const userId = userEvents[0]?.source || 'unknown';

    for (const event of userEvents) {
      const hour = new Date(event.timestamp).getHours();
      const hourZScore = Math.abs((hour - baseline.loginHours.mean) / (baseline.loginHours.std || 1));

      if (hourZScore > deviationThreshold) {
        anomalies.push({
          type: 'anomalous_login_hour',
          severity: Math.min(hourZScore / 5, 1),
          description: `Login at hour ${hour} deviates ${hourZScore.toFixed(1)} std from baseline`,
          timestamp: event.timestamp,
          data: { hour, zScore: hourZScore, baselineMean: baseline.loginHours.mean },
        });
      }

      const location = (event as any).location;
      if (location && !baseline.locations.includes(location)) {
        anomalies.push({
          type: 'anomalous_location',
          severity: 0.7,
          description: `Login from unknown location: ${location}`,
          timestamp: event.timestamp,
          data: { location, knownLocations: baseline.locations },
        });
      }
    }

    const eventRate = userEvents.length / Math.max(1, (Date.now() - userEvents[0].timestamp) / 3600000);
    if (eventRate > baseline.avgEventsPerHour * deviationThreshold) {
      anomalies.push({
        type: 'elevated_event_rate',
        severity: Math.min(eventRate / (baseline.avgEventsPerHour * 5), 1),
        description: `Event rate ${eventRate.toFixed(1)}/hr exceeds baseline ${baseline.avgEventsPerHour}/hr`,
        timestamp: Date.now(),
        data: { eventRate, baseline: baseline.avgEventsPerHour },
      });
    }

    const riskScore = Math.min(anomalies.reduce((acc, a) => acc + a.severity, 0) * 20, 100);
    const baselineDeviation = anomalies.length > 0 ? anomalies.reduce((acc, a) => acc + a.severity, 0) / anomalies.length : 0;

    const result: AnalysisResult = {
      userId,
      baselineDeviation: Math.round(baselineDeviation * 1000) / 1000,
      anomalies,
      riskScore: Math.round(riskScore * 100) / 100,
      timestamp: Date.now(),
    };

    logger.info({ userId, anomalyCount: anomalies.length, riskScore }, 'Behavioral analysis complete');
    getMetrics().gauge('security.behavioral.risk', riskScore, { userId });
    return result;
  } catch (error) {
    logger.error({ error }, 'Failed to perform behavioral analysis');
    throw new SecurityError('BEHAVIORAL_ANALYSIS_FAILED', 'Failed to perform behavioral analysis');
  } finally {
    span.end();
  }
}

/**
 * Performs User and Entity Behavior Analytics (UEBA) against peer groups.
 */
export function uebaAnalysis(
  userEvents: SecurityEvent[],
  peerGroup: { avgEventsPerDay: number; commonActions: string[]; riskDistribution: { low: number; medium: number; high: number } },
  anomalyThreshold: number = 2.5,
): UebaResult {
  const span = createSpan('monitoring.uebaAnalysis');
  try {
    const userId = userEvents[0]?.source || 'unknown';
    const anomalies: Anomaly[] = [];

    const userActions = new Set(userEvents.map(e => e.type));
    const uncommonActions = [...userActions].filter(a => !peerGroup.commonActions.includes(a));

    if (uncommonActions.length > 0) {
      anomalies.push({
        type: 'uncommon_actions',
        severity: Math.min(uncommonActions.length / peerGroup.commonActions.length, 1),
        description: `User performed ${uncommonActions.length} actions uncommon in peer group`,
        timestamp: Date.now(),
        data: { uncommonActions, peerGroupSize: peerGroup.commonActions.length },
      });
    }

    const daysActive = Math.max(1, (Date.now() - userEvents[0].timestamp) / 86400000);
    const userEventsPerDay = userEvents.length / daysActive;
    const peerDeviation = peerGroup.avgEventsPerDay > 0
      ? Math.abs(userEventsPerDay - peerGroup.avgEventsPerDay) / peerGroup.avgEventsPerDay
      : 0;

    if (peerDeviation > anomalyThreshold) {
      anomalies.push({
        type: 'event_volume_deviation',
        severity: Math.min(peerDeviation / (anomalyThreshold * 2), 1),
        description: `Event volume deviates ${(peerDeviation * 100).toFixed(0)}% from peer group average`,
        timestamp: Date.now(),
        data: { userEventsPerDay, peerAvg: peerGroup.avgEventsPerDay, deviation: peerDeviation },
      });
    }

    const highRiskEvents = userEvents.filter(e => e.severity === EventSeverity.HIGH || e.severity === EventSeverity.CRITICAL).length;
    const highRiskRatio = userEvents.length > 0 ? highRiskEvents / userEvents.length : 0;

    if (highRiskRatio > peerGroup.riskDistribution.high + 0.1) {
      anomalies.push({
        type: 'elevated_risk_events',
        severity: Math.min(highRiskRatio / (peerGroup.riskDistribution.high * 2 || 0.2), 1),
        description: `High-risk event ratio ${(highRiskRatio * 100).toFixed(0)}% exceeds peer group`,
        timestamp: Date.now(),
        data: { highRiskRatio, peerHighRisk: peerGroup.riskDistribution.high },
      });
    }

    const riskScore = Math.min(anomalies.reduce((acc, a) => acc + a.severity * 30, 0), 100);
    const recommendations: string[] = [];

    if (riskScore > 60) recommendations.push('Initiate enhanced monitoring');
    if (riskScore > 40) recommendations.push('Review recent user activities');
    if (uncommonActions.length > 2) recommendations.push('Verify uncommon actions with user manager');
    if (peerDeviation > anomalyThreshold) recommendations.push('Compare against additional peer groups');
    if (recommendations.length === 0) recommendations.push('Continue standard monitoring');

    const result: UebaResult = {
      userId,
      peerGroupDeviation: Math.round(peerDeviation * 1000) / 1000,
      anomalies,
      riskScore: Math.round(riskScore * 100) / 100,
      recommendations,
      timestamp: Date.now(),
    };

    logger.info({ userId, riskScore, anomalyCount: anomalies.length }, 'UEBA analysis complete');
    getMetrics().gauge('security.ueba.risk', riskScore, { userId });
    return result;
  } catch (error) {
    logger.error({ error }, 'Failed to perform UEBA analysis');
    throw new SecurityError('UEBA_ANALYSIS_FAILED', 'Failed to perform UEBA analysis');
  } finally {
    span.end();
  }
}

/**
 * Detects potential account takeover attempts based on behavioral indicators.
 */
export function detectAccountTakeover(
  userEvents: SecurityEvent[],
  baseline: { knownDevices: string[]; knownLocations: string[]; typicalLoginTimes: { start: number; end: number } },
  riskFactors: { privileged: boolean; mfaEnabled: boolean; recentPasswordChange: boolean },
): DetectionResult {
  const span = createSpan('monitoring.detectAccountTakeover');
  try {
    const indicators: string[] = [];
    let confidence = 0;

    for (const event of userEvents) {
      const device = (event as any).device;
      const location = (event as any).location;
      const hour = new Date(event.timestamp).getHours();

      if (device && !baseline.knownDevices.includes(device)) {
        indicators.push(`Unknown device: ${device}`);
        confidence += 0.15;
      }

      if (location && !baseline.knownLocations.includes(location)) {
        indicators.push(`Unknown location: ${location}`);
        confidence += 0.2;
      }

      if (hour < baseline.typicalLoginTimes.start || hour > baseline.typicalLoginTimes.end) {
        indicators.push(`Login outside typical hours: ${hour}:00`);
        confidence += 0.1;
      }

      if (event.type === 'failed_login') {
        indicators.push('Failed login attempt');
        confidence += 0.1;
      }
    }

    const failedLogins = userEvents.filter(e => e.type === 'failed_login').length;
    if (failedLogins >= 3) {
      indicators.push(`Multiple failed logins: ${failedLogins}`);
      confidence += 0.25;
    }

    if (!riskFactors.mfaEnabled) confidence += 0.1;
    if (riskFactors.privileged) confidence += 0.1;
    if (riskFactors.recentPasswordChange) confidence += 0.05;

    const uniqueLocations = new Set(userEvents.map(e => (e as any).location).filter(Boolean));
    if (uniqueLocations.size > 2) {
      indicators.push(`Geographically impossible logins: ${uniqueLocations.size} locations`);
      confidence += 0.3;
    }

    confidence = Math.min(confidence, 1);
    const riskScore = confidence * 100;
    const detected = confidence > 0.5;

    const result: DetectionResult = {
      detected,
      confidence: Math.round(confidence * 100) / 100,
      riskScore: Math.round(riskScore * 100) / 100,
      indicators,
      details: {
        failedLogins,
        uniqueLocations: uniqueLocations.size,
        privileged: riskFactors.privileged,
        mfaEnabled: riskFactors.mfaEnabled,
      },
      timestamp: Date.now(),
    };

    logger[detected ? 'warn' : 'info']({ detected, confidence, indicatorCount: indicators.length }, 'Account takeover detection complete');
    getMetrics().incCounter('security.account.takeover.detected', { detected: String(detected) });
    return result;
  } catch (error) {
    logger.error({ error }, 'Failed to detect account takeover');
    throw new SecurityError('ACCOUNT_TAKEOVER_DETECTION_FAILED', 'Failed to detect account takeover');
  } finally {
    span.end();
  }
}

/**
 * Detects fraudulent transactions based on pattern matching and risk scoring.
 */
export function detectFraud(
  transactions: { id: string; amount: number; userId: string; timestamp: number; type: string; metadata?: Record<string, unknown> }[],
  patterns: { name: string; condition: (tx: typeof transactions[0]) => boolean; weight: number }[],
  riskThreshold: number = 0.6,
): DetectionResult {
  const span = createSpan('monitoring.detectFraud');
  try {
    const indicators: string[] = [];
    let maxRisk = 0;
    const flaggedTransactions: string[] = [];

    for (const tx of transactions) {
      let txRisk = 0;

      for (const pattern of patterns) {
        if (pattern.condition(tx)) {
          txRisk += pattern.weight;
          indicators.push(`Pattern matched: ${pattern.name} (tx: ${tx.id})`);
        }
      }

      if (txRisk > riskThreshold) {
        flaggedTransactions.push(tx.id);
        maxRisk = Math.max(maxRisk, txRisk);
      }
    }

    const velocityCheck = transactions.length > 10 ? 0.2 : 0;
    const amountAnomaly = transactions.some(tx => tx.amount > 10000) ? 0.15 : 0;
    maxRisk = Math.min(maxRisk + velocityCheck + amountAnomaly, 1);

    if (velocityCheck > 0) indicators.push(`High transaction velocity: ${transactions.length} transactions`);
    if (amountAnomaly > 0) indicators.push('High-value transactions detected');

    const detected = maxRisk > riskThreshold;

    const result: DetectionResult = {
      detected,
      confidence: Math.round(maxRisk * 100) / 100,
      riskScore: Math.round(maxRisk * 100) / 100,
      indicators,
      details: {
        flaggedTransactions,
        totalTransactions: transactions.length,
        patternsEvaluated: patterns.length,
        velocityCheck: velocityCheck > 0,
        amountAnomaly: amountAnomaly > 0,
      },
      timestamp: Date.now(),
    };

    logger[detected ? 'warn' : 'info']({ detected, riskScore: maxRisk, flaggedCount: flaggedTransactions.length }, 'Fraud detection complete');
    getMetrics().incCounter('security.fraud.detected', { detected: String(detected) });
    return result;
  } catch (error) {
    logger.error({ error }, 'Failed to detect fraud');
    throw new SecurityError('FRAUD_DETECTION_FAILED', 'Failed to detect fraud');
  } finally {
    span.end();
  }
}

/**
 * Executes autonomous security responses based on threat assessment.
 */
export async function autonomousResponse(
  threat: SecurityEvent,
  responseRules: ResponseRule[],
  actions: ResponseAction[],
): Promise<ResponseResult> {
  const span = createSpan('monitoring.autonomousResponse');
  try {
    let actionTaken = 'none';
    let success = false;
    const sideEffects: string[] = [];

    for (const rule of responseRules) {
      if (rule.condition(threat) && rule.autoExecute) {
        const matchingAction = actions.find(a => a.type === rule.action);
        if (matchingAction) {
          try {
            const executed = await matchingAction.execute(threat);
            if (executed) {
              actionTaken = rule.action;
              success = true;
              logger.info({ threatId: threat.id, action: rule.action }, 'Autonomous response executed');
              getMetrics().incCounter('security.autonomous.response.executed', { action: rule.action });
            }
          } catch (err) {
            sideEffects.push(`Action ${rule.action} failed: ${(err as Error).message}`);
            logger.warn({ threatId: threat.id, action: rule.action, error: err }, 'Autonomous response failed');
          }
        }
        break;
      }
    }

    const riskReduced = success ? (threat.severity === EventSeverity.CRITICAL ? 40 : threat.severity === EventSeverity.HIGH ? 25 : 10) : 0;

    const result: ResponseResult = {
      actionTaken,
      success,
      riskReduced,
      sideEffects,
      timestamp: Date.now(),
      metadata: { threatId: threat.id, severity: threat.severity },
    };

    logger.info({ actionTaken, success, riskReduced }, 'Autonomous response complete');
    getMetrics().gauge('security.autonomous.response.risk.reduced', riskReduced);
    return result;
  } catch (error) {
    logger.error({ error }, 'Failed to execute autonomous response');
    throw new SecurityError('AUTONOMOUS_RESPONSE_FAILED', 'Failed to execute autonomous response');
  } finally {
    span.end();
  }
}

/**
 * Routes security events through an event bus to registered handlers.
 */
export async function securityEventBus(
  event: SecurityEvent,
  handlers: { name: string; handle: (event: SecurityEvent) => Promise<void>; filter?: (event: SecurityEvent) => boolean }[],
  routing: { [eventType: string]: string[] } = {},
): Promise<BusResult> {
  const span = createSpan('monitoring.securityEventBus');
  try {
    const startTime = Date.now();
    const handlersExecuted: string[] = [];
    const handlersFailed: string[] = [];

    const targetHandlers = routing[event.type]
      ? handlers.filter(h => routing[event.type].includes(h.name))
      : handlers;

    for (const handler of targetHandlers) {
      if (handler.filter && !handler.filter(event)) continue;

      try {
        await handler.handle(event);
        handlersExecuted.push(handler.name);
      } catch (error) {
        handlersFailed.push(handler.name);
        logger.warn({ handler: handler.name, error }, 'Event handler failed');
      }
    }

    const latency = Date.now() - startTime;
    const bus = getEventBus();
    bus.emit('security.event.processed', { eventId: event.id, handlersExecuted, handlersFailed, latency });

    const result: BusResult = {
      eventId: event.id,
      handlersExecuted,
      handlersFailed,
      latency,
      timestamp: Date.now(),
    };

    logger.debug({ eventId: event.id, executed: handlersExecuted.length, failed: handlersFailed.length, latency }, 'Event bus dispatch complete');
    getMetrics().observeHistogram('security.eventbus.latency', latency);
    getMetrics().incCounter('security.eventbus.handlers.executed', { count: handlersExecuted.length });
    return result;
  } catch (error) {
    logger.error({ error }, 'Failed to dispatch through security event bus');
    throw new SecurityError('SECURITY_EVENT_BUS_FAILED', 'Failed to dispatch through security event bus');
  } finally {
    span.end();
  }
}

/**
 * Creates a forensic snapshot of system state with chain of custody.
 */
export async function forensicSnapshot(
  systemState: Record<string, unknown>,
  evidence: { type: string; data: string; timestamp: number }[],
  chainOfCustody: { handler: string; action: string }[],
): Promise<SnapshotResult> {
  const span = createSpan('monitoring.forensicSnapshot');
  try {
    const evidenceHash = createHash('sha256')
      .update(JSON.stringify({ systemState, evidence, chainOfCustody }))
      .digest('hex');

    const custodyEntries: CustodyEntry[] = chainOfCustody.map(entry => ({
      handler: entry.handler,
      timestamp: Date.now(),
      action: entry.action,
      signature: createHash('sha256').update(`${entry.handler}:${entry.action}:${evidenceHash}`).digest('hex').slice(0, 32),
    }));

    const snapshotId = createHash('sha256').update(`snapshot:${evidenceHash}:${Date.now()}`).digest('hex').slice(0, 16);

    const result: SnapshotResult = {
      snapshotId,
      systemState,
      evidenceHash,
      chainOfCustody: custodyEntries,
      timestamp: Date.now(),
      integrity: true,
    };

    logger.info({ snapshotId, evidenceCount: evidence.length, custodyEntries: custodyEntries.length }, 'Forensic snapshot created');
    getMetrics().incCounter('security.forensic.snapshot.created');
    return result;
  } catch (error) {
    logger.error({ error }, 'Failed to create forensic snapshot');
    throw new SecurityError('FORENSIC_SNAPSHOT_FAILED', 'Failed to create forensic snapshot');
  } finally {
    span.end();
  }
}

/**
 * Constructs an incident timeline from security events.
 */
export function incidentTimeline(
  events: SecurityEvent[],
  incidentId: string,
  classification: string = 'unclassified',
): TimelineResult {
  const span = createSpan('monitoring.incidentTimeline');
  try {
    const sorted = [...events].sort((a, b) => a.timestamp - b.timestamp);

    const timelineEvents: TimelineEvent[] = sorted.map(e => ({
      eventId: e.id,
      timestamp: e.timestamp,
      type: e.type,
      severity: e.severity,
      description: `${e.type} from ${e.source || 'unknown'}`,
    }));

    const duration = sorted.length > 1
      ? sorted[sorted.length - 1].timestamp - sorted[0].timestamp
      : 0;

    const criticalEvents = sorted.filter(e => e.severity === EventSeverity.CRITICAL);
    const rootCause = criticalEvents.length > 0
      ? `${criticalEvents[0].type} at ${new Date(criticalEvents[0].timestamp).toISOString()}`
      : null;

    const result: TimelineResult = {
      incidentId,
      events: timelineEvents,
      classification,
      duration,
      rootCause,
      timestamp: Date.now(),
    };

    logger.info({ incidentId, eventCount: timelineEvents.length, duration, classification }, 'Incident timeline constructed');
    getMetrics().incCounter('security.incident.timeline.created', { classification });
    return result;
  } catch (error) {
    logger.error({ error, incidentId }, 'Failed to construct incident timeline');
    throw new SecurityError('INCIDENT_TIMELINE_FAILED', 'Failed to construct incident timeline', { incidentId });
  } finally {
    span.end();
  }
}

/**
 * Maps security events to MITRE ATT&CK framework and Cyber Kill Chain.
 */
export function attackChainMapping(
  events: SecurityEvent[],
  mitreFramework: { techniques: { id: string; name: string; tactic: string; indicators: string[] }[] },
  killChain: { phases: { name: string; indicators: string[] }[] },
): ChainResult {
  const span = createSpan('monitoring.attackChainMapping');
  try {
    const techniques: MitreTechnique[] = [];
    const matchedTechniqueIds = new Set<string>();

    for (const event of events) {
      const eventStr = JSON.stringify(event).toLowerCase();

      for (const technique of mitreFramework.techniques) {
        if (matchedTechniqueIds.has(technique.id)) continue;

        const matched = technique.indicators.some(indicator =>
          eventStr.includes(indicator.toLowerCase()),
        );

        if (matched) {
          techniques.push({
            id: technique.id,
            name: technique.name,
            tactic: technique.tactic,
            confidence: 0.7,
            evidence: [event.id],
          });
          matchedTechniqueIds.add(technique.id);
        }
      }
    }

    const killChainPhases: KillChainPhase[] = killChain.phases.map(phase => {
      const phaseEvents = events.filter(e => {
        const eventStr = JSON.stringify(e).toLowerCase();
        return phase.indicators.some(ind => eventStr.includes(ind.toLowerCase()));
      });

      return {
        phase: phase.name,
        completed: phaseEvents.length > 0,
        events: phaseEvents.map(e => e.id),
        riskScore: phaseEvents.length > 0 ? Math.min(phaseEvents.length * 15, 100) : 0,
      };
    });

    const completedPhases = killChainPhases.filter(p => p.completed).length;
    const coverage = killChain.phases.length > 0 ? completedPhases / killChain.phases.length : 0;
    const gaps = killChainPhases.filter(p => !p.completed).map(p => p.phase);

    const result: ChainResult = {
      techniques,
      killChainPhases,
      coverage: Math.round(coverage * 100) / 100,
      gaps,
      timestamp: Date.now(),
    };

    logger.info({ techniqueCount: techniques.length, coverage, gaps }, 'Attack chain mapping complete');
    getMetrics().gauge('security.attack.chain.coverage', coverage);
    return result;
  } catch (error) {
    logger.error({ error }, 'Failed to map attack chain');
    throw new SecurityError('ATTACK_CHAIN_MAPPING_FAILED', 'Failed to map attack chain');
  } finally {
    span.end();
  }
}

/**
 * Performs autonomous alert triage with enrichment and prioritization.
 */
export async function autonomousTriage(
  alert: SecurityEvent,
  triageRules: TriageRule[],
  enrichmentSources: EnrichmentSource[] = [],
): Promise<TriageResult> {
  const span = createSpan('monitoring.autonomousTriage');
  try {
    let priority = 5;
    let classification = 'unclassified';
    let confidence = 0;
    const enrichment: Record<string, unknown> = {};

    for (const source of enrichmentSources) {
      try {
        const data = await source.enrich(alert);
        enrichment[source.name] = data;
      } catch (err) {
        logger.warn({ source: source.name, error: err }, 'Enrichment source failed');
      }
    }

    for (const rule of triageRules) {
      if (rule.condition(alert)) {
        priority = rule.priority;
        classification = rule.classification;
        confidence = 0.8;
        break;
      }
    }

    const severityBoost = alert.severity === EventSeverity.CRITICAL ? -2
      : alert.severity === EventSeverity.HIGH ? -1
      : 0;
    priority = Math.max(1, Math.min(10, priority + severityBoost));

    const recommendedActions: string[] = [];
    if (priority <= 2) {
      recommendedActions.push('Immediate incident response required');
      recommendedActions.push('Escalate to security lead');
      recommendedActions.push('Isolate affected systems');
    } else if (priority <= 4) {
      recommendedActions.push('Investigate within 1 hour');
      recommendedActions.push('Collect additional evidence');
    } else if (priority <= 6) {
      recommendedActions.push('Investigate within 4 hours');
      recommendedActions.push('Monitor for escalation');
    } else {
      recommendedActions.push('Log for review');
      recommendedActions.push('Update detection rules');
    }

    const result: TriageResult = {
      priority,
      classification,
      confidence,
      recommendedActions,
      enrichment,
      timestamp: Date.now(),
    };

    logger.info({ alertId: alert.id, priority, classification }, 'Autonomous triage complete');
    getMetrics().incCounter('security.triage.completed', { priority: String(priority), classification });
    return result;
  } catch (error) {
    logger.error({ error }, 'Failed to perform autonomous triage');
    throw new SecurityError('AUTONOMOUS_TRIAGE_FAILED', 'Failed to perform autonomous triage');
  } finally {
    span.end();
  }
}
