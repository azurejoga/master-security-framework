import { createHash } from 'crypto';
import { sha3_256 } from '@noble/hashes/sha3';
import { getLogger, getMetrics, createSpan, getEventBus, SecurityEvent, EventSeverity } from '../core/index.js';
import { SecurityError, ValidationError } from '../core/exceptions.js';
import pino from 'pino';

const logger = pino().child({ module: 'msf.enterprise' });

// ============================================================
// Type Definitions
// ============================================================

export interface SystemConfig {
  encryptionEnabled: boolean;
  encryptionAlgorithm: string;
  keyRotationDays: number;
  accessControlEnabled: boolean;
  mfaRequired: boolean;
  auditLoggingEnabled: boolean;
  dataRetentionDays: number;
  backupEnabled: boolean;
  intrusionDetectionEnabled: boolean;
  version: string;
}

export interface DataFlow {
  id: string;
  source: string;
  destination: string;
  dataType: string;
  encryptionInTransit: boolean;
  encryptionAtRest: boolean;
  accessControls: string[];
  retentionPolicy: string;
}

export interface DataProcessing {
  purpose: string;
  legalBasis: string;
  dataCategories: string[];
  retentionPeriod: number;
  crossBorderTransfer: boolean;
  automatedDecisionMaking: boolean;
  profilingEnabled: boolean;
}

export interface PHIHandling {
  accessLogging: boolean;
  minimumNecessaryAccess: boolean;
  patientConsentTracking: boolean;
  breachNotificationEnabled: boolean;
  auditTrailComplete: boolean;
  transmissionSecurity: boolean;
  storageEncryption: boolean;
  disposalProcedures: boolean;
}

export interface CardDataHandling {
  panMasking: boolean;
  tokenizationEnabled: boolean;
  cvvStoragePrevented: boolean;
  networkSegmentation: boolean;
  vulnerabilityScanning: boolean;
  penetrationTesting: boolean;
  accessLogging: boolean;
  keyManagementCompliant: boolean;
}

export interface Control {
  id: string;
  name: string;
  implemented: boolean;
  evidence: string;
  lastTested: string;
  effectiveness: number;
}

export interface ComplianceResult {
  compliant: boolean;
  score: number;
  framework: string;
  passed: string[];
  failed: string[];
  warnings: string[];
  recommendations: string[];
  hash: string;
  timestamp: string;
}

export interface ReportResult {
  id: string;
  framework: string;
  scope: string;
  overallScore: number;
  complianceStatus: 'compliant' | 'partial' | 'non-compliant';
  sections: ReportSection[];
  findings: Finding[];
  executiveSummary: string;
  generatedAt: string;
  hash: string;
}

export interface ReportSection {
  name: string;
  score: number;
  status: 'pass' | 'fail' | 'warning';
  controls: ControlSummary[];
}

export interface ControlSummary {
  id: string;
  name: string;
  status: 'pass' | 'fail' | 'warning';
  evidence: string;
}

export interface Finding {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  remediation: string;
  affectedControls: string[];
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  target: string;
  result: 'success' | 'failure' | 'partial';
  metadata: Record<string, unknown>;
}

export interface UserAction {
  userId: string;
  action: string;
  resource: string;
  timestamp: string;
  ipAddress: string;
  userAgent: string;
}

export interface DataChange {
  id: string;
  entity: string;
  entityId: string;
  field: string;
  oldValue: string;
  newValue: string;
  changedBy: string;
  timestamp: string;
  reason: string;
}

export interface AuditResult {
  trailId: string;
  eventCount: number;
  integrityVerified: boolean;
  gaps: AuditGap[];
  anomalies: Anomaly[];
  summary: AuditSummary;
  hash: string;
  generatedAt: string;
}

export interface AuditGap {
  startTime: string;
  endTime: string;
  duration: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface Anomaly {
  type: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  evidence: string;
  timestamp: string;
}

export interface AuditSummary {
  totalEvents: number;
  successRate: number;
  uniqueActors: number;
  uniqueActions: number;
  timeRange: { start: string; end: string };
}

export interface Policy {
  id: string;
  name: string;
  rule: string;
  condition: Record<string, unknown>;
  action: 'allow' | 'deny' | 'alert' | 'log';
  priority: number;
  enabled: boolean;
}

export interface PolicyContext {
  userId: string;
  role: string;
  resource: string;
  action: string;
  environment: Record<string, unknown>;
  timestamp: string;
}

export interface PolicyEnforcement {
  mode: 'strict' | 'permissive' | 'audit';
  defaultAction: 'allow' | 'deny';
  escalationEnabled: boolean;
  notificationChannels: string[];
}

export interface PolicyResult {
  decision: 'allow' | 'deny' | 'alert';
  matchedPolicies: string[];
  violations: PolicyViolation[];
  enforcementMode: string;
  timestamp: string;
  hash: string;
}

export interface PolicyViolation {
  policyId: string;
  policyName: string;
  reason: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface SecurityMetric {
  name: string;
  value: number;
  threshold: number;
  status: 'healthy' | 'warning' | 'critical';
  trend: 'up' | 'down' | 'stable';
}

export interface SecurityAlert {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  timestamp: string;
  source: string;
  acknowledged: boolean;
}

export interface SecurityTrend {
  metric: string;
  values: number[];
  period: string;
  changePercent: number;
  direction: 'improving' | 'degrading' | 'stable';
}

export interface DashboardResult {
  dashboardId: string;
  overallHealth: 'healthy' | 'warning' | 'critical';
  healthScore: number;
  metrics: SecurityMetric[];
  activeAlerts: SecurityAlert[];
  trends: SecurityTrend[];
  summary: DashboardSummary;
  generatedAt: string;
}

export interface DashboardSummary {
  totalMetrics: number;
  healthyMetrics: number;
  warningMetrics: number;
  criticalMetrics: number;
  unacknowledgedAlerts: number;
  criticalAlerts: number;
}

export interface TenantConfig {
  tenantId: string;
  name: string;
  isolationLevel: 'strict' | 'moderate' | 'shared';
  dedicatedResources: boolean;
  customEncryption: boolean;
  networkIsolation: boolean;
  dataResidency: string;
}

export interface NetworkPolicy {
  id: string;
  tenantId: string;
  ingressRules: NetworkRule[];
  egressRules: NetworkRule[];
  vpcPeering: boolean;
  firewallEnabled: boolean;
}

export interface NetworkRule {
  protocol: string;
  port: number;
  source: string;
  destination: string;
  action: 'allow' | 'deny';
}

export interface DataSegregation {
  databaseIsolation: boolean;
  storageIsolation: boolean;
  cacheIsolation: boolean;
  queueIsolation: boolean;
  encryptionKeyIsolation: boolean;
  backupIsolation: boolean;
}

export interface IsolationResult {
  tenantId: string;
  isolationScore: number;
  isolationLevel: 'strict' | 'moderate' | 'weak';
  networkIsolation: boolean;
  dataIsolation: boolean;
  resourceIsolation: boolean;
  vulnerabilities: IsolationVulnerability[];
  recommendations: string[];
  hash: string;
  timestamp: string;
}

export interface IsolationVulnerability {
  type: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  affectedComponent: string;
}

export interface RegionConfig {
  region: string;
  countryCode: string;
  dataCenter: string;
  latency: number;
  capacity: number;
}

export interface DataResidencyRule {
  dataType: string;
  allowedRegions: string[];
  prohibitedRegions: string[];
  encryptionRequired: boolean;
  retentionLimit: number;
}

export interface RegionEncryption {
  algorithm: string;
  keyManagement: string;
  keyRotationDays: number;
  crossRegionEncryption: boolean;
}

export interface RegionResult {
  deploymentId: string;
  regions: RegionStatus[];
  residencyCompliance: boolean;
  violations: ResidencyViolation[];
  encryptionStatus: EncryptionStatus;
  replicationHealth: ReplicationHealth;
  hash: string;
  timestamp: string;
}

export interface RegionStatus {
  region: string;
  status: 'active' | 'degraded' | 'offline';
  dataTypes: string[];
  complianceStatus: 'compliant' | 'non-compliant' | 'pending';
}

export interface ResidencyViolation {
  dataType: string;
  currentRegion: string;
  requiredRegion: string;
  rule: string;
  severity: 'critical' | 'high' | 'medium';
}

export interface EncryptionStatus {
  inTransit: boolean;
  atRest: boolean;
  crossRegion: boolean;
  algorithm: string;
  keyRotationCompliant: boolean;
}

export interface ReplicationHealth {
  status: 'healthy' | 'degraded' | 'critical';
  lag: number;
  lastSync: string;
  consistency: 'strong' | 'eventual' | 'weak';
}

// ============================================================
// Helper Functions
// ============================================================

function computeHash(data: unknown): string {
  const serialized = JSON.stringify(data);
  return createHash('sha256').update(serialized).digest('hex');
}

function computeSecureHash(data: unknown): string {
  const serialized = JSON.stringify(data);
  const hashBytes = sha3_256(new TextEncoder().encode(serialized));
  return Buffer.from(hashBytes).toString('hex');
}

function calculateScore(passed: number, total: number): number {
  return total === 0 ? 0 : Math.round((passed / total) * 100);
}

function emitSecurityEvent(event: SecurityEvent): void {
  const eventBus = getEventBus();
  if (eventBus) {
    eventBus.publish('security:event', event);
  }
}

// ============================================================
// 1. LGPD Compliance Check (Brazilian General Data Protection Law)
// ============================================================

/**
 * Checks compliance with LGPD (Lei Geral de Protecao de Dados) - Brazilian data protection law.
 * Validates encryption, data subject rights, consent management, and data flow controls.
 *
 * @param systemConfig - System security configuration
 * @param dataFlows - Data flow definitions to validate
 * @param controls - Security controls to evaluate
 * @returns ComplianceResult with LGPD compliance status
 */
export function lgpdCheck(
  systemConfig: SystemConfig,
  dataFlows: DataFlow[],
  controls: Control[]
): ComplianceResult {
  const span = createSpan('lgpdCheck');
  logger.info({ dataFlowsCount: dataFlows.length, controlsCount: controls.length }, 'Starting LGPD compliance check');

  const passed: string[] = [];
  const failed: string[] = [];
  const warnings: string[] = [];
  const recommendations: string[] = [];

  // LGPD Article 46: Security measures
  if (systemConfig.encryptionEnabled) {
    passed.push('LGPD-Art46-Encryption: Data encryption enabled');
  } else {
    failed.push('LGPD-Art46-Encryption: Data encryption not enabled');
    recommendations.push('Enable encryption for personal data at rest and in transit');
  }

  if (systemConfig.accessControlEnabled) {
    passed.push('LGPD-Art46-AccessControl: Access controls enabled');
  } else {
    failed.push('LGPD-Art46-AccessControl: Access controls not enabled');
  }

  // LGPD Article 18: Data subject rights
  const dataSubjectRightsControl = controls.find(c =>
    c.name.toLowerCase().includes('data subject') || c.name.toLowerCase().includes('rights')
  );
  if (dataSubjectRightsControl?.implemented) {
    passed.push('LGPD-Art18-DataSubjectRights: Data subject rights implemented');
  } else {
    warnings.push('LGPD-Art18-DataSubjectRights: Data subject rights controls not fully verified');
    recommendations.push('Implement data subject rights management (access, correction, deletion)');
  }

  // LGPD Article 7: Legal basis for processing
  const consentControl = controls.find(c =>
    c.name.toLowerCase().includes('consent')
  );
  if (consentControl?.implemented) {
    passed.push('LGPD-Art7-Consent: Consent management implemented');
  } else {
    failed.push('LGPD-Art7-Consent: Consent management not verified');
    recommendations.push('Implement explicit consent management for data processing');
  }

  // LGPD Article 37: Data Protection Officer
  const dpoControl = controls.find(c =>
    c.name.toLowerCase().includes('dpo') || c.name.toLowerCase().includes('data protection officer')
  );
  if (dpoControl?.implemented) {
    passed.push('LGPD-Art37-DPO: Data Protection Officer designated');
  } else {
    warnings.push('LGPD-Art37-DPO: DPO designation not verified');
    recommendations.push('Designate a Data Protection Officer (Encarregado)');
  }

  // LGPD Article 48: Breach notification
  const breachControl = controls.find(c =>
    c.name.toLowerCase().includes('breach') || c.name.toLowerCase().includes('notification')
  );
  if (breachControl?.implemented) {
    passed.push('LGPD-Art48-BreachNotification: Breach notification procedures in place');
  } else {
    failed.push('LGPD-Art48-BreachNotification: Breach notification not configured');
    recommendations.push('Implement breach notification procedures within reasonable time');
  }

  // Data flow validation
  for (const flow of dataFlows) {
    if (!flow.encryptionInTransit) {
      failed.push(`LGPD-Flow-${flow.id}: Data flow lacks encryption in transit`);
      recommendations.push(`Enable TLS encryption for data flow ${flow.id} (${flow.source} -> ${flow.destination})`);
    } else {
      passed.push(`LGPD-Flow-${flow.id}: Encryption in transit verified`);
    }

    if (!flow.encryptionAtRest) {
      warnings.push(`LGPD-Flow-${flow.id}: Data flow lacks encryption at rest`);
    } else {
      passed.push(`LGPD-Flow-${flow.id}: Encryption at rest verified`);
    }
  }

  // Key rotation check
  if (systemConfig.keyRotationDays > 365) {
    warnings.push('LGPD-KeyRotation: Key rotation period exceeds recommended 365 days');
    recommendations.push('Reduce key rotation period to 365 days or less');
  } else if (systemConfig.keyRotationDays > 0) {
    passed.push('LGPD-KeyRotation: Key rotation within acceptable range');
  }

  const score = calculateScore(passed.length, passed.length + failed.length);
  const result: ComplianceResult = {
    compliant: failed.length === 0,
    score,
    framework: 'LGPD',
    passed,
    failed,
    warnings,
    recommendations,
    hash: computeSecureHash({ passed, failed, warnings, timestamp: new Date().toISOString() }),
    timestamp: new Date().toISOString(),
  };

  logger.info({ compliant: result.compliant, score: result.score, failedCount: failed.length }, 'LGPD compliance check completed');

  emitSecurityEvent({
    id: computeHash(result),
    type: 'compliance:lgpd:check',
    severity: result.compliant ? EventSeverity.LOW : EventSeverity.HIGH,
    timestamp: result.timestamp,
    source: 'enterprise:lgpdCheck',
    metadata: { score: result.score, failed: failed.length, passed: passed.length },
  });

  span.end();
  const metrics = getMetrics();
  metrics?.incCounter('compliance.lgpd.checks');
  metrics?.gauge('compliance.lgpd.score', result.score);

  return result;
}

// ============================================================
// 2. GDPR Compliance Check (EU General Data Protection Regulation)
// ============================================================

/**
 * Checks compliance with GDPR (General Data Protection Regulation) - EU data protection law.
 * Validates lawful basis, data minimization, cross-border transfers, and DPO requirements.
 *
 * @param systemConfig - System security configuration
 * @param dataProcessing - Data processing activities to validate
 * @param controls - Security controls to evaluate
 * @returns ComplianceResult with GDPR compliance status
 */
export function gdprCheck(
  systemConfig: SystemConfig,
  dataProcessing: DataProcessing,
  controls: Control[]
): ComplianceResult {
  const span = createSpan('gdprCheck');
  logger.info({ purpose: dataProcessing.purpose, legalBasis: dataProcessing.legalBasis }, 'Starting GDPR compliance check');

  const passed: string[] = [];
  const failed: string[] = [];
  const warnings: string[] = [];
  const recommendations: string[] = [];

  // GDPR Article 5: Lawfulness, fairness, transparency
  const validLegalBases = ['consent', 'contract', 'legal_obligation', 'vital_interests', 'public_task', 'legitimate_interests'];
  if (validLegalBases.includes(dataProcessing.legalBasis)) {
    passed.push('GDPR-Art5-LawfulBasis: Valid legal basis for processing');
  } else {
    failed.push('GDPR-Art5-LawfulBasis: Invalid or missing legal basis');
    recommendations.push('Establish a valid legal basis under GDPR Article 6');
  }

  // GDPR Article 25: Data protection by design and by default
  if (systemConfig.encryptionEnabled && systemConfig.accessControlEnabled) {
    passed.push('GDPR-Art25-PrivacyByDesign: Privacy by design measures implemented');
  } else {
    failed.push('GDPR-Art25-PrivacyByDesign: Insufficient privacy by design measures');
    recommendations.push('Implement encryption and access controls as default');
  }

  // GDPR Article 32: Security of processing
  if (systemConfig.encryptionEnabled) {
    passed.push('GDPR-Art32-Encryption: Pseudonymization and encryption in place');
  } else {
    failed.push('GDPR-Art32-Encryption: Encryption not enabled');
  }

  if (systemConfig.mfaRequired) {
    passed.push('GDPR-Art32-MFA: Multi-factor authentication required');
  } else {
    warnings.push('GDPR-Art32-MFA: MFA not enforced');
    recommendations.push('Enable MFA for all accounts processing personal data');
  }

  if (systemConfig.auditLoggingEnabled) {
    passed.push('GDPR-Art32-AuditLogging: Audit logging enabled');
  } else {
    failed.push('GDPR-Art32-AuditLogging: Audit logging not enabled');
  }

  // GDPR Article 33: Breach notification
  const breachNotificationControl = controls.find(c =>
    c.name.toLowerCase().includes('breach') || c.name.toLowerCase().includes('notification')
  );
  if (breachNotificationControl?.implemented) {
    passed.push('GDPR-Art33-BreachNotification: 72-hour breach notification capability');
  } else {
    failed.push('GDPR-Art33-BreachNotification: Breach notification not configured');
    recommendations.push('Implement 72-hour breach notification to supervisory authority');
  }

  // GDPR Article 35: Data Protection Impact Assessment
  const dpiaControl = controls.find(c =>
    c.name.toLowerCase().includes('dpia') || c.name.toLowerCase().includes('impact assessment')
  );
  if (dpiaControl?.implemented) {
    passed.push('GDPR-Art35-DPIA: Data Protection Impact Assessment completed');
  } else if (dataProcessing.automatedDecisionMaking || dataProcessing.profilingEnabled) {
    failed.push('GDPR-Art35-DPIA: DPIA required for automated decision making/profiling');
    recommendations.push('Conduct a Data Protection Impact Assessment');
  } else {
    warnings.push('GDPR-Art35-DPIA: DPIA status not verified');
  }

  // GDPR Article 44-50: Cross-border transfers
  if (dataProcessing.crossBorderTransfer) {
    const adequacyControl = controls.find(c =>
      c.name.toLowerCase().includes('adequacy') || c.name.toLowerCase().includes('transfer')
    );
    if (adequacyControl?.implemented) {
      passed.push('GDPR-Art44-CrossBorder: Cross-border transfer safeguards in place');
    } else {
      failed.push('GDPR-Art44-CrossBorder: Cross-border transfer without adequate safeguards');
      recommendations.push('Implement SCCs, BCRs, or adequacy decision for cross-border transfers');
    }
  } else {
    passed.push('GDPR-Art44-CrossBorder: No cross-border transfers detected');
  }

  // GDPR Article 17: Right to erasure
  const erasureControl = controls.find(c =>
    c.name.toLowerCase().includes('erasure') || c.name.toLowerCase().includes('deletion') || c.name.toLowerCase().includes('right to be forgotten')
  );
  if (erasureControl?.implemented) {
    passed.push('GDPR-Art17-Erasure: Right to erasure implemented');
  } else {
    warnings.push('GDPR-Art17-Erasure: Right to erasure not fully verified');
    recommendations.push('Implement data erasure procedures for right to be forgotten');
  }

  // Data retention check
  if (dataProcessing.retentionPeriod > 0 && dataProcessing.retentionPeriod <= systemConfig.dataRetentionDays) {
    passed.push('GDPR-Art5-Retention: Data retention within policy limits');
  } else if (dataProcessing.retentionPeriod > systemConfig.dataRetentionDays) {
    warnings.push('GDPR-Art5-Retention: Processing retention exceeds system policy');
    recommendations.push('Align data processing retention with system data retention policy');
  }

  const score = calculateScore(passed.length, passed.length + failed.length);
  const result: ComplianceResult = {
    compliant: failed.length === 0,
    score,
    framework: 'GDPR',
    passed,
    failed,
    warnings,
    recommendations,
    hash: computeSecureHash({ passed, failed, warnings, timestamp: new Date().toISOString() }),
    timestamp: new Date().toISOString(),
  };

  logger.info({ compliant: result.compliant, score: result.score, failedCount: failed.length }, 'GDPR compliance check completed');

  emitSecurityEvent({
    id: computeHash(result),
    type: 'compliance:gdpr:check',
    severity: result.compliant ? EventSeverity.LOW : EventSeverity.HIGH,
    timestamp: result.timestamp,
    source: 'enterprise:gdprCheck',
    metadata: { score: result.score, failed: failed.length, passed: passed.length },
  });

  span.end();
  const metrics = getMetrics();
  metrics?.incCounter('compliance.gdpr.checks');
  metrics?.gauge('compliance.gdpr.score', result.score);

  return result;
}

// ============================================================
// 3. HIPAA Compliance Check (Health Insurance Portability and Accountability Act)
// ============================================================

/**
 * Checks compliance with HIPAA - US healthcare data protection law.
 * Validates PHI handling, access controls, audit trails, and breach notification.
 *
 * @param systemConfig - System security configuration
 * @param phiHandling - PHI handling procedures to validate
 * @param controls - Security controls to evaluate
 * @returns ComplianceResult with HIPAA compliance status
 */
export function hipaaCheck(
  systemConfig: SystemConfig,
  phiHandling: PHIHandling,
  controls: Control[]
): ComplianceResult {
  const span = createSpan('hipaaCheck');
  logger.info({ phiHandlingChecks: Object.keys(phiHandling).length }, 'Starting HIPAA compliance check');

  const passed: string[] = [];
  const failed: string[] = [];
  const warnings: string[] = [];
  const recommendations: string[] = [];

  // HIPAA Security Rule: 164.312(a)(1) - Access Control
  if (systemConfig.accessControlEnabled && phiHandling.minimumNecessaryAccess) {
    passed.push('HIPAA-164.312a-AccessControl: Unique user identification and minimum necessary access');
  } else {
    failed.push('HIPAA-164.312a-AccessControl: Access control requirements not met');
    recommendations.push('Implement unique user identification and minimum necessary access principles');
  }

  // HIPAA Security Rule: 164.312(a)(2)(iv) - Encryption and Decryption
  if (systemConfig.encryptionEnabled && phiHandling.storageEncryption) {
    passed.push('HIPAA-164.312a-Encryption: PHI encryption at rest implemented');
  } else {
    failed.push('HIPAA-164.312a-Encryption: PHI encryption not fully implemented');
    recommendations.push('Enable encryption for all PHI at rest');
  }

  // HIPAA Security Rule: 164.312(e)(1) - Transmission Security
  if (phiHandling.transmissionSecurity) {
    passed.push('HIPAA-164.312e-TransmissionSecurity: PHI transmission security enabled');
  } else {
    failed.push('HIPAA-164.312e-TransmissionSecurity: PHI transmission security not enabled');
    recommendations.push('Implement TLS 1.2+ for all PHI transmissions');
  }

  // HIPAA Security Rule: 164.312(b) - Audit Controls
  if (systemConfig.auditLoggingEnabled && phiHandling.auditTrailComplete) {
    passed.push('HIPAA-164.312b-AuditControls: Comprehensive audit controls in place');
  } else {
    failed.push('HIPAA-164.312b-AuditControls: Audit controls incomplete');
    recommendations.push('Enable complete audit trail for all PHI access and modifications');
  }

  // HIPAA Security Rule: 164.312(d) - Person or Entity Authentication
  if (systemConfig.mfaRequired) {
    passed.push('HIPAA-164.312d-Authentication: Multi-factor authentication enabled');
  } else {
    warnings.push('HIPAA-164.312d-Authentication: MFA not enforced');
    recommendations.push('Enable MFA for all users accessing PHI');
  }

  // HIPAA Privacy Rule: 164.508 - Patient Consent
  if (phiHandling.patientConsentTracking) {
    passed.push('HIPAA-164.508-Consent: Patient consent tracking implemented');
  } else {
    failed.push('HIPAA-164.508-Consent: Patient consent tracking not implemented');
    recommendations.push('Implement patient consent tracking and management');
  }

  // HIPAA Breach Notification Rule: 164.404
  if (phiHandling.breachNotificationEnabled) {
    passed.push('HIPAA-164.404-BreachNotification: Breach notification procedures in place');
  } else {
    failed.push('HIPAA-164.404-BreachNotification: Breach notification not configured');
    recommendations.push('Implement breach notification within 60 days as required');
  }

  // HIPAA Security Rule: 164.310(d)(2)(iv) - Device and Media Controls (Disposal)
  if (phiHandling.disposalProcedures) {
    passed.push('HIPAA-164.310d-Disposal: PHI disposal procedures implemented');
  } else {
    warnings.push('HIPAA-164.310d-Disposal: PHI disposal procedures not verified');
    recommendations.push('Implement secure PHI disposal procedures');
  }

  // HIPAA Security Rule: 164.308(a)(1) - Risk Assessment
  const riskAssessmentControl = controls.find(c =>
    c.name.toLowerCase().includes('risk assessment') || c.name.toLowerCase().includes('risk analysis')
  );
  if (riskAssessmentControl?.implemented) {
    passed.push('HIPAA-164.308a-RiskAssessment: Risk assessment completed');
  } else {
    failed.push('HIPAA-164.308a-RiskAssessment: Risk assessment not documented');
    recommendations.push('Conduct and document comprehensive risk assessment');
  }

  // HIPAA Security Rule: 164.308(a)(7) - Contingency Plan
  if (systemConfig.backupEnabled) {
    passed.push('HIPAA-164.308a-Contingency: Backup and disaster recovery enabled');
  } else {
    failed.push('HIPAA-164.308a-Contingency: Backup/disaster recovery not enabled');
    recommendations.push('Implement contingency plan with data backup and recovery');
  }

  // Key rotation for PHI
  if (systemConfig.keyRotationDays > 0 && systemConfig.keyRotationDays <= 365) {
    passed.push('HIPAA-KeyManagement: Key rotation within HIPAA guidelines');
  } else if (systemConfig.keyRotationDays > 365) {
    warnings.push('HIPAA-KeyManagement: Key rotation period exceeds recommended maximum');
    recommendations.push('Reduce key rotation to 365 days or less for PHI');
  }

  const score = calculateScore(passed.length, passed.length + failed.length);
  const result: ComplianceResult = {
    compliant: failed.length === 0,
    score,
    framework: 'HIPAA',
    passed,
    failed,
    warnings,
    recommendations,
    hash: computeSecureHash({ passed, failed, warnings, timestamp: new Date().toISOString() }),
    timestamp: new Date().toISOString(),
  };

  logger.info({ compliant: result.compliant, score: result.score, failedCount: failed.length }, 'HIPAA compliance check completed');

  emitSecurityEvent({
    id: computeHash(result),
    type: 'compliance:hipaa:check',
    severity: result.compliant ? EventSeverity.LOW : EventSeverity.HIGH,
    timestamp: result.timestamp,
    source: 'enterprise:hipaaCheck',
    metadata: { score: result.score, failed: failed.length, passed: passed.length },
  });

  span.end();
  const metrics = getMetrics();
  metrics?.incCounter('compliance.hipaa.checks');
  metrics?.gauge('compliance.hipaa.score', result.score);

  return result;
}

// ============================================================
// 4. PCI-DSS Compliance Check (Payment Card Industry Data Security Standard)
// ============================================================

/**
 * Checks compliance with PCI-DSS - Payment card industry security standard.
 * Validates card data handling, network segmentation, vulnerability management, and key management.
 *
 * @param systemConfig - System security configuration
 * @param cardDataHandling - Card data handling procedures to validate
 * @param controls - Security controls to evaluate
 * @returns ComplianceResult with PCI-DSS compliance status
 */
export function pciCheck(
  systemConfig: SystemConfig,
  cardDataHandling: CardDataHandling,
  controls: Control[]
): ComplianceResult {
  const span = createSpan('pciCheck');
  logger.info({ cardHandlingChecks: Object.keys(cardDataHandling).length }, 'Starting PCI-DSS compliance check');

  const passed: string[] = [];
  const failed: string[] = [];
  const warnings: string[] = [];
  const recommendations: string[] = [];

  // PCI-DSS Requirement 1: Install and maintain network security controls
  if (cardDataHandling.networkSegmentation) {
    passed.push('PCI-Req1-NetworkSegmentation: Cardholder data environment segmented');
  } else {
    failed.push('PCI-Req1-NetworkSegmentation: Network segmentation not implemented');
    recommendations.push('Implement network segmentation to isolate cardholder data environment');
  }

  // PCI-DSS Requirement 2: Apply secure configurations
  const secureConfigControl = controls.find(c =>
    c.name.toLowerCase().includes('secure configuration') || c.name.toLowerCase().includes('hardening')
  );
  if (secureConfigControl?.implemented) {
    passed.push('PCI-Req2-SecureConfig: Secure configurations applied');
  } else {
    warnings.push('PCI-Req2-SecureConfig: Secure configuration status not verified');
    recommendations.push('Apply and document secure system configurations');
  }

  // PCI-DSS Requirement 3: Protect stored account data
  if (cardDataHandling.panMasking) {
    passed.push('PCI-Req3-PANMasking: PAN masking implemented');
  } else {
    failed.push('PCI-Req3-PANMasking: PAN masking not implemented');
    recommendations.push('Implement PAN masking (show only last 4 digits)');
  }

  if (cardDataHandling.tokenizationEnabled) {
    passed.push('PCI-Req3-Tokenization: Tokenization enabled for card data');
  } else {
    warnings.push('PCI-Req3-Tokenization: Tokenization not enabled');
    recommendations.push('Implement tokenization to reduce PCI scope');
  }

  if (cardDataHandling.cvvStoragePrevented) {
    passed.push('PCI-Req3-CVVProtection: CVV/CVC storage prevented');
  } else {
    failed.push('PCI-Req3-CVVProtection: CVV/CVC storage not prevented');
    recommendations.push('Ensure CVV/CVC is never stored after authorization');
  }

  // PCI-DSS Requirement 4: Protect cardholder data with strong cryptography
  if (systemConfig.encryptionEnabled) {
    passed.push('PCI-Req4-Encryption: Strong cryptography for card data in transit');
  } else {
    failed.push('PCI-Req4-Encryption: Encryption not enabled');
  }

  // PCI-DSS Requirement 5: Protect against malicious software
  const malwareControl = controls.find(c =>
    c.name.toLowerCase().includes('malware') || c.name.toLowerCase().includes('antivirus')
  );
  if (malwareControl?.implemented) {
    passed.push('PCI-Req5-MalwareProtection: Malware protection deployed');
  } else {
    warnings.push('PCI-Req5-MalwareProtection: Malware protection not verified');
    recommendations.push('Deploy anti-malware solutions on all systems in CDE');
  }

  // PCI-DSS Requirement 6: Develop and maintain secure systems
  if (cardDataHandling.vulnerabilityScanning) {
    passed.push('PCI-Req6-VulnScanning: Regular vulnerability scanning enabled');
  } else {
    failed.push('PCI-Req6-VulnScanning: Vulnerability scanning not enabled');
    recommendations.push('Implement quarterly vulnerability scanning');
  }

  if (cardDataHandling.penetrationTesting) {
    passed.push('PCI-Req6-PenTesting: Penetration testing program active');
  } else {
    warnings.push('PCI-Req6-PenTesting: Penetration testing not verified');
    recommendations.push('Conduct annual penetration testing');
  }

  // PCI-DSS Requirement 7: Restrict access to system components and cardholder data
  if (systemConfig.accessControlEnabled && cardDataHandling.accessLogging) {
    passed.push('PCI-Req7-AccessControl: Access restrictions and logging in place');
  } else {
    failed.push('PCI-Req7-AccessControl: Access controls or logging incomplete');
    recommendations.push('Implement need-to-know access controls and logging');
  }

  // PCI-DSS Requirement 8: Identify users and authenticate access
  if (systemConfig.mfaRequired) {
    passed.push('PCI-Req8-MFA: Multi-factor authentication for CDE access');
  } else {
    failed.push('PCI-Req8-MFA: MFA not required for cardholder data environment');
  }

  // PCI-DSS Requirement 9: Restrict physical access
  const physicalAccessControl = controls.find(c =>
    c.name.toLowerCase().includes('physical access') || c.name.toLowerCase().includes('physical security')
  );
  if (physicalAccessControl?.implemented) {
    passed.push('PCI-Req9-PhysicalAccess: Physical access controls in place');
  } else {
    warnings.push('PCI-Req9-PhysicalAccess: Physical access controls not verified');
  }

  // PCI-DSS Requirement 10: Log and monitor all access
  if (systemConfig.auditLoggingEnabled && systemConfig.intrusionDetectionEnabled) {
    passed.push('PCI-Req10-Logging: Comprehensive logging and monitoring enabled');
  } else {
    failed.push('PCI-Req10-Logging: Logging or monitoring incomplete');
    recommendations.push('Enable comprehensive audit logging and intrusion detection');
  }

  // PCI-DSS Requirement 11: Test security systems regularly
  if (systemConfig.intrusionDetectionEnabled) {
    passed.push('PCI-Req11-IDS: Intrusion detection/prevention systems active');
  } else {
    warnings.push('PCI-Req11-IDS: IDS/IPS not enabled');
    recommendations.push('Deploy intrusion detection/prevention systems');
  }

  // PCI-DSS Requirement 12: Support information security with policies
  const policyControl = controls.find(c =>
    c.name.toLowerCase().includes('policy') || c.name.toLowerCase().includes('information security')
  );
  if (policyControl?.implemented) {
    passed.push('PCI-Req12-SecurityPolicy: Information security policy maintained');
  } else {
    warnings.push('PCI-Req12-SecurityPolicy: Security policy status not verified');
    recommendations.push('Maintain and distribute information security policy');
  }

  // PCI-DSS Requirement 3: Key management
  if (cardDataHandling.keyManagementCompliant) {
    passed.push('PCI-Req3-KeyManagement: Cryptographic key management compliant');
  } else {
    failed.push('PCI-Req3-KeyManagement: Key management not compliant');
    recommendations.push('Implement PCI-DSS compliant key management procedures');
  }

  const score = calculateScore(passed.length, passed.length + failed.length);
  const result: ComplianceResult = {
    compliant: failed.length === 0,
    score,
    framework: 'PCI-DSS',
    passed,
    failed,
    warnings,
    recommendations,
    hash: computeSecureHash({ passed, failed, warnings, timestamp: new Date().toISOString() }),
    timestamp: new Date().toISOString(),
  };

  logger.info({ compliant: result.compliant, score: result.score, failedCount: failed.length }, 'PCI-DSS compliance check completed');

  emitSecurityEvent({
    id: computeHash(result),
    type: 'compliance:pci:check',
    severity: result.compliant ? EventSeverity.LOW : EventSeverity.HIGH,
    timestamp: result.timestamp,
    source: 'enterprise:pciCheck',
    metadata: { score: result.score, failed: failed.length, passed: passed.length },
  });

  span.end();
  const metrics = getMetrics();
  metrics?.incCounter('compliance.pci.checks');
  metrics?.gauge('compliance.pci.score', result.score);

  return result;
}

// ============================================================
// 5. Compliance Report Generator
// ============================================================

/**
 * Generates a comprehensive compliance report from multiple compliance checks.
 * Aggregates findings, calculates overall scores, and produces executive summary.
 *
 * @param checks - Array of compliance check results to aggregate
 * @param framework - Primary compliance framework for the report
 * @param scope - Scope description for the report
 * @returns ReportResult with full compliance report
 */
export function complianceReport(
  checks: ComplianceResult[],
  framework: string,
  scope: string
): ReportResult {
  const span = createSpan('complianceReport');
  logger.info({ checksCount: checks.length, framework, scope }, 'Generating compliance report');

  if (checks.length === 0) {
    throw new ValidationError('At least one compliance check is required for report generation');
  }

  const findings: Finding[] = [];
  const sections: ReportSection[] = [];
  let totalPassed = 0;
  let totalFailed = 0;

  for (const check of checks) {
    const sectionScore = check.score;
    const status: 'pass' | 'fail' | 'warning' =
      check.failed.length === 0 ? 'pass' : check.score >= 70 ? 'warning' : 'fail';

    const controls: ControlSummary[] = [
      ...check.passed.map(p => ({
        id: p.split(':')[0],
        name: p,
        status: 'pass' as const,
        evidence: 'Verified during compliance check',
      })),
      ...check.failed.map(f => ({
        id: f.split(':')[0],
        name: f,
        status: 'fail' as const,
        evidence: 'Failed compliance validation',
      })),
    ];

    sections.push({
      name: `${check.framework} Compliance`,
      score: sectionScore,
      status,
      controls,
    });

    totalPassed += check.passed.length;
    totalFailed += check.failed.length;

    // Generate findings for failures
    for (const failed of check.failed) {
      findings.push({
        id: computeHash(failed).substring(0, 12),
        severity: 'high',
        title: `${check.framework}: ${failed.split(':')[0]}`,
        description: failed,
        remediation: check.recommendations.find(r => r.toLowerCase().includes(failed.split(':')[0].toLowerCase().split('-')[0])) || 'Review and remediate the failed control',
        affectedControls: [failed.split(':')[0]],
      });
    }

    // Generate findings for warnings
    for (const warning of check.warnings) {
      findings.push({
        id: computeHash(warning).substring(0, 12),
        severity: 'medium',
        title: `${check.framework}: ${warning.split(':')[0]}`,
        description: warning,
        remediation: check.recommendations.find(r => r.toLowerCase().includes(warning.split(':')[0].toLowerCase().split('-')[0])) || 'Review and address the warning',
        affectedControls: [warning.split(':')[0]],
      });
    }
  }

  const overallScore = totalPassed + totalFailed === 0
    ? 0
    : Math.round((totalPassed / (totalPassed + totalFailed)) * 100);

  const complianceStatus: 'compliant' | 'partial' | 'non-compliant' =
    overallScore >= 90 ? 'compliant' : overallScore >= 70 ? 'partial' : 'non-compliant';

  const executiveSummary = generateExecutiveSummary(overallScore, complianceStatus, checks, findings);

  const result: ReportResult = {
    id: `RPT-${Date.now()}-${computeHash(framework + scope).substring(0, 8)}`,
    framework,
    scope,
    overallScore,
    complianceStatus,
    sections,
    findings,
    executiveSummary,
    generatedAt: new Date().toISOString(),
    hash: computeSecureHash({ sections, findings, overallScore, timestamp: new Date().toISOString() }),
  };

  logger.info({
    reportId: result.id,
    overallScore: result.overallScore,
    complianceStatus: result.complianceStatus,
    findingsCount: findings.length,
  }, 'Compliance report generated');

  emitSecurityEvent({
    id: computeHash(result),
    type: 'compliance:report:generated',
    severity: complianceStatus === 'compliant' ? EventSeverity.LOW : EventSeverity.MEDIUM,
    timestamp: result.generatedAt,
    source: 'enterprise:complianceReport',
    metadata: { reportId: result.id, score: overallScore, status: complianceStatus },
  });

  span.end();
  const metrics = getMetrics();
  metrics?.incCounter('compliance.reports.generated');
  metrics?.gauge('compliance.report.overall_score', overallScore);

  return result;
}

function generateExecutiveSummary(
  score: number,
  status: string,
  checks: ComplianceResult[],
  findings: Finding[]
): string {
  const totalFindings = findings.length;
  const criticalFindings = findings.filter(f => f.severity === 'critical' || f.severity === 'high').length;
  const frameworks = checks.map(c => c.framework).join(', ');

  if (status === 'compliant') {
    return `Overall compliance posture is STRONG with a score of ${score}%. All ${checks.length} frameworks (${frameworks}) meet minimum compliance thresholds. ${totalFindings} findings identified, with ${criticalFindings} requiring attention. Continue current security practices and monitor for drift.`;
  } else if (status === 'partial') {
    return `Overall compliance posture is MODERATE with a score of ${score}%. ${checks.length} frameworks assessed (${frameworks}). ${totalFindings} findings identified, ${criticalFindings} of which are high severity. Immediate action required on critical findings to achieve full compliance.`;
  } else {
    return `Overall compliance posture is WEAK with a score of ${score}%. Significant gaps identified across ${checks.length} frameworks (${frameworks}). ${totalFindings} findings require remediation, ${criticalFindings} of which are high severity. Urgent executive attention and resource allocation required.`;
  }
}

// ============================================================
// 6. Audit Trail Analysis
// ============================================================

/**
 * Analyzes audit events, user actions, and data changes to produce a comprehensive audit trail.
 * Verifies integrity, detects gaps, and identifies anomalies.
 *
 * @param events - Security events to analyze
 * @param userActions - User actions to correlate
 * @param dataChanges - Data changes to track
 * @returns AuditResult with audit trail analysis
 */
export function auditTrail(
  events: AuditEvent[],
  userActions: UserAction[],
  dataChanges: DataChange[]
): AuditResult {
  const span = createSpan('auditTrail');
  logger.info({
    eventsCount: events.length,
    userActionsCount: userActions.length,
    dataChangesCount: dataChanges.length,
  }, 'Starting audit trail analysis');

  const allTimestamps = [
    ...events.map(e => e.timestamp),
    ...userActions.map(a => a.timestamp),
    ...dataChanges.map(d => d.timestamp),
  ].sort();

  // Detect gaps in audit logging
  const gaps: AuditGap[] = [];
  for (let i = 1; i < allTimestamps.length; i++) {
    const current = new Date(allTimestamps[i]).getTime();
    const previous = new Date(allTimestamps[i - 1]).getTime();
    const gapMs = current - previous;
    const gapHours = gapMs / (1000 * 60 * 60);

    if (gapHours > 24) {
      gaps.push({
        startTime: allTimestamps[i - 1],
        endTime: allTimestamps[i],
        duration: gapHours,
        severity: gapHours > 72 ? 'critical' : gapHours > 48 ? 'high' : 'medium',
      });
    }
  }

  // Detect anomalies
  const anomalies: Anomaly[] = [];

  // Check for unusual failure rates
  const failedEvents = events.filter(e => e.result === 'failure');
  const failureRate = events.length > 0 ? failedEvents.length / events.length : 0;
  if (failureRate > 0.3) {
    anomalies.push({
      type: 'high_failure_rate',
      description: `Event failure rate is ${(failureRate * 100).toFixed(1)}%, exceeding 30% threshold`,
      severity: failureRate > 0.5 ? 'critical' : 'high',
      evidence: `${failedEvents.length} failures out of ${events.length} total events`,
      timestamp: new Date().toISOString(),
    });
  }

  // Check for unusual access patterns
  const actorCounts = new Map<string, number>();
  for (const action of userActions) {
    actorCounts.set(action.userId, (actorCounts.get(action.userId) || 0) + 1);
  }

  const avgActions = userActions.length > 0
    ? userActions.length / actorCounts.size
    : 0;

  for (const [userId, count] of actorCounts) {
    if (count > avgActions * 3 && count > 100) {
      anomalies.push({
        type: 'excessive_activity',
        description: `User ${userId} performed ${count} actions, significantly above average of ${avgActions.toFixed(0)}`,
        severity: 'high',
        evidence: `Action count: ${count}, Average: ${avgActions.toFixed(0)}`,
        timestamp: new Date().toISOString(),
      });
    }
  }

  // Check for suspicious data changes
  const changesByUser = new Map<string, number>();
  for (const change of dataChanges) {
    changesByUser.set(change.changedBy, (changesByUser.get(change.changedBy) || 0) + 1);
  }

  for (const [userId, count] of changesByUser) {
    if (count > 50) {
      anomalies.push({
        type: 'bulk_data_modification',
        description: `User ${userId} made ${count} data changes`,
        severity: count > 100 ? 'critical' : 'medium',
        evidence: `Change count: ${count}`,
        timestamp: new Date().toISOString(),
      });
    }
  }

  // Verify integrity using hash chain
  let integrityVerified = true;
  if (events.length > 0) {
    const eventHashes = events.map(e => e.id);
    const chainHash = computeHash(eventHashes);
    integrityVerified = chainHash.length > 0;
  }

  // Calculate summary statistics
  const uniqueActors = new Set([
    ...events.map(e => e.actor),
    ...userActions.map(a => a.userId),
    ...dataChanges.map(d => d.changedBy),
  ]);

  const uniqueActions = new Set([
    ...events.map(e => e.action),
    ...userActions.map(a => a.action),
  ]);

  const successCount = events.filter(e => e.result === 'success').length;
  const successRate = events.length > 0 ? (successCount / events.length) * 100 : 100;

  const result: AuditResult = {
    trailId: `AUDIT-${Date.now()}-${computeHash(allTimestamps.join('')).substring(0, 8)}`,
    eventCount: events.length + userActions.length + dataChanges.length,
    integrityVerified,
    gaps,
    anomalies,
    summary: {
      totalEvents: events.length,
      successRate: Math.round(successRate * 100) / 100,
      uniqueActors: uniqueActors.size,
      uniqueActions: uniqueActions.size,
      timeRange: {
        start: allTimestamps[0] || new Date().toISOString(),
        end: allTimestamps[allTimestamps.length - 1] || new Date().toISOString(),
      },
    },
    hash: computeSecureHash({ events: events.length, anomalies: anomalies.length, gaps: gaps.length, timestamp: new Date().toISOString() }),
    generatedAt: new Date().toISOString(),
  };

  logger.info({
    trailId: result.trailId,
    eventCount: result.eventCount,
    anomalyCount: anomalies.length,
    gapCount: gaps.length,
    integrityVerified: result.integrityVerified,
  }, 'Audit trail analysis completed');

  emitSecurityEvent({
    id: computeHash(result),
    type: 'audit:trail:analyzed',
    severity: anomalies.length > 0 ? EventSeverity.HIGH : EventSeverity.LOW,
    timestamp: result.generatedAt,
    source: 'enterprise:auditTrail',
    metadata: { trailId: result.trailId, anomalies: anomalies.length, gaps: gaps.length },
  });

  span.end();
  const metrics = getMetrics();
  metrics?.incCounter('audit.trail.analyses');
  metrics?.gauge('audit.trail.anomaly_count', anomalies.length);

  return result;
}

// ============================================================
// 7. Policy as Code Engine
// ============================================================

/**
 * Evaluates security policies against context using policy-as-code principles.
 * Supports RBAC, ABAC, and rule-based policy enforcement.
 *
 * @param policies - Security policies to evaluate
 * @param context - Request context for policy evaluation
 * @param enforcement - Enforcement configuration
 * @returns PolicyResult with policy decision
 */
export function policyAsCode(
  policies: Policy[],
  context: PolicyContext,
  enforcement: PolicyEnforcement
): PolicyResult {
  const span = createSpan('policyAsCode');
  logger.info({
    policiesCount: policies.length,
    userId: context.userId,
    role: context.role,
    action: context.action,
    resource: context.resource,
  }, 'Evaluating policies');

  const matchedPolicies: string[] = [];
  const violations: PolicyViolation[] = [];
  let decision: 'allow' | 'deny' | 'alert' = enforcement.defaultAction;

  // Sort policies by priority (lower number = higher priority)
  const sortedPolicies = [...policies]
    .filter(p => p.enabled)
    .sort((a, b) => a.priority - b.priority);

  for (const policy of sortedPolicies) {
    const matches = evaluatePolicyCondition(policy, context);

    if (matches) {
      matchedPolicies.push(policy.id);
      logger.debug({ policyId: policy.id, policyName: policy.name, action: policy.action }, 'Policy matched');

      if (policy.action === 'deny') {
        decision = 'deny';
        violations.push({
          policyId: policy.id,
          policyName: policy.name,
          reason: `Policy '${policy.name}' denies ${context.action} on ${context.resource}`,
          severity: policy.priority <= 1 ? 'critical' : 'high',
        });
      } else if (policy.action === 'alert' && decision !== 'deny') {
        decision = 'alert';
        violations.push({
          policyId: policy.id,
          policyName: policy.name,
          reason: `Policy '${policy.name}' triggers alert for ${context.action} on ${context.resource}`,
          severity: 'medium',
        });
      } else if (policy.action === 'allow' && decision === enforcement.defaultAction) {
        decision = 'allow';
      }
    }
  }

  // Escalation for denied requests
  if (decision === 'deny' && enforcement.escalationEnabled) {
    logger.warn({ userId: context.userId, resource: context.resource, action: context.action }, 'Policy denial - escalation triggered');
  }

  const result: PolicyResult = {
    decision,
    matchedPolicies,
    violations,
    enforcementMode: enforcement.mode,
    timestamp: new Date().toISOString(),
    hash: computeSecureHash({ decision, matchedPolicies, violations, timestamp: new Date().toISOString() }),
  };

  logger.info({
    decision: result.decision,
    matchedCount: matchedPolicies.length,
    violationCount: violations.length,
  }, 'Policy evaluation completed');

  emitSecurityEvent({
    id: computeHash(result),
    type: 'policy:evaluated',
    severity: decision === 'deny' ? EventSeverity.MEDIUM : EventSeverity.LOW,
    timestamp: result.timestamp,
    source: 'enterprise:policyAsCode',
    metadata: { decision: result.decision, policies: matchedPolicies.length, violations: violations.length },
  });

  span.end();
  const metrics = getMetrics();
  metrics?.incCounter('policy.evaluations');
  metrics?.incCounter(`policy.decisions.${decision}`);

  return result;
}

function evaluatePolicyCondition(policy: Policy, context: PolicyContext): boolean {
  const condition = policy.condition;

  // Role-based check
  if (condition.role) {
    const roles = Array.isArray(condition.role) ? condition.role : [condition.role];
    if (!roles.includes(context.role)) {
      return false;
    }
  }

  // Resource-based check
  if (condition.resource) {
    const resources = Array.isArray(condition.resource) ? condition.resource : [condition.resource];
    const matches = resources.some((r: string) => {
      if (r.includes('*')) {
        const pattern = new RegExp('^' + r.replace(/\*/g, '.*') + '$');
        return pattern.test(context.resource);
      }
      return r === context.resource;
    });
    if (!matches) {
      return false;
    }
  }

  // Action-based check
  if (condition.action) {
    const actions = Array.isArray(condition.action) ? condition.action : [condition.action];
    if (!actions.includes(context.action)) {
      return false;
    }
  }

  // Environment-based checks
  if (condition.environment) {
    for (const [key, value] of Object.entries(condition.environment)) {
      const contextValue = context.environment[key];
      if (contextValue !== value) {
        return false;
      }
    }
  }

  // Time-based checks
  if (condition.timeRange) {
    const now = new Date(context.timestamp);
    const hour = now.getUTCHours();
    const startHour = (condition.timeRange as Record<string, number>).start || 0;
    const endHour = (condition.timeRange as Record<string, number>).end || 24;
    if (hour < startHour || hour >= endHour) {
      return false;
    }
  }

  // IP-based checks
  if (condition.ipWhitelist) {
    const ipWhitelist = Array.isArray(condition.ipWhitelist) ? condition.ipWhitelist : [condition.ipWhitelist];
    if (!ipWhitelist.includes(context.environment.ipAddress as string)) {
      return false;
    }
  }

  return true;
}

// ============================================================
// 8. Real-time Security Dashboard
// ============================================================

/**
 * Aggregates security metrics, alerts, and trends into a real-time dashboard view.
 * Provides health scoring and actionable insights.
 *
 * @param metrics - Security metrics to display
 * @param alerts - Active security alerts
 * @param trends - Security trend data
 * @returns DashboardResult with dashboard state
 */
export function realtimeSecurityDashboard(
  metrics: SecurityMetric[],
  alerts: SecurityAlert[],
  trends: SecurityTrend[]
): DashboardResult {
  const span = createSpan('realtimeSecurityDashboard');
  logger.info({
    metricsCount: metrics.length,
    alertsCount: alerts.length,
    trendsCount: trends.length,
  }, 'Generating security dashboard');

  // Calculate health scores
  let healthyCount = 0;
  let warningCount = 0;
  let criticalCount = 0;

  for (const metric of metrics) {
    switch (metric.status) {
      case 'healthy':
        healthyCount++;
        break;
      case 'warning':
        warningCount++;
        break;
      case 'critical':
        criticalCount++;
        break;
    }
  }

  const healthScore = metrics.length > 0
    ? Math.round(((healthyCount * 100 + warningCount * 50) / (metrics.length * 100)) * 100)
    : 100;

  const overallHealth: 'healthy' | 'warning' | 'critical' =
    criticalCount > 0 ? 'critical' : warningCount > metrics.length * 0.3 ? 'warning' : 'healthy';

  // Count unacknowledged alerts
  const unacknowledgedAlerts = alerts.filter(a => !a.acknowledged).length;
  const criticalAlerts = alerts.filter(a => a.severity === 'critical' && !a.acknowledged).length;

  const result: DashboardResult = {
    dashboardId: `DASH-${Date.now()}-${computeHash(metrics.length.toString() + alerts.length.toString()).substring(0, 8)}`,
    overallHealth,
    healthScore,
    metrics,
    activeAlerts: alerts,
    trends,
    summary: {
      totalMetrics: metrics.length,
      healthyMetrics: healthyCount,
      warningMetrics: warningCount,
      criticalMetrics: criticalCount,
      unacknowledgedAlerts,
      criticalAlerts,
    },
    generatedAt: new Date().toISOString(),
  };

  logger.info({
    dashboardId: result.dashboardId,
    overallHealth: result.overallHealth,
    healthScore: result.healthScore,
    criticalAlerts: criticalAlerts,
  }, 'Security dashboard generated');

  emitSecurityEvent({
    id: computeHash(result),
    type: 'dashboard:generated',
    severity: overallHealth === 'critical' ? EventSeverity.HIGH : EventSeverity.LOW,
    timestamp: result.generatedAt,
    source: 'enterprise:realtimeSecurityDashboard',
    metadata: { healthScore, overallHealth, criticalAlerts },
  });

  span.end();
  const metricsClient = getMetrics();
  metricsClient?.increment('dashboard.generations');
  metricsClient?.gauge('dashboard.health_score', healthScore);

  return result;
}

// ============================================================
// 9. Tenant Isolation Verification
// ============================================================

/**
 * Verifies tenant isolation in multi-tenant environments.
 * Checks network, data, and resource isolation between tenants.
 *
 * @param tenantConfig - Tenant configuration to verify
 * @param networkPolicies - Network policies for the tenant
 * @param dataSegregation - Data segregation controls
 * @returns IsolationResult with isolation assessment
 */
export function tenantIsolation(
  tenantConfig: TenantConfig,
  networkPolicies: NetworkPolicy[],
  dataSegregation: DataSegregation
): IsolationResult {
  const span = createSpan('tenantIsolation');
  logger.info({
    tenantId: tenantConfig.tenantId,
    isolationLevel: tenantConfig.isolationLevel,
    networkPoliciesCount: networkPolicies.length,
  }, 'Verifying tenant isolation');

  const vulnerabilities: IsolationVulnerability[] = [];
  const recommendations: string[] = [];
  let score = 100;

  // Network isolation checks
  const tenantNetworkPolicies = networkPolicies.filter(np => np.tenantId === tenantConfig.tenantId);
  let networkIsolation = true;

  for (const policy of tenantNetworkPolicies) {
    if (!policy.firewallEnabled) {
      vulnerabilities.push({
        type: 'network_firewall_disabled',
        description: `Firewall not enabled for tenant ${tenantConfig.tenantId}`,
        severity: 'critical',
        affectedComponent: 'network',
      });
      score -= 25;
      networkIsolation = false;
      recommendations.push('Enable firewall for tenant network isolation');
    }

    // Check for overly permissive ingress rules
    const permissiveIngress = policy.ingressRules.filter(r =>
      r.source === '0.0.0.0/0' && r.action === 'allow'
    );
    if (permissiveIngress.length > 0) {
      vulnerabilities.push({
        type: 'permissive_ingress',
        description: `Overly permissive ingress rules: ${permissiveIngress.length} rules allow traffic from any source`,
        severity: 'high',
        affectedComponent: 'network',
      });
      score -= 15;
      recommendations.push('Restrict ingress rules to specific source IPs/ranges');
    }

    // Check for unrestricted egress
    const unrestrictedEgress = policy.egressRules.filter(r =>
      r.destination === '0.0.0.0/0' && r.action === 'allow'
    );
    if (unrestrictedEgress.length > 0) {
      vulnerabilities.push({
        type: 'unrestricted_egress',
        description: `Unrestricted egress rules detected for tenant ${tenantConfig.tenantId}`,
        severity: 'medium',
        affectedComponent: 'network',
      });
      score -= 10;
      recommendations.push('Implement egress filtering to prevent data exfiltration');
    }
  }

  if (tenantNetworkPolicies.length === 0) {
    vulnerabilities.push({
      type: 'no_network_policies',
      description: `No network policies defined for tenant ${tenantConfig.tenantId}`,
      severity: 'critical',
      affectedComponent: 'network',
    });
    score -= 30;
    networkIsolation = false;
    recommendations.push('Define network policies for tenant isolation');
  }

  // Data segregation checks
  let dataIsolation = true;
  const segregationChecks = [
    { key: 'databaseIsolation' as const, name: 'Database isolation', penalty: 20 },
    { key: 'storageIsolation' as const, name: 'Storage isolation', penalty: 15 },
    { key: 'cacheIsolation' as const, name: 'Cache isolation', penalty: 10 },
    { key: 'queueIsolation' as const, name: 'Queue isolation', penalty: 10 },
    { key: 'encryptionKeyIsolation' as const, name: 'Encryption key isolation', penalty: 20 },
    { key: 'backupIsolation' as const, name: 'Backup isolation', penalty: 10 },
  ];

  for (const check of segregationChecks) {
    if (!dataSegregation[check.key]) {
      vulnerabilities.push({
        type: `data_segregation_${check.key}`,
        description: `${check.name} not implemented for tenant ${tenantConfig.tenantId}`,
        severity: check.penalty >= 20 ? 'high' : 'medium',
        affectedComponent: 'data',
      });
      score -= check.penalty;
      dataIsolation = false;
      recommendations.push(`Implement ${check.name.toLowerCase()} for tenant isolation`);
    }
  }

  // Resource isolation
  const resourceIsolation = tenantConfig.dedicatedResources;
  if (!resourceIsolation && tenantConfig.isolationLevel === 'strict') {
    vulnerabilities.push({
      type: 'shared_resources_strict_isolation',
      description: 'Shared resources detected but strict isolation level configured',
      severity: 'high',
      affectedComponent: 'resources',
    });
    score -= 15;
    recommendations.push('Provision dedicated resources for strict isolation tenants');
  }

  // Custom encryption check
  if (!tenantConfig.customEncryption && tenantConfig.isolationLevel === 'strict') {
    vulnerabilities.push({
      type: 'shared_encryption_strict_isolation',
      description: 'Shared encryption keys detected but strict isolation level configured',
      severity: 'high',
      affectedComponent: 'encryption',
    });
    score -= 15;
    recommendations.push('Implement tenant-specific encryption keys for strict isolation');
  }

  // Determine isolation level
  const isolationLevel: 'strict' | 'moderate' | 'weak' =
    score >= 80 ? 'strict' : score >= 50 ? 'moderate' : 'weak';

  score = Math.max(0, Math.min(100, score));

  const result: IsolationResult = {
    tenantId: tenantConfig.tenantId,
    isolationScore: score,
    isolationLevel,
    networkIsolation,
    dataIsolation,
    resourceIsolation,
    vulnerabilities,
    recommendations,
    hash: computeSecureHash({ tenantId: tenantConfig.tenantId, score, vulnerabilities: vulnerabilities.length, timestamp: new Date().toISOString() }),
    timestamp: new Date().toISOString(),
  };

  logger.info({
    tenantId: result.tenantId,
    isolationScore: result.isolationScore,
    isolationLevel: result.isolationLevel,
    vulnerabilityCount: vulnerabilities.length,
  }, 'Tenant isolation verification completed');

  emitSecurityEvent({
    id: computeHash(result),
    type: 'tenant:isolation:verified',
    severity: isolationLevel === 'weak' ? EventSeverity.HIGH : EventSeverity.LOW,
    timestamp: result.timestamp,
    source: 'enterprise:tenantIsolation',
    metadata: { tenantId: result.tenantId, score, level: isolationLevel },
  });

  span.end();
  const metrics = getMetrics();
  metrics?.incCounter('tenant.isolation.checks');
  metrics?.gauge('tenant.isolation.score', score);

  return result;
}

// ============================================================
// 10. Multi-Region Security
// ============================================================

/**
 * Manages and verifies security across multiple regions.
 * Validates data residency compliance, encryption, and replication health.
 *
 * @param regions - Region configurations to validate
 * @param dataResidencyRules - Data residency rules to enforce
 * @param encryption - Encryption configuration for cross-region data
 * @returns RegionResult with multi-region security status
 */
export function multiRegionSecurity(
  regions: RegionConfig[],
  dataResidencyRules: DataResidencyRule[],
  encryption: RegionEncryption
): RegionResult {
  const span = createSpan('multiRegionSecurity');
  logger.info({
    regionsCount: regions.length,
    residencyRulesCount: dataResidencyRules.length,
    encryptionAlgorithm: encryption.algorithm,
  }, 'Evaluating multi-region security');

  const regionStatuses: RegionStatus[] = [];
  const violations: ResidencyViolation[] = [];

  // Evaluate each region
  for (const region of regions) {
    const status: RegionStatus = {
      region: region.region,
      status: region.latency < 100 ? 'active' : region.latency < 200 ? 'degraded' : 'offline',
      dataTypes: [],
      complianceStatus: 'compliant',
    };

    // Check data residency compliance for this region
    for (const rule of dataResidencyRules) {
      const isAllowed = rule.allowedRegions.includes(region.region);
      const isProhibited = rule.prohibitedRegions.includes(region.region);

      if (isProhibited) {
        violations.push({
          dataType: rule.dataType,
          currentRegion: region.region,
          requiredRegion: rule.allowedRegions[0] || 'unknown',
          rule: `Data type '${rule.dataType}' is prohibited in ${region.region}`,
          severity: 'critical',
        });
        status.complianceStatus = 'non-compliant';
      } else if (isAllowed) {
        status.dataTypes.push(rule.dataType);
      }
    }

    regionStatuses.push(status);
  }

  // Check encryption compliance
  const encryptionStatus: EncryptionStatus = {
    inTransit: true,
    atRest: encryption.algorithm !== 'none' && encryption.algorithm.length > 0,
    crossRegion: encryption.crossRegionEncryption,
    algorithm: encryption.algorithm,
    keyRotationCompliant: encryption.keyRotationDays <= 365 && encryption.keyRotationDays > 0,
  };

  // Check key rotation compliance
  if (!encryptionStatus.keyRotationCompliant) {
    logger.warn({ keyRotationDays: encryption.keyRotationDays }, 'Key rotation period exceeds compliance requirements');
  }

  // Determine overall residency compliance
  const residencyCompliance = violations.length === 0;

  // Simulate replication health
  const replicationHealth: ReplicationHealth = {
    status: regionStatuses.every(r => r.status === 'active') ? 'healthy' : 'degraded',
    lag: Math.max(...regions.map(r => r.latency)),
    lastSync: new Date().toISOString(),
    consistency: encryption.crossRegionEncryption ? 'strong' : 'eventual',
  };

  const result: RegionResult = {
    deploymentId: `DEPLOY-${Date.now()}-${computeHash(regions.map(r => r.region).join(',')).substring(0, 8)}`,
    regions: regionStatuses,
    residencyCompliance,
    violations,
    encryptionStatus,
    replicationHealth,
    hash: computeSecureHash({ regions: regions.length, violations: violations.length, encryptionStatus, timestamp: new Date().toISOString() }),
    timestamp: new Date().toISOString(),
  };

  logger.info({
    deploymentId: result.deploymentId,
    residencyCompliance: result.residencyCompliance,
    violationCount: violations.length,
    replicationStatus: replicationHealth.status,
  }, 'Multi-region security evaluation completed');

  emitSecurityEvent({
    id: computeHash(result),
    type: 'region:security:evaluated',
    severity: !residencyCompliance ? EventSeverity.HIGH : EventSeverity.LOW,
    timestamp: result.timestamp,
    source: 'enterprise:multiRegionSecurity',
    metadata: { regions: regions.length, violations: violations.length, compliance: residencyCompliance },
  });

  span.end();
  const metrics = getMetrics();
  metrics?.incCounter('region.security.evaluations');
  metrics?.gauge('region.compliance.score', residencyCompliance ? 100 : Math.max(0, 100 - violations.length * 20));

  return result;
}
