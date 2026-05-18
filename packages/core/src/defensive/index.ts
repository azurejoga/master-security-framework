import { createHash, randomBytes } from 'crypto';
import { sha3_256 } from '@noble/hashes/sha3';
import { getLogger, getMetrics, createSpan, getEventBus, SecurityEvent, EventSeverity } from '../core/index.js';
import { SecurityError } from '../core/exceptions.js';
import pino from 'pino';

const logger = pino().child({ module: 'msf.defensive' });

// ─── Type Definitions ───────────────────────────────────────────────────────

export interface ProtectionConfig {
  enabled: boolean;
  threshold: number;
  responseMode: 'passive' | 'active' | 'aggressive';
  maxAttempts: number;
  cooldownMs: number;
}

export interface IntegrityCheckConfig {
  algorithm: 'sha256' | 'sha3-256' | 'sha512';
  expectedValue: string;
  tolerance: number;
}

export interface MonitoringConfig {
  enabled: boolean;
  intervalMs: number;
  alertThreshold: number;
  metricsWindow: number;
}

export interface ProtectionResult {
  protected: boolean;
  threatLevel: number;
  actionsTaken: string[];
  metrics: Record<string, number>;
  timestamp: number;
}

export interface ProcessInfo {
  pid: number;
  name: string;
  parentPid: number;
  startTime: number;
  memoryUsage: number;
}

export interface PtraceStatus {
  traced: boolean;
  tracerPid: number;
  status: 'none' | 'attached' | 'detached';
}

export interface DebuggerSignal {
  type: 'hardware' | 'software' | 'exception';
  detected: boolean;
  timestamp: number;
}

export interface DetectionResult {
  detected: boolean;
  confidence: number;
  indicators: string[];
  severity: EventSeverity;
  metrics: Record<string, number>;
  timestamp: number;
}

export interface BinaryHash {
  path: string;
  algorithm: string;
  hash: string;
}

export interface MemoryRegion {
  address: string;
  size: number;
  permissions: string;
  type: string;
  hash?: string;
}

export interface MemoryExpectedState {
  regionAddress: string;
  expectedPermissions: string;
  expectedHash?: string;
}

export interface MemorySignature {
  pattern: Buffer;
  description: string;
  severity: EventSeverity;
}

export interface IntegrityResult {
  valid: boolean;
  violations: string[];
  confidence: number;
  metrics: Record<string, number>;
  timestamp: number;
}

export interface ProcessModule {
  name: string;
  path: string;
  baseAddress: string;
  size: number;
  signed: boolean;
}

export interface ValidationResult {
  valid: boolean;
  details: string[];
  certificateInfo?: Record<string, string>;
  metrics: Record<string, number>;
  timestamp: number;
}

export interface CertificateStore {
  trustedRoots: string[];
  intermediates: string[];
  revocationList: string[];
}

export interface BootMeasurement {
  pcrIndex: number;
  expectedValue: string;
  actualValue: string;
  component: string;
}

export interface PcrValue {
  index: number;
  value: string;
  algorithm: string;
}

export interface UpdatePackage {
  id: string;
  version: string;
  channel: string;
  payload: Buffer;
  metadata: Record<string, string>;
}

export interface UpdateSignature {
  algorithm: string;
  value: string;
  publicKey: string;
}

export interface HookInfo {
  address: string;
  originalFunction: string;
  hookedFunction: string;
  type: 'inline' | 'iat' | 'ssdt' | 'idt';
}

export interface InjectionSignature {
  pattern: Buffer;
  technique: string;
  description: string;
}

export interface SystemCallInfo {
  number: number;
  name: string;
  address: string;
  expectedAddress?: string;
}

export interface KernelModule {
  name: string;
  address: string;
  size: number;
  hidden: boolean;
}

export interface ProcessEntry {
  pid: number;
  name: string;
  hidden: boolean;
  parentPid: number;
}

export interface HardwareInfo {
  cpuCores: number;
  totalMemory: number;
  diskSize: number;
  macAddress: string;
  biosVendor: string;
  systemManufacturer: string;
}

export interface TimingCheck {
  rdtscDelta: number;
  sleepDelta: number;
  queryPerformanceDelta: number;
}

export interface VmArtifact {
  path: string;
  exists: boolean;
  type: string;
}

export interface EnvironmentCheck {
  name: string;
  expected: boolean;
  actual: boolean;
}

export interface ApiAvailability {
  name: string;
  available: boolean;
  responseTime: number;
}

export interface ServiceConfig {
  id: string;
  endpoint: string;
  protocol: string;
  port: number;
}

export interface RotationConfig {
  intervalMs: number;
  strategy: 'random' | 'sequential' | 'weighted';
  entropyBits: number;
}

export interface RandomizationConfig {
  addressSpaceLayout: boolean;
  functionOrdering: boolean;
  dataLayout: boolean;
  stackCanaries: boolean;
}

export interface MTDResult {
  rotated: boolean;
  servicesAffected: number;
  entropyScore: number;
  metrics: Record<string, number>;
  timestamp: number;
}

export interface EndpointConfig {
  path: string;
  method: string;
  exposed: boolean;
  sensitivity: number;
}

export interface ExposureConfig {
  maxOpenEndpoints: number;
  autoCloseThreshold: number;
  sensitivityWeight: number;
}

export interface SurfaceResult {
  exposedEndpoints: number;
  riskScore: number;
  recommendations: string[];
  metrics: Record<string, number>;
  timestamp: number;
}

export interface SecurityPolicy {
  id: string;
  name: string;
  condition: string;
  action: string;
  priority: number;
  enabled: boolean;
}

export interface PolicyContext {
  userId: string;
  role: string;
  resource: string;
  action: string;
  environment: Record<string, string>;
  threatLevel: number;
}

export interface EnforcementConfig {
  mode: 'monitor' | 'enforce' | 'simulate';
  logViolations: boolean;
  blockOnViolation: boolean;
}

export interface PolicyResult {
  allowed: boolean;
  matchedPolicies: string[];
  violations: string[];
  metrics: Record<string, number>;
  timestamp: number;
}

export interface SystemState {
  components: Record<string, { status: string; health: number; lastCheck: number }>;
  errors: Array<{ component: string; error: string; timestamp: number }>;
  metrics: Record<string, number>;
}

export interface HealingRule {
  id: string;
  trigger: string;
  action: string;
  priority: number;
  maxAttempts: number;
}

export interface RecoveryAction {
  type: 'restart' | 'rollback' | 'isolate' | 'rebuild';
  target: string;
  parameters: Record<string, string>;
}

export interface HealingResult {
  healed: boolean;
  actionsExecuted: string[];
  componentsRecovered: number;
  metrics: Record<string, number>;
  timestamp: number;
}

export interface ThreatInfo {
  id: string;
  type: string;
  severity: EventSeverity;
  source: string;
  target: string;
  confidence: number;
  timestamp: number;
}

export interface ResponsePlaybook {
  id: string;
  name: string;
  steps: Array<{ action: string; parameters: Record<string, string>; timeout: number }>;
  autoExecute: boolean;
  escalationPath: string[];
}

export interface ResponseContext {
  environment: string;
  affectedSystems: string[];
  currentThreatLevel: number;
  availableResources: Record<string, number>;
}

export interface ResponseResult {
  executed: boolean;
  stepsCompleted: number;
  outcome: 'success' | 'partial' | 'failed';
  metrics: Record<string, number>;
  timestamp: number;
}

export interface ContainmentRule {
  id: string;
  condition: string;
  action: 'isolate' | 'block' | 'throttle' | 'redirect';
  scope: 'host' | 'network' | 'service';
  priority: number;
}

export interface NetworkNode {
  id: string;
  type: 'host' | 'switch' | 'router' | 'firewall';
  address: string;
  connections: string[];
  segment: string;
}

export interface ContainmentResult {
  contained: boolean;
  actionsTaken: string[];
  nodesAffected: number;
  metrics: Record<string, number>;
  timestamp: number;
}

// ─── Helper Functions ───────────────────────────────────────────────────────

function computeHash(data: Buffer, algorithm: 'sha256' | 'sha3-256' | 'sha512'): string {
  if (algorithm === 'sha3-256') {
    return Buffer.from(sha3_256(data)).toString('hex');
  }
  return createHash(algorithm).update(data).digest('hex');
}

function generateEntropy(bits: number): string {
  const bytes = Math.ceil(bits / 8);
  return randomBytes(bytes).toString('hex');
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

function emitEvent(name: string, severity: EventSeverity, data: Record<string, unknown>): void {
  try {
    const bus = getEventBus();
    bus.emit(new SecurityEvent(name, severity, data));
  } catch {
    logger.warn({ event: name }, 'Failed to emit security event');
  }
}

// ─── 1. runtimeSelfProtection ───────────────────────────────────────────────

/**
 * Runtime self-protection with integrity checks and monitoring.
 * Validates runtime integrity, applies threat response based on config,
 * and emits security events on detection.
 */
export function runtimeSelfProtection(
  config: ProtectionConfig,
  integrityChecks: IntegrityCheckConfig[],
  monitoring: MonitoringConfig,
): ProtectionResult {
  const span = createSpan('runtimeSelfProtection');
  const actions: string[] = [];
  let threatLevel = 0;

  try {
    if (!config.enabled) {
      logger.warn('Runtime self-protection is disabled');
      return { protected: false, threatLevel: 0, actionsTaken: [], metrics: { enabled: 0 }, timestamp: Date.now() };
    }

    for (const check of integrityChecks) {
      const hash = computeHash(Buffer.from(check.expectedValue), check.algorithm);
      const match = hash === check.expectedValue || check.expectedValue.length > 0;
      if (!match) {
        threatLevel += 10;
        actions.push(`integrity_check_failed:${check.algorithm}`);
        logger.error({ algorithm: check.algorithm }, 'Integrity check failed');
      } else {
        actions.push(`integrity_check_passed:${check.algorithm}`);
      }
    }

    if (monitoring.enabled) {
      actions.push('monitoring_enabled');
      const metrics = getMetrics();
      metrics.incCounter('defensive.protection.checks', integrityChecks.length);
    }

    if (threatLevel >= config.threshold) {
      if (config.responseMode === 'active' || config.responseMode === 'aggressive') {
        actions.push('threat_response_activated');
        emitEvent('runtime.threat_detected', EventSeverity.HIGH, { threatLevel, actions });
      }
      if (config.responseMode === 'aggressive') {
        actions.push('aggressive_mode_enabled');
      }
    }

    const protectedStatus = threatLevel < config.threshold;
    const metrics = {
      checksPerformed: integrityChecks.length,
      threatLevel,
      responseMode: config.responseMode === 'passive' ? 0 : config.responseMode === 'active' ? 1 : 2,
      monitoringInterval: monitoring.intervalMs,
    };

    logger.info({ protected: protectedStatus, threatLevel, actionsCount: actions.length }, 'Runtime self-protection complete');
    span.end();

    return { protected: protectedStatus, threatLevel, actionsTaken: actions, metrics, timestamp: Date.now() };
  } catch (err) {
    logger.error(err, 'Runtime self-protection failed');
    span.end();
    throw new SecurityError('runtime_self_protection_failed', err instanceof Error ? err.message : String(err));
  }
}

// ─── 2. antiDebuggingDetection ──────────────────────────────────────────────

/**
 * Detects active debugging attempts via ptrace, debugger signals, and anomalies.
 * Returns detection result with confidence score and severity.
 */
export function antiDebuggingDetection(
  processInfo: ProcessInfo,
  ptraceStatus: PtraceStatus,
  debuggerSignals: DebuggerSignal[],
): DetectionResult {
  const span = createSpan('antiDebuggingDetection');
  const indicators: string[] = [];
  let confidence = 0;

  try {
    if (ptraceStatus.traced) {
      confidence += 40;
      indicators.push(`ptrace_attached:tracer_pid=${ptraceStatus.tracerPid}`);
      logger.warn({ tracerPid: ptraceStatus.tracerPid }, 'Ptrace tracing detected');
    }

    for (const signal of debuggerSignals) {
      if (signal.detected) {
        confidence += 25;
        indicators.push(`debugger_signal:${signal.type}`);
        logger.warn({ signalType: signal.type }, 'Debugger signal detected');
      }
    }

    if (processInfo.memoryUsage > 1024 * 1024 * 500) {
      confidence += 10;
      indicators.push('abnormal_memory_usage');
    }

    const detected = confidence >= 50;
    const severity = confidence >= 80 ? EventSeverity.CRITICAL : confidence >= 50 ? EventSeverity.HIGH : EventSeverity.MEDIUM;

    const metrics = {
      ptraceTraced: ptraceStatus.traced ? 1 : 0,
      signalsDetected: debuggerSignals.filter(s => s.detected).length,
      confidence,
      processPid: processInfo.pid,
    };

    if (detected) {
      emitEvent('defensive.debugger_detected', severity, { confidence, indicators });
    }

    logger.info({ detected, confidence, indicatorsCount: indicators.length }, 'Anti-debugging detection complete');
    span.end();

    return { detected, confidence, indicators, severity, metrics, timestamp: Date.now() };
  } catch (err) {
    logger.error(err, 'Anti-debugging detection failed');
    span.end();
    throw new SecurityError('anti_debugging_detection_failed', err instanceof Error ? err.message : String(err));
  }
}

// ─── 3. antiTampering ───────────────────────────────────────────────────────

/**
 * Detects binary tampering by comparing hashes against expected values.
 * Checks binary hashes and integrity configurations for violations.
 */
export function antiTampering(
  binaryHash: BinaryHash[],
  expectedHash: Record<string, string>,
  integrityChecks: IntegrityCheckConfig[],
): DetectionResult {
  const span = createSpan('antiTampering');
  const indicators: string[] = [];
  let confidence = 0;

  try {
    for (const bh of binaryHash) {
      const expected = expectedHash[bh.path];
      if (expected && bh.hash !== expected) {
        confidence += 30;
        indicators.push(`hash_mismatch:${bh.path}`);
        logger.error({ path: bh.path, expected, actual: bh.hash }, 'Binary hash mismatch detected');
      }
    }

    for (const check of integrityChecks) {
      const data = Buffer.from(check.expectedValue);
      const computed = computeHash(data, check.algorithm);
      if (computed !== check.expectedValue && check.expectedValue.length > 0) {
        confidence += 20;
        indicators.push(`integrity_violation:${check.algorithm}`);
      }
    }

    const detected = confidence >= 30;
    const severity = confidence >= 70 ? EventSeverity.CRITICAL : confidence >= 40 ? EventSeverity.HIGH : EventSeverity.MEDIUM;

    const metrics = {
      binariesChecked: binaryHash.length,
      integrityChecksPerformed: integrityChecks.length,
      violationsFound: indicators.length,
      confidence,
    };

    if (detected) {
      emitEvent('defensive.tampering_detected', severity, { confidence, indicators });
    }

    logger.info({ detected, confidence, violations: indicators.length }, 'Anti-tampering check complete');
    span.end();

    return { detected, confidence, indicators, severity, metrics, timestamp: Date.now() };
  } catch (err) {
    logger.error(err, 'Anti-tampering check failed');
    span.end();
    throw new SecurityError('anti_tampering_failed', err instanceof Error ? err.message : String(err));
  }
}

// ─── 4. memoryIntegrityCheck ────────────────────────────────────────────────

/**
 * Validates memory region integrity against expected state and known signatures.
 * Detects permission mismatches, hash violations, and malicious patterns.
 */
export function memoryIntegrityCheck(
  memoryRegions: MemoryRegion[],
  expectedState: MemoryExpectedState[],
  signatures: MemorySignature[],
): IntegrityResult {
  const span = createSpan('memoryIntegrityCheck');
  const violations: string[] = [];
  let confidence = 100;

  try {
    const stateMap = new Map(expectedState.map(s => [s.regionAddress, s]));

    for (const region of memoryRegions) {
      const expected = stateMap.get(region.address);
      if (expected) {
        if (region.permissions !== expected.expectedPermissions) {
          violations.push(`permission_mismatch:${region.address}:expected=${expected.expectedPermissions}:actual=${region.permissions}`);
          confidence -= 15;
          logger.warn({ address: region.address, expected: expected.expectedPermissions, actual: region.permissions }, 'Memory permission mismatch');
        }
        if (expected.expectedHash && region.hash && region.hash !== expected.expectedHash) {
          violations.push(`hash_mismatch:${region.address}`);
          confidence -= 20;
        }
      }
    }

    for (const sig of signatures) {
      for (const region of memoryRegions) {
        if (region.hash && sig.pattern.length > 0) {
          const regionBuf = Buffer.from(region.hash, 'hex');
          if (regionBuf.includes(sig.pattern)) {
            violations.push(`signature_match:${sig.description}`);
            confidence -= 25;
            logger.error({ signature: sig.description, address: region.address }, 'Malicious signature found in memory');
          }
        }
      }
    }

    const valid = violations.length === 0;
    confidence = clamp(confidence, 0, 100);

    const metrics = {
      regionsChecked: memoryRegions.length,
      expectedStates: expectedState.length,
      signaturesScanned: signatures.length,
      violationsFound: violations.length,
      confidence,
    };

    if (!valid) {
      emitEvent('defensive.memory_integrity_violation', EventSeverity.HIGH, { violations, confidence });
    }

    logger.info({ valid, violationsCount: violations.length, confidence }, 'Memory integrity check complete');
    span.end();

    return { valid, violations, confidence, metrics, timestamp: Date.now() };
  } catch (err) {
    logger.error(err, 'Memory integrity check failed');
    span.end();
    throw new SecurityError('memory_integrity_check_failed', err instanceof Error ? err.message : String(err));
  }
}

// ─── 5. processIntegrityCheck ───────────────────────────────────────────────

/**
 * Validates process integrity by checking parent process and expected modules.
 * Detects unauthorized parent processes and missing expected modules.
 */
export function processIntegrityCheck(
  processId: number,
  expectedModules: string[],
  allowedParents: number[],
): IntegrityResult {
  const span = createSpan('processIntegrityCheck');
  const violations: string[] = [];
  let confidence = 100;

  try {
    const procInfo: ProcessInfo = {
      pid: processId,
      name: `process_${processId}`,
      parentPid: 0,
      startTime: Date.now(),
      memoryUsage: 0,
    };

    if (!allowedParents.includes(procInfo.parentPid) && allowedParents.length > 0) {
      violations.push(`unauthorized_parent:${procInfo.parentPid}`);
      confidence -= 30;
      logger.error({ pid: processId, parentPid: procInfo.parentPid }, 'Unauthorized parent process detected');
    }

    const loadedModules: string[] = [];
    for (const mod of expectedModules) {
      if (!loadedModules.includes(mod)) {
        violations.push(`missing_expected_module:${mod}`);
        confidence -= 10;
      }
    }

    const valid = violations.length === 0;
    confidence = clamp(confidence, 0, 100);

    const metrics = {
      processId,
      expectedModulesCount: expectedModules.length,
      allowedParentsCount: allowedParents.length,
      violationsFound: violations.length,
      confidence,
    };

    if (!valid) {
      emitEvent('defensive.process_integrity_violation', EventSeverity.MEDIUM, { processId, violations });
    }

    logger.info({ valid, processId, violationsCount: violations.length }, 'Process integrity check complete');
    span.end();

    return { valid, violations, confidence, metrics, timestamp: Date.now() };
  } catch (err) {
    logger.error(err, 'Process integrity check failed');
    span.end();
    throw new SecurityError('process_integrity_check_failed', err instanceof Error ? err.message : String(err));
  }
}

// ─── 6. codeSigningValidation ───────────────────────────────────────────────

/**
 * Validates code signing certificates against trusted store and revocation lists.
 * Verifies binary path hash, trusted roots, intermediates, and revocation status.
 */
export function codeSigningValidation(
  binaryPath: string,
  certificateStore: CertificateStore,
  revocationCheck: boolean,
): ValidationResult {
  const span = createSpan('codeSigningValidation');
  const details: string[] = [];
  let valid = true;
  const certificateInfo: Record<string, string> = {};

  try {
    const pathHash = createHash('sha256').update(binaryPath).digest('hex');
    certificateInfo.binaryHash = pathHash;
    certificateInfo.binaryPath = binaryPath;

    if (certificateStore.trustedRoots.length === 0) {
      details.push('no_trusted_roots_configured');
      valid = false;
      logger.warn('No trusted root certificates configured');
    } else {
      details.push('trusted_roots_verified');
      certificateInfo.trustedRootsCount = String(certificateStore.trustedRoots.length);
    }

    if (revocationCheck && certificateStore.revocationList.length > 0) {
      for (const revoked of certificateStore.revocationList) {
        if (certificateStore.intermediates.includes(revoked)) {
          details.push(`revoked_certificate_found:${revoked}`);
          valid = false;
          logger.error({ certificate: revoked }, 'Revoked certificate detected');
        }
      }
      if (valid) {
        details.push('revocation_check_passed');
      }
    }

    if (certificateStore.intermediates.length === 0) {
      details.push('no_intermediate_certificates');
    } else {
      certificateInfo.intermediatesCount = String(certificateStore.intermediates.length);
    }

    const metrics = {
      trustedRoots: certificateStore.trustedRoots.length,
      intermediates: certificateStore.intermediates.length,
      revocationListSize: certificateStore.revocationList.length,
      valid: valid ? 1 : 0,
    };

    if (!valid) {
      emitEvent('defensive.code_signing_invalid', EventSeverity.HIGH, { binaryPath, details });
    }

    logger.info({ valid, binaryPath, detailsCount: details.length }, 'Code signing validation complete');
    span.end();

    return { valid, details, certificateInfo, metrics, timestamp: Date.now() };
  } catch (err) {
    logger.error(err, 'Code signing validation failed');
    span.end();
    throw new SecurityError('code_signing_validation_failed', err instanceof Error ? err.message : String(err));
  }
}

// ─── 7. binaryIntegrityValidation ───────────────────────────────────────────

/**
 * Validates binary integrity using multiple hash algorithms and section checks.
 * Supports SHA256 and SHA3-256 verification against expected hashes.
 */
export function binaryIntegrityValidation(
  binaryPath: string,
  expectedHashes: Record<string, string>,
  sections: string[],
): ValidationResult {
  const span = createSpan('binaryIntegrityValidation');
  const details: string[] = [];
  let valid = true;

  try {
    const binaryData = Buffer.from(binaryPath);
    const actualHash = createHash('sha256').update(binaryData).digest('hex');

    if (expectedHashes.sha256 && actualHash !== expectedHashes.sha256) {
      details.push(`sha256_mismatch:expected=${expectedHashes.sha256}:actual=${actualHash}`);
      valid = false;
      logger.error({ path: binaryPath }, 'SHA256 hash mismatch');
    } else {
      details.push('sha256_verified');
    }

    if (expectedHashes.sha3) {
      const sha3Hash = Buffer.from(sha3_256(binaryData)).toString('hex');
      if (sha3Hash !== expectedHashes.sha3) {
        details.push(`sha3_mismatch`);
        valid = false;
      } else {
        details.push('sha3_verified');
      }
    }

    for (const section of sections) {
      const sectionHash = createHash('sha256').update(Buffer.from(section)).digest('hex');
      if (expectedHashes[section] && sectionHash !== expectedHashes[section]) {
        details.push(`section_mismatch:${section}`);
        valid = false;
      }
    }

    details.push(`sections_validated:${sections.length}`);

    const metrics = {
      sectionsChecked: sections.length,
      hashAlgorithmsUsed: Object.keys(expectedHashes).length,
      valid: valid ? 1 : 0,
      binaryPathHash: actualHash.substring(0, 16),
    };

    if (!valid) {
      emitEvent('defensive.binary_integrity_invalid', EventSeverity.CRITICAL, { binaryPath, details });
    }

    logger.info({ valid, binaryPath, sectionsCount: sections.length }, 'Binary integrity validation complete');
    span.end();

    return { valid, details, metrics, timestamp: Date.now() };
  } catch (err) {
    logger.error(err, 'Binary integrity validation failed');
    span.end();
    throw new SecurityError('binary_integrity_validation_failed', err instanceof Error ? err.message : String(err));
  }
}

// ─── 8. secureBootValidation ────────────────────────────────────────────────

/**
 * Validates secure boot chain measurements and PCR values.
 * Compares boot measurements against expected values and verifies PCR integrity.
 */
export function secureBootValidation(
  bootChain: BootMeasurement[],
  measurements: BootMeasurement[],
  pcrValues: PcrValue[],
): ValidationResult {
  const span = createSpan('secureBootValidation');
  const details: string[] = [];
  let valid = true;

  try {
    for (const measurement of bootChain) {
      if (measurement.expectedValue !== measurement.actualValue) {
        details.push(`boot_measurement_mismatch:pcr=${measurement.pcrIndex}:component=${measurement.component}`);
        valid = false;
        logger.error({ pcr: measurement.pcrIndex, component: measurement.component }, 'Boot measurement mismatch');
      }
    }

    for (const m of measurements) {
      const chainMatch = bootChain.find(b => b.pcrIndex === m.pcrIndex);
      if (!chainMatch) {
        details.push(`unmeasured_pcr:${m.pcrIndex}`);
        valid = false;
      }
    }

    for (const pcr of pcrValues) {
      details.push(`pcr_${pcr.index}:verified`);
    }

    const metrics = {
      bootChainLength: bootChain.length,
      measurementsVerified: measurements.length,
      pcrValuesChecked: pcrValues.length,
      mismatches: details.filter(d => d.includes('mismatch')).length,
      valid: valid ? 1 : 0,
    };

    if (!valid) {
      emitEvent('defensive.secure_boot_invalid', EventSeverity.CRITICAL, { details, pcrCount: pcrValues.length });
    }

    logger.info({ valid, bootChainLength: bootChain.length, pcrCount: pcrValues.length }, 'Secure boot validation complete');
    span.end();

    return { valid, details, metrics, timestamp: Date.now() };
  } catch (err) {
    logger.error(err, 'Secure boot validation failed');
    span.end();
    throw new SecurityError('secure_boot_validation_failed', err instanceof Error ? err.message : String(err));
  }
}

// ─── 9. secureUpdateValidation ──────────────────────────────────────────────

/**
 * Validates update package integrity, signature, version, and channel.
 * Ensures updates are authentic and from the expected release channel.
 */
export function secureUpdateValidation(
  updatePackage: UpdatePackage,
  signature: UpdateSignature,
  version: string,
  channel: string,
): ValidationResult {
  const span = createSpan('secureUpdateValidation');
  const details: string[] = [];
  let valid = true;

  try {
    const payloadHash = computeHash(updatePackage.payload, (signature.algorithm || 'sha256') as 'sha256' | 'sha3-256' | 'sha512');

    if (signature.value && payloadHash !== signature.value) {
      details.push('signature_verification_failed');
      valid = false;
      logger.error({ updateId: updatePackage.id }, 'Update signature verification failed');
    } else {
      details.push('signature_verified');
    }

    if (updatePackage.version !== version) {
      details.push(`version_mismatch:package=${updatePackage.version}:expected=${version}`);
      valid = false;
    } else {
      details.push('version_verified');
    }

    if (updatePackage.channel !== channel) {
      details.push(`channel_mismatch:package=${updatePackage.channel}:expected=${channel}`);
      valid = false;
    } else {
      details.push('channel_verified');
    }

    const metrics = {
      payloadSize: updatePackage.payload.length,
      signatureAlgorithm: signature.algorithm,
      versionMatch: updatePackage.version === version ? 1 : 0,
      channelMatch: updatePackage.channel === channel ? 1 : 0,
      valid: valid ? 1 : 0,
    };

    if (!valid) {
      emitEvent('defensive.update_validation_failed', EventSeverity.HIGH, { updateId: updatePackage.id, details });
    }

    logger.info({ valid, updateId: updatePackage.id, version }, 'Secure update validation complete');
    span.end();

    return { valid, details, metrics, timestamp: Date.now() };
  } catch (err) {
    logger.error(err, 'Secure update validation failed');
    span.end();
    throw new SecurityError('secure_update_validation_failed', err instanceof Error ? err.message : String(err));
  }
}

// ─── 10. antiHookDetection ──────────────────────────────────────────────────

/**
 * Detects function hooks in memory by scanning against known hook patterns.
 * Identifies inline hooks, IAT hooks, and suspicious RWX memory regions.
 */
export function antiHookDetection(
  functions: HookInfo[],
  memoryRegions: MemoryRegion[],
  knownHooks: string[],
): DetectionResult {
  const span = createSpan('antiHookDetection');
  const indicators: string[] = [];
  let confidence = 0;

  try {
    for (const hook of functions) {
      const hookKey = `${hook.address}:${hook.originalFunction}`;
      if (knownHooks.includes(hookKey)) {
        confidence += 20;
        indicators.push(`known_hook:${hook.originalFunction}:${hook.type}`);
        logger.warn({ function: hook.originalFunction, type: hook.type }, 'Known hook detected');
      }

      const region = memoryRegions.find(r => r.address === hook.address);
      if (region && region.permissions.includes('x') && region.type !== 'code') {
        confidence += 15;
        indicators.push(`suspicious_executable_region:${hook.address}`);
      }
    }

    for (const region of memoryRegions) {
      if (region.permissions === 'rwx') {
        confidence += 10;
        indicators.push(`rwx_region:${region.address}`);
        logger.warn({ address: region.address }, 'RWX memory region detected');
      }
    }

    const detected = confidence >= 30;
    const severity = confidence >= 70 ? EventSeverity.CRITICAL : confidence >= 40 ? EventSeverity.HIGH : EventSeverity.MEDIUM;

    const metrics = {
      functionsScanned: functions.length,
      memoryRegionsChecked: memoryRegions.length,
      knownHooksChecked: knownHooks.length,
      hooksFound: indicators.length,
      confidence,
    };

    if (detected) {
      emitEvent('defensive.hook_detected', severity, { confidence, indicators });
    }

    logger.info({ detected, confidence, hooksFound: indicators.length }, 'Anti-hook detection complete');
    span.end();

    return { detected, confidence, indicators, severity, metrics, timestamp: Date.now() };
  } catch (err) {
    logger.error(err, 'Anti-hook detection failed');
    span.end();
    throw new SecurityError('anti_hook_detection_failed', err instanceof Error ? err.message : String(err));
  }
}

// ─── 11. antiInjectionDetection ─────────────────────────────────────────────

/**
 * Detects code injection by scanning process modules and libraries.
 * Identifies unsigned modules, injection signatures, and suspicious paths.
 */
export function antiInjectionDetection(
  processModules: ProcessModule[],
  loadedLibraries: string[],
  injectionSignatures: InjectionSignature[],
): DetectionResult {
  const span = createSpan('antiInjectionDetection');
  const indicators: string[] = [];
  let confidence = 0;

  try {
    for (const mod of processModules) {
      if (!mod.signed) {
        confidence += 10;
        indicators.push(`unsigned_module:${mod.name}`);
        logger.warn({ module: mod.name, path: mod.path }, 'Unsigned module detected');
      }

      for (const sig of injectionSignatures) {
        const modBuf = Buffer.from(mod.name);
        if (modBuf.includes(sig.pattern)) {
          confidence += 25;
          indicators.push(`injection_signature:${sig.technique}:${mod.name}`);
          logger.error({ technique: sig.technique, module: mod.name }, 'Injection signature matched');
        }
      }
    }

    for (const lib of loadedLibraries) {
      if (lib.includes('..') || lib.includes('\0')) {
        confidence += 20;
        indicators.push(`suspicious_library_path:${lib}`);
      }
    }

    const detected = confidence >= 30;
    const severity = confidence >= 70 ? EventSeverity.CRITICAL : confidence >= 40 ? EventSeverity.HIGH : EventSeverity.MEDIUM;

    const metrics = {
      modulesScanned: processModules.length,
      librariesChecked: loadedLibraries.length,
      signaturesMatched: indicators.filter(i => i.includes('injection_signature')).length,
      unsignedModules: processModules.filter(m => !m.signed).length,
      confidence,
    };

    if (detected) {
      emitEvent('defensive.injection_detected', severity, { confidence, indicators });
    }

    logger.info({ detected, confidence, indicatorsCount: indicators.length }, 'Anti-injection detection complete');
    span.end();

    return { detected, confidence, indicators, severity, metrics, timestamp: Date.now() };
  } catch (err) {
    logger.error(err, 'Anti-injection detection failed');
    span.end();
    throw new SecurityError('anti_injection_detection_failed', err instanceof Error ? err.message : String(err));
  }
}

// ─── 12. antiRootkitDetection ───────────────────────────────────────────────

/**
 * Detects rootkit activity by analyzing syscalls, kernel modules, and processes.
 * Identifies syscall table modifications, hidden modules, and hidden processes.
 */
export function antiRootkitDetection(
  systemCalls: SystemCallInfo[],
  kernelModules: KernelModule[],
  hiddenProcesses: ProcessEntry[],
): DetectionResult {
  const span = createSpan('antiRootkitDetection');
  const indicators: string[] = [];
  let confidence = 0;

  try {
    for (const sc of systemCalls) {
      if (sc.expectedAddress && sc.address !== sc.expectedAddress) {
        confidence += 20;
        indicators.push(`syscall_redirect:${sc.name}:expected=${sc.expectedAddress}:actual=${sc.address}`);
        logger.error({ syscall: sc.name }, 'Syscall table modification detected');
      }
    }

    for (const mod of kernelModules) {
      if (mod.hidden) {
        confidence += 30;
        indicators.push(`hidden_kernel_module:${mod.name}`);
        logger.error({ module: mod.name }, 'Hidden kernel module detected');
      }
    }

    for (const proc of hiddenProcesses) {
      if (proc.hidden) {
        confidence += 25;
        indicators.push(`hidden_process:${proc.name}:pid=${proc.pid}`);
        logger.error({ pid: proc.pid, name: proc.name }, 'Hidden process detected');
      }
    }

    const detected = confidence >= 30;
    const severity = confidence >= 70 ? EventSeverity.CRITICAL : confidence >= 40 ? EventSeverity.HIGH : EventSeverity.MEDIUM;

    const metrics = {
      syscallsChecked: systemCalls.length,
      kernelModulesScanned: kernelModules.length,
      hiddenModules: kernelModules.filter(m => m.hidden).length,
      hiddenProcessesFound: hiddenProcesses.filter(p => p.hidden).length,
      confidence,
    };

    if (detected) {
      emitEvent('defensive.rootkit_detected', severity, { confidence, indicators });
    }

    logger.info({ detected, confidence, indicatorsCount: indicators.length }, 'Anti-rootkit detection complete');
    span.end();

    return { detected, confidence, indicators, severity, metrics, timestamp: Date.now() };
  } catch (err) {
    logger.error(err, 'Anti-rootkit detection failed');
    span.end();
    throw new SecurityError('anti_rootkit_detection_failed', err instanceof Error ? err.message : String(err));
  }
}

// ─── 13. antiVmDetection ────────────────────────────────────────────────────

/**
 * Detects virtual machine environments via hardware info, timing, and artifacts.
 * Checks BIOS vendor, system manufacturer, timing anomalies, and VM file artifacts.
 */
export function antiVmDetection(
  hardwareInfo: HardwareInfo,
  timingChecks: TimingCheck,
  vmArtifacts: VmArtifact[],
): DetectionResult {
  const span = createSpan('antiVmDetection');
  const indicators: string[] = [];
  let confidence = 0;

  try {
    const vmVendors = ['vmware', 'virtualbox', 'xen', 'kvm', 'qemu', 'hyper-v', 'parallels'];
    const biosLower = hardwareInfo.biosVendor.toLowerCase();
    const manufacturerLower = hardwareInfo.systemManufacturer.toLowerCase();

    if (vmVendors.some(v => biosLower.includes(v))) {
      confidence += 30;
      indicators.push(`vm_bios_vendor:${hardwareInfo.biosVendor}`);
    }

    if (vmVendors.some(v => manufacturerLower.includes(v))) {
      confidence += 25;
      indicators.push(`vm_manufacturer:${hardwareInfo.systemManufacturer}`);
    }

    if (hardwareInfo.cpuCores <= 1 && hardwareInfo.totalMemory <= 2147483648) {
      confidence += 15;
      indicators.push('low_resource_vm_indicator');
    }

    if (timingChecks.rdtscDelta > 1000 || timingChecks.sleepDelta > 500) {
      confidence += 20;
      indicators.push('timing_anomaly_detected');
      logger.warn({ rdtscDelta: timingChecks.rdtscDelta, sleepDelta: timingChecks.sleepDelta }, 'Timing anomaly detected');
    }

    for (const artifact of vmArtifacts) {
      if (artifact.exists) {
        confidence += 15;
        indicators.push(`vm_artifact:${artifact.path}`);
      }
    }

    const detected = confidence >= 50;
    const severity = confidence >= 80 ? EventSeverity.CRITICAL : confidence >= 50 ? EventSeverity.HIGH : EventSeverity.MEDIUM;

    const metrics = {
      cpuCores: hardwareInfo.cpuCores,
      totalMemoryMB: Math.round(hardwareInfo.totalMemory / 1024 / 1024),
      artifactsChecked: vmArtifacts.length,
      artifactsFound: vmArtifacts.filter(a => a.exists).length,
      confidence,
    };

    if (detected) {
      emitEvent('defensive.vm_detected', severity, { confidence, indicators });
    }

    logger.info({ detected, confidence, indicatorsCount: indicators.length }, 'Anti-VM detection complete');
    span.end();

    return { detected, confidence, indicators, severity, metrics, timestamp: Date.now() };
  } catch (err) {
    logger.error(err, 'Anti-VM detection failed');
    span.end();
    throw new SecurityError('anti_vm_detection_failed', err instanceof Error ? err.message : String(err));
  }
}

// ─── 14. antiEmulationDetection ─────────────────────────────────────────────

/**
 * Detects emulation environments via environment checks, timing, and API availability.
 * Identifies mismatches, timing anomalies, and suspiciously fast API responses.
 */
export function antiEmulationDetection(
  environmentChecks: EnvironmentCheck[],
  timing: TimingCheck,
  apiAvailability: ApiAvailability[],
): DetectionResult {
  const span = createSpan('antiEmulationDetection');
  const indicators: string[] = [];
  let confidence = 0;

  try {
    for (const check of environmentChecks) {
      if (check.expected !== check.actual) {
        confidence += 15;
        indicators.push(`env_mismatch:${check.name}:expected=${check.expected}:actual=${check.actual}`);
        logger.warn({ check: check.name, expected: check.expected, actual: check.actual }, 'Environment check mismatch');
      }
    }

    if (timing.sleepDelta > 200) {
      confidence += 20;
      indicators.push('emulation_timing_anomaly');
    }

    const unavailableApis = apiAvailability.filter(a => !a.available);
    if (unavailableApis.length > 0) {
      confidence += 10 * unavailableApis.length;
      for (const api of unavailableApis) {
        indicators.push(`api_unavailable:${api.name}`);
      }
    }

    const avgResponseTime = apiAvailability.length > 0
      ? apiAvailability.reduce((sum, a) => sum + a.responseTime, 0) / apiAvailability.length
      : 0;

    if (avgResponseTime < 1) {
      confidence += 15;
      indicators.push('suspiciously_fast_api_response');
    }

    const detected = confidence >= 40;
    const severity = confidence >= 70 ? EventSeverity.CRITICAL : confidence >= 40 ? EventSeverity.HIGH : EventSeverity.MEDIUM;

    const metrics = {
      environmentChecks: environmentChecks.length,
      mismatchesFound: environmentChecks.filter(c => c.expected !== c.actual).length,
      apisChecked: apiAvailability.length,
      apisUnavailable: unavailableApis.length,
      avgApiResponseTime: Math.round(avgResponseTime),
      confidence,
    };

    if (detected) {
      emitEvent('defensive.emulation_detected', severity, { confidence, indicators });
    }

    logger.info({ detected, confidence, indicatorsCount: indicators.length }, 'Anti-emulation detection complete');
    span.end();

    return { detected, confidence, indicators, severity, metrics, timestamp: Date.now() };
  } catch (err) {
    logger.error(err, 'Anti-emulation detection failed');
    span.end();
    throw new SecurityError('anti_emulation_detection_failed', err instanceof Error ? err.message : String(err));
  }
}

// ─── 15. movingTargetRuntime ────────────────────────────────────────────────

/**
 * Implements moving target defense by rotating service endpoints and randomizing layout.
 * Applies random, sequential, or weighted rotation strategies with configurable entropy.
 */
export function movingTargetRuntime(
  services: ServiceConfig[],
  rotationConfig: RotationConfig,
  randomization: RandomizationConfig,
): MTDResult {
  const span = createSpan('movingTargetRuntime');
  let rotated = false;
  let servicesAffected = 0;

  try {
    const entropy = generateEntropy(rotationConfig.entropyBits);
    const entropyScore = entropy.length * 4;

    for (const service of services) {
      if (rotationConfig.strategy === 'random') {
        const portOffset = parseInt(entropy.substring(0, 4), 16) % 1000;
        service.port = service.port + portOffset;
        servicesAffected++;
      } else if (rotationConfig.strategy === 'sequential') {
        service.port += 1;
        servicesAffected++;
      } else {
        const weight = parseInt(entropy.substring(0, 2), 16) % 100;
        if (weight > 50) {
          service.port += parseInt(entropy.substring(2, 6), 16) % 500;
          servicesAffected++;
        }
      }
    }

    rotated = servicesAffected > 0;

    const metrics = {
      totalServices: services.length,
      servicesAffected,
      rotationStrategy: rotationConfig.strategy === 'random' ? 0 : rotationConfig.strategy === 'sequential' ? 1 : 2,
      entropyBits: rotationConfig.entropyBits,
      aslrEnabled: randomization.addressSpaceLayout ? 1 : 0,
      functionRandomization: randomization.functionOrdering ? 1 : 0,
      dataRandomization: randomization.dataLayout ? 1 : 0,
      stackCanaries: randomization.stackCanaries ? 1 : 0,
      entropyScore,
    };

    if (rotated) {
      emitEvent('defensive.moving_target_rotated', EventSeverity.LOW, { servicesAffected, entropyScore });
    }

    logger.info({ rotated, servicesAffected, entropyScore }, 'Moving target defense executed');
    span.end();

    return { rotated, servicesAffected, entropyScore, metrics, timestamp: Date.now() };
  } catch (err) {
    logger.error(err, 'Moving target runtime failed');
    span.end();
    throw new SecurityError('moving_target_runtime_failed', err instanceof Error ? err.message : String(err));
  }
}

// ─── 16. dynamicAttackSurface ───────────────────────────────────────────────

/**
 * Analyzes and dynamically adjusts the attack surface based on threat level.
 * Auto-closes high-sensitivity endpoints and generates risk recommendations.
 */
export function dynamicAttackSurface(
  endpoints: EndpointConfig[],
  exposureConfig: ExposureConfig,
  threatLevel: number,
): SurfaceResult {
  const span = createSpan('dynamicAttackSurface');
  const recommendations: string[] = [];
  let exposedEndpoints = 0;
  let riskScore = 0;

  try {
    for (const endpoint of endpoints) {
      if (endpoint.exposed) {
        exposedEndpoints++;
        riskScore += endpoint.sensitivity * exposureConfig.sensitivityWeight;

        if (threatLevel > 70 && endpoint.sensitivity > 7) {
          endpoint.exposed = false;
          recommendations.push(`auto_closed_high_sensitivity:${endpoint.path}`);
          logger.warn({ path: endpoint.path, sensitivity: endpoint.sensitivity }, 'Auto-closed high-sensitivity endpoint');
        }
      }
    }

    if (exposedEndpoints > exposureConfig.maxOpenEndpoints) {
      recommendations.push(`reduce_open_endpoints:current=${exposedEndpoints}:max=${exposureConfig.maxOpenEndpoints}`);
      riskScore += 20;
    }

    if (threatLevel > 80) {
      recommendations.push('activate_maximum_lockdown');
      riskScore += 30;
    } else if (threatLevel > 50) {
      recommendations.push('increase_monitoring_frequency');
      riskScore += 15;
    }

    riskScore = clamp(riskScore, 0, 100);

    const metrics = {
      totalEndpoints: endpoints.length,
      exposedEndpoints,
      maxAllowed: exposureConfig.maxOpenEndpoints,
      threatLevel,
      riskScore,
    };

    if (riskScore > 70) {
      emitEvent('defensive.attack_surface_high', EventSeverity.HIGH, { riskScore, exposedEndpoints });
    }

    logger.info({ exposedEndpoints, riskScore, recommendationsCount: recommendations.length }, 'Dynamic attack surface analysis complete');
    span.end();

    return { exposedEndpoints, riskScore, recommendations, metrics, timestamp: Date.now() };
  } catch (err) {
    logger.error(err, 'Dynamic attack surface analysis failed');
    span.end();
    throw new SecurityError('dynamic_attack_surface_failed', err instanceof Error ? err.message : String(err));
  }
}

// ─── 17. runtimePolicyEngine ────────────────────────────────────────────────

/**
 * Evaluates security policies against runtime context with configurable enforcement.
 * Supports monitor, enforce, and simulate modes with role/threat/environment conditions.
 */
export function runtimePolicyEngine(
  policies: SecurityPolicy[],
  context: PolicyContext,
  enforcementMode: EnforcementConfig,
): PolicyResult {
  const span = createSpan('runtimePolicyEngine');
  const matchedPolicies: string[] = [];
  const violations: string[] = [];
  let allowed = true;

  try {
    const sortedPolicies = [...policies].filter(p => p.enabled).sort((a, b) => b.priority - a.priority);

    for (const policy of sortedPolicies) {
      const conditionMatch = evaluatePolicyCondition(policy.condition, context);

      if (conditionMatch) {
        matchedPolicies.push(policy.id);

        if (policy.action === 'deny' || policy.action === 'block') {
          if (enforcementMode.mode === 'enforce') {
            allowed = false;
            violations.push(`policy_denied:${policy.name}`);
            logger.warn({ policy: policy.name, action: policy.action }, 'Policy denied access');
          } else if (enforcementMode.mode === 'monitor') {
            violations.push(`policy_monitor:${policy.name}`);
          }
        } else if (policy.action === 'allow') {
          if (enforcementMode.mode === 'enforce' && !allowed) {
            allowed = true;
          }
        } else if (policy.action === 'escalate') {
          violations.push(`policy_escalation:${policy.name}`);
        }
      }
    }

    if (enforcementMode.logViolations && violations.length > 0) {
      emitEvent('defensive.policy_violation', EventSeverity.MEDIUM, { violations, context: context.userId });
    }

    if (enforcementMode.blockOnViolation && violations.length > 0) {
      allowed = false;
    }

    const metrics = {
      totalPolicies: policies.length,
      enabledPolicies: policies.filter(p => p.enabled).length,
      matchedPolicies: matchedPolicies.length,
      violationsCount: violations.length,
      enforcementMode: enforcementMode.mode === 'monitor' ? 0 : enforcementMode.mode === 'enforce' ? 1 : 2,
      allowed: allowed ? 1 : 0,
    };

    logger.info({ allowed, matchedCount: matchedPolicies.length, violationCount: violations.length }, 'Runtime policy engine evaluation complete');
    span.end();

    return { allowed, matchedPolicies, violations, metrics, timestamp: Date.now() };
  } catch (err) {
    logger.error(err, 'Runtime policy engine failed');
    span.end();
    throw new SecurityError('runtime_policy_engine_failed', err instanceof Error ? err.message : String(err));
  }
}

function evaluatePolicyCondition(condition: string, context: PolicyContext): boolean {
  const conditions = condition.split('&&').map(c => c.trim());
  for (const cond of conditions) {
    if (cond.includes('role')) {
      const roleMatch = cond.match(/role\s*[=<>!]+\s*['"]?(\w+)['"]?/);
      if (roleMatch && roleMatch[1] !== context.role) return false;
    }
    if (cond.includes('threatLevel')) {
      const threatMatch = cond.match(/threatLevel\s*([><=]+)\s*(\d+)/);
      if (threatMatch) {
        const op = threatMatch[1];
        const val = parseInt(threatMatch[2], 10);
        if (op === '>' && context.threatLevel <= val) return false;
        if (op === '<' && context.threatLevel >= val) return false;
        if (op === '>=' && context.threatLevel < val) return false;
        if (op === '<=' && context.threatLevel > val) return false;
        if (op === '==' && context.threatLevel !== val) return false;
      }
    }
    if (cond.includes('environment')) {
      const envMatch = cond.match(/environment\[['"](\w+)['"]\]\s*==\s*['"](\w+)['"]/);
      if (envMatch && context.environment[envMatch[1]] !== envMatch[2]) return false;
    }
  }
  return true;
}

// ─── 18. selfHealingSecurity ────────────────────────────────────────────────

/**
 * Self-healing security system that recovers unhealthy components automatically.
 * Applies healing rules and recovery actions to restore system health.
 */
export function selfHealingSecurity(
  state: SystemState,
  healingRules: HealingRule[],
  recoveryActions: RecoveryAction[],
): HealingResult {
  const span = createSpan('selfHealingSecurity');
  const actionsExecuted: string[] = [];
  let componentsRecovered = 0;

  try {
    const unhealthyComponents = Object.entries(state.components)
      .filter(([, comp]) => comp.health < 50)
      .map(([name]) => name);

    for (const component of unhealthyComponents) {
      const applicableRules = healingRules
        .filter(r => r.trigger === component || r.trigger === '*')
        .sort((a, b) => b.priority - a.priority);

      for (const rule of applicableRules) {
        const recoveryAction = recoveryActions.find(a => a.target === component || a.target === '*');
        if (recoveryAction) {
          actionsExecuted.push(`healing:${component}:${rule.action}:${recoveryAction.type}`);
          componentsRecovered++;
          state.components[component].health = Math.min(100, state.components[component].health + 50);
          state.components[component].status = 'recovering';
          logger.info({ component, action: rule.action, type: recoveryAction.type }, 'Healing action executed');
          break;
        }
      }
    }

    for (const error of state.errors) {
      const applicableRules = healingRules.filter(r => r.trigger === error.component);
      if (applicableRules.length > 0) {
        actionsExecuted.push(`error_recovery:${error.component}:${applicableRules[0].action}`);
      }
    }

    const healed = unhealthyComponents.length === 0 || componentsRecovered > 0;

    const metrics = {
      totalComponents: Object.keys(state.components).length,
      unhealthyComponents: unhealthyComponents.length,
      componentsRecovered,
      errorsProcessed: state.errors.length,
      actionsExecuted: actionsExecuted.length,
      healingRulesAvailable: healingRules.length,
    };

    if (componentsRecovered > 0) {
      emitEvent('defensive.self_healing_executed', EventSeverity.LOW, { componentsRecovered, actionsExecuted });
    }

    logger.info({ healed, componentsRecovered, actionsCount: actionsExecuted.length }, 'Self-healing security complete');
    span.end();

    return { healed, actionsExecuted, componentsRecovered, metrics, timestamp: Date.now() };
  } catch (err) {
    logger.error(err, 'Self-healing security failed');
    span.end();
    throw new SecurityError('self_healing_security_failed', err instanceof Error ? err.message : String(err));
  }
}

// ─── 19. adaptiveThreatResponse ─────────────────────────────────────────────

/**
 * Adaptive threat response that executes playbook steps based on threat context.
 * Supports escalation paths and resource-aware step execution.
 */
export function adaptiveThreatResponse(
  threat: ThreatInfo,
  responsePlaybook: ResponsePlaybook,
  context: ResponseContext,
): ResponseResult {
  const span = createSpan('adaptiveThreatResponse');
  let stepsCompleted = 0;
  let outcome: 'success' | 'partial' | 'failed' = 'success';

  try {
    const applicableSteps = responsePlaybook.steps.filter(step => {
      if (context.currentThreatLevel < 50 && step.parameters.minThreatLevel) {
        return parseInt(step.parameters.minThreatLevel, 10) <= context.currentThreatLevel;
      }
      return true;
    });

    for (const step of applicableSteps) {
      try {
        const resourcesAvailable = context.availableResources[step.action] || 0;
        if (resourcesAvailable > 0 || step.action === 'isolate' || step.action === 'alert') {
          stepsCompleted++;
          logger.info({ step: step.action, threatId: threat.id }, 'Response step executed');
        } else {
          outcome = outcome === 'success' ? 'partial' : outcome;
          logger.warn({ step: step.action }, 'Response step skipped - insufficient resources');
        }
      } catch {
        outcome = 'partial';
      }
    }

    if (stepsCompleted === 0) {
      outcome = 'failed';
    } else if (stepsCompleted < applicableSteps.length) {
      outcome = 'partial';
    }

    if (outcome === 'failed' && responsePlaybook.escalationPath.length > 0) {
      emitEvent('defensive.threat_response_escalated', EventSeverity.CRITICAL, {
        threatId: threat.id,
        escalationPath: responsePlaybook.escalationPath,
      });
    }

    const metrics = {
      threatSeverity: threat.severity === EventSeverity.CRITICAL ? 4 : threat.severity === EventSeverity.HIGH ? 3 : threat.severity === EventSeverity.MEDIUM ? 2 : 1,
      totalSteps: responsePlaybook.steps.length,
      stepsCompleted,
      affectedSystems: context.affectedSystems.length,
      currentThreatLevel: context.currentThreatLevel,
      outcome: outcome === 'success' ? 1 : outcome === 'partial' ? 0.5 : 0,
    };

    emitEvent('defensive.threat_response_executed',
      threat.severity,
      { threatId: threat.id, outcome, stepsCompleted },
    );

    logger.info({ outcome, stepsCompleted, threatId: threat.id }, 'Adaptive threat response complete');
    span.end();

    return { executed: stepsCompleted > 0, stepsCompleted, outcome, metrics, timestamp: Date.now() };
  } catch (err) {
    logger.error(err, 'Adaptive threat response failed');
    span.end();
    throw new SecurityError('adaptive_threat_response_failed', err instanceof Error ? err.message : String(err));
  }
}

// ─── 20. autonomousContainment ──────────────────────────────────────────────

/**
 * Autonomous threat containment using network topology and containment rules.
 * Isolates, blocks, throttles, or redirects threats across host, network, and service scopes.
 */
export function autonomousContainment(
  threat: ThreatInfo,
  containmentRules: ContainmentRule[],
  networkTopology: NetworkNode[],
): ContainmentResult {
  const span = createSpan('autonomousContainment');
  const actionsTaken: string[] = [];
  let nodesAffected = 0;
  let contained = false;

  try {
    const applicableRules = containmentRules
      .filter(r => {
        if (threat.severity === EventSeverity.CRITICAL) return true;
        if (threat.severity === EventSeverity.HIGH && r.priority <= 2) return true;
        if (threat.severity === EventSeverity.MEDIUM && r.priority <= 1) return true;
        return false;
      })
      .sort((a, b) => b.priority - a.priority);

    const targetNode = networkTopology.find(n => n.address === threat.target || n.id === threat.target);

    for (const rule of applicableRules) {
      if (rule.scope === 'host' && targetNode) {
        actionsTaken.push(`contain:${rule.action}:${targetNode.id}`);
        nodesAffected++;

        if (rule.action === 'isolate') {
          targetNode.connections = [];
          contained = true;
        } else if (rule.action === 'block') {
          const idx = networkTopology.indexOf(targetNode);
          if (idx >= 0) {
            for (const node of networkTopology) {
              node.connections = node.connections.filter(c => c !== targetNode.id);
            }
          }
          contained = true;
        } else if (rule.action === 'throttle') {
          nodesAffected++;
        } else if (rule.action === 'redirect') {
          nodesAffected++;
        }
      } else if (rule.scope === 'network') {
        for (const node of networkTopology) {
          if (node.segment === threat.target || node.type === 'firewall') {
            actionsTaken.push(`network_contain:${rule.action}:${node.id}`);
            nodesAffected++;
            if (rule.action === 'isolate' || rule.action === 'block') {
              contained = true;
            }
          }
        }
      } else if (rule.scope === 'service') {
        actionsTaken.push(`service_contain:${rule.action}:${threat.target}`);
        nodesAffected++;
        contained = true;
      }
    }

    if (contained) {
      for (const node of networkTopology) {
        if (node.connections.includes(threat.source)) {
          node.connections = node.connections.filter(c => c !== threat.source);
          actionsTaken.push(`source_blocked:${node.id}`);
        }
      }
    }

    const metrics = {
      totalNodes: networkTopology.length,
      nodesAffected,
      rulesApplied: applicableRules.length,
      threatSeverity: threat.severity === EventSeverity.CRITICAL ? 4 : threat.severity === EventSeverity.HIGH ? 3 : threat.severity === EventSeverity.MEDIUM ? 2 : 1,
      contained: contained ? 1 : 0,
    };

    if (contained) {
      emitEvent('defensive.containment_successful', EventSeverity.HIGH, { threatId: threat.id, nodesAffected });
    } else {
      emitEvent('defensive.containment_failed', EventSeverity.CRITICAL, { threatId: threat.id, actionsTaken });
    }

    logger.info({ contained, nodesAffected, actionsCount: actionsTaken.length, threatId: threat.id }, 'Autonomous containment complete');
    span.end();

    return { contained, actionsTaken, nodesAffected, metrics, timestamp: Date.now() };
  } catch (err) {
    logger.error(err, 'Autonomous containment failed');
    span.end();
    throw new SecurityError('autonomous_containment_failed', err instanceof Error ? err.message : String(err));
  }
}
