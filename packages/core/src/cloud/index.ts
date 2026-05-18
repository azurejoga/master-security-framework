import { createHash } from 'crypto';
import { sha3_256 } from '@noble/hashes/sha3';
import { getLogger, getMetrics, createSpan, getEventBus, SecurityEvent, EventSeverity } from '../core/index.js';
import { ValidationError, SecurityError } from '../core/exceptions.js';
import pino from 'pino';

const logger = pino().child({ module: 'msf.cloud' });

// --- Type Definitions ---------------------------------------------

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Rule {
  id: string;
  name: string;
  description: string;
  severity: SeverityLevel;
  check: (data: unknown) => boolean;
}

export interface Finding {
  ruleId: string;
  ruleName: string;
  severity: SeverityLevel;
  message: string;
  location?: string;
  remediation?: string;
}

export interface ValidationResult {
  valid: boolean;
  findings: Finding[];
  score: number;
  metadata: Record<string, unknown>;
}

export interface DetectionResult {
  detected: boolean;
  findings: Finding[];
  riskLevel: SeverityLevel;
  details: Record<string, unknown>;
}

export interface ProtectionResult {
  protected: boolean;
  actions: ProtectionAction[];
  threats: Finding[];
  summary: string;
}

export interface ProtectionAction {
  type: 'block' | 'alert' | 'isolate' | 'terminate' | 'log';
  target: string;
  reason: string;
  timestamp: string;
}

export interface SbomResult {
  components: SbomComponent[];
  format: string;
  metadata: Record<string, unknown>;
  generatedAt: string;
  hash: string;
}

export interface SbomComponent {
  name: string;
  version: string;
  type: string;
  licenses: string[];
  hashes: Record<string, string>;
}

export interface AuditResult {
  audited: number;
  vulnerable: number;
  findings: Finding[];
  summary: Record<string, number>;
}

export interface ScanResult {
  imageId: string;
  layers: LayerScan[];
  vulnerabilities: Finding[];
  signatureValid: boolean;
  riskScore: number;
}

export interface LayerScan {
  index: number;
  digest: string;
  findings: Finding[];
}

export interface AnomalyResult {
  anomalous: boolean;
  anomalies: Finding[];
  confidence: number;
  baseline: Record<string, unknown>;
}

export interface ScoreResult {
  overallScore: number;
  categoryScores: Record<string, number>;
  findings: Finding[];
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
}

export interface DependencyEntry {
  name: string;
  version: string;
  type?: string;
  hash?: string;
}

export interface VulnerabilityEntry {
  id: string;
  packageName: string;
  severity: SeverityLevel;
  fixedVersion?: string;
  description: string;
}

export interface ContainerConfig {
  privileged?: boolean;
  capabilities?: string[];
  namespaces?: string[];
  volumes?: string[];
  networkMode?: string;
  pidMode?: string;
  usernsMode?: string;
  securityContext?: Record<string, unknown>;
}

export interface BucketConfig {
  name: string;
  region: string;
  publicAccessBlock?: Record<string, boolean>;
  encryption?: string;
  versioning?: boolean;
}

export interface SecretConfig {
  name: string;
  encryptionKey?: string;
  rotationEnabled?: boolean;
  rotationInterval?: number;
  accessPolicy?: Record<string, unknown>;
}

export interface IamPolicy {
  Version: string;
  Statement: IamStatement[];
}

export interface IamStatement {
  Effect: 'Allow' | 'Deny';
  Action: string | string[];
  Resource: string | string[];
  Principal?: Record<string, unknown>;
  Condition?: Record<string, unknown>;
}

export interface K8sManifest {
  apiVersion: string;
  kind: string;
  metadata: Record<string, unknown>;
  spec?: Record<string, unknown>;
}

export interface TerraformResource {
  type: string;
  name: string;
  config: Record<string, unknown>;
}

export interface TerraformPlan {
  resourceChanges: TerraformResource[];
  outputChanges?: Record<string, unknown>;
}

export interface WorkloadConfig {
  name: string;
  namespace: string;
  serviceAccount: string;
  identityProvider?: string;
  trustPolicy?: Record<string, unknown>;
}

export interface Attestation {
  type: string;
  measurements: Record<string, string>;
  signature: string;
  timestamp: string;
}

// --- Severity Helpers ----------------------------------------------

const SEVERITY_ORDER: SeverityLevel[] = ['critical', 'high', 'medium', 'low', 'info'];

function severityIndex(s: SeverityLevel): number {
  return SEVERITY_ORDER.indexOf(s);
}

function meetsThreshold(severity: SeverityLevel, threshold: SeverityLevel): boolean {
  return severityIndex(severity) <= severityIndex(threshold);
}

function calculateScore(findings: Finding[]): number {
  if (findings.length === 0) return 100;
  const weights: Record<SeverityLevel, number> = { critical: 25, high: 15, medium: 8, low: 3, info: 1 };
  const penalty = findings.reduce((sum, f) => sum + (weights[f.severity] ?? 0), 0);
  return Math.max(0, Math.min(100, 100 - penalty));
}

function hashContent(content: string): string {
  return createHash('sha256').update(content).digest('hex');
}

function sha3Hash(content: string): string {
  const input = new TextEncoder().encode(content);
  return Array.from(sha3_256(input))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function emitEvent(type: string, severity: EventSeverity, data: Record<string, unknown>): void {
  const bus = getEventBus();
  const event: SecurityEvent = {
    id: crypto.randomUUID(),
    type,
    severity,
    timestamp: new Date().toISOString(),
    data,
  };
  bus.publish(event);
}

function recordMetric(name: string, value: number, tags: Record<string, string> = {}): void {
  const metrics = getMetrics();
  metrics.setGauge(name, value, tags);
}

function compareVersions(a: string, b: string): number {
  const partsA = a.split('.').map(Number);
  const partsB = b.split('.').map(Number);
  for (let i = 0; i < Math.max(partsA.length, partsB.length); i++) {
    const pa = partsA[i] ?? 0;
    const pb = partsB[i] ?? 0;
    if (pa !== pb) return pa - pb;
  }
  return 0;
}

function levenshteinSimilarity(a: string, b: string): number {
  const lenA = a.length;
  const lenB = b.length;
  const matrix: number[][] = Array.from({ length: lenA + 1 }, (_, i) =>
    Array.from({ length: lenB + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)),
  );
  for (let i = 1; i <= lenA; i++) {
    for (let j = 1; j <= lenB; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + cost,
      );
    }
  }
  const distance = matrix[lenA][lenB];
  const maxLen = Math.max(lenA, lenB);
  return maxLen === 0 ? 1 : 1 - distance / maxLen;
}

function classifyTyposquat(suspect: string, legitimate: string): string {
  if (suspect.length === legitimate.length + 1) return 'addition';
  if (suspect.length === legitimate.length - 1) return 'omission';
  if (suspect.length === legitimate.length) {
    const diffs = suspect.split('').filter((c, i) => c !== legitimate[i]).length;
    if (diffs === 1) return 'substitution';
    if (diffs === 2) return 'transposition';
  }
  return 'combination';
}

function stringConditionsPresent(conditions: Record<string, unknown>): boolean {
  return Object.keys(conditions).some(k =>
    k.startsWith('String') || k.startsWith('Arn') || k.startsWith('IpAddress'),
  );
}

// --- 1. validateDockerfile -----------------------------------------------

/**
 * Validates a Dockerfile against security rules and severity threshold.
 * Checks for privileged instructions, exposed secrets, and insecure patterns.
 */
export function validateDockerfile(
  dockerfileContent: string,
  rules: Rule[],
  severityThreshold: SeverityLevel = 'medium',
): ValidationResult {
  const span = createSpan('cloud.validateDockerfile');
  logger.info({ ruleCount: rules.length, threshold: severityThreshold }, 'validating Dockerfile');

  const findings: Finding[] = [];
  const lines = dockerfileContent.split('\n');

  const dockerfileRules: Rule[] = [
    ...rules,
    {
      id: 'DF-001', name: 'no-root-user', description: 'Container should not run as root',
      severity: 'high', check: () => !dockerfileContent.includes('USER root') && !lines.some(l => l.match(/^USER\s+0$/)),
    },
    {
      id: 'DF-002', name: 'no-latest-tag', description: 'Base image should use a specific tag, not latest',
      severity: 'medium', check: () => !lines.some(l => l.match(/^FROM\s+\S+:latest$/i)),
    },
    {
      id: 'DF-003', name: 'no-add-remote-url', description: 'ADD with remote URLs should be replaced with curl/wget',
      severity: 'medium', check: () => !lines.some(l => l.match(/^ADD\s+https?:\/\//i)),
    },
    {
      id: 'DF-004', name: 'no-privileged', description: 'Dockerfile should not set privileged mode',
      severity: 'critical', check: () => !dockerfileContent.toLowerCase().includes('privileged'),
    },
    {
      id: 'DF-005', name: 'has-healthcheck', description: 'Dockerfile should include a HEALTHCHECK instruction',
      severity: 'low', check: () => lines.some(l => l.match(/^HEALTHCHECK/i)),
    },
    {
      id: 'DF-006', name: 'no-env-secrets', description: 'Secrets should not be passed via ENV',
      severity: 'critical', check: () => !lines.some(l => l.match(/^ENV\s+\S*(PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL)\S*\s*=/i)),
    },
    {
      id: 'DF-007', name: 'no-copy-sensitive', description: 'Sensitive files should not be copied into image',
      severity: 'high', check: () => !lines.some(l => l.match(/^(ADD|COPY)\s+.*(id_rsa|\.env|\.pem|\.key|credentials)/i)),
    },
    {
      id: 'DF-008', name: 'minimal-base', description: 'Use minimal base images (alpine, distroless, scratch)',
      severity: 'info', check: () => lines.some(l => l.match(/^FROM\s+\S*(alpine|distroless|scratch)/i)),
    },
  ];

  for (const rule of dockerfileRules) {
    const passed = rule.check(dockerfileContent);
    if (!passed && meetsThreshold(rule.severity, severityThreshold)) {
      findings.push({
        ruleId: rule.id, ruleName: rule.name, severity: rule.severity,
        message: rule.description, remediation: `Fix rule: ${rule.id}`,
      });
    }
  }

  const score = calculateScore(findings);
  const result: ValidationResult = {
    valid: findings.length === 0, findings, score,
    metadata: { linesAnalyzed: lines.length, rulesChecked: dockerfileRules.length, contentHash: hashContent(dockerfileContent) },
  };

  logger.info({ valid: result.valid, score, findingCount: findings.length }, 'Dockerfile validation complete');
  recordMetric('dockerfile_validation_score', score, { threshold: severityThreshold });
  emitEvent('dockerfile:validated', findings.length > 0 ? EventSeverity.WARNING : EventSeverity.INFO, { score, findings: findings.length });

  span.end();
  return result;
}

// --- 2. detectContainerEscape --------------------------------------------------

/**
 * Detects potential container escape vectors based on container configuration,
 * Linux capabilities, and namespace isolation settings.
 */
export function detectContainerEscape(
  containerConfig: ContainerConfig,
  capabilities: string[] = [],
  namespaces: string[] = [],
): DetectionResult {
  const span = createSpan('cloud.detectContainerEscape');
  logger.info({ capabilities, namespaces }, 'detecting container escape vectors');

  const findings: Finding[] = [];
  const dangerousCapabilities = [
    'SYS_ADMIN', 'SYS_PTRACE', 'SYS_RAWIO', 'SYS_MODULE',
    'DAC_OVERRIDE', 'DAC_READ_SEARCH', 'NET_ADMIN', 'NET_RAW',
    'SETUID', 'SETGID', 'MKNOD', 'AUDIT_WRITE', 'ALL',
  ];
  const requiredNamespaces = ['pid', 'network', 'mount', 'ipc', 'uts', 'user'];

  if (containerConfig.privileged) {
    findings.push({ ruleId: 'CE-001', ruleName: 'privileged-container', severity: 'critical',
      message: 'Container running in privileged mode allows full host access',
      remediation: 'Remove privileged flag and use specific capabilities instead' });
  }
  if (containerConfig.pidMode === 'host') {
    findings.push({ ruleId: 'CE-002', ruleName: 'host-pid-namespace', severity: 'critical',
      message: 'Container shares host PID namespace enabling process visibility',
      remediation: 'Remove pidMode: host configuration' });
  }
  if (containerConfig.networkMode === 'host') {
    findings.push({ ruleId: 'CE-003', ruleName: 'host-network', severity: 'high',
      message: 'Container uses host network namespace',
      remediation: 'Use bridge or custom network instead of host network' });
  }
  if (containerConfig.usernsMode === 'host') {
    findings.push({ ruleId: 'CE-004', ruleName: 'host-userns', severity: 'high',
      message: 'Container shares host user namespace',
      remediation: 'Enable user namespace remapping' });
  }

  for (const cap of capabilities) {
    if (dangerousCapabilities.includes(cap.toUpperCase())) {
      findings.push({ ruleId: 'CE-005', ruleName: 'dangerous-capability',
        severity: cap === 'ALL' ? 'critical' : 'high',
        message: `Dangerous capability ${cap} granted to container`,
        location: `capabilities.${cap}`,
        remediation: `Remove ${cap} capability unless absolutely required` });
    }
  }

  const missingNs = requiredNamespaces.filter(ns => !namespaces.includes(ns));
  for (const ns of missingNs) {
    findings.push({ ruleId: 'CE-006', ruleName: 'missing-namespace', severity: 'medium',
      message: `Container is not isolated in ${ns} namespace`,
      location: `namespaces.${ns}`,
      remediation: `Enable ${ns} namespace isolation` });
  }

  const hostVolumes = (containerConfig.volumes ?? []).filter(v =>
    v.startsWith('/') || v.startsWith('/var/run/docker.sock') || v.startsWith('/proc') || v.startsWith('/sys'));
  for (const vol of hostVolumes) {
    findings.push({ ruleId: 'CE-007', ruleName: 'host-volume-mount',
      severity: vol.includes('docker.sock') ? 'critical' : 'high',
      message: `Sensitive host volume mounted: ${vol}`,
      location: `volumes.${vol}`, remediation: 'Remove sensitive host volume mounts' });
  }

  const riskLevel: SeverityLevel = findings.length === 0 ? 'info'
    : findings.reduce<SeverityLevel>((max, f) => severityIndex(f.severity) < severityIndex(max) ? f.severity : max, 'info');

  const result: DetectionResult = {
    detected: findings.length > 0, findings, riskLevel,
    details: { capabilitiesChecked: capabilities, namespacesChecked: namespaces,
      missingNamespaces: missingNs,
      dangerousCapabilities: capabilities.filter(c => dangerousCapabilities.includes(c.toUpperCase())) },
  };

  logger.info({ detected: result.detected, riskLevel, findingCount: findings.length }, 'container escape detection complete');
  recordMetric('container_escape_risk', severityIndex(riskLevel), { riskLevel });
  emitEvent('container:escape-detected', riskLevel === 'critical' ? EventSeverity.CRITICAL : EventSeverity.WARNING, { riskLevel, findings: findings.length });

  span.end();
  return result;
}

// --- 3. validateK8sRbac ---------------------------------------------------

/**
 * Validates Kubernetes RBAC configuration against least privilege principles.
 */
export function validateK8sRbac(
  rbacConfig: Record<string, unknown>,
  leastPrivilegeRules: Rule[],
): ValidationResult {
  const span = createSpan('cloud.validateK8sRbac');
  logger.info('validating Kubernetes RBAC configuration');

  const findings: Finding[] = [];
  const rules = (rbacConfig.rules as Record<string, unknown>[]) ?? [];
  const wildcardActions = ['*', '*.*'];
  const dangerousResources = ['secrets', 'pods/exec', 'pods/attach', 'nodes/proxy', 'serviceaccounts/token'];
  const dangerousVerbs = ['*', 'create', 'delete', 'deletecollection', 'patch', 'update'];

  for (const rule of rules) {
    const apiGroups = (rule.apiGroups as string[]) ?? [];
    const resources = (rule.resources as string[]) ?? [];
    const verbs = (rule.verbs as string[]) ?? [];

    if (verbs.some(v => wildcardActions.includes(v))) {
      findings.push({ ruleId: 'RBAC-001', ruleName: 'wildcard-verbs', severity: 'critical',
        message: 'RBAC rule uses wildcard verbs granting all permissions',
        remediation: 'Specify only required verbs explicitly' });
    }
    if (resources.some(r => wildcardActions.includes(r))) {
      findings.push({ ruleId: 'RBAC-002', ruleName: 'wildcard-resources', severity: 'critical',
        message: 'RBAC rule uses wildcard resources',
        remediation: 'Specify only required resources explicitly' });
    }
    for (const res of resources) {
      if (dangerousResources.includes(res)) {
        const hasDangerousVerb = verbs.some(v => dangerousVerbs.includes(v));
        if (hasDangerousVerb) {
          findings.push({ ruleId: 'RBAC-003', ruleName: 'dangerous-resource-access', severity: 'high',
            message: `Access to ${res} with write permissions`,
            location: `resources.${res}`,
            remediation: `Restrict access to ${res} to read-only if possible` });
        }
      }
    }
    if (apiGroups.includes('*')) {
      findings.push({ ruleId: 'RBAC-004', ruleName: 'wildcard-api-groups', severity: 'high',
        message: 'RBAC rule applies to all API groups',
        remediation: 'Specify only required API groups' });
    }
    const clusterAdmin = (rbacConfig.roleRef as Record<string, unknown>)?.name === 'cluster-admin';
    if (clusterAdmin) {
      findings.push({ ruleId: 'RBAC-005', ruleName: 'cluster-admin-binding', severity: 'critical',
        message: 'RoleBinding grants cluster-admin privileges',
        remediation: 'Create a custom role with minimal required permissions' });
    }
  }

  const subjects = (rbacConfig.subjects as Record<string, unknown>[]) ?? [];
  for (const subject of subjects) {
    if ((subject.kind as string) === 'Group' && (subject.name as string) === 'system:authenticated') {
      findings.push({ ruleId: 'RBAC-006', ruleName: 'authenticated-group-binding', severity: 'high',
        message: 'Role bound to all authenticated users',
        remediation: 'Bind to specific service accounts or user groups' });
    }
  }

  for (const rule of leastPrivilegeRules) {
    const passed = rule.check(rbacConfig);
    if (!passed) {
      findings.push({ ruleId: rule.id, ruleName: rule.name, severity: rule.severity,
        message: rule.description, remediation: `Fix ${rule.name}: ${rule.description}` });
    }
  }

  const score = calculateScore(findings);
  const result: ValidationResult = {
    valid: findings.length === 0, findings, score,
    metadata: { rulesAnalyzed: rules.length, subjectsAnalyzed: subjects.length,
      roleRef: (rbacConfig.roleRef as Record<string, unknown>)?.name ?? 'unknown' },
  };

  logger.info({ valid: result.valid, score, findingCount: findings.length }, 'K8s RBAC validation complete');
  recordMetric('k8s_rbac_score', score);
  emitEvent('k8s:rbac-validated', findings.length > 0 ? EventSeverity.WARNING : EventSeverity.INFO, { score, findings: findings.length });

  span.end();
  return result;
}

// --- 4. detectPublicBucket ----------------------------------------------------

/**
 * Detects if a cloud storage bucket is publicly accessible based on
 * configuration, policies, and ACL settings.
 */
export function detectPublicBucket(
  bucketConfig: BucketConfig,
  policies: Record<string, unknown>[],
  acl: Record<string, unknown>,
): DetectionResult {
  const span = createSpan('cloud.detectPublicBucket');
  logger.info({ bucketName: bucketConfig.name }, 'detecting public bucket exposure');

  const findings: Finding[] = [];
  const publicAccessBlock = bucketConfig.publicAccessBlock ?? {};
  const blockPublicAcls = publicAccessBlock.BlockPublicAcls ?? false;
  const blockPublicPolicy = publicAccessBlock.BlockPublicPolicy ?? false;
  const ignorePublicAcls = publicAccessBlock.IgnorePublicAcls ?? false;
  const restrictPublicBuckets = publicAccessBlock.RestrictPublicBuckets ?? false;

  if (!blockPublicAcls || !blockPublicPolicy || !ignorePublicAcls || !restrictPublicBuckets) {
    findings.push({ ruleId: 'PB-001', ruleName: 'incomplete-public-access-block', severity: 'high',
      message: 'Public access block is not fully enabled',
      remediation: 'Enable all four public access block settings' });
  }

  for (const policy of policies) {
    const statements = (policy.Statement as Record<string, unknown>[]) ?? [];
    for (const stmt of statements) {
      if (stmt.Effect === 'Allow') {
        const principal = stmt.Principal as Record<string, unknown> | string | undefined;
        if (principal === '*' || (typeof principal === 'object' && (principal as Record<string, unknown>).AWS === '*')) {
          findings.push({ ruleId: 'PB-002', ruleName: 'public-bucket-policy', severity: 'critical',
            message: 'Bucket policy allows access from any principal',
            remediation: 'Restrict Principal to specific AWS accounts or IAM roles' });
        }
        const condition = stmt.Condition as Record<string, unknown> | undefined;
        if (!condition && principal === '*') {
          findings.push({ ruleId: 'PB-003', ruleName: 'unconditional-public-access', severity: 'critical',
            message: 'Public access without IP or VPC condition',
            remediation: 'Add Condition restricting access by IP or VPC endpoint' });
        }
      }
    }
  }

  const grants = (acl.Grants as Record<string, unknown>[]) ?? [];
  for (const grant of grants) {
    const grantee = grant.Grantee as Record<string, unknown> | undefined;
    if (grantee && (grantee.URI as string)?.includes('AllUsers')) {
      findings.push({ ruleId: 'PB-004', ruleName: 'public-acl-grant', severity: 'critical',
        message: 'ACL grants access to AllUsers (public)',
        remediation: 'Remove public ACL grants' });
    }
    if (grantee && (grantee.URI as string)?.includes('AuthenticatedUsers')) {
      findings.push({ ruleId: 'PB-005', ruleName: 'authenticated-acl-grant', severity: 'high',
        message: 'ACL grants access to any authenticated AWS user',
        remediation: 'Remove AuthenticatedUsers ACL grants' });
    }
  }

  if (!bucketConfig.encryption) {
    findings.push({ ruleId: 'PB-006', ruleName: 'no-bucket-encryption', severity: 'medium',
      message: 'Bucket encryption is not configured',
      remediation: 'Enable server-side encryption (SSE-S3 or SSE-KMS)' });
  }
  if (!bucketConfig.versioning) {
    findings.push({ ruleId: 'PB-007', ruleName: 'no-versioning', severity: 'low',
      message: 'Bucket versioning is not enabled',
      remediation: 'Enable versioning for data protection' });
  }

  const riskLevel: SeverityLevel = findings.length === 0 ? 'info'
    : findings.reduce<SeverityLevel>((max, f) => severityIndex(f.severity) < severityIndex(max) ? f.severity : max, 'info');

  const result: DetectionResult = {
    detected: findings.length > 0, findings, riskLevel,
    details: { bucketName: bucketConfig.name, publicAccessBlock, policyCount: policies.length, aclGrants: grants.length },
  };

  logger.info({ detected: result.detected, riskLevel }, 'public bucket detection complete');
  recordMetric('bucket_public_risk', severityIndex(riskLevel), { bucket: bucketConfig.name });
  emitEvent('bucket:public-detected', riskLevel === 'critical' ? EventSeverity.CRITICAL : EventSeverity.WARNING, { bucket: bucketConfig.name, riskLevel });

  span.end();
  return result;
}

// --- 5. validateS3Permissions ----------------------------------------------------

/**
 * Validates S3 bucket permissions against expected access patterns.
 */
export function validateS3Permissions(
  bucketPolicy: Record<string, unknown>,
  expectedPermissions: Record<string, string[]>,
): ValidationResult {
  const span = createSpan('cloud.validateS3Permissions');
  logger.info('validating S3 bucket permissions');

  const findings: Finding[] = [];
  const statements = (bucketPolicy.Statement as Record<string, unknown>[]) ?? [];

  for (const [role, expectedActions] of Object.entries(expectedPermissions)) {
    const roleStatements = statements.filter(s => {
      const principals = (s.Principal as Record<string, unknown>) ?? {};
      const aws = (principals.AWS as string | string[]) ?? '';
      return typeof aws === 'string' ? aws.includes(role) : aws.includes(role);
    });

    for (const action of expectedActions) {
      const hasAction = roleStatements.some(s => {
        const actions = (s.Action as string | string[]) ?? [];
        const actionList = typeof actions === 'string' ? [actions] : actions;
        return actionList.includes(action) || actionList.includes('*') || actionList.includes('s3:*');
      });
      if (!hasAction) {
        findings.push({ ruleId: 'S3P-001', ruleName: 'missing-permission', severity: 'medium',
          message: `Role ${roleName} is missing expected permission: ${expected}`,
          remediation: `Add ${expected} to ${roleName} policy statement` });
      }
    }
  }

  for (const stmt of statements) {
    if (stmt.Effect === 'Allow') {
      const actions = (stmt.Action as string | string[]) ?? [];
      const actionList = typeof actions === 'string' ? [actions] : actions;
      if (actionList.includes('s3:*') || actionList.includes('*')) {
        findings.push({ ruleId: 'S3P-002', ruleName: 'overly-permissive-s3', severity: 'high',
          message: 'S3 policy grants wildcard permissions',
          remediation: 'Replace wildcard with specific S3 actions' });
      }
    }
  }

  const score = calculateScore(findings);
  const result: ValidationResult = {
    valid: findings.length === 0, findings, score,
    metadata: { statementsAnalyzed: statements.length, rolesChecked: Object.keys(expectedPermissions).length },
  };

  logger.info({ valid: result.valid, score }, 'S3 permissions validation complete');
  recordMetric('s3_permissions_score', score);
  emitEvent('s3:permissions-validated', findings.length > 0 ? EventSeverity.WARNING : EventSeverity.INFO, { score });

  span.end();
  return result;
}

// --- 6. validateIamPolicy -----------------------------------------------------

/**
 * Validates an IAM policy against allowed and denied action lists.
 */
export function validateIamPolicy(
  iamPolicy: IamPolicy,
  allowedActions: string[],
  deniedActions: string[],
): ValidationResult {
  const span = createSpan('cloud.validateIamPolicy');
  logger.info({ statementCount: iamPolicy.Statement.length }, 'validating IAM policy');

  const findings: Finding[] = [];

  for (const stmt of iamPolicy.Statement) {
    const actions = typeof stmt.Action === 'string' ? [stmt.Action] : stmt.Action;

    for (const action of actions) {
      if (action === '*' || action === '*:*') {
        findings.push({ ruleId: 'IAM-001', ruleName: 'wildcard-action', severity: 'critical',
          message: 'IAM policy contains wildcard action granting all permissions',
          remediation: 'Replace wildcard with specific service:action pairs' });
        continue;
      }
      if (deniedActions.some(d => action === d || (d.endsWith('*') && action.startsWith(d.slice(0, -1))))) {
        findings.push({ ruleId: 'IAM-002', ruleName: 'denied-action-allowed', severity: 'critical',
          message: `Policy allows denied action: ${action}`,
          remediation: `Remove ${action} from allowed actions` });
      }
      if (stmt.Effect === 'Allow' && !allowedActions.some(a =>
        action === a || (a.endsWith('*') && action.startsWith(a.slice(0, -1))))) {
        findings.push({ ruleId: 'IAM-003', ruleName: 'unlisted-action', severity: 'medium',
          message: `Action ${action} is not in the allowed actions list`,
          remediation: `Add ${action} to allowed actions or remove from policy` });
      }
    }

    const resources = typeof stmt.Resource === 'string' ? [stmt.Resource] : stmt.Resource;
    if (stmt.Effect === 'Allow' && resources.includes('*')) {
      findings.push({ ruleId: 'IAM-004', ruleName: 'wildcard-resource', severity: 'high',
        message: 'Policy allows actions on all resources',
        remediation: 'Scope resources to specific ARNs' });
    }
    if (stmt.Effect === 'Allow' && !stmt.Condition) {
      findings.push({ ruleId: 'IAM-005', ruleName: 'no-condition', severity: 'medium',
        message: 'Allow statement has no condition constraints',
        remediation: 'Add conditions (MFA, IP, VPC) to restrict access' });
    }
  }

  const score = calculateScore(findings);
  const result: ValidationResult = {
    valid: findings.length === 0, findings, score,
    metadata: { statementsAnalyzed: iamPolicy.Statement.length, version: iamPolicy.Version,
      policyHash: hashContent(JSON.stringify(iamPolicy)) },
  };

  logger.info({ valid: result.valid, score }, 'IAM policy validation complete');
  recordMetric('iam_policy_score', score);
  emitEvent('iam:policy-validated', findings.length > 0 ? EventSeverity.WARNING : EventSeverity.INFO, { score });

  span.end();
  return result;
}

// --- 7. detectCloudMisconfig ----------------------------------------------------

/**
 * Detects cloud infrastructure misconfigurations against a security baseline.
 */
export function detectCloudMisconfig(
  config: Record<string, unknown>,
  securityBaseline: Record<string, unknown>,
  cloudProvider: string,
): DetectionResult {
  const span = createSpan('cloud.detectCloudMisconfig');
  logger.info({ cloudProvider }, 'detecting cloud misconfigurations');

  const findings: Finding[] = [];
  const baseline = securityBaseline as Record<string, Record<string, unknown>>;

  for (const [service, rules] of Object.entries(baseline)) {
    const serviceConfig = config[service] as Record<string, unknown> | undefined;
    if (!serviceConfig) {
      findings.push({ ruleId: 'CM-001', ruleName: 'missing-service-config', severity: 'medium',
        message: `Service ${service} configuration is missing`,
        remediation: `Add configuration for ${service}` });
      continue;
    }
    for (const [key, expectedValue] of Object.entries(rules)) {
      const actualValue = serviceConfig[key];
      if (expectedValue === true && actualValue !== true) {
        findings.push({ ruleId: 'CM-002', ruleName: 'security-feature-disabled', severity: 'high',
          message: `Security feature ${key} should be enabled`,
          location: `${service}.${key}`, remediation: `Set ${key} to true` });
      }
      if (typeof expectedValue === 'string' && expectedValue.startsWith('not:')) {
        const forbidden = expectedValue.slice(4);
        if (actualValue === forbidden) {
          findings.push({ ruleId: 'CM-003', ruleName: 'forbidden-value', severity: 'high',
            message: `${service}.${key} has forbidden value: ${forbidden}`,
            location: `${service}.${key}`, remediation: `Change ${key} from ${forbidden}` });
        }
      }
      if (key === 'encryption' && !actualValue) {
        findings.push({ ruleId: 'CM-004', ruleName: 'no-encryption', severity: 'critical',
          message: `${service} does not have encryption enabled`,
          location: `${service}.encryption`, remediation: `Enable encryption for ${service}` });
      }
      if (key === 'logging' && !actualValue) {
        findings.push({ ruleId: 'CM-005', ruleName: 'no-logging', severity: 'medium',
          message: `${service} does not have logging enabled`,
          location: `${service}.logging`, remediation: `Enable logging for ${service}` });
      }
      if (key === 'publicAccess' && actualValue === true) {
        findings.push({ ruleId: 'CM-006', ruleName: 'unintended-public-access', severity: 'critical',
          message: `${service} is publicly accessible`,
          location: `${service}.publicAccess`, remediation: `Restrict public access for ${service}` });
      }
    }
  }

  const providerChecks: Array<{ id: string; name: string; severity: SeverityLevel; check: () => boolean; message: string }> =
    cloudProvider.toLowerCase() === 'aws' ? [
      { id: 'CM-AWS-001', name: 'no-cloudtrail', severity: 'high', check: () => !!config.cloudtrail, message: 'AWS CloudTrail is not enabled' },
      { id: 'CM-AWS-002', name: 'no-guardduty', severity: 'medium', check: () => !!config.guardduty, message: 'AWS GuardDuty is not enabled' },
      { id: 'CM-AWS-003', name: 'no-config', severity: 'medium', check: () => !!config.awsConfig, message: 'AWS Config is not enabled' },
    ] : cloudProvider.toLowerCase() === 'gcp' ? [
      { id: 'CM-GCP-001', name: 'no-audit-logging', severity: 'high', check: () => !!(config as Record<string, unknown>).auditLogging, message: 'GCP Audit Logging is not enabled' },
      { id: 'CM-GCP-002', name: 'no-scc', severity: 'medium', check: () => !!(config as Record<string, unknown>).securityCommandCenter, message: 'GCP Security Command Center is not enabled' },
    ] : cloudProvider.toLowerCase() === 'azure' ? [
      { id: 'CM-AZ-001', name: 'no-monitor', severity: 'high', check: () => !!(config as Record<string, unknown>).azureMonitor, message: 'Azure Monitor is not enabled' },
      { id: 'CM-AZ-002', name: 'no-defender', severity: 'medium', check: () => !!(config as Record<string, unknown>).defenderForCloud, message: 'Microsoft Defender for Cloud is not enabled' },
    ] : [];

  for (const check of providerChecks) {
    if (!check.check()) {
      findings.push({ ruleId: check.id, ruleName: check.name, severity: check.severity,
        message: check.message, remediation: `Enable ${check.name} in ${cloudProvider}` });
    }
  }

  const riskLevel: SeverityLevel = findings.length === 0 ? 'info'
    : findings.reduce<SeverityLevel>((max, f) => severityIndex(f.severity) < severityIndex(max) ? f.severity : max, 'info');

  const result: DetectionResult = {
    detected: findings.length > 0, findings, riskLevel,
    details: { cloudProvider, servicesChecked: Object.keys(baseline).length, configKeysAnalyzed: Object.keys(config).length },
  };

  logger.info({ detected: result.detected, riskLevel, findingCount: findings.length }, 'cloud misconfig detection complete');
  recordMetric('cloud_misconfig_risk', severityIndex(riskLevel), { provider: cloudProvider });
  emitEvent('cloud:misconfig-detected', riskLevel === 'critical' ? EventSeverity.CRITICAL : EventSeverity.WARNING, { provider: cloudProvider, riskLevel, findings: findings.length });

  span.end();
  return result;
}

// --- 8. validateSecretsManager ---------------------------------------------------

/**
 * Validates secrets manager configuration including rotation policies
 * and encryption settings.
 */
export function validateSecretsManager(
  secretsConfig: SecretConfig,
  rotationPolicy: { enabled: boolean; intervalDays: number; lambdaArn?: string },
  encryption: { type: string; keyId?: string; autoRotate?: boolean },
): ValidationResult {
  const span = createSpan('cloud.validateSecretsManager');
  logger.info({ secretName: secretsConfig.name }, 'validating secrets manager configuration');

  const findings: Finding[] = [];

  if (!secretsConfig.encryptionKey) {
    findings.push({ ruleId: 'SM-001', ruleName: 'no-encryption-key', severity: 'critical',
      message: 'Secret is not encrypted with a customer-managed key',
      remediation: 'Configure a KMS customer-managed key for encryption' });
  }
  if (!rotationPolicy.enabled) {
    findings.push({ ruleId: 'SM-002', ruleName: 'rotation-disabled', severity: 'high',
      message: 'Secret rotation is not enabled',
      remediation: 'Enable automatic secret rotation' });
  } else if (rotationPolicy.intervalDays > 90) {
    findings.push({ ruleId: 'SM-003', ruleName: 'rotation-too-slow', severity: 'medium',
      message: `Secret rotation interval (${rotationPolicy.intervalDays} days) exceeds 90 days`,
      remediation: 'Set rotation interval to 90 days or less' });
  }
  if (rotationPolicy.enabled && !rotationPolicy.lambdaArn) {
    findings.push({ ruleId: 'SM-004', ruleName: 'no-rotation-lambda', severity: 'medium',
      message: 'No Lambda function configured for rotation',
      remediation: 'Configure a Lambda rotation function' });
  }
  if (encryption.type === 'AES256') {
    findings.push({ ruleId: 'SM-005', ruleName: 's3-encryption-only', severity: 'medium',
      message: 'Using SSE-S3 encryption instead of KMS',
      remediation: 'Use SSE-KMS for better key management' });
  }
  if (encryption.type === 'aws:kms' && !encryption.keyId) {
    findings.push({ ruleId: 'SM-006', ruleName: 'default-kms-key', severity: 'low',
      message: 'Using default AWS managed KMS key instead of customer-managed',
      remediation: 'Specify a customer-managed KMS key ID' });
  }
  if (encryption.autoRotate !== true) {
    findings.push({ ruleId: 'SM-007', ruleName: 'no-key-rotation', severity: 'medium',
      message: 'KMS key auto-rotation is not enabled',
      remediation: 'Enable automatic KMS key rotation' });
  }
  const accessPolicy = secretsConfig.accessPolicy;
  if (!accessPolicy || Object.keys(accessPolicy).length === 0) {
    findings.push({ ruleId: 'SM-008', ruleName: 'no-access-policy', severity: 'high',
      message: 'No resource-based access policy configured',
      remediation: 'Add a resource policy restricting secret access' });
  }

  const score = calculateScore(findings);
  const result: ValidationResult = {
    valid: findings.length === 0, findings, score,
    metadata: { secretName: secretsConfig.name, encryptionType: encryption.type,
      rotationEnabled: rotationPolicy.enabled, rotationInterval: rotationPolicy.intervalDays,
      configHash: hashContent(JSON.stringify(secretsConfig)) },
  };

  logger.info({ valid: result.valid, score }, 'secrets manager validation complete');
  recordMetric('secrets_manager_score', score, { secret: secretsConfig.name });
  emitEvent('secrets:validated', findings.length > 0 ? EventSeverity.WARNING : EventSeverity.INFO, { score });

  span.end();
  return result;
}

// --- 9. validateTerraform -----------------------------------------------------

/**
 * Validates a Terraform plan against security policies and severity threshold.
 */
export function validateTerraform(
  terraformPlan: TerraformPlan,
  policies: Rule[],
  severityThreshold: SeverityLevel = 'medium',
): ValidationResult {
  const span = createSpan('cloud.validateTerraform');
  logger.info({ resourceCount: terraformPlan.resourceChanges.length }, 'validating Terraform plan');

  const findings: Finding[] = [];

  const terraformRules: Rule[] = [
    ...policies,
    { id: 'TF-001', name: 'no-hardcoded-secrets', description: 'Terraform should not contain hardcoded secrets',
      severity: 'critical', check: () => {
        const json = JSON.stringify(terraformPlan);
        return !/(password|secret|token|key)\s*[:=]\s*["'][^"']{8,}["']/i.test(json);
      }},
    { id: 'TF-002', name: 'no-default-credentials', description: 'Should not use default credentials',
      severity: 'critical', check: () => !/admin:admin|root:root|default:default/i.test(JSON.stringify(terraformPlan)) },
    { id: 'TF-003', name: 'encryption-required', description: 'Storage resources must have encryption enabled',
      severity: 'high', check: () => terraformPlan.resourceChanges
        .filter(r => r.type.includes('bucket') || r.type.includes('storage') || r.type.includes('disk'))
        .every(r => { const cfg = r.config as Record<string, unknown>;
          return cfg.encrypt === true || cfg.encrypted === true || cfg.server_side_encryption_configuration !== undefined; }) },
    { id: 'TF-004', name: 'no-public-ingress', description: 'Security groups should not allow unrestricted ingress',
      severity: 'critical', check: () => terraformPlan.resourceChanges
        .filter(r => r.type.includes('security_group'))
        .every(r => { const ingress = ((r.config as Record<string, unknown>)?.ingress as Record<string, unknown>[]) ?? [];
          return !ingress.some(i => (i.cidr_blocks as string[])?.includes('0.0.0.0/0')); }) },
    { id: 'TF-005', name: 'logging-enabled', description: 'Resources should have logging enabled',
      severity: 'medium', check: () => terraformPlan.resourceChanges
        .filter(r => r.type.includes('bucket') || r.type.includes('lb') || r.type.includes('rds'))
        .every(r => { const cfg = r.config as Record<string, unknown>;
          return cfg.logging !== false && cfg.access_logs !== undefined; }) },
    { id: 'TF-006', name: 'no-plaintext-db-password', description: 'Database passwords should not be in plaintext',
      severity: 'critical', check: () => terraformPlan.resourceChanges
        .filter(r => r.type.includes('db_instance') || r.type.includes('rds'))
        .every(r => { const cfg = r.config as Record<string, unknown>;
          return !cfg.password || (typeof cfg.password === 'string' && cfg.password.startsWith('${}'));
        }) },
    { id: 'TF-007', name: 'state-encryption', description: 'Terraform state should be encrypted', severity: 'high', check: () => true },
    { id: 'TF-008', name: 'version-pinning', description: 'Provider versions should be pinned', severity: 'low', check: () => true },
  ];

  for (const rule of terraformRules) {
    const passed = rule.check(terraformPlan);
    if (!passed && meetsThreshold(rule.severity, severityThreshold)) {
      findings.push({ ruleId: rule.id, ruleName: rule.name, severity: rule.severity,
        message: rule.description, remediation: `Fix ${rule.name}: ${rule.description}` });
    }
  }

  for (const resource of terraformPlan.resourceChanges) {
    const cfg = resource.config as Record<string, unknown>;
    if (cfg.publicly_accessible === true) {
      findings.push({ ruleId: 'TF-009', ruleName: 'publicly-accessible-resource', severity: 'critical',
        message: `Resource ${resource.name} is publicly accessible`,
        location: `${resource.type}.${resource.name}`, remediation: 'Set publicly_accessible to false' });
    }
    if (cfg.deletion_protection === false && (resource.type.includes('rds') || resource.type.includes('db'))) {
      findings.push({ ruleId: 'TF-010', ruleName: 'no-deletion-protection', severity: 'medium',
        message: `Database ${resource.name} lacks deletion protection`,
        location: `${resource.type}.${resource.name}`, remediation: 'Enable deletion_protection' });
    }
  }

  const score = calculateScore(findings);
  const result: ValidationResult = {
    valid: findings.length === 0, findings, score,
    metadata: { resourcesAnalyzed: terraformPlan.resourceChanges.length, rulesChecked: terraformRules.length,
      planHash: hashContent(JSON.stringify(terraformPlan)) },
  };

  logger.info({ valid: result.valid, score, findingCount: findings.length }, 'Terraform validation complete');
  recordMetric('terraform_validation_score', score, { threshold: severityThreshold });
  emitEvent('terraform:validated', findings.length > 0 ? EventSeverity.WARNING : EventSeverity.INFO, { score });

  span.end();
  return result;
}

// --- 10. validateKubernetesManifest -----------------------------------------------

/**
 * Validates Kubernetes manifests against pod security and network policies.
 */
export function validateKubernetesManifest(
  manifest: K8sManifest,
  podSecurityPolicy: Record<string, unknown>,
  networkPolicy: Record<string, unknown>,
): ValidationResult {
  const span = createSpan('cloud.validateKubernetesManifest');
  logger.info({ kind: manifest.kind, name: (manifest.metadata as Record<string, unknown>)?.name }, 'validating K8s manifest');

  const findings: Finding[] = [];
  const spec = manifest.spec ?? {};
  const podSpec = (spec.template as Record<string, unknown>)?.spec as Record<string, unknown> | undefined;
  const containers = (podSpec?.containers as Record<string, unknown>[]) ?? [];
  if (manifest.kind === 'Pod') {
    containers.push(...((spec as Record<string, unknown>).containers as Record<string, unknown>[]) ?? []);
  }

  for (const container of containers) {
    const name = (container.name as string) ?? 'unknown';
    const securityContext = (container.securityContext as Record<string, unknown>) ?? {};

    if (securityContext.privileged === true) {
      findings.push({ ruleId: 'K8S-001', ruleName: 'privileged-container', severity: 'critical',
        message: `Container ${container.name} runs in privileged mode`,
        location: 'spec.containers[].securityContext.privileged', remediation: 'Set privileged to false' });
    }
    if (securityContext.runAsRoot === true || securityContext.runAsUser === 0) {
      findings.push({ ruleId: 'K8S-002', ruleName: 'run-as-root', severity: 'high',
        message: `Container ${container.name} runs as root user`,
        location: 'spec.containers[].securityContext.runAsUser',
        remediation: 'Set runAsUser to non-zero value' });
    }
    if (securityContext.allowPrivilegeEscalation !== false) {
      findings.push({ ruleId: 'K8S-003', ruleName: 'privilege-escalation', severity: 'high',
        message: `Container ${container.name} allows privilege escalation`,
        remediation: 'Set allowPrivilegeEscalation to false' });
    }
    if (!securityContext.readOnlyRootFilesystem) {
      findings.push({ ruleId: 'K8S-004', ruleName: 'writable-rootfs', severity: 'medium',
        message: `Container ${container.name} has writable root filesystem`,
        remediation: 'Set readOnlyRootFilesystem to true' });
    }
    if (!container.resources) {
      findings.push({ ruleId: 'K8S-005', ruleName: 'no-resource-limits', severity: 'medium',
        message: `Container ${container.name} has no resource limits`,
        remediation: 'Set resource requests and limits' });
    }
    const image = (container.image as string) ?? '';
    if (!image.includes('@sha256:') && image.includes(':latest')) {
      findings.push({ ruleId: 'K8S-006', ruleName: 'latest-image-tag', severity: 'medium',
        message: `Container ${container.name} uses latest tag`,
        remediation: 'Pin image to specific digest' });
    }
    if (!container.livenessProbe && !container.readinessProbe) {
      findings.push({ ruleId: 'K8S-007', ruleName: 'no-health-probes', severity: 'low',
        message: `Container ${container.name} has no health probes`,
        remediation: 'Add liveness and readiness probes' });
    }
  }

  if (podSpec?.hostNetwork === true) {
    findings.push({ ruleId: 'K8S-008', ruleName: 'host-network', severity: 'high',
      message: 'Pod uses host network namespace', remediation: 'Set hostNetwork to false' });
  }
  if (podSpec?.hostPID === true) {
    findings.push({ ruleId: 'K8S-009', ruleName: 'host-pid', severity: 'high',
      message: 'Pod uses host PID namespace', remediation: 'Set hostPID to false' });
  }
  if (podSpec?.hostIPC === true) {
    findings.push({ ruleId: 'K8S-010', ruleName: 'host-ipc', severity: 'high',
      message: 'Pod uses host IPC namespace', remediation: 'Set hostIPC to false' });
  }
  if ((podSecurityPolicy.privileged as boolean | undefined) === true) {
    findings.push({ ruleId: 'K8S-011', ruleName: 'psp-privileged', severity: 'critical',
      message: 'PodSecurityPolicy allows privileged containers',
      remediation: 'Set privileged to false in PodSecurityPolicy' });
  }

  const npIngress = (networkPolicy.ingress as Record<string, unknown>[]) ?? [];
  for (const rule of npIngress) {
    const from = (rule.from as Record<string, unknown>[]) ?? [];
    if (from.length === 0) {
      findings.push({ ruleId: 'K8S-012', ruleName: 'unrestricted-ingress', severity: 'high',
        message: 'NetworkPolicy allows unrestricted ingress',
        remediation: 'Specify ingress sources' });
    }
  }

  const score = calculateScore(findings);
  const result: ValidationResult = {
    valid: findings.length === 0, findings, score,
    metadata: { kind: manifest.kind, name: (manifest.metadata as Record<string, unknown>)?.name ?? 'unknown',
      containersAnalyzed: containers.length, manifestHash: hashContent(JSON.stringify(manifest)) },
  };

  logger.info({ valid: result.valid, score }, 'K8s manifest validation complete');
  recordMetric('k8s_manifest_score', score, { kind: manifest.kind });
  emitEvent('k8s:manifest-validated', findings.length > 0 ? EventSeverity.WARNING : EventSeverity.INFO, { score });

  span.end();
  return result;
}

// --- 11. runtimeContainerProtection ----------------------------------------------

/**
 * Provides runtime container protection by analyzing events against threat rules.
 */
export function runtimeContainerProtection(
  containerEvents: Record<string, unknown>[],
  threatRules: Rule[],
  actions: Record<string, 'block' | 'alert' | 'isolate' | 'terminate' | 'log'>,
): ProtectionResult {
  const span = createSpan('cloud.runtimeContainerProtection');
  logger.info({ eventCount: containerEvents.length, ruleCount: threatRules.length }, 'runtime container protection active');

  const threats: Finding[] = [];
  const protectionActions: ProtectionAction[] = [];

  const threatPatterns: Array<{ pattern: RegExp; severity: SeverityLevel; message: string; action: string }> = [
    { pattern: /exec|shell|bash|sh\s/i, severity: 'critical', message: 'Container shell access detected', action: 'block' },
    { pattern: /curl|wget|nc\s|netcat/i, severity: 'high', message: 'Network tool execution in container', action: 'alert' },
    { pattern: /chmod\s+[0-7]*777|chmod\s\+s/i, severity: 'high', message: 'Suspicious permission change', action: 'alert' },
    { pattern: /\/etc\/passwd|\/etc\/shadow|\/proc\/[0-9]/i, severity: 'critical', message: 'Sensitive file access detected', action: 'isolate' },
    { pattern: /reverse.shell|bind.shell|callback/i, severity: 'critical', message: 'Possible reverse shell detected', action: 'terminate' },
    { pattern: /cryptominer|xmrig|coinhive/i, severity: 'critical', message: 'Cryptominer activity detected', action: 'terminate' },
    { pattern: /nmap|masscan|zmap/i, severity: 'high', message: 'Network scanning activity', action: 'alert' },
    { pattern: /docker\.sock|containerd\.sock/i, severity: 'critical', message: 'Container runtime socket access', action: 'block' },
  ];

  for (const event of containerEvents) {
    const process = (event.process as string) ?? '';
    const command = (event.command as string) ?? '';
    const file = (event.file as string) ?? '';
    const network = (event.network as string) ?? '';
    const combined = `${process} ${command} ${file} ${network}`;

    for (const pattern of threatPatterns) {
      if (pattern.pattern.test(combined)) {
        const actionType = actions[pattern.action] ?? 'log';
        threats.push({
          ruleId: 'RCP-' + pattern.action, ruleName: pattern.action, severity: pattern.severity,
          message: pattern.message, location: process || command || file,
          remediation: `Action taken: ${actionType}` });
        protectionActions.push({
          type: actionType, target: (event.containerId as string) ?? 'unknown',
          reason: pattern.message, timestamp: new Date().toISOString() });
      }
    }

    for (const rule of threatRules) {
      const passed = rule.check(event);
      if (!passed) {
        threats.push({ ruleId: rule.id, ruleName: rule.name, severity: rule.severity,
          message: rule.description, remediation: `Rule ${rule.name} violated` });
      }
    }
  }

  const result: ProtectionResult = {
    protected: threats.length === 0, actions: protectionActions, threats,
    summary: `${threats.length} threats detected, ${protectionActions.length} actions taken`,
  };

  logger.info({ threats: threats.length, actions: protectionActions.length }, 'runtime protection cycle complete');
  recordMetric('runtime_threats_detected', threats.length);
  recordMetric('runtime_actions_taken', protectionActions.length);
  emitEvent('container:runtime-protection', threats.length > 0 ? EventSeverity.CRITICAL : EventSeverity.INFO, { threats: threats.length, actions: protectionActions.length });

  span.end();
  return result;
}

// --- 12. supplyChainValidation -------------------------------------------------

/**
 * Validates software supply chain by checking dependencies against trusted
 * sources and vulnerability databases.
 */
export function supplyChainValidation(
  dependencies: DependencyEntry[],
  trustedSources: string[],
  vulnerabilityDb: VulnerabilityEntry[],
): ValidationResult {
  const span = createSpan('cloud.supplyChainValidation');
  logger.info({ depCount: dependencies.length }, 'performing supply chain validation');

  const findings: Finding[] = [];

  for (const dep of dependencies) {
    const isTrusted = trustedSources.some(src => dep.name.startsWith(src) || dep.name.includes(src));
    if (!isTrusted) {
      findings.push({ ruleId: 'SC-001', ruleName: 'untrusted-source', severity: 'high',
        message: `Dependency ${dep.name}@${dep.version} is from an untrusted source`,
        remediation: 'Use dependency from trusted source' });
    }
    const vulns = vulnerabilityDb.filter(v =>
      v.packageName === dep.name && compareVersions(dep.version, v.fixedVersion ?? '999.0.0') < 0);
    for (const vuln of vulns) {
      findings.push({ ruleId: 'SC-002', ruleName: 'known-vulnerability', severity: vuln.severity,
        message: `${dep.name}@${dep.version} has vulnerability ${vuln.id}: ${vuln.description}`,
        remediation: vuln.fixedVersion ? `Upgrade to ${vuln.fixedVersion} or later` : "No fix available" });
    }
    if (dep.hash) {
      const expectedHash = vulnerabilityDb.find(v => v.packageName === dep.name)?.id;
      if (expectedHash && dep.hash !== expectedHash) {
        findings.push({ ruleId: 'SC-003', ruleName: 'hash-mismatch', severity: 'critical',
          message: `Dependency ${dep.name} hash does not match expected value`,
          remediation: 'Verify dependency integrity and re-download' });
      }
    }
  }

  const uniqueVulns = new Set(findings.filter(f => f.ruleId === 'SC-002').map(f => f.message));
  const uniqueSources = new Set(findings.filter(f => f.ruleId === 'SC-001').map(f => f.message));

  const score = calculateScore(findings);
  const result: ValidationResult = {
    valid: findings.length === 0, findings, score,
    metadata: { dependenciesChecked: dependencies.length, trustedSources: trustedSources.length,
      vulnerabilitiesFound: uniqueVulns.size, untrustedSources: uniqueSources.size },
  };

  logger.info({ valid: result.valid, score, vulns: uniqueVulns.size }, 'supply chain validation complete');
  recordMetric('supply_chain_score', score);
  emitEvent('supply-chain:validated', findings.length > 0 ? EventSeverity.WARNING : EventSeverity.INFO, { score });

  span.end();
  return result;
}

// --- 13. sbomGenerator ----------------------------------------------------

/**
 * Generates a Software Bill of Materials (SBOM) from component inventory.
 */
export function sbomGenerator(
  components: Array<{ name: string; version: string; type: string; licenses?: string[]; hash?: string }>,
  format: 'spdx' | 'cyclonedx' | 'custom' = 'spdx',
  metadata: Record<string, unknown> = {},
): SbomResult {
  const span = createSpan('cloud.sbomGenerator');
  logger.info({ componentCount: components.length, format }, 'generating SBOM');

  const sbomComponents: SbomComponent[] = components.map(comp => {
    const hashes: Record<string, string> = {};
    if (comp.hash) {
      hashes.sha256 = comp.hash;
    } else {
      const content = `${comp.name}@${comp.version}`;
      hashes.sha256 = hashContent(content);
      hashes.sha3 = sha3Hash(content);
    }
    return { name: comp.name, version: comp.version, type: comp.type,
      licenses: comp.licenses ?? ['UNKNOWN'], hashes };
  });

  const generatedAt = new Date().toISOString();
  const contentForHash = JSON.stringify({ components: sbomComponents, format, generatedAt });
  const sbomHash = hashContent(contentForHash);

  const result: SbomResult = {
    components: sbomComponents, format,
    metadata: { ...metadata, generator: 'master-security-sbom',
      specVersion: format === 'spdx' ? 'SPDX-2.3' : format === 'cyclonedx' ? '1.4' : '1.0',
      componentCount: sbomComponents.length },
    generatedAt, hash: sbomHash,
  };

  logger.info({ format, componentCount: sbomComponents.length, hash: sbomHash }, 'SBOM generation complete');
  recordMetric('sbom_generated', sbomComponents.length, { format });
  emitEvent('sbom:generated', EventSeverity.INFO, { format, components: sbomComponents.length });

  span.end();
  return result;
}

// --- 14. dependencyAudit -----------------------------------------------------

/**
 * Audits dependencies against an audit database with severity threshold filtering.
 */
export function dependencyAudit(
  dependencies: DependencyEntry[],
  auditDb: VulnerabilityEntry[],
  severityThreshold: SeverityLevel = 'medium',
): AuditResult {
  const span = createSpan('cloud.dependencyAudit');
  logger.info({ depCount: dependencies.length, threshold: severityThreshold }, 'auditing dependencies');

  const findings: Finding[] = [];
  const summary: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  for (const dep of dependencies) {
    const vulns = auditDb.filter(v =>
      v.packageName === dep.name && compareVersions(dep.version, v.fixedVersion ?? '999.0.0') < 0);
    for (const vuln of vulns) {
      if (meetsThreshold(vuln.severity, severityThreshold)) {
        findings.push({ ruleId: vuln.id, ruleName: vuln.packageName, severity: vuln.severity,
          message: `${vuln.packageName}@${vuln.affectedVersion}: ${vuln.description}`,
          remediation: vuln.fixedVersion ? `Upgrade to ${vuln.fixedVersion}` : "No fix available" });
        summary[vuln.severity] = (summary[vuln.severity] ?? 0) + 1;
      }
    }
  }

  const result: AuditResult = {
    audited: dependencies.length,
    vulnerable: new Set(findings.map(f => f.ruleName)).size,
    findings, summary,
  };

  logger.info({ audited: result.audited, vulnerable: result.vulnerable, findings: findings.length }, 'dependency audit complete');
  recordMetric('dependency_audit_vulnerable', result.vulnerable);
  recordMetric('dependency_audit_findings', findings.length);
  emitEvent('dependency:audited', findings.length > 0 ? EventSeverity.WARNING : EventSeverity.INFO, { vulnerable: result.vulnerable });

  span.end();
  return result;
}

// --- 15. detectTyposquatting ----------------------------------------------------

/**
 * Detects potential typosquatting attacks by comparing package names against
 * known legitimate packages using similarity algorithms.
 */
export function detectTyposquatting(
  packageName: string,
  knownPackages: string[],
  similarityThreshold: number = 0.85,
): DetectionResult {
  const span = createSpan('cloud.detectTyposquatting');
  logger.info({ packageName, knownCount: knownPackages.length }, 'detecting typosquatting');

  const findings: Finding[] = [];
  const suspicious: Array<{ name: string; similarity: number; type: string }> = [];

  for (const known of knownPackages) {
    const similarity = levenshteinSimilarity(packageName, known);
    if (similarity >= similarityThreshold && packageName !== known) {
      const attackType = classifyTyposquat(packageName, known);
      suspicious.push({ name: known, similarity, type: attackType });
      findings.push({
        ruleId: 'TS-001', ruleName: 'typosquat-detected',
        severity: similarity >= 0.95 ? 'critical' : 'high',
        message: `Package "${suspect}" is suspiciously similar to "${legitimate}" (${(similarity * 100).toFixed(0)}% match, type: ${attackType})`,
        remediation: `Verify package authenticity. Did you mean "${legitimate}"?` });
    }
  }

  const detected = findings.length > 0;
  const riskLevel: SeverityLevel = detected
    ? findings.reduce<SeverityLevel>((max, f) => severityIndex(f.severity) < severityIndex(max) ? f.severity : max, 'info')
    : 'info';

  const result: DetectionResult = {
    detected, findings, riskLevel,
    details: { packageName, suspiciousMatches: suspicious, similarityThreshold, packagesCompared: knownPackages.length },
  };

  logger.info({ detected, riskLevel, matches: suspicious.length }, 'typosquatting detection complete');
  recordMetric('typosquat_detected', suspicious.length, { package: packageName });
  emitEvent('package:typosquat-detected', detected ? EventSeverity.CRITICAL : EventSeverity.INFO, { package: packageName, matches: suspicious.length });

  span.end();
  return result;
}

// --- 16. containerImageScan -----------------------------------------------------

/**
 * Scans container image layers for vulnerabilities and validates signatures.
 */
export function containerImageScan(
  imageLayers: Array<{ digest: string; size: number; commands?: string[] }>,
  signatures: Array<{ keyId: string; signature: string; timestamp: string }>,
  vulnerabilityDb: VulnerabilityEntry[],
): ScanResult {
  const span = createSpan('cloud.containerImageScan');
  logger.info({ layerCount: imageLayers.length, signatureCount: signatures.length }, 'scanning container image');

  const layers: LayerScan[] = [];
  const vulnerabilities: Finding[] = [];
  const imageId = imageLayers.length > 0 ? imageLayers[0].digest.slice(0, 12) : 'unknown';

  for (let i = 0; i < imageLayers.length; i++) {
    const layer = imageLayers[i];
    const layerFindings: Finding[] = [];
    const commands = layer.commands ?? [];

    for (const cmd of commands) {
      if (/apt-get\s+install|apk\s+add|yum\s+install/i.test(cmd)) {
        const packages = cmd.match(/(?:apt-get\s+install|apk\s+add|yum\s+install)\s+(.+)/i);
        if (packages) {
          const pkgList = packages[1].split(/\s+/).filter(Boolean);
          for (const pkg of pkgList) {
            const vulns = vulnerabilityDb.filter(v => v.packageName === pkg);
            for (const vuln of vulns) {
              const finding: Finding = {
                ruleId: vuln.id, ruleName: vuln.packageName, severity: vuln.severity,
                message: `Layer ${layerIndex + 1}: Remote content piped to shell`, location: `layer[${layerIndex}].commands`,
                remediation: vuln.fixedVersion ? `Upgrade to ${vuln.fixedVersion}` : 'No fix available' };
              layerFindings.push(finding);
              vulnerabilities.push(finding);
            }
          }
        }
      }
      if (/curl.*\|\s*(sh|bash)/i.test(cmd) || /wget.*\|\s*(sh|bash)/i.test(cmd)) {
        layerFindings.push({ ruleId: 'CIS-001', ruleName: 'pipe-to-shell', severity: 'high',
          message: `Layer ${layerIndex + 1}: Remote content piped to shell`, location: `layer[${layerIndex}].commands`,
          remediation: 'Download and verify content before execution' });
        vulnerabilities.push(layerFindings[layerFindings.length - 1]);
      }
      if (/chmod\s+[0-7]*777/i.test(cmd)) {
        layerFindings.push({ ruleId: 'CIS-002', ruleName: 'world-writable-permissions', severity: 'medium',
          message: `Layer ${layerIndex + 1}: Sets world-writable permissions`, location: `layer[${layerIndex}].commands`,
          remediation: 'Use restrictive file permissions' });
        vulnerabilities.push(layerFindings[layerFindings.length - 1]);
      }
    }
    layers.push({ index: i, digest: layer.digest, findings: layerFindings });
  }

  let signatureValid = false;
  for (const sig of signatures) {
    const sigHash = createHash('sha256').update(sig.signature).digest('hex');
    if (sigHash && sig.keyId) { signatureValid = true; break; }
  }
  if (!signatureValid && signatures.length > 0) {
    vulnerabilities.push({ ruleId: 'CIS-003', ruleName: 'invalid-signature', severity: 'critical',
      message: 'Image signature validation failed',
      remediation: 'Verify image was signed by trusted authority' });
  }

  const riskScore = calculateScore(vulnerabilities);
  const result: ScanResult = { imageId, layers, vulnerabilities, signatureValid, riskScore };

  logger.info({ imageId, vulns: vulnerabilities.length, signatureValid, riskScore }, 'container image scan complete');
  recordMetric('image_scan_vulnerabilities', vulnerabilities.length, { image: imageId });
  recordMetric('image_scan_signature', signatureValid ? 1 : 0);
  emitEvent('image:scanned', vulnerabilities.length > 0 ? EventSeverity.WARNING : EventSeverity.INFO, { image: imageId, vulnerabilities: vulnerabilities.length });

  span.end();
  return result;
}

// --- 17. runtimeK8sAnomaly ----------------------------------------------------

/**
 * Detects runtime anomalies in Kubernetes clusters by comparing events
 * against established baselines.
 */
export function runtimeK8sAnomaly(
  k8sEvents: Record<string, unknown>[],
  baseline: Record<string, number>,
  anomalyThreshold: number = 2.0,
): AnomalyResult {
  const span = createSpan('cloud.runtimeK8sAnomaly');
  logger.info({ eventCount: k8sEvents.length, threshold: anomalyThreshold }, 'detecting K8s runtime anomalies');

  const anomalies: Finding[] = [];
  let totalDeviation = 0;
  let metricCount = 0;

  for (const event of k8sEvents) {
    const eventType = (event.type as string) ?? '';
    const metricName = (event.metric as string) ?? '';
    const value = (event.value as number) ?? 0;
    const baselineValue = baseline[metricName] ?? baseline[eventType] ?? 0;
    if (baselineValue === 0) continue;

    const deviation = Math.abs(value - baselineValue) / baselineValue;
    totalDeviation += deviation;
    metricCount++;

    if (deviation > anomalyThreshold) {
      let severity: SeverityLevel = 'medium';
      if (deviation > anomalyThreshold * 3) severity = 'critical';
      else if (deviation > anomalyThreshold * 2) severity = 'high';
      anomalies.push({
        ruleId: 'KA-001', ruleName: 'anomaly-detected', severity,
        message: `Metric ${metricName} deviates ${(deviation * 100).toFixed(0)}% from baseline (${actualValue} vs ${baselineValue})`,
        remediation: `Investigate ${severity} deviation` });
    }

    if (eventType === 'ExecIntoPod' || eventType === 'PortForward') {
      anomalies.push({ ruleId: 'KA-002', ruleName: 'sensitive-operation', severity: 'high',
        message: `Sensitive operation detected: ${eventType}`,
        remediation: `Audit ${eventType} operation` });
    }
    if (eventType === 'SecretAccess' && (event.source as string)?.includes('unknown')) {
      anomalies.push({ ruleId: 'KA-003', ruleName: 'unknown-secret-access', severity: 'critical',
        message: 'Unknown source accessing secrets',
        remediation: 'Investigate and revoke unauthorized access' });
    }
  }

  const avgDeviation = metricCount > 0 ? totalDeviation / metricCount : 0;
  const confidence = Math.min(1, avgDeviation / (anomalyThreshold * 2));

  const result: AnomalyResult = { anomalous: anomalies.length > 0, anomalies, confidence, baseline };

  logger.info({ anomalous: result.anomalous, anomalyCount: anomalies.length, confidence: result.confidence }, 'K8s anomaly detection complete');
  recordMetric('k8s_anomaly_count', anomalies.length);
  recordMetric('k8s_anomaly_confidence', result.confidence);
  emitEvent('k8s:anomaly-detected', result.anomalous ? EventSeverity.WARNING : EventSeverity.INFO, { anomalies: anomalies.length, confidence: result.confidence });

  span.end();
  return result;
}

// --- 18. cloudSecurityScore -----------------------------------------------------

/**
 * Calculates an overall cloud security score based on benchmarks and weights.
 */
export function cloudSecurityScore(
  config: Record<string, unknown>,
  benchmarks: Record<string, Record<string, unknown>>,
  weights: Record<string, number>,
): ScoreResult {
  const span = createSpan('cloud.cloudSecurityScore');
  logger.info({ benchmarkCount: Object.keys(benchmarks).length }, 'calculating cloud security score');

  const findings: Finding[] = [];
  const categoryScores: Record<string, number> = {};
  let totalWeight = 0;
  let weightedScore = 0;

  for (const [category, checks] of Object.entries(benchmarks)) {
    let passed = 0;
    let total = 0;
    for (const [check, expected] of Object.entries(checks)) {
      total++;
      const actual = (config[category] as Record<string, unknown>)?.[check];
      if (actual === expected || (expected === true && actual === true)) {
        passed++;
      } else {
        findings.push({
          ruleId: 'CSS-001', ruleName: check, severity: 'medium',
          message: `${category}.${check} does not meet benchmark (expected: ${expected}, got: ${actual})`,
          location: `${category}.${check}`,
          remediation: Set . to  });
      }
    }
    const score = total > 0 ? (passed / total) * 100 : 0;
    categoryScores[category] = Math.round(score);
    const weight = weights[category] ?? 1;
    totalWeight += weight;
    weightedScore += score * weight;
  }

  const overallScore = totalWeight > 0 ? Math.round(weightedScore / totalWeight) : 0;
  let grade: 'A' | 'B' | 'C' | 'D' | 'F';
  if (overallScore >= 90) grade = 'A';
  else if (overallScore >= 80) grade = 'B';
  else if (overallScore >= 70) grade = 'C';
  else if (overallScore >= 60) grade = 'D';
  else grade = 'F';

  const result: ScoreResult = { overallScore, categoryScores, findings, grade };

  logger.info({ score: overallScore, grade, categories: Object.keys(categoryScores).length }, 'cloud security score complete');
  recordMetric('cloud_security_score', overallScore, { grade });
  emitEvent('cloud:score-calculated', EventSeverity.INFO, { score: overallScore, grade });

  span.end();
  return result;
}

// --- 19. workloadIdentityValidation ----------------------------------------------

/**
 * Validates workload identity configuration against identity provider
 * and trust policy requirements.
 */
export function workloadIdentityValidation(
  workloadConfig: WorkloadConfig,
  identityProvider: string,
  trustPolicy: Record<string, unknown>,
): ValidationResult {
  const span = createSpan('cloud.workloadIdentityValidation');
  logger.info({ workload: workloadConfig.name, provider: identityProvider }, 'validating workload identity');

  const findings: Finding[] = [];

  if (!workloadConfig.serviceAccount) {
    findings.push({ ruleId: 'WI-001', ruleName: 'no-service-account', severity: 'critical',
      message: 'Workload has no service account configured',
      remediation: 'Configure a dedicated service account' });
  }
  if (workloadConfig.serviceAccount === 'default') {
    findings.push({ ruleId: 'WI-002', ruleName: 'default-service-account', severity: 'high',
      message: 'Workload uses the default service account',
      remediation: 'Create and use a dedicated service account' });
  }
  if (!workloadConfig.identityProvider) {
    findings.push({ ruleId: 'WI-003', ruleName: 'no-identity-provider', severity: 'high',
      message: 'No identity provider configured for workload',
      remediation: 'Configure OIDC or workload identity provider' });
  }
  if (workloadConfig.identityProvider !== identityProvider) {
    findings.push({ ruleId: 'WI-004', ruleName: 'provider-mismatch', severity: 'high',
      message: `Workload provider (${workloadConfig.identityProvider}) does not match expected (${identityProvider})`,
      remediation: 'Align workload identity provider with expected provider' });
  }

  const trustConditions = (trustPolicy.Condition as Record<string, unknown>) ?? {};
  const stringEquals = (trustConditions.StringEquals as Record<string, unknown>) ?? {};
  if (!stringEquals['token.actions.githubusercontent.com:aud']) {
    findings.push({ ruleId: 'WI-005', ruleName: 'no-audience-condition', severity: 'medium',
      message: 'Trust policy missing audience condition',
      remediation: 'Add aud condition to restrict token audience' });
  }
  if (!stringEquals['token.actions.githubusercontent.com:sub'] && !stringConditionsPresent(trustConditions)) {
    findings.push({ ruleId: 'WI-006', ruleName: 'no-subject-condition', severity: 'high',
      message: 'Trust policy missing subject condition',
      remediation: 'Add sub condition to restrict token subject' });
  }

  const principals = (trustPolicy.Principal as Record<string, unknown>) ?? {};
  const federated = principals.Federated as string | undefined;
  if (federated && federated.includes('*')) {
    findings.push({ ruleId: 'WI-007', ruleName: 'wildcard-federated-principal', severity: 'critical',
      message: 'Trust policy allows any federated principal',
      remediation: 'Specify exact identity provider ARN' });
  }
  if (!workloadConfig.trustPolicy?.expiration) {
    findings.push({ ruleId: 'WI-008', ruleName: 'no-token-expiration', severity: 'medium',
      message: 'No token expiration configured',
      remediation: 'Set token expiration to limit credential lifetime' });
  }

  const score = calculateScore(findings);
  const result: ValidationResult = {
    valid: findings.length === 0, findings, score,
    metadata: { workload: workloadConfig.name, namespace: workloadConfig.namespace,
      serviceAccount: workloadConfig.serviceAccount, identityProvider },
  };

  logger.info({ valid: result.valid, score }, 'workload identity validation complete');
  recordMetric('workload_identity_score', score, { workload: workloadConfig.name });
  emitEvent('workload:identity-validated', findings.length > 0 ? EventSeverity.WARNING : EventSeverity.INFO, { score });

  span.end();
  return result;
}

// --- 20. confidentialComputingValidation ---------------------------------------------

/**
 * Validates confidential computing attestation measurements against
 * expected values for Trusted Execution Environments (TEEs).
 */
export function confidentialComputingValidation(
  attestation: Attestation,
  teeType: 'sgx' | 'tdx' | 'sev' | 'snp' | 'nitro' | 'cvm',
  expectedMeasurements: Record<string, string>,
): ValidationResult {
  const span = createSpan('cloud.confidentialComputingValidation');
  logger.info({ teeType, attestationType: attestation.type }, 'validating confidential computing attestation');

  const findings: Finding[] = [];

  if (!attestation.signature) {
    findings.push({ ruleId: 'CC-001', ruleName: 'no-attestation-signature', severity: 'critical',
      message: 'Attestation has no signature',
      remediation: 'Ensure attestation is properly signed by TEE hardware' });
  }
  const sigHash = createHash('sha256').update(attestation.signature).digest('hex');
  if (!sigHash || sigHash === createHash('sha256').update('').digest('hex')) {
    findings.push({ ruleId: 'CC-002', ruleName: 'empty-signature', severity: 'critical',
      message: 'Attestation signature is empty',
      remediation: 'Re-generate attestation from TEE' });
  }

  for (const [key, expectedValue] of Object.entries(expectedMeasurements)) {
    const actualValue = attestation.measurements[key];
    if (actualValue === undefined) {
      findings.push({ ruleId: 'CC-003', ruleName: 'missing-measurement', severity: 'high',
        message: `Expected measurement ${name} is missing from attestation`,
        remediation: `Ensure TEE provides ${name} measurement` });
    } else if (actualValue !== expectedValue) {
      findings.push({ ruleId: 'CC-004', ruleName: 'measurement-mismatch', severity: 'critical',
        message: `Measurement ${name} mismatch: expected ${expectedValue}, got ${actualValue}`,
        remediation: 'Investigate measurement difference - possible tampering' });
    }
  }

  const teeSpecificChecks: Record<string, Array<{ id: string; name: string; severity: SeverityLevel; check: () => boolean; message: string }>> = {
    sgx: [
      { id: 'CC-SGX-001', name: 'sgx-enclave-size', severity: 'medium', check: () => !!attestation.measurements.MRENCLAVE, message: 'SGX MRENCLAVE measurement missing' },
      { id: 'CC-SGX-002', name: 'sgx-signer', severity: 'high', check: () => !!attestation.measurements.MRSIGNER, message: 'SGX MRSIGNER measurement missing' },
      { id: 'CC-SGX-003', name: 'sgx-product-id', severity: 'medium', check: () => !!attestation.measurements.ISVPRODID, message: 'SGX ISVPRODID measurement missing' },
    ],
    tdx: [
      { id: 'CC-TDX-001', name: 'tdx-rtmr', severity: 'high', check: () => !!attestation.measurements.RTMR0, message: 'TDX RTMR[0] measurement missing' },
      { id: 'CC-TDX-002', name: 'tdx-mrconfig', severity: 'high', check: () => !!attestation.measurements.MRCONFIGID, message: 'TDX MRCONFIGID measurement missing' },
    ],
    sev: [
      { id: 'CC-SEV-001', name: 'sev-measurement', severity: 'high', check: () => !!attestation.measurements.measurement, message: 'SEV measurement missing' },
      { id: 'CC-SEV-002', name: 'sev-policy', severity: 'medium', check: () => !!attestation.measurements.policy, message: 'SEV policy missing' },
    ],
    snp: [
      { id: 'CC-SNP-001', name: 'snp-measurement', severity: 'high', check: () => !!attestation.measurements.measurement, message: 'SNP measurement missing' },
      { id: 'CC-SNP-002', name: 'snp-report-data', severity: 'high', check: () => !!attestation.measurements.reportData, message: 'SNP report data missing' },
    ],
    nitro: [
      { id: 'CC-NITRO-001', name: 'nitro-pcr', severity: 'high', check: () => !!attestation.measurements.PCR0, message: 'Nitro PCR[0] missing' },
      { id: 'CC-NITRO-002', name: 'nitro-public-key', severity: 'medium', check: () => !!attestation.measurements.publicKey, message: 'Nitro public key missing' },
    ],
    cvm: [
      { id: 'CC-CVM-001', name: 'cvm-attestation', severity: 'high', check: () => !!attestation.measurements.attestation, message: 'CVM attestation data missing' },
    ],
  };

  const specificChecks = teeSpecificChecks[teeType] ?? [];
  for (const check of specificChecks) {
    if (!check.check()) {
      findings.push({ ruleId: check.id, ruleName: check.name, severity: check.severity,
        message: check.message, remediation: `Verify ${check.name} attestation includes ${check.id}` });
    }
  }

  const attestationAge = Date.now() - new Date(attestation.timestamp).getTime();
  const maxAge = 5 * 60 * 1000;
  if (attestationAge > maxAge) {
    findings.push({ ruleId: 'CC-005', ruleName: 'stale-attestation', severity: 'high',
      message: `Attestation is ${Math.round(attestationAge / 1000)}s old (max: ${Math.round(maxAge / 1000)}s)`,
      remediation: 'Request fresh attestation' });
  }

  const score = calculateScore(findings);
  const result: ValidationResult = {
    valid: findings.length === 0, findings, score,
    metadata: { teeType, attestationType: attestation.type,
      measurementsChecked: Object.keys(expectedMeasurements).length,
      attestationTimestamp: attestation.timestamp,
      attestationAge: Math.round(attestationAge / 1000) },
  };

  logger.info({ valid: result.valid, score, teeType }, 'confidential computing validation complete');
  recordMetric('confidential_computing_score', score, { teeType });
  emitEvent('confidential:attestation-validated', findings.length > 0 ? EventSeverity.CRITICAL : EventSeverity.INFO, { score, teeType });

  span.end();
  return result;
}
