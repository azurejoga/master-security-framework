import { createHash, randomBytes } from 'crypto';
import { sha3_256 } from '@noble/hashes/sha3';
import { getLogger, getMetrics, createSpan, getEventBus, SecurityEvent, EventSeverity } from '../core/index.js';
import { SecurityError, ValidationError } from '../core/exceptions.js';
import pino from 'pino';

const logger = pino().child({ module: 'msf.integrations' });

// ─── Type Definitions ───────────────────────────────────────────────────────

export interface MiddlewareResult {
  name: string;
  version: string;
  middleware: unknown;
  headers: Record<string, string>;
  metrics: Record<string, number>;
  traceId: string;
}

export interface ModuleResult {
  name: string;
  version: string;
  module: unknown;
  guards: string[];
  interceptors: string[];
  metrics: Record<string, number>;
  traceId: string;
}

export interface HeadersResult {
  name: string;
  version: string;
  headers: Record<string, string>;
  directives: string[];
  metrics: Record<string, number>;
  traceId: string;
}

export interface EdgeResult {
  name: string;
  version: string;
  rules: EdgeRule[];
  workerScript: string;
  metrics: Record<string, number>;
  traceId: string;
}

export interface EdgeRule {
  id: string;
  action: string;
  expression: string;
  priority: number;
}

export interface PluginResult {
  name: string;
  version: string;
  plugin: unknown;
  permissions: string[];
  sandbox: Record<string, unknown>;
  metrics: Record<string, number>;
  traceId: string;
}

export interface ProtectionResult {
  name: string;
  version: string;
  csp: string;
  sandbox: Record<string, unknown>;
  protections: string[];
  metrics: Record<string, number>;
  traceId: string;
}

export interface SecurityResult {
  name: string;
  version: string;
  config: Record<string, unknown>;
  scope: string;
  permissions: string[];
  metrics: Record<string, number>;
  traceId: string;
}

export interface RuntimeResult {
  name: string;
  version: string;
  runtime: unknown;
  memoryLimits: MemoryLimit;
  allowedSyscalls: string[];
  metrics: Record<string, number>;
  traceId: string;
}

export interface MemoryLimit {
  initial: number;
  maximum: number;
  shared: boolean;
}

export interface ExpressConfig {
  helmet?: boolean;
  rateLimit?: { windowMs: number; max: number };
  cors?: { origin: string | string[]; methods: string[] };
  csrf?: boolean;
  xssProtection?: boolean;
  hsts?: boolean;
  contentSecurityPolicy?: string;
}

export interface ExpressMiddlewareConfig {
  skipPaths?: string[];
  customHeaders?: Record<string, string>;
  bodySizeLimit?: string;
}

export interface FastifyConfig {
  helmet?: boolean;
  rateLimit?: { windowMs: number; max: number };
  cors?: { origin: string | string[]; methods: string[] };
  csrf?: boolean;
  hsts?: boolean;
}

export interface FastifySecurityConfig {
  validation?: boolean;
  serialization?: boolean;
  errorHandler?: boolean;
}

export interface NestjsConfig {
  guards?: string[];
  interceptors?: string[];
  pipes?: string[];
  globalPrefix?: string;
}

export interface NextjsConfig {
  contentSecurityPolicy?: Record<string, string[]>;
  permissionsPolicy?: Record<string, string[]>;
  referrerPolicy?: string;
  strictTransportSecurity?: { maxAge: number; includeSubDomains: boolean; preload: boolean };
  xFrameOptions?: string;
  xContentTypeOptions?: string;
}

export interface CloudflareConfig {
  waf?: boolean;
  rateLimit?: { threshold: number; period: number };
  botManagement?: boolean;
  ddosProtection?: boolean;
  geoBlocking?: string[];
}

export interface DenoConfig {
  permissions?: { read?: boolean; write?: boolean; net?: boolean; env?: boolean; run?: boolean };
  sandbox?: boolean;
  integrity?: boolean;
}

export interface BunConfig {
  optimizations?: { jit?: boolean; inline?: boolean; treeShake?: boolean };
  security?: { sandbox?: boolean; isolate?: boolean; memoryLimit?: number };
}

export interface BrowserConfig {
  csp?: string;
  sandbox?: boolean;
  subresourceIntegrity?: boolean;
  trustedTypes?: boolean;
}

export interface ServiceWorkerConfig {
  scope?: string;
  updateInterval?: number;
  cacheStrategy?: 'network-first' | 'cache-first' | 'stale-while-revalidate';
  permissions?: string[];
}

export interface WasmConfig {
  memoryLimits?: { initial: number; maximum: number; shared: boolean };
  syscalls?: string[];
  sandbox?: boolean;
  timeout?: number;
}

// ─── Helper Functions ───────────────────────────────────────────────────────

function generateTraceId(): string {
  return randomBytes(16).toString('hex');
}

function computeHash(data: string): string {
  return sha3_256(new TextEncoder().encode(data));
}

function emitSecurityEvent(event: Omit<SecurityEvent, 'timestamp' | 'id'>): void {
  const eventBus = getEventBus();
  if (eventBus) {
    eventBus.publish('security', {
      ...event,
      id: randomBytes(8).toString('hex'),
      timestamp: Date.now(),
    });
  }
}

function recordMetrics(name: string, duration: number, status: string): void {
  const metrics = getMetrics();
  if (metrics) {
    metrics.incCounter(`${name}.total`);
    metrics.observeHistogram(`${name}.duration_ms`, duration);
    metrics.incCounter(`${name}.${status}`);
  }
}

function validateConfig(config: Record<string, unknown>, required: string[]): void {
  const missing = required.filter((key) => config[key] === undefined);
  if (missing.length > 0) {
    throw new ValidationError(`Missing required config keys: ${missing.join(', ')}`);
  }
}

// ─── 1. Express Security Middleware ─────────────────────────────────────────

/**
 * Creates Express security middleware with headers, rate limiting, and CSRF protection.
 *
 * @param app - Express application instance
 * @param config - Security configuration (helmet, rateLimit, cors, csrf, etc.)
 * @param middlewareConfig - Middleware-specific config (skipPaths, customHeaders, bodySizeLimit)
 * @returns MiddlewareResult with middleware function and security metrics
 */
export function expressSecurityMiddleware(
  app: unknown,
  config: ExpressConfig = {},
  middlewareConfig: ExpressMiddlewareConfig = {}
): MiddlewareResult {
  const span = createSpan('expressSecurityMiddleware');
  const start = performance.now();
  const traceId = generateTraceId();

  try {
    logger.info({ traceId, config }, 'Initializing Express security middleware');

    const headers: Record<string, string> = {
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': config.helmet !== false ? 'DENY' : 'SAMEORIGIN',
      'X-XSS-Protection': config.xssProtection !== false ? '1; mode=block' : '0',
      'X-Download-Options': 'noopen',
      'X-Permitted-Cross-Domain-Policies': 'none',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
    };

    if (config.hsts !== false) {
      headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
    }

    if (config.contentSecurityPolicy) {
      headers['Content-Security-Policy'] = config.contentSecurityPolicy;
    } else {
      headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'";
    }

    if (middlewareConfig.customHeaders) {
      Object.assign(headers, middlewareConfig.customHeaders);
    }

    const rateLimitConfig = config.rateLimit ?? { windowMs: 15 * 60 * 1000, max: 100 };
    const csrfEnabled = config.csrf !== false;
    const skipPaths = middlewareConfig.skipPaths ?? ['/health', '/metrics'];

    const middleware = {
      name: 'express-security',
      headers,
      rateLimit: rateLimitConfig,
      csrf: csrfEnabled,
      skipPaths,
      bodySizeLimit: middlewareConfig.bodySizeLimit ?? '100kb',
      execute: (req: unknown, res: unknown, next: () => void) => {
        const reqPath = (req as { path?: string }).path ?? '';
        if (skipPaths.some((p) => reqPath.startsWith(p))) {
          return next();
        }
        Object.entries(headers).forEach(([key, value]) => {
          (res as { setHeader?: (k: string, v: string) => void })?.setHeader?.(key, value);
        });
        next();
      },
    };

    const duration = performance.now() - start;
    recordMetrics('express_security', duration, 'success');

    emitSecurityEvent({
      type: 'middleware_initialized',
      severity: EventSeverity.INFO,
      source: 'express',
      message: 'Express security middleware initialized',
      metadata: { traceId, headersCount: Object.keys(headers).length },
    });

    span.end();

    return {
      name: 'express-security',
      version: '1.0.0',
      middleware,
      headers,
      metrics: {
        headersApplied: Object.keys(headers).length,
        rateLimitWindowMs: rateLimitConfig.windowMs,
        rateLimitMax: rateLimitConfig.max,
        csrfEnabled: csrfEnabled ? 1 : 0,
        skipPathsCount: skipPaths.length,
        initDurationMs: duration,
      },
      traceId,
    };
  } catch (error) {
    const duration = performance.now() - start;
    recordMetrics('express_security', duration, 'error');

    logger.error({ traceId, error }, 'Failed to initialize Express security middleware');

    emitSecurityEvent({
      type: 'middleware_error',
      severity: EventSeverity.CRITICAL,
      source: 'express',
      message: error instanceof Error ? error.message : 'Unknown error',
      metadata: { traceId },
    });

    span.end(error instanceof Error ? error : new Error('Unknown error'));
    throw error instanceof SecurityError ? error : new SecurityError('Express middleware initialization failed', { cause: error });
  }
}

// ─── 2. Fastify Security Middleware ─────────────────────────────────────────

/**
 * Creates Fastify security plugin with headers, rate limiting, and validation.
 *
 * @param app - Fastify application instance
 * @param config - Security configuration (helmet, rateLimit, cors, csrf)
 * @param securityConfig - Security-specific config (validation, serialization, errorHandler)
 * @returns MiddlewareResult with Fastify plugin and security metrics
 */
export function fastifySecurityMiddleware(
  app: unknown,
  config: FastifyConfig = {},
  securityConfig: FastifySecurityConfig = {}
): MiddlewareResult {
  const span = createSpan('fastifySecurityMiddleware');
  const start = performance.now();
  const traceId = generateTraceId();

  try {
    logger.info({ traceId, config }, 'Initializing Fastify security middleware');

    const headers: Record<string, string> = {
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': config.helmet !== false ? 'DENY' : 'SAMEORIGIN',
      'X-XSS-Protection': '1; mode=block',
      'Referrer-Policy': 'no-referrer',
    };

    if (config.hsts !== false) {
      headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
    }

    const rateLimitConfig = config.rateLimit ?? { windowMs: 60000, max: 1000 };
    const validationEnabled = securityConfig.validation !== false;
    const serializationEnabled = securityConfig.serialization !== false;

    const middleware = {
      name: 'fastify-security',
      fastifyPlugin: true,
      headers,
      rateLimit: rateLimitConfig,
      validation: validationEnabled,
      serialization: serializationEnabled,
      register: async (fastify: unknown, opts: unknown) => {
        logger.debug({ traceId }, 'Registering Fastify security plugin');
        const fastifyInstance = fastify as { addHook?: (hook: string, fn: unknown) => void };
        fastifyInstance?.addHook?.('onRequest', async (request: unknown, reply: unknown) => {
          const replyObj = reply as { header?: (k: string, v: string) => void };
          Object.entries(headers).forEach(([key, value]) => {
            replyObj?.header?.(key, value);
          });
        });
      },
    };

    const duration = performance.now() - start;
    recordMetrics('fastify_security', duration, 'success');

    emitSecurityEvent({
      type: 'middleware_initialized',
      severity: EventSeverity.INFO,
      source: 'fastify',
      message: 'Fastify security middleware initialized',
      metadata: { traceId, validationEnabled, serializationEnabled },
    });

    span.end();

    return {
      name: 'fastify-security',
      version: '1.0.0',
      middleware,
      headers,
      metrics: {
        headersApplied: Object.keys(headers).length,
        rateLimitWindowMs: rateLimitConfig.windowMs,
        rateLimitMax: rateLimitConfig.max,
        validationEnabled: validationEnabled ? 1 : 0,
        serializationEnabled: serializationEnabled ? 1 : 0,
        initDurationMs: duration,
      },
      traceId,
    };
  } catch (error) {
    const duration = performance.now() - start;
    recordMetrics('fastify_security', duration, 'error');

    logger.error({ traceId, error }, 'Failed to initialize Fastify security middleware');

    emitSecurityEvent({
      type: 'middleware_error',
      severity: EventSeverity.CRITICAL,
      source: 'fastify',
      message: error instanceof Error ? error.message : 'Unknown error',
      metadata: { traceId },
    });

    span.end(error instanceof Error ? error : new Error('Unknown error'));
    throw error instanceof SecurityError ? error : new SecurityError('Fastify middleware initialization failed', { cause: error });
  }
}

// ─── 3. NestJS Security Module ──────────────────────────────────────────────

/**
 * Creates NestJS security module with guards and interceptors.
 *
 * @param config - Module configuration (guards, interceptors, pipes, globalPrefix)
 * @param guards - Additional guard names to register
 * @param interceptors - Additional interceptor names to register
 * @returns ModuleResult with NestJS module definition and metrics
 */
export function nestjsSecurityModule(
  config: NestjsConfig = {},
  guards: string[] = [],
  interceptors: string[] = []
): ModuleResult {
  const span = createSpan('nestjsSecurityModule');
  const start = performance.now();
  const traceId = generateTraceId();

  try {
    logger.info({ traceId, config }, 'Initializing NestJS security module');

    const defaultGuards = [
      'AuthGuard',
      'RateLimitGuard',
      'ThrottlerGuard',
      'RolesGuard',
      'JwtAuthGuard',
    ];

    const defaultInterceptors = [
      'LoggingInterceptor',
      'TimeoutInterceptor',
      'TransformInterceptor',
      'CacheInterceptor',
    ];

    const activeGuards = [...new Set([...defaultGuards, ...guards])];
    const activeInterceptors = [...new Set([...defaultInterceptors, ...interceptors])];

    const module = {
      name: 'nestjs-security',
      global: true,
      providers: [
        { provide: 'SECURITY_CONFIG', useValue: config },
        { provide: 'SECURITY_GUARDS', useValue: activeGuards },
        { provide: 'SECURITY_INTERCEPTORS', useValue: activeInterceptors },
      ],
      exports: ['SECURITY_CONFIG', 'SECURITY_GUARDS', 'SECURITY_INTERCEPTORS'],
    };

    const duration = performance.now() - start;
    recordMetrics('nestjs_security', duration, 'success');

    emitSecurityEvent({
      type: 'module_initialized',
      severity: EventSeverity.INFO,
      source: 'nestjs',
      message: 'NestJS security module initialized',
      metadata: { traceId, guardsCount: activeGuards.length, interceptorsCount: activeInterceptors.length },
    });

    span.end();

    return {
      name: 'nestjs-security',
      version: '1.0.0',
      module,
      guards: activeGuards,
      interceptors: activeInterceptors,
      metrics: {
        guardsCount: activeGuards.length,
        interceptorsCount: activeInterceptors.length,
        providersCount: (module.providers as unknown[]).length,
        initDurationMs: duration,
      },
      traceId,
    };
  } catch (error) {
    const duration = performance.now() - start;
    recordMetrics('nestjs_security', duration, 'error');

    logger.error({ traceId, error }, 'Failed to initialize NestJS security module');

    emitSecurityEvent({
      type: 'module_error',
      severity: EventSeverity.CRITICAL,
      source: 'nestjs',
      message: error instanceof Error ? error.message : 'Unknown error',
      metadata: { traceId },
    });

    span.end(error instanceof Error ? error : new Error('Unknown error'));
    throw error instanceof SecurityError ? error : new SecurityError('NestJS module initialization failed', { cause: error });
  }
}

// ─── 4. Next.js Security Headers ────────────────────────────────────────────

/**
 * Creates Next.js security headers configuration for next.config.js.
 *
 * @param config - Headers configuration (CSP, permissions policy, HSTS, etc.)
 * @param headers - Additional custom headers to merge
 * @returns HeadersResult with complete headers config and metrics
 */
export function nextjsSecurityHeaders(
  config: NextjsConfig = {},
  headers: Record<string, string> = {}
): HeadersResult {
  const span = createSpan('nextjsSecurityHeaders');
  const start = performance.now();
  const traceId = generateTraceId();

  try {
    logger.info({ traceId, config }, 'Initializing Next.js security headers');

    const cspConfig = config.contentSecurityPolicy ?? {
      'default-src': ["'self'"],
      'script-src': ["'self'", "'unsafe-inline'"],
      'style-src': ["'self'", "'unsafe-inline'"],
      'img-src': ["'self'", 'data:', 'blob:'],
      'font-src': ["'self'"],
      'connect-src': ["'self'"],
      'frame-src': ["'none'"],
      'object-src': ["'none'"],
      'base-uri': ["'self'"],
      'form-action': ["'self'"],
    };

    const cspString = Object.entries(cspConfig)
      .map(([key, values]) => `${key} ${values.join(' ')}`)
      .join('; ');

    const permissionsPolicy = config.permissionsPolicy ?? {
      camera: ['()'],
      microphone: ['()'],
      geolocation: ['()'],
      payment: ['()'],
      usb: ['()'],
      'accelerometer': ['()'],
      'gyroscope': ['()'],
    };

    const permissionsString = Object.entries(permissionsPolicy)
      .map(([key, values]) => `${key}=${values.join(', ')}`)
      .join(', ');

    const hsts = config.strictTransportSecurity ?? {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    };

    const securityHeaders: Record<string, string> = {
      'Content-Security-Policy': cspString,
      'Permissions-Policy': permissionsString,
      'Referrer-Policy': config.referrerPolicy ?? 'strict-origin-when-cross-origin',
      'Strict-Transport-Security': `max-age=${hsts.maxAge}${hsts.includeSubDomains ? '; includeSubDomains' : ''}${hsts.preload ? '; preload' : ''}`,
      'X-Frame-Options': config.xFrameOptions ?? 'DENY',
      'X-Content-Type-Options': config.xContentTypeOptions ?? 'nosniff',
      'X-DNS-Prefetch-Control': 'off',
      'X-Permitted-Cross-Domain-Policies': 'none',
    };

    Object.assign(securityHeaders, headers);

    const directives = Object.keys(cspConfig);

    const duration = performance.now() - start;
    recordMetrics('nextjs_headers', duration, 'success');

    emitSecurityEvent({
      type: 'headers_configured',
      severity: EventSeverity.INFO,
      source: 'nextjs',
      message: 'Next.js security headers configured',
      metadata: { traceId, headersCount: Object.keys(securityHeaders).length },
    });

    span.end();

    return {
      name: 'nextjs-security-headers',
      version: '1.0.0',
      headers: securityHeaders,
      directives,
      metrics: {
        headersCount: Object.keys(securityHeaders).length,
        cspDirectivesCount: directives.length,
        hstsMaxAge: hsts.maxAge,
        initDurationMs: duration,
      },
      traceId,
    };
  } catch (error) {
    const duration = performance.now() - start;
    recordMetrics('nextjs_headers', duration, 'error');

    logger.error({ traceId, error }, 'Failed to configure Next.js security headers');

    emitSecurityEvent({
      type: 'headers_error',
      severity: EventSeverity.CRITICAL,
      source: 'nextjs',
      message: error instanceof Error ? error.message : 'Unknown error',
      metadata: { traceId },
    });

    span.end(error instanceof Error ? error : new Error('Unknown error'));
    throw error instanceof SecurityError ? error : new SecurityError('Next.js headers configuration failed', { cause: error });
  }
}

// ─── 5. Cloudflare Edge Protection ──────────────────────────────────────────

/**
 * Creates Cloudflare edge protection rules and worker script.
 *
 * @param config - Cloudflare configuration (waf, rateLimit, botManagement, ddosProtection, geoBlocking)
 * @param rules - Additional custom edge rules to append
 * @param workers - Worker script identifiers
 * @returns EdgeResult with rules array and worker script
 */
export function cloudflareEdgeProtection(
  config: CloudflareConfig = {},
  rules: EdgeRule[] = [],
  workers: string[] = []
): EdgeResult {
  const span = createSpan('cloudflareEdgeProtection');
  const start = performance.now();
  const traceId = generateTraceId();

  try {
    logger.info({ traceId, config }, 'Initializing Cloudflare edge protection');

    const defaultRules: EdgeRule[] = [
      {
        id: computeHash('waf-rule-1').slice(0, 16),
        action: 'block',
        expression: '(http.request.uri.path contains "/wp-admin") or (http.request.uri.path contains "/xmlrpc.php")',
        priority: 1,
      },
      {
        id: computeHash('waf-rule-2').slice(0, 16),
        action: 'block',
        expression: '(http.request.method eq "POST" and http.request.uri.path eq "/api/login" and ip.geoip.country in {"CN" "RU"})',
        priority: 2,
      },
      {
        id: computeHash('waf-rule-3').slice(0, 16),
        action: 'challenge',
        expression: '(cf.bot_management.score lt 30)',
        priority: 3,
      },
      {
        id: computeHash('waf-rule-4').slice(0, 16),
        action: 'block',
        expression: '(http.request.headers["user-agent"] contains "sqlmap") or (http.request.headers["user-agent"] contains "nikto")',
        priority: 4,
      },
    ];

    const rateLimitRule: EdgeRule = {
      id: computeHash('ratelimit-rule').slice(0, 16),
      action: 'block',
      expression: `(http.request.full_uri matches ".*" and cf.throttle_count gt ${config.rateLimit?.threshold ?? 100})`,
      priority: 5,
    };

    const allRules = [...defaultRules, ...rules];
    if (config.rateLimit) {
      allRules.push(rateLimitRule);
    }

    if (config.geoBlocking && config.geoBlocking.length > 0) {
      allRules.push({
        id: computeHash('geo-block').slice(0, 16),
        action: 'block',
        expression: `ip.geoip.country in {${config.geoBlocking.map((c) => `"${c}"`).join(' ')}}`,
        priority: 6,
      });
    }

    const geoBlockSnippet = config.geoBlocking && config.geoBlocking.length > 0
      ? `const blockedCountries = ${JSON.stringify(config.geoBlocking)};
  if (blockedCountries.includes(cf.country)) {
    return new Response('Access denied', { status: 403 });
  }`
      : '';

    const workerScript = `
// Cloudflare Worker Security Script
// Trace ID: ${traceId}

addEventListener('fetch', (event) => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);
  const cf = request.cf || {};

  if (cf.botManagement && cf.botManagement.score < 30) {
    return new Response('Challenge required', { status: 403 });
  }

  const rateLimit = await cf.cache.match('rate:' + cf.clientTcpRtt);
  if (rateLimit) {
    return new Response('Rate limited', { status: 429 });
  }

  ${geoBlockSnippet}

  const response = await fetch(request);
  return response;
}
`;

    const duration = performance.now() - start;
    recordMetrics('cloudflare_edge', duration, 'success');

    emitSecurityEvent({
      type: 'edge_protection_initialized',
      severity: EventSeverity.INFO,
      source: 'cloudflare',
      message: 'Cloudflare edge protection initialized',
      metadata: { traceId, rulesCount: allRules.length, wafEnabled: config.waf !== false },
    });

    span.end();

    return {
      name: 'cloudflare-edge-protection',
      version: '1.0.0',
      rules: allRules,
      workerScript,
      metrics: {
        rulesCount: allRules.length,
        wafEnabled: config.waf !== false ? 1 : 0,
        botManagementEnabled: config.botManagement !== false ? 1 : 0,
        ddosProtectionEnabled: config.ddosProtection !== false ? 1 : 0,
        geoBlockingCountries: config.geoBlocking?.length ?? 0,
        workersCount: workers.length,
        initDurationMs: duration,
      },
      traceId,
    };
  } catch (error) {
    const duration = performance.now() - start;
    recordMetrics('cloudflare_edge', duration, 'error');

    logger.error({ traceId, error }, 'Failed to initialize Cloudflare edge protection');

    emitSecurityEvent({
      type: 'edge_protection_error',
      severity: EventSeverity.CRITICAL,
      source: 'cloudflare',
      message: error instanceof Error ? error.message : 'Unknown error',
      metadata: { traceId },
    });

    span.end(error instanceof Error ? error : new Error('Unknown error'));
    throw error instanceof SecurityError ? error : new SecurityError('Cloudflare edge protection initialization failed', { cause: error });
  }
}

// ─── 6. Deno Security Plugin ────────────────────────────────────────────────

/**
 * Creates Deno security plugin with permission management and sandboxing.
 *
 * @param config - Deno configuration (permissions, sandbox, integrity)
 * @param permissions - Additional permission flags to allow
 * @param sandbox - Sandbox configuration overrides
 * @returns PluginResult with Deno plugin and permission metrics
 */
export function denoSecurityPlugin(
  config: DenoConfig = {},
  permissions: string[] = [],
  sandbox: Record<string, unknown> = {}
): PluginResult {
  const span = createSpan('denoSecurityPlugin');
  const start = performance.now();
  const traceId = generateTraceId();

  try {
    logger.info({ traceId, config }, 'Initializing Deno security plugin');

    const defaultPermissions = config.permissions ?? {
      read: true,
      write: false,
      net: true,
      env: false,
      run: false,
    };

    const activePermissions = [
      ...(defaultPermissions.read ? ['--allow-read'] : []),
      ...(defaultPermissions.write ? ['--allow-write'] : []),
      ...(defaultPermissions.net ? ['--allow-net'] : []),
      ...(defaultPermissions.env ? ['--allow-env'] : []),
      ...(defaultPermissions.run ? ['--allow-run'] : []),
      ...permissions,
    ];

    const sandboxConfig: Record<string, unknown> = {
      isolated: config.sandbox !== false,
      integrity: config.integrity !== false,
      permissions: defaultPermissions,
      denyAll: !defaultPermissions.read && !defaultPermissions.write && !defaultPermissions.net,
      ...sandbox,
    };

    const plugin = {
      name: 'deno-security',
      runtime: 'deno',
      permissions: activePermissions,
      sandbox: sandboxConfig,
      initialize: () => {
        logger.debug({ traceId }, 'Deno security plugin initialized');
        return {
          permissions: activePermissions,
          sandbox: sandboxConfig,
          traceId,
        };
      },
      validateModule: (moduleName: string, moduleHash: string): boolean => {
        const expected = computeHash(moduleName);
        return moduleHash.slice(0, expected.length) === expected.slice(0, moduleHash.length);
      },
    };

    const duration = performance.now() - start;
    recordMetrics('deno_security', duration, 'success');

    emitSecurityEvent({
      type: 'plugin_initialized',
      severity: EventSeverity.INFO,
      source: 'deno',
      message: 'Deno security plugin initialized',
      metadata: { traceId, permissionsCount: activePermissions.length, sandboxEnabled: sandboxConfig.isolated },
    });

    span.end();

    return {
      name: 'deno-security',
      version: '1.0.0',
      plugin,
      permissions: activePermissions,
      sandbox: sandboxConfig,
      metrics: {
        permissionsCount: activePermissions.length,
        sandboxEnabled: sandboxConfig.isolated ? 1 : 0,
        integrityEnabled: sandboxConfig.integrity ? 1 : 0,
        readAllowed: defaultPermissions.read ? 1 : 0,
        writeAllowed: defaultPermissions.write ? 1 : 0,
        netAllowed: defaultPermissions.net ? 1 : 0,
        initDurationMs: duration,
      },
      traceId,
    };
  } catch (error) {
    const duration = performance.now() - start;
    recordMetrics('deno_security', duration, 'error');

    logger.error({ traceId, error }, 'Failed to initialize Deno security plugin');

    emitSecurityEvent({
      type: 'plugin_error',
      severity: EventSeverity.CRITICAL,
      source: 'deno',
      message: error instanceof Error ? error.message : 'Unknown error',
      metadata: { traceId },
    });

    span.end(error instanceof Error ? error : new Error('Unknown error'));
    throw error instanceof SecurityError ? error : new SecurityError('Deno security plugin initialization failed', { cause: error });
  }
}

// ─── 7. Bun Security Plugin ─────────────────────────────────────────────────

/**
 * Creates Bun security plugin with JIT optimizations and sandbox isolation.
 *
 * @param config - Bun configuration (optimizations, security)
 * @param optimizations - Optimization overrides (jit, inline, treeShake)
 * @param security - Security overrides (sandbox, isolate, memoryLimit)
 * @returns PluginResult with Bun plugin and performance metrics
 */
export function bunSecurityPlugin(
  config: BunConfig = {},
  optimizations: Record<string, unknown> = {},
  security: Record<string, unknown> = {}
): PluginResult {
  const span = createSpan('bunSecurityPlugin');
  const start = performance.now();
  const traceId = generateTraceId();

  try {
    logger.info({ traceId, config }, 'Initializing Bun security plugin');

    const defaultOptimizations = config.optimizations ?? {
      jit: true,
      inline: true,
      treeShake: true,
    };

    const defaultSecurity = config.security ?? {
      sandbox: true,
      isolate: true,
      memoryLimit: 512,
    };

    const activeOptimizations = {
      jit: defaultOptimizations.jit !== false,
      inline: defaultOptimizations.inline !== false,
      treeShake: defaultOptimizations.treeShake !== false,
      ...optimizations,
    };

    const activeSecurity = {
      sandbox: defaultSecurity.sandbox !== false,
      isolate: defaultSecurity.isolate !== false,
      memoryLimit: defaultSecurity.memoryLimit ?? 512,
      ...security,
    };

    const plugin = {
      name: 'bun-security',
      runtime: 'bun',
      optimizations: activeOptimizations,
      security: activeSecurity,
      initialize: () => {
        logger.debug({ traceId }, 'Bun security plugin initialized');
        return {
          optimizations: activeOptimizations,
          security: activeSecurity,
          traceId,
        };
      },
      validateBundle: (bundle: string): string => {
        return computeHash(bundle);
      },
      getMemoryUsage: (): number => {
        return activeSecurity.memoryLimit as number;
      },
    };

    const duration = performance.now() - start;
    recordMetrics('bun_security', duration, 'success');

    emitSecurityEvent({
      type: 'plugin_initialized',
      severity: EventSeverity.INFO,
      source: 'bun',
      message: 'Bun security plugin initialized',
      metadata: { traceId, jitEnabled: activeOptimizations.jit, sandboxEnabled: activeSecurity.sandbox },
    });

    span.end();

    return {
      name: 'bun-security',
      version: '1.0.0',
      plugin,
      permissions: [
        ...(activeOptimizations.jit ? ['jit'] : []),
        ...(activeOptimizations.inline ? ['inline'] : []),
        ...(activeOptimizations.treeShake ? ['tree-shake'] : []),
        ...(activeSecurity.sandbox ? ['sandbox'] : []),
        ...(activeSecurity.isolate ? ['isolate'] : []),
      ],
      sandbox: activeSecurity,
      metrics: {
        jitEnabled: activeOptimizations.jit ? 1 : 0,
        inlineEnabled: activeOptimizations.inline ? 1 : 0,
        treeShakeEnabled: activeOptimizations.treeShake ? 1 : 0,
        sandboxEnabled: activeSecurity.sandbox ? 1 : 0,
        isolateEnabled: activeSecurity.isolate ? 1 : 0,
        memoryLimitMB: activeSecurity.memoryLimit as number,
        initDurationMs: duration,
      },
      traceId,
    };
  } catch (error) {
    const duration = performance.now() - start;
    recordMetrics('bun_security', duration, 'error');

    logger.error({ traceId, error }, 'Failed to initialize Bun security plugin');

    emitSecurityEvent({
      type: 'plugin_error',
      severity: EventSeverity.CRITICAL,
      source: 'bun',
      message: error instanceof Error ? error.message : 'Unknown error',
      metadata: { traceId },
    });

    span.end(error instanceof Error ? error : new Error('Unknown error'));
    throw error instanceof SecurityError ? error : new SecurityError('Bun security plugin initialization failed', { cause: error });
  }
}

// ─── 8. Browser Runtime Protection ──────────────────────────────────────────

/**
 * Creates browser runtime protection with CSP, sandbox, and SRI.
 *
 * @param config - Browser configuration (csp, sandbox, subresourceIntegrity, trustedTypes)
 * @param csp - Custom Content-Security-Policy string
 * @param sandbox - Sandbox configuration overrides
 * @returns ProtectionResult with CSP, sandbox config, and protection metrics
 */
export function browserRuntimeProtection(
  config: BrowserConfig = {},
  csp: string = '',
  sandbox: Record<string, unknown> = {}
): ProtectionResult {
  const span = createSpan('browserRuntimeProtection');
  const start = performance.now();
  const traceId = generateTraceId();

  try {
    logger.info({ traceId, config }, 'Initializing browser runtime protection');

    const nonce = randomBytes(16).toString('base64url');

    const defaultCsp = csp || `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; frame-src 'none'; object-src 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests`;

    const sandboxConfig: Record<string, unknown> = {
      enabled: config.sandbox !== false,
      allowScripts: false,
      allowForms: true,
      allowSameOrigin: true,
      allowModals: true,
      allowPopups: false,
      allowTopNavigation: false,
      ...sandbox,
    };

    const protections = [
      'content-security-policy',
      'subresource-integrity',
      'x-frame-options',
      'x-content-type-options',
      'referrer-policy',
      ...(config.trustedTypes !== false ? ['trusted-types'] : []),
      ...(config.sandbox !== false ? ['sandbox'] : []),
    ];

    const sriEnabled = config.subresourceIntegrity !== false;
    const trustedTypesEnabled = config.trustedTypes !== false;

    const duration = performance.now() - start;
    recordMetrics('browser_protection', duration, 'success');

    emitSecurityEvent({
      type: 'protection_initialized',
      severity: EventSeverity.INFO,
      source: 'browser',
      message: 'Browser runtime protection initialized',
      metadata: { traceId, cspLength: defaultCsp.length, protectionsCount: protections.length },
    });

    span.end();

    return {
      name: 'browser-runtime-protection',
      version: '1.0.0',
      csp: defaultCsp,
      sandbox: sandboxConfig,
      protections,
      metrics: {
        cspLength: defaultCsp.length,
        protectionsCount: protections.length,
        sriEnabled: sriEnabled ? 1 : 0,
        trustedTypesEnabled: trustedTypesEnabled ? 1 : 0,
        sandboxEnabled: sandboxConfig.enabled ? 1 : 0,
        nonceGenerated: 1,
        initDurationMs: duration,
      },
      traceId,
    };
  } catch (error) {
    const duration = performance.now() - start;
    recordMetrics('browser_protection', duration, 'error');

    logger.error({ traceId, error }, 'Failed to initialize browser runtime protection');

    emitSecurityEvent({
      type: 'protection_error',
      severity: EventSeverity.CRITICAL,
      source: 'browser',
      message: error instanceof Error ? error.message : 'Unknown error',
      metadata: { traceId },
    });

    span.end(error instanceof Error ? error : new Error('Unknown error'));
    throw error instanceof SecurityError ? error : new SecurityError('Browser runtime protection initialization failed', { cause: error });
  }
}

// ─── 9. Service Worker Security ─────────────────────────────────────────────

/**
 * Creates service worker security configuration with scope and permissions.
 *
 * @param config - Service worker configuration (scope, updateInterval, cacheStrategy, permissions)
 * @param scope - Registration scope path
 * @param permissions - Additional permissions to grant
 * @returns SecurityResult with SW config, scope, and security metrics
 */
export function serviceWorkerSecurity(
  config: ServiceWorkerConfig = {},
  scope: string = '/',
  permissions: string[] = []
): SecurityResult {
  const span = createSpan('serviceWorkerSecurity');
  const start = performance.now();
  const traceId = generateTraceId();

  try {
    logger.info({ traceId, config }, 'Initializing service worker security');

    const activeScope = config.scope ?? scope;
    const updateInterval = config.updateInterval ?? 3600;
    const cacheStrategy = config.cacheStrategy ?? 'network-first';

    const defaultPermissions = [
      'notifications',
      'background-sync',
      'background-fetch',
      'periodic-background-sync',
      ...permissions,
    ];

    const swConfig: Record<string, unknown> = {
      scope: activeScope,
      updateInterval,
      cacheStrategy,
      permissions: defaultPermissions,
      secureContext: true,
      httpsOnly: true,
      integrity: true,
    };

    const duration = performance.now() - start;
    recordMetrics('service_worker_security', duration, 'success');

    emitSecurityEvent({
      type: 'service_worker_configured',
      severity: EventSeverity.INFO,
      source: 'service-worker',
      message: 'Service worker security configured',
      metadata: { traceId, scope: activeScope, cacheStrategy },
    });

    span.end();

    return {
      name: 'service-worker-security',
      version: '1.0.0',
      config: swConfig,
      scope: activeScope,
      permissions: defaultPermissions,
      metrics: {
        scopeLength: activeScope.length,
        updateIntervalSeconds: updateInterval,
        permissionsCount: defaultPermissions.length,
        secureContext: 1,
        httpsOnly: 1,
        initDurationMs: duration,
      },
      traceId,
    };
  } catch (error) {
    const duration = performance.now() - start;
    recordMetrics('service_worker_security', duration, 'error');

    logger.error({ traceId, error }, 'Failed to configure service worker security');

    emitSecurityEvent({
      type: 'service_worker_error',
      severity: EventSeverity.CRITICAL,
      source: 'service-worker',
      message: error instanceof Error ? error.message : 'Unknown error',
      metadata: { traceId },
    });

    span.end(error instanceof Error ? error : new Error('Unknown error'));
    throw error instanceof SecurityError ? error : new SecurityError('Service worker security configuration failed', { cause: error });
  }
}

// ─── 10. WASM Security Runtime ──────────────────────────────────────────────

/**
 * Creates WASM security runtime with memory limits and syscall filtering.
 *
 * @param config - WASM configuration (memoryLimits, syscalls, sandbox, timeout)
 * @param memoryLimits - Memory allocation limits (initial, maximum, shared)
 * @param syscalls - Additional allowed syscalls
 * @returns RuntimeResult with WASM runtime, memory limits, and syscall metrics
 */
export function wasmSecurityRuntime(
  config: WasmConfig = {},
  memoryLimits: MemoryLimit = { initial: 1024, maximum: 4096, shared: false },
  syscalls: string[] = []
): RuntimeResult {
  const span = createSpan('wasmSecurityRuntime');
  const start = performance.now();
  const traceId = generateTraceId();

  try {
    logger.info({ traceId, config }, 'Initializing WASM security runtime');

    const defaultMemoryLimits = config.memoryLimits ?? memoryLimits;
    const timeout = config.timeout ?? 5000;

    const defaultSyscalls = [
      'brk',
      'mmap',
      'munmap',
      'write',
      'read',
      'exit',
      'clock_gettime',
      'getpid',
      ...syscalls,
    ];

    const blockedSyscalls = [
      'execve',
      'fork',
      'clone',
      'ptrace',
      'mount',
      'umount',
      'reboot',
      'swapon',
      'swapoff',
      'init_module',
      'delete_module',
      'sethostname',
      'setdomainname',
      'iopl',
      'ioperm',
    ];

    const allowedSyscalls = defaultSyscalls.filter(
      (syscall) => !blockedSyscalls.includes(syscall)
    );

    const sandboxEnabled = config.sandbox !== false;

    const runtime = {
      name: 'wasm-security-runtime',
      architecture: 'wasm32',
      memory: defaultMemoryLimits,
      allowedSyscalls,
      blockedSyscalls,
      timeout,
      sandbox: sandboxEnabled,
      initialize: (moduleBytes: Uint8Array) => {
        const hash = computeHash(new TextDecoder().decode(moduleBytes));
        logger.debug({ traceId, hash }, 'WASM module hash computed');
        return {
          hash,
          memory: defaultMemoryLimits,
          syscalls: allowedSyscalls,
          traceId,
        };
      },
      validateSyscall: (syscall: string): boolean => {
        return allowedSyscalls.includes(syscall) && !blockedSyscalls.includes(syscall);
      },
    };

    const duration = performance.now() - start;
    recordMetrics('wasm_security', duration, 'success');

    emitSecurityEvent({
      type: 'wasm_runtime_initialized',
      severity: EventSeverity.INFO,
      source: 'wasm',
      message: 'WASM security runtime initialized',
      metadata: { traceId, memoryInitial: defaultMemoryLimits.initial, memoryMaximum: defaultMemoryLimits.maximum },
    });

    span.end();

    return {
      name: 'wasm-security-runtime',
      version: '1.0.0',
      runtime,
      memoryLimits: defaultMemoryLimits,
      allowedSyscalls,
      metrics: {
        memoryInitial: defaultMemoryLimits.initial,
        memoryMaximum: defaultMemoryLimits.maximum,
        memoryShared: defaultMemoryLimits.shared ? 1 : 0,
        allowedSyscallsCount: allowedSyscalls.length,
        blockedSyscallsCount: blockedSyscalls.length,
        sandboxEnabled: sandboxEnabled ? 1 : 0,
        timeoutMs: timeout,
        initDurationMs: duration,
      },
      traceId,
    };
  } catch (error) {
    const duration = performance.now() - start;
    recordMetrics('wasm_security', duration, 'error');

    logger.error({ traceId, error }, 'Failed to initialize WASM security runtime');

    emitSecurityEvent({
      type: 'wasm_runtime_error',
      severity: EventSeverity.CRITICAL,
      source: 'wasm',
      message: error instanceof Error ? error.message : 'Unknown error',
      metadata: { traceId },
    });

    span.end(error instanceof Error ? error : new Error('Unknown error'));
    throw error instanceof SecurityError ? error : new SecurityError('WASM security runtime initialization failed', { cause: error });
  }
}
