import { createHash, createHmac, randomBytes, timingSafeEqual } from 'crypto';
import { sha3_256 } from '@noble/hashes/sha3';
import { getLogger, getMetrics, createSpan, getCache, getEventBus, SecurityEvent } from '../core/index.js';
import { ValidationError, SecurityError, RateLimitError } from '../core/exceptions.js';
import pino from 'pino';

const logger = pino().child({ module: 'msf.api' });

// --- Type Definitions -------------------------------------------------------

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  sanitized?: unknown;
  score: number;
}

export interface SanitizedData {
  data: unknown;
  removedFields: string[];
  warnings: string[];
}

export interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
  burstLimit?: number;
  keyPrefix?: string;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  limit: number;
  resetAt: number;
  retryAfter?: number;
}

export interface AbuseDetectionResult {
  isAbusive: boolean;
  confidence: number;
  matchedPatterns: string[];
  riskScore: number;
  recommendedAction: 'allow' | 'throttle' | 'block' | 'challenge';
}

export interface AuthValidationResult {
  valid: boolean;
  errors: string[];
  scopes: string[];
  expiresAt?: number;
  riskScore: number;
}

export interface MassAssignmentResult {
  safe: boolean;
  blockedFields: string[];
  allowedFields: string[];
  riskScore: number;
}

export interface ShadowApiResult {
  isShadow: boolean;
  confidence: number;
  similarEndpoints: string[];
  riskScore: number;
  recommendation: 'document' | 'block' | 'monitor' | 'allow';
}

export interface GraphqlValidationResult {
  valid: boolean;
  depth: number;
  errors: string[];
  warnings: string[];
}

export interface GraphqlCostResult {
  cost: number;
  allowed: boolean;
  breakdown: Record<string, number>;
  warnings: string[];
}

export interface GraphqlAbuseResult {
  isAbusive: boolean;
  riskScore: number;
  anomalies: string[];
  recommendedAction: 'allow' | 'throttle' | 'block';
}

export interface GrpcValidationResult {
  valid: boolean;
  errors: string[];
  tlsValid: boolean;
  metadataValid: boolean;
  riskScore: number;
}

export interface WsSecurityResult {
  secure: boolean;
  errors: string[];
  warnings: string[];
  negotiatedProtocol?: string;
}

export interface FloodResult {
  allowed: boolean;
  currentConnections: number;
  maxConnections: number;
  blocked: boolean;
  retryAfter?: number;
}

export interface KeyRotationResult {
  newKey: string;
  oldKeyHash: string;
  expiresAt: Date;
  algorithm: string;
  rotationId: string;
}

export interface KeyValidationResult {
  valid: boolean;
  scopes: string[];
  expiresAt?: Date;
  errors: string[];
  riskScore: number;
}

export interface ApiThreatContext {
  ip: string;
  userAgent: string;
  geoLocation?: string;
  reputation?: number;
  historicalThreats?: number;
}

export interface ThreatIntelEntry {
  ip: string;
  threatLevel: number;
  categories: string[];
  lastSeen: Date;
}

export interface RequestPattern {
  type: string;
  threshold: number;
  windowMs: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface ClientBehavior {
  requestRate: number;
  errorRate: number;
  avgResponseTime: number;
  lastActivity: Date;
  trustScore: number;
}

export interface TrafficPattern {
  endpoint: string;
  requestCount: number;
  uniqueClients: number;
  avgResponseSize: number;
  errorRate: number;
}

// --- Helper Functions -------------------------------------------------------

function getSlidingWindowKey(prefix: string, clientId: string, endpoint: string, windowMs: number): string {
  const windowStart = Math.floor(Date.now() / windowMs) * windowMs;
  return `${prefix}:${clientId}:${endpoint}:${windowStart}`;
}

function calculateEntropy(data: string): number {
  const freq: Record<string, number> = {};
  for (const char of data) {
    freq[char] = (freq[char] || 0) + 1;
  }
  let entropy = 0;
  const len = data.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function normalizeEndpoint(endpoint: string): string {
  return endpoint
    .replace(/\/\d+/g, '/:id')
    .replace(/\/[0-9a-f]{24,}/g, '/:id')
    .replace(/\/+$/, '')
    .toLowerCase();
}

function levenshteinDistance(a: string, b: string): number {
  const matrix: number[][] = [];
  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

function getObjectDepth(obj: Record<string, unknown>, currentDepth = 0): number {
  if (currentDepth >= 100) return currentDepth;
  let maxDepth = currentDepth;
  for (const value of Object.values(obj)) {
    if (typeof value === 'object' && value !== null) {
      const childDepth = Array.isArray(value)
        ? value.reduce((max: number, item) => {
            return typeof item === 'object' && item !== null
              ? Math.max(max, getObjectDepth(item, currentDepth + 1))
              : max;
          }, currentDepth)
        : getObjectDepth(value as Record<string, unknown>, currentDepth + 1);
      maxDepth = Math.max(maxDepth, childDepth);
    }
  }
  return maxDepth;
}

// --- 1. validateJsonSchema -------------------------------------------------

/**
 * @description Validates data against a JSON schema with strict mode support
 * @param data - The data to validate
 * @param schema - JSON schema definition
 * @param strictMode - When true, rejects additional properties and enforces type strictness
 * @returns ValidationResult with validity status, errors, and confidence score
 * @example
 * ```ts
 * const result = validateJsonSchema({ name: "test" }, { type: "object", properties: { name: { type: "string" } } }, true);
 * console.log(result.valid); // true
 * ```
 */
export function validateJsonSchema(
  data: unknown,
  schema: Record<string, unknown>,
  strictMode = false
): ValidationResult {
  const span = createSpan('api.validateJsonSchema');
  const startTime = Date.now();
  const errors: string[] = [];
  const metrics = getMetrics();

  try {
    validateSchemaNode(data, schema, '', strictMode, errors);

    const result: ValidationResult = {
      valid: errors.length === 0,
      errors,
      score: errors.length === 0 ? 1 : Math.max(0, 1 - errors.length * 0.1),
    };

    metrics.incCounter('api.schema.validation', { valid: String(result.valid) });
    metrics.observeHistogram('api.schema.validation.duration', Date.now() - startTime);
    span.end();

    logger.debug({ valid: result.valid, errorCount: errors.length }, 'JSON schema validation completed');
    return result;
  } catch (err) {
    metrics.incCounter('api.schema.validation.error');
    span.end(err);
    throw new ValidationError(`Schema validation failed: ${(err as Error).message}`);
  }
}

function validateSchemaNode(
  data: unknown,
  schema: Record<string, unknown>,
  path: string,
  strictMode: boolean,
  errors: string[]
): void {
  const type = schema.type as string | undefined;

  if (type) {
    const actualType = Array.isArray(data) ? 'array' : typeof data;
    if (type === 'array' && !Array.isArray(data)) {
      errors.push(`${path || 'root'}: expected array, got ${actualType}`);
      return;
    }
    if (type === 'object' && (typeof data !== 'object' || data === null || Array.isArray(data))) {
      errors.push(`${path || 'root'}: expected object, got ${actualType}`);
      return;
    }
    if (type === 'string' && typeof data !== 'string') {
      errors.push(`${path || 'root'}: expected string, got ${actualType}`);
      return;
    }
    if (type === 'number' && typeof data !== 'number') {
      errors.push(`${path || 'root'}: expected number, got ${actualType}`);
      return;
    }
    if (type === 'boolean' && typeof data !== 'boolean') {
      errors.push(`${path || 'root'}: expected boolean, got ${actualType}`);
      return;
    }
    if (type === 'integer' && (typeof data !== 'number' || !Number.isInteger(data))) {
      errors.push(`${path || 'root'}: expected integer, got ${actualType}`);
      return;
    }
  }

  if (typeof data === 'string' && schema.maxLength !== undefined) {
    if (data.length > (schema.maxLength as number)) {
      errors.push(`${path || 'root'}: string length ${data.length} exceeds max ${(schema.maxLength as number)}`);
    }
    if (schema.minLength !== undefined && data.length < (schema.minLength as number)) {
      errors.push(`${path || 'root'}: string length ${data.length} below min ${(schema.minLength as number)}`);
    }
    if (schema.pattern !== undefined) {
      const regex = new RegExp(schema.pattern as string);
      if (!regex.test(data)) {
        errors.push(`${path || 'root'}: string does not match pattern ${schema.pattern}`);
      }
    }
  }

  if (typeof data === 'number') {
    if (schema.maximum !== undefined && data > (schema.maximum as number)) {
      errors.push(`${path || 'root'}: value ${data} exceeds maximum ${(schema.maximum as number)}`);
    }
    if (schema.minimum !== undefined && data < (schema.minimum as number)) {
      errors.push(`${path || 'root'}: value ${data} below minimum ${(schema.minimum as number)}`);
    }
  }

  if (Array.isArray(data)) {
    if (schema.maxItems !== undefined && data.length > (schema.maxItems as number)) {
      errors.push(`${path || 'root'}: array length ${data.length} exceeds max ${(schema.maxItems as number)}`);
    }
    if (schema.items) {
      data.forEach((item, i) => {
        validateSchemaNode(item, schema.items as Record<string, unknown>, `${path}[${i}]`, strictMode, errors);
      });
    }
  }

  if (typeof data === 'object' && data !== null && !Array.isArray(data)) {
    const properties = schema.properties as Record<string, Record<string, unknown>> | undefined;
    const required = schema.required as string[] | undefined;
    const additionalProperties = schema.additionalProperties;

    if (required) {
      for (const field of required) {
        if (!(field in (data as Record<string, unknown>))) {
          errors.push(`${path || 'root'}: missing required field "${field}"`);
        }
      }
    }

    if (properties) {
      for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
        if (properties[key]) {
          validateSchemaNode(value, properties[key], path ? `${path}.${key}` : key, strictMode, errors);
        } else if (strictMode && additionalProperties === false) {
          errors.push(`${path || 'root'}: additional property "${key}" not allowed`);
        }
      }
    }
  }
}

// --- 2. validateInput ------------------------------------------------------

/**
 * @description Validates input data against a set of rules with depth and size constraints
 * @param data - The input data to validate
 * @param rules - Validation rules map (field -> { type, required, pattern, min, max, enum })
 * @param maxDepth - Maximum nesting depth allowed (default: 5)
 * @param maxSize - Maximum serialized size in bytes (default: 1MB)
 * @returns ValidationResult with validation status and error details
 * @example
 * ```ts
 * const result = validateInput({ email: "test@example.com" }, { email: { type: "string", pattern: "^[^@]+@[^@]+$" } });
 * ```
 */
export function validateInput(
  data: unknown,
  rules: Record<string, { type?: string; required?: boolean; pattern?: string; min?: number; max?: number; enum?: unknown[] }>,
  maxDepth = 5,
  maxSize = 1048576
): ValidationResult {
  const span = createSpan('api.validateInput');
  const metrics = getMetrics();
  const startTime = Date.now();
  const errors: string[] = [];

  try {
    const serialized = JSON.stringify(data);
    if (Buffer.byteLength(serialized) > maxSize) {
      errors.push(`Input size ${Buffer.byteLength(serialized)} bytes exceeds maximum ${maxSize} bytes`);
      return { valid: false, errors, score: 0 };
    }

    if (typeof data !== 'object' || data === null) {
      errors.push('Input must be a non-null object');
      return { valid: false, errors, score: 0 };
    }

    const depth = getObjectDepth(data as Record<string, unknown>);
    if (depth > maxDepth) {
      errors.push(`Object depth ${depth} exceeds maximum ${maxDepth}`);
    }

    const dataObj = data as Record<string, unknown>;

    for (const [field, rule] of Object.entries(rules)) {
      const value = dataObj[field];

      if (rule.required && (value === undefined || value === null || value === '')) {
        errors.push(`Field "${field}" is required`);
        continue;
      }

      if (value === undefined || value === null) {
        continue;
      }

      if (rule.type) {
        const actualType = Array.isArray(value) ? 'array' : typeof value;
        if (actualType !== rule.type) {
          errors.push(`Field "${field}" expected ${rule.type}, got ${actualType}`);
        }
      }

      if (rule.pattern && typeof value === 'string') {
        const regex = new RegExp(rule.pattern);
        if (!regex.test(value)) {
          errors.push(`Field "${field}" does not match pattern ${rule.pattern}`);
        }
      }

      if (typeof value === 'number') {
        if (rule.min !== undefined && value < rule.min) {
          errors.push(`Field "${field}" value ${value} below minimum ${rule.min}`);
        }
        if (rule.max !== undefined && value > rule.max) {
          errors.push(`Field "${field}" value ${value} exceeds maximum ${rule.max}`);
        }
      }

      if (typeof value === 'string') {
        if (rule.min !== undefined && value.length < rule.min) {
          errors.push(`Field "${field}" length ${value.length} below minimum ${rule.min}`);
        }
        if (rule.max !== undefined && value.length > rule.max) {
          errors.push(`Field "${field}" length ${value.length} exceeds maximum ${rule.max}`);
        }
      }

      if (rule.enum && !rule.enum.includes(value)) {
        errors.push(`Field "${field}" value not in allowed values: ${rule.enum.join(', ')}`);
      }
    }

    const result: ValidationResult = {
      valid: errors.length === 0,
      errors,
      score: errors.length === 0 ? 1 : Math.max(0, 1 - errors.length * 0.15),
    };

    metrics.incCounter('api.input.validation', { valid: String(result.valid) });
    metrics.observeHistogram('api.input.validation.duration', Date.now() - startTime);
    span.end();

    logger.debug({ valid: result.valid, errorCount: errors.length, depth }, 'Input validation completed');
    return result;
  } catch (err) {
    metrics.incCounter('api.input.validation.error');
    span.end(err);
    throw new ValidationError(`Input validation failed: ${(err as Error).message}`);
  }
}

// --- 3. sanitizeJson -------------------------------------------------------

/**
 * @description Sanitizes JSON data by removing disallowed types and truncating strings
 * @param data - The JSON data to sanitize
 * @param allowedTypes - Array of allowed type names (default: ['string', 'number', 'boolean', 'null', 'array', 'object'])
 * @param maxStringLength - Maximum string length before truncation (default: 10000)
 * @returns SanitizedData with cleaned data, removed fields, and warnings
 * @example
 * ```ts
 * const result = sanitizeJson({ name: "test", secret: Buffer.from("x") }, ['string', 'object'], 100);
 * ```
 */
export function sanitizeJson(
  data: unknown,
  allowedTypes: string[] = ['string', 'number', 'boolean', 'null', 'array', 'object'],
  maxStringLength = 10000
): SanitizedData {
  const span = createSpan('api.sanitizeJson');
  const metrics = getMetrics();
  const removedFields: string[] = [];
  const warnings: string[] = [];

  try {
    const sanitized = sanitizeNode(data, '', allowedTypes, maxStringLength, removedFields, warnings);

    metrics.incCounter('api.sanitize.json', {
      removedCount: String(removedFields.length),
      warningCount: String(warnings.length),
    });
    span.end();

    logger.debug({ removedFields, warningCount: warnings.length }, 'JSON sanitization completed');
    return { data: sanitized, removedFields, warnings };
  } catch (err) {
    metrics.incCounter('api.sanitize.json.error');
    span.end(err);
    throw new SecurityError(`JSON sanitization failed: ${(err as Error).message}`);
  }
}

function sanitizeNode(
  data: unknown,
  path: string,
  allowedTypes: string[],
  maxStringLength: number,
  removedFields: string[],
  warnings: string[]
): unknown {
  if (data === null || data === undefined) {
    return data;
  }

  const type = Array.isArray(data) ? 'array' : typeof data;

  if (type === 'function' || type === 'symbol' || type === 'bigint') {
    removedFields.push(path || 'root');
    warnings.push(`Removed disallowed type "${type}" at ${path || 'root'}`);
    return undefined;
  }

  if (data instanceof Date) {
    return data.toISOString();
  }

  if (data instanceof Buffer || data instanceof Uint8Array) {
    removedFields.push(path || 'root');
    warnings.push(`Removed binary data at ${path || 'root'}`);
    return undefined;
  }

  if (typeof data === 'string') {
    if (data.length > maxStringLength) {
      warnings.push(`Truncated string at ${path || 'root'} from ${data.length} to ${maxStringLength}`);
      return data.substring(0, maxStringLength);
    }
    return data;
  }

  if (Array.isArray(data)) {
    return data
      .map((item, i) => sanitizeNode(item, `${path}[${i}]`, allowedTypes, maxStringLength, removedFields, warnings))
      .filter(item => item !== undefined);
  }

  if (typeof data === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(data)) {
      const childPath = path ? `${path}.${key}` : key;
      const sanitized = sanitizeNode(value, childPath, allowedTypes, maxStringLength, removedFields, warnings);
      if (sanitized !== undefined) {
        result[key] = sanitized;
      }
    }
    return result;
  }

  return data;
}

// --- 4. apiRateLimit -------------------------------------------------------

/**
 * @description Implements sliding window rate limiting for API endpoints
 * @param clientId - Unique identifier for the client
 * @param endpoint - API endpoint being accessed
 * @param config - Rate limit configuration with window and max requests
 * @returns RateLimitResult with allowance status and remaining quota
 * @example
 * ```ts
 * const result = apiRateLimit('user-123', '/api/data', { windowMs: 60000, maxRequests: 100 });
 * console.log(result.allowed); // true if under limit
 * ```
 */
export async function apiRateLimit(
  clientId: string,
  endpoint: string,
  config: RateLimitConfig
): Promise<RateLimitResult> {
  const span = createSpan('api.rateLimit');
  const metrics = getMetrics();
  const cache = getCache();
  const now = Date.now();
  const prefix = config.keyPrefix || 'ratelimit';
  const key = getSlidingWindowKey(prefix, clientId, endpoint, config.windowMs);

  try {
    let current = await cache.get<number>(key);
    if (current === undefined) {
      current = 0;
    }

    const remaining = Math.max(0, config.maxRequests - current);
    const resetAt = Math.ceil(now / config.windowMs) * config.windowMs + config.windowMs;

    if (current >= config.maxRequests) {
      metrics.incCounter('api.ratelimit.exceeded', { clientId, endpoint });
      span.end();

      logger.warn({ clientId, endpoint, current, limit: config.maxRequests }, 'Rate limit exceeded');
      return {
        allowed: false,
        remaining: 0,
        limit: config.maxRequests,
        resetAt,
        retryAfter: resetAt - now,
      };
    }

    await cache.set(key, current + 1, { ttl: config.windowMs / 1000 });

    if (config.burstLimit !== undefined) {
      const burstKey = `${prefix}:burst:${clientId}:${endpoint}:${Math.floor(now / 1000)}`;
      let burstCount = await cache.get<number>(burstKey);
      if (burstCount === undefined) burstCount = 0;

      if (burstCount >= config.burstLimit) {
        metrics.incCounter('api.ratelimit.burst.exceeded', { clientId, endpoint });
        return {
          allowed: false,
          remaining,
          limit: config.maxRequests,
          resetAt: now + 1000,
          retryAfter: 1000,
        };
      }
      await cache.set(burstKey, burstCount + 1, { ttl: 1 });
    }

    metrics.incCounter('api.ratelimit.allowed', { clientId, endpoint });
    metrics.setGauge('api.ratelimit.remaining', remaining);
    span.end();

    return {
      allowed: true,
      remaining: remaining - 1,
      limit: config.maxRequests,
      resetAt,
    };
  } catch (err) {
    metrics.incCounter('api.ratelimit.error');
    span.end(err);
    logger.error({ err }, 'Rate limit check failed');
    return {
      allowed: true,
      remaining: config.maxRequests,
      limit: config.maxRequests,
      resetAt: now + config.windowMs,
    };
  }
}

// --- 5. adaptiveRateLimit --------------------------------------------------

/**
 * @description Adaptive rate limiting that adjusts limits based on client behavior
 * @param clientId - Unique identifier for the client
 * @param endpoint - API endpoint being accessed
 * @param behavior - Current client behavior metrics
 * @param config - Base rate limit configuration
 * @returns RateLimitResult with dynamically adjusted limits
 * @example
 * ```ts
 * const result = adaptiveRateLimit('user-123', '/api/data', { requestRate: 10, errorRate: 0.01, trustScore: 0.9 }, { windowMs: 60000, maxRequests: 100 });
 * ```
 */
export async function adaptiveRateLimit(
  clientId: string,
  endpoint: string,
  behavior: ClientBehavior,
  config: RateLimitConfig
): Promise<RateLimitResult> {
  const span = createSpan('api.adaptiveRateLimit');
  const metrics = getMetrics();
  const cache = getCache();
  const now = Date.now();

  try {
    const trustFactor = behavior.trustScore ?? 0.5;
    const errorPenalty = (behavior.errorRate ?? 0) * 2;
    const rateFactor = behavior.requestRate > config.maxRequests / (config.windowMs / 1000) ? 0.5 : 1;

    const adjustedMax = Math.max(
      Math.floor(config.maxRequests * trustFactor * rateFactor * (1 - errorPenalty)),
      Math.floor(config.maxRequests * 0.1)
    );

    const adjustedConfig: RateLimitConfig = {
      ...config,
      maxRequests: adjustedMax,
    };

    const result = await apiRateLimit(clientId, endpoint, adjustedConfig);

    metrics.setGauge('api.adaptive.ratelimit.adjusted_max', adjustedMax);
    metrics.setGauge('api.adaptive.ratelimit.trust_factor', trustFactor);
    span.end();

    logger.debug({ clientId, adjustedMax, trustFactor, errorPenalty }, 'Adaptive rate limit applied');
    return result;
  } catch (err) {
    metrics.incCounter('api.adaptive.ratelimit.error');
    span.end(err);
    return apiRateLimit(clientId, endpoint, config);
  }
}

// --- 6. detectApiAbuse -----------------------------------------------------

/**
 * @description Detects API abuse patterns by analyzing request patterns against known abuse signatures
 * @param requests - Array of request timestamps and metadata
 * @param patterns - Abuse patterns to check against
 * @param window - Time window in milliseconds for pattern analysis
 * @returns AbuseDetectionResult with abuse status and recommended action
 * @example
 * ```ts
 * const result = detectApiAbuse(requests, [{ type: 'rapid_fire', threshold: 50, windowMs: 10000 }], 60000);
 * ```
 */
export function detectApiAbuse(
  requests: Array<{ timestamp: number; endpoint: string; method: string; statusCode?: number }>,
  patterns: RequestPattern[],
  window: number
): AbuseDetectionResult {
  const span = createSpan('api.detectApiAbuse');
  const metrics = getMetrics();
  const now = Date.now();
  const windowStart = now - window;
  const matchedPatterns: string[] = [];
  let maxRiskScore = 0;

  try {
    const windowedRequests = requests.filter(r => r.timestamp >= windowStart);

    for (const pattern of patterns) {
      const patternWindow = requests.filter(r => r.timestamp >= now - pattern.windowMs);

      if (pattern.type === 'rapid_fire') {
        if (patternWindow.length >= pattern.threshold) {
          matchedPatterns.push(pattern.type);
          maxRiskScore = Math.max(maxRiskScore, pattern.severity === 'critical' ? 1 : pattern.severity === 'high' ? 0.8 : pattern.severity === 'medium' ? 0.5 : 0.2);
        }
      }

      if (pattern.type === 'endpoint_enumeration') {
        const uniqueEndpoints = new Set(patternWindow.map(r => r.endpoint));
        if (uniqueEndpoints.size >= pattern.threshold) {
          matchedPatterns.push(pattern.type);
          maxRiskScore = Math.max(maxRiskScore, 0.9);
        }
      }

      if (pattern.type === 'error_flood') {
        const errorCount = patternWindow.filter(r => (r.statusCode ?? 0) >= 400).length;
        if (errorCount >= pattern.threshold) {
          matchedPatterns.push(pattern.type);
          maxRiskScore = Math.max(maxRiskScore, 0.7);
        }
      }

      if (pattern.type === 'credential_stuffing') {
        const authRequests = patternWindow.filter(r => r.endpoint.includes('/auth') || r.endpoint.includes('/login'));
        const authErrors = authRequests.filter(r => (r.statusCode ?? 0) >= 401 && (r.statusCode ?? 0) < 500);
        if (authErrors.length >= pattern.threshold) {
          matchedPatterns.push(pattern.type);
          maxRiskScore = Math.max(maxRiskScore, 1);
        }
      }

      if (pattern.type === 'data_scraping') {
        const getRequests = patternWindow.filter(r => r.method === 'GET');
        if (getRequests.length >= pattern.threshold) {
          matchedPatterns.push(pattern.type);
          maxRiskScore = Math.max(maxRiskScore, 0.6);
        }
      }
    }

    const isAbusive = matchedPatterns.length > 0;
    let recommendedAction: AbuseDetectionResult['recommendedAction'] = 'allow';
    if (maxRiskScore >= 0.9) recommendedAction = 'block';
    else if (maxRiskScore >= 0.7) recommendedAction = 'challenge';
    else if (maxRiskScore >= 0.4) recommendedAction = 'throttle';

    const result: AbuseDetectionResult = {
      isAbusive,
      confidence: matchedPatterns.length > 0 ? Math.min(1, matchedPatterns.length * 0.3) : 0,
      matchedPatterns,
      riskScore: maxRiskScore,
      recommendedAction,
    };

    metrics.incCounter('api.abuse.detection', { abusive: String(isAbusive), patternCount: String(matchedPatterns.length) });
    span.end();

    logger.info({ isAbusive, matchedPatterns, riskScore: maxRiskScore }, 'API abuse detection completed');
    return result;
  } catch (err) {
    metrics.incCounter('api.abuse.detection.error');
    span.end(err);
    return { isAbusive: false, confidence: 0, matchedPatterns: [], riskScore: 0, recommendedAction: 'allow' };
  }
}

// --- 7. detectBola ---------------------------------------------------------

/**
 * @description Detects Broken Object Level Authorization (BOLA/IDOR) by checking resource ownership
 * @param resourceId - The resource being accessed
 * @param userId - The ID of the user making the request
 * @param ownershipMap - Map of resource IDs to their owner user IDs
 * @returns true if BOLA is detected (user accessing resource they don't own)
 * @example
 * ```ts
 * const isBola = detectBola('order-456', 'user-123', { 'order-456': 'user-789' });
 * console.log(isBola); // true - user accessing another user's order
 * ```
 */
export function detectBola(
  resourceId: string,
  userId: string,
  ownershipMap: Record<string, string>
): boolean {
  const span = createSpan('api.detectBola');
  const metrics = getMetrics();

  try {
    const owner = ownershipMap[resourceId];

    if (owner === undefined) {
      metrics.incCounter('api.bola.unknown_resource');
      span.end();
      logger.warn({ resourceId }, 'BOLA check: unknown resource');
      return true;
    }

    const isBola = owner !== userId;

    if (isBola) {
      metrics.incCounter('api.bola.detected', { resourceId, userId });
      logger.warn({ resourceId, userId, owner }, 'BOLA detected: unauthorized resource access attempt');
    } else {
      metrics.incCounter('api.bola.allowed');
    }

    span.end();
    return isBola;
  } catch (err) {
    metrics.incCounter('api.bola.error');
    span.end(err);
    return true;
  }
}

// --- 8. detectBrokenAuth ---------------------------------------------------

/**
 * @description Detects broken authentication by validating auth headers, scopes, and tokens
 * @param authHeader - Authorization header value
 * @param requiredScopes - Array of scopes required for the operation
 * @param token - Parsed token object with claims (optional if authHeader is provided)
 * @returns AuthValidationResult with validation status and risk assessment
 * @example
 * ```ts
 * const result = detectBrokenAuth('Bearer eyJ...', ['read:users', 'write:users'], { scope: 'read:users', exp: Date.now() + 3600000 });
 * ```
 */
export function detectBrokenAuth(
  authHeader: string,
  requiredScopes: string[],
  token?: Record<string, unknown>
): AuthValidationResult {
  const span = createSpan('api.detectBrokenAuth');
  const metrics = getMetrics();
  const errors: string[] = [];
  const scopes: string[] = [];
  let riskScore = 0;

  try {
    if (!authHeader) {
      errors.push('Missing authorization header');
      riskScore += 0.5;
    } else {
      const parts = authHeader.split(' ');
      if (parts.length !== 2) {
        errors.push('Malformed authorization header');
        riskScore += 0.4;
      } else {
        const [scheme, credentials] = parts;

        if (scheme.toLowerCase() !== 'bearer') {
          errors.push(`Unsupported auth scheme: ${scheme}`);
          riskScore += 0.3;
        }

        if (credentials.length < 10) {
          errors.push('Token too short, possibly malformed');
          riskScore += 0.3;
        }

        const entropy = calculateEntropy(credentials);
        if (entropy < 3) {
          errors.push('Token has low entropy, possibly predictable');
          riskScore += 0.4;
        }
      }
    }

    if (token) {
      const tokenScopes = (token.scope as string) || (token.scopes as string[]) || '';
      const tokenScopeList = typeof tokenScopes === 'string' ? tokenScopes.split(' ') : tokenScopes;
      scopes.push(...tokenScopeList);

      const exp = token.exp as number | undefined;
      if (exp !== undefined) {
        if (exp * 1000 < Date.now()) {
          errors.push('Token has expired');
          riskScore += 0.5;
        }
      }

      const nbf = token.nbf as number | undefined;
      if (nbf !== undefined && nbf * 1000 > Date.now()) {
        errors.push('Token is not yet valid (nbf in future)');
        riskScore += 0.3;
      }

      for (const required of requiredScopes) {
        if (!tokenScopeList.includes(required)) {
          errors.push(`Missing required scope: ${required}`);
          riskScore += 0.2;
        }
      }
    } else if (requiredScopes.length > 0) {
      errors.push('No token provided for scope-restricted endpoint');
      riskScore += 0.5;
    }

    const valid = errors.length === 0;
    const result: AuthValidationResult = {
      valid,
      errors,
      scopes,
      expiresAt: token?.exp ? (token.exp as number) * 1000 : undefined,
      riskScore: Math.min(1, riskScore),
    };

    metrics.incCounter('api.auth.validation', { valid: String(valid) });
    span.end();

    logger.debug({ valid, errorCount: errors.length, riskScore }, 'Authentication validation completed');
    return result;
  } catch (err) {
    metrics.incCounter('api.auth.validation.error');
    span.end(err);
    return { valid: false, errors: [`Auth validation error: ${(err as Error).message}`], scopes: [], riskScore: 1 };
  }
}

// --- 9. detectMassAssignment -----------------------------------------------

/**
 * @description Detects mass assignment vulnerabilities by comparing input fields against model and readonly fields
 * @param inputData - The input data being submitted
 * @param modelFields - Array of valid model field names
 * @param readonlyFields - Array of fields that should not be modifiable via API
 * @returns MassAssignmentResult with safety status and blocked fields
 * @example
 * ```ts
 * const result = detectMassAssignment({ name: "test", role: "admin", id: 1 }, ['name', 'role', 'id'], ['id', 'role']);
 * console.log(result.blockedFields); // ['id', 'role']
 * ```
 */
export function detectMassAssignment(
  inputData: Record<string, unknown>,
  modelFields: string[],
  readonlyFields: string[]
): MassAssignmentResult {
  const span = createSpan('api.detectMassAssignment');
  const metrics = getMetrics();
  const blockedFields: string[] = [];
  const allowedFields: string[] = [];

  try {
    const readonlySet = new Set(readonlyFields);
    const modelSet = new Set(modelFields);

    for (const field of Object.keys(inputData)) {
      if (readonlySet.has(field)) {
        blockedFields.push(field);
      } else if (!modelSet.has(field)) {
        blockedFields.push(field);
      } else {
        allowedFields.push(field);
      }
    }

    const sensitiveFields = ['isAdmin', 'role', 'permissions', 'id', 'userId', 'createdAt', 'updatedAt', '__proto__', 'constructor', 'prototype'];
    const sensitiveBlocked = blockedFields.filter(f => sensitiveFields.includes(f));
    const riskScore = blockedFields.length > 0
      ? Math.min(1, 0.3 + sensitiveBlocked.length * 0.2 + blockedFields.length * 0.05)
      : 0;

    const result: MassAssignmentResult = {
      safe: blockedFields.length === 0,
      blockedFields,
      allowedFields,
      riskScore,
    };

    metrics.incCounter('api.mass_assignment.detection', { safe: String(result.safe), blockedCount: String(blockedFields.length) });
    span.end();

    logger.debug({ safe: result.safe, blockedFields, riskScore }, 'Mass assignment detection completed');
    return result;
  } catch (err) {
    metrics.incCounter('api.mass_assignment.error');
    span.end(err);
    return { safe: false, blockedFields: Object.keys(inputData), allowedFields: [], riskScore: 1 };
  }
}

// --- 10. detectShadowApi ---------------------------------------------------

/**
 * @description Detects shadow API endpoints by comparing traffic against documented endpoints
 * @param endpoint - The endpoint being accessed
 * @param documentedApis - Array of documented/known API endpoints
 * @param trafficPatterns - Traffic patterns for the endpoint
 * @returns ShadowApiResult with shadow detection status and recommendations
 * @example
 * ```ts
 * const result = detectShadowApi('/api/v2/internal/users', ['/api/v1/users', '/api/v2/users'], []);
 * console.log(result.isShadow); // likely true - undocumented endpoint
 * ```
 */
export function detectShadowApi(
  endpoint: string,
  documentedApis: string[],
  trafficPatterns: TrafficPattern[]
): ShadowApiResult {
  const span = createSpan('api.detectShadowApi');
  const metrics = getMetrics();
  const similarEndpoints: string[] = [];

  try {
    const normalizedEndpoint = normalizeEndpoint(endpoint);
    const normalizedDocumented = documentedApis.map(normalizeEndpoint);

    const isDocumented = normalizedDocumented.includes(normalizedEndpoint);

    if (!isDocumented) {
      for (const docEndpoint of normalizedDocumented) {
        const distance = levenshteinDistance(normalizedEndpoint, docEndpoint);
        const maxLen = Math.max(normalizedEndpoint.length, docEndpoint.length);
        const similarity = 1 - distance / maxLen;

        if (similarity > 0.5) {
          similarEndpoints.push(docEndpoint);
        }
      }
    }

    const trafficForEndpoint = trafficPatterns.find(t => normalizeEndpoint(t.endpoint) === normalizedEndpoint);
    const hasSignificantTraffic = trafficForEndpoint ? trafficForEndpoint.requestCount > 10 : false;

    const confidence = isDocumented
      ? 0
      : similarEndpoints.length > 0
        ? Math.min(0.8, 0.4 + similarEndpoints.length * 0.1)
        : 0.9;

    const riskScore = isDocumented ? 0 : hasSignificantTraffic ? 0.8 : 0.5;

    let recommendation: ShadowApiResult['recommendation'] = 'allow';
    if (!isDocumented && riskScore >= 0.7) recommendation = 'block';
    else if (!isDocumented && hasSignificantTraffic) recommendation = 'document';
    else if (!isDocumented) recommendation = 'monitor';

    const result: ShadowApiResult = {
      isShadow: !isDocumented,
      confidence,
      similarEndpoints,
      riskScore,
      recommendation,
    };

    metrics.incCounter('api.shadow_api.detection', { isShadow: String(result.isShadow) });
    span.end();

    logger.debug({ isShadow: result.isShadow, confidence, recommendation }, 'Shadow API detection completed');
    return result;
  } catch (err) {
    metrics.incCounter('api.shadow_api.error');
    span.end(err);
    return { isShadow: false, confidence: 0, similarEndpoints: [], riskScore: 0, recommendation: 'allow' };
  }
}

// --- 11. apiThreatScore ----------------------------------------------------

/**
 * @description Calculates a comprehensive threat score for an API request
 * @param request - Request metadata (method, path, headers, body size)
 * @param context - Contextual information about the request source
 * @param threatIntel - Threat intelligence data for known bad actors
 * @returns number between 0 (safe) and 1 (critical threat)
 * @example
 * ```ts
 * const score = apiThreatScore({ method: 'POST', path: '/api/login' }, { ip: '1.2.3.4', userAgent: 'curl/7.68' }, []);
 * ```
 */
export function apiThreatScore(
  request: { method: string; path: string; headers?: Record<string, string>; bodySize?: number },
  context: ApiThreatContext,
  threatIntel: ThreatIntelEntry[]
): number {
  const span = createSpan('api.threatScore');
  const metrics = getMetrics();
  let score = 0;

  try {
    const threatEntry = threatIntel.find(t => t.ip === context.ip);
    if (threatEntry) {
      score += threatEntry.threatLevel * 0.4;
      if (threatEntry.categories.includes('api_abuse')) score += 0.2;
      if (threatEntry.categories.includes('bot')) score += 0.15;
    }

    if (context.reputation !== undefined) {
      score += (1 - context.reputation) * 0.2;
    }

    if (context.historicalThreats !== undefined && context.historicalThreats > 0) {
      score += Math.min(0.3, context.historicalThreats * 0.05);
    }

    const suspiciousMethods = ['DELETE', 'PATCH'];
    if (suspiciousMethods.includes(request.method.toUpperCase())) {
      score += 0.1;
    }

    const suspiciousPaths = ['/admin', '/config', '/debug', '/internal', '/.env', '/wp-admin', '/phpmyadmin'];
    for (const path of suspiciousPaths) {
      if (request.path.toLowerCase().includes(path)) {
        score += 0.2;
        break;
      }
    }

    if (request.bodySize !== undefined && request.bodySize > 1048576) {
      score += 0.15;
    }

    if (context.userAgent) {
      const suspiciousAgents = ['sqlmap', 'nikto', 'nmap', 'masscan', 'dirbuster', 'gobuster', 'hydra'];
      const lowerAgent = context.userAgent.toLowerCase();
      for (const agent of suspiciousAgents) {
        if (lowerAgent.includes(agent)) {
          score += 0.3;
          break;
        }
      }
      if (lowerAgent === '' || lowerAgent === 'unknown') {
        score += 0.1;
      }
    }

    const result = Math.min(1, score);

    metrics.setGauge('api.threat_score', result);
    metrics.incCounter('api.threat_score.calculated', { level: result > 0.7 ? 'high' : result > 0.4 ? 'medium' : 'low' });
    span.end();

    logger.debug({ score: result, ip: context.ip, path: request.path }, 'Threat score calculated');
    return result;
  } catch (err) {
    metrics.incCounter('api.threat_score.error');
    span.end(err);
    return 0.5;
  }
}

// --- 12. graphqlDepthLimit -------------------------------------------------

/**
 * @description Validates GraphQL query depth against a maximum allowed depth
 * @param query - GraphQL query string
 * @param maxDepth - Maximum allowed query depth (default: 10)
 * @param introspectionEnabled - Whether introspection queries are allowed
 * @returns GraphqlValidationResult with depth analysis and validation status
 * @example
 * ```ts
 * const result = graphqlDepthLimit('{ user { posts { comments { author { name } } } } }', 5, false);
 * console.log(result.depth); // 5
 * ```
 */
export function graphqlDepthLimit(
  query: string,
  maxDepth = 10,
  introspectionEnabled = false
): GraphqlValidationResult {
  const span = createSpan('api.graphqlDepthLimit');
  const metrics = getMetrics();
  const errors: string[] = [];
  const warnings: string[] = [];

  try {
    const depth = calculateGraphqlDepth(query);

    if (!introspectionEnabled) {
      if (query.includes('__schema') || query.includes('__type')) {
        errors.push('Introspection queries are disabled');
      }
    }

    if (depth > maxDepth) {
      errors.push(`Query depth ${depth} exceeds maximum allowed depth ${maxDepth}`);
    }

    if (depth > maxDepth * 0.8) {
      warnings.push(`Query depth ${depth} is approaching the maximum limit of ${maxDepth}`);
    }

    const hasAliases = /(\w+)\s*:\s*(\w+)\s*\{/.test(query);
    if (hasAliases) {
      warnings.push('Query uses aliases which may indicate batching abuse');
    }

    const result: GraphqlValidationResult = {
      valid: errors.length === 0,
      depth,
      errors,
      warnings,
    };

    metrics.incCounter('api.graphql.depth_limit', { valid: String(result.valid) });
    metrics.observeHistogram('api.graphql.depth', depth);
    span.end();

    logger.debug({ valid: result.valid, depth, maxDepth }, 'GraphQL depth limit check completed');
    return result;
  } catch (err) {
    metrics.incCounter('api.graphql.depth_limit.error');
    span.end(err);
    return { valid: false, depth: 0, errors: [`Depth limit error: ${(err as Error).message}`], warnings: [] };
  }
}

function calculateGraphqlDepth(query: string): number {
  let maxDepth = 0;
  let currentDepth = 0;
  let inString = false;
  let escapeNext = false;

  for (let i = 0; i < query.length; i++) {
    const char = query[i];

    if (escapeNext) {
      escapeNext = false;
      continue;
    }

    if (char === '\\') {
      escapeNext = true;
      continue;
    }

    if (char === '"') {
      inString = !inString;
      continue;
    }

    if (inString) continue;

    if (char === '{') {
      currentDepth++;
      maxDepth = Math.max(maxDepth, currentDepth);
    } else if (char === '}') {
      currentDepth--;
    }
  }

  return maxDepth;
}

// --- 13. graphqlCostAnalysis -----------------------------------------------

/**
 * @description Analyzes GraphQL query cost based on field complexity weights
 * @param query - GraphQL query string
 * @param complexityMap - Map of field names to their complexity costs
 * @param maxCost - Maximum allowed query cost (default: 1000)
 * @returns GraphqlCostResult with cost breakdown and allowance status
 * @example
 * ```ts
 * const result = graphqlCostAnalysis('{ users { posts { comments } } }', { users: 10, posts: 5, comments: 2 }, 100);
 * ```
 */
export function graphqlCostAnalysis(
  query: string,
  complexityMap: Record<string, number>,
  maxCost = 1000
): GraphqlCostResult {
  const span = createSpan('api.graphqlCostAnalysis');
  const metrics = getMetrics();
  const breakdown: Record<string, number> = {};
  const warnings: string[] = [];

  try {
    const totalCost = calculateGraphqlCost(query, complexityMap, breakdown);

    if (totalCost > maxCost) {
      warnings.push(`Query cost ${totalCost} exceeds maximum allowed cost ${maxCost}`);
    }

    for (const [field, cost] of Object.entries(breakdown)) {
      if (cost > maxCost * 0.5) {
        warnings.push(`Field "${field}" contributes ${cost} to total cost (${((cost / totalCost) * 100).toFixed(1)}%)`);
      }
    }

    const result: GraphqlCostResult = {
      cost: totalCost,
      allowed: totalCost <= maxCost,
      breakdown,
      warnings,
    };

    metrics.incCounter('api.graphql.cost_analysis', { allowed: String(result.allowed) });
    metrics.observeHistogram('api.graphql.cost', totalCost);
    span.end();

    logger.debug({ cost: totalCost, allowed: result.allowed, warningCount: warnings.length }, 'GraphQL cost analysis completed');
    return result;
  } catch (err) {
    metrics.incCounter('api.graphql.cost_analysis.error');
    span.end(err);
    return { cost: 0, allowed: false, breakdown: {}, warnings: [`Cost analysis error: ${(err as Error).message}`] };
  }
}

function calculateGraphqlCost(
  query: string,
  complexityMap: Record<string, number>,
  breakdown: Record<string, number>
): number {
  let totalCost = 0;
  const fieldRegex = /(\w+)\s*(?:\([^)]*\))?\s*\{/g;
  let match: RegExpExecArray | null;

  while ((match = fieldRegex.exec(query)) !== null) {
    const fieldName = match[1];
    if (fieldName.startsWith('__')) continue;

    const baseCost = complexityMap[fieldName] ?? 1;
    const nestingLevel = countNestingLevel(query, match.index);
    const fieldCost = baseCost * Math.pow(2, Math.max(0, nestingLevel - 1));

    breakdown[fieldName] = (breakdown[fieldName] || 0) + fieldCost;
    totalCost += fieldCost;
  }

  const leafRegex = /(\w+)\s*(?:\([^)]*\))?\s*(?!\{)/g;
  while ((match = leafRegex.exec(query)) !== null) {
    const fieldName = match[1];
    if (fieldName.startsWith('__') || fieldName === 'query' || fieldName === 'mutation' || fieldName === 'subscription') continue;
    if (breakdown[fieldName]) continue;

    const leafCost = complexityMap[fieldName] ?? 0.5;
    breakdown[fieldName] = (breakdown[fieldName] || 0) + leafCost;
    totalCost += leafCost;
  }

  return Math.round(totalCost * 100) / 100;
}

function countNestingLevel(query: string, position: number): number {
  let level = 0;
  for (let i = 0; i < position; i++) {
    if (query[i] === '{') level++;
    else if (query[i] === '}') level--;
  }
  return Math.max(0, level);
}

// --- 14. graphqlAbuseDetection ---------------------------------------------

/**
 * @description Detects GraphQL abuse patterns across multiple queries in a time window
 * @param queries - Array of executed queries with metadata
 * @param window - Time window in milliseconds for analysis
 * @param thresholds - Abuse detection thresholds
 * @returns GraphqlAbuseResult with abuse status and anomalies
 * @example
 * ```ts
 * const result = graphqlAbuseDetection(queries, 60000, { maxQueriesPerMinute: 100, maxAvgDepth: 8, maxAvgCost: 500 });
 * ```
 */
export function graphqlAbuseDetection(
  queries: Array<{ query: string; timestamp: number; cost?: number; depth?: number; duration?: number }>,
  window: number,
  thresholds: { maxQueriesPerMinute?: number; maxAvgDepth?: number; maxAvgCost?: number; maxAvgDuration?: number }
): GraphqlAbuseResult {
  const span = createSpan('api.graphqlAbuseDetection');
  const metrics = getMetrics();
  const anomalies: string[] = [];
  let riskScore = 0;

  try {
    const now = Date.now();
    const windowedQueries = queries.filter(q => q.timestamp >= now - window);

    const queriesPerMinute = windowedQueries.length;
    const maxQpm = thresholds.maxQueriesPerMinute ?? 100;
    if (queriesPerMinute > maxQpm) {
      anomalies.push(`Query rate ${queriesPerMinute}/min exceeds threshold ${maxQpm}/min`);
      riskScore += 0.3;
    }

    const depths = windowedQueries.map(q => q.depth ?? calculateGraphqlDepth(q.query));
    const avgDepth = depths.reduce((a, b) => a + b, 0) / (depths.length || 1);
    const maxAvgDepth = thresholds.maxAvgDepth ?? 8;
    if (avgDepth > maxAvgDepth) {
      anomalies.push(`Average query depth ${avgDepth.toFixed(1)} exceeds threshold ${maxAvgDepth}`);
      riskScore += 0.2;
    }

    const costs = windowedQueries.map(q => q.cost ?? 0);
    const avgCost = costs.reduce((a, b) => a + b, 0) / (costs.length || 1);
    const maxAvgCost = thresholds.maxAvgCost ?? 500;
    if (avgCost > maxAvgCost) {
      anomalies.push(`Average query cost ${avgCost.toFixed(1)} exceeds threshold ${maxAvgCost}`);
      riskScore += 0.2;
    }

    const durations = windowedQueries.map(q => q.duration ?? 0);
    const avgDuration = durations.reduce((a, b) => a + b, 0) / (durations.length || 1);
    if (thresholds.maxAvgDuration && avgDuration > thresholds.maxAvgDuration) {
      anomalies.push(`Average query duration ${avgDuration.toFixed(0)}ms exceeds threshold ${thresholds.maxAvgDuration}ms`);
      riskScore += 0.15;
    }

    const uniqueQueries = new Set(windowedQueries.map(q => q.query.trim()));
    if (uniqueQueries.size === 1 && windowedQueries.length > 10) {
      anomalies.push('Identical query repeated excessively');
      riskScore += 0.15;
    }

    const introspectionCount = windowedQueries.filter(q =>
      q.query.includes('__schema') || q.query.includes('__type')
    ).length;
    if (introspectionCount > 3) {
      anomalies.push(`Excessive introspection queries: ${introspectionCount}`);
      riskScore += 0.2;
    }

    const isAbusive = anomalies.length > 0;
    let recommendedAction: GraphqlAbuseResult['recommendedAction'] = 'allow';
    if (riskScore >= 0.7) recommendedAction = 'block';
    else if (riskScore >= 0.4) recommendedAction = 'throttle';

    const result: GraphqlAbuseResult = {
      isAbusive,
      riskScore: Math.min(1, riskScore),
      anomalies,
      recommendedAction,
    };

    metrics.incCounter('api.graphql.abuse_detection', { isAbusive: String(isAbusive) });
    span.end();

    logger.info({ isAbusive, anomalyCount: anomalies.length, riskScore }, 'GraphQL abuse detection completed');
    return result;
  } catch (err) {
    metrics.incCounter('api.graphql.abuse_detection.error');
    span.end(err);
    return { isAbusive: false, riskScore: 0, anomalies: [], recommendedAction: 'allow' };
  }
}

// --- 15. grpcSecurityValidation --------------------------------------------

/**
 * @description Validates gRPC request security including metadata, headers, and TLS configuration
 * @param metadata - gRPC metadata key-value pairs
 * @param requiredHeaders - Array of required metadata header names
 * @param tlsInfo - TLS connection information
 * @returns GrpcValidationResult with validation status for metadata and TLS
 * @example
 * ```ts
 * const result = grpcSecurityValidation({ 'authorization': 'Bearer token' }, ['authorization'], { authorized: true, cipherSuite: 'TLS_AES_256_GCM_SHA384' });
 * ```
 */
export function grpcSecurityValidation(
  metadata: Record<string, string | string[]>,
  requiredHeaders: string[],
  tlsInfo: { authorized: boolean; cipherSuite?: string; protocol?: string; peerCertificate?: Record<string, unknown> }
): GrpcValidationResult {
  const span = createSpan('api.grpcSecurityValidation');
  const metrics = getMetrics();
  const errors: string[] = [];
  let tlsValid = true;
  let metadataValid = true;
  let riskScore = 0;

  try {
    for (const header of requiredHeaders) {
      const normalizedHeader = header.toLowerCase();
      const found = Object.keys(metadata).some(k => k.toLowerCase() === normalizedHeader);
      if (!found) {
        errors.push(`Missing required header: ${header}`);
        metadataValid = false;
        riskScore += 0.2;
      }
    }

    if (!tlsInfo.authorized) {
      errors.push('TLS connection not authorized');
      tlsValid = false;
      riskScore += 0.5;
    }

    if (tlsInfo.cipherSuite) {
      const weakCiphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon'];
      const cipherUpper = tlsInfo.cipherSuite.toUpperCase();
      for (const weak of weakCiphers) {
        if (cipherUpper.includes(weak)) {
          errors.push(`Weak cipher suite detected: ${tlsInfo.cipherSuite}`);
          tlsValid = false;
          riskScore += 0.3;
          break;
        }
      }
    } else {
      errors.push('No cipher suite information available');
      tlsValid = false;
      riskScore += 0.2;
    }

    if (tlsInfo.protocol) {
      const weakProtocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.0', 'TLSv1.1'];
      if (weakProtocols.includes(tlsInfo.protocol)) {
        errors.push(`Weak TLS protocol version: ${tlsInfo.protocol}`);
        tlsValid = false;
        riskScore += 0.3;
      }
    }

    const valid = errors.length === 0;
    const result: GrpcValidationResult = {
      valid,
      errors,
      tlsValid,
      metadataValid,
      riskScore: Math.min(1, riskScore),
    };

    metrics.incCounter('api.grpc.validation', { valid: String(valid), tlsValid: String(tlsValid) });
    span.end();

    logger.debug({ valid, tlsValid, metadataValid, errorCount: errors.length }, 'gRPC security validation completed');
    return result;
  } catch (err) {
    metrics.incCounter('api.grpc.validation.error');
    span.end(err);
    return { valid: false, errors: [`gRPC validation error: ${(err as Error).message}`], tlsValid: false, metadataValid: false, riskScore: 1 };
  }
}

// --- 16. secureWebsocket ---------------------------------------------------

/**
 * @description Validates WebSocket connection security including origin and subprotocol negotiation
 * @param origin - The origin of the WebSocket connection
 * @param allowedOrigins - Array of allowed origin strings/regex patterns
 * @param subprotocols - Array of requested subprotocols
 * @returns WsSecurityResult with security status and negotiated protocol
 * @example
 * ```ts
 * const result = secureWebsocket('https://app.example.com', ['https://app.example.com', 'https://admin.example.com'], ['graphql-ws']);
 * ```
 */
export function secureWebsocket(
  origin: string,
  allowedOrigins: string[],
  subprotocols?: string[]
): WsSecurityResult {
  const span = createSpan('api.secureWebsocket');
  const metrics = getMetrics();
  const errors: string[] = [];
  const warnings: string[] = [];
  let negotiatedProtocol: string | undefined;

  try {
    const originValid = websocketOriginValidation(origin, allowedOrigins);
    if (!originValid) {
      errors.push(`Origin "${origin}" is not in the allowed origins list`);
    }

    try {
      const originUrl = new URL(origin);
      if (originUrl.protocol !== 'https:' && originUrl.protocol !== 'wss:') {
        warnings.push(`WebSocket connection using insecure protocol: ${originUrl.protocol}`);
      }
    } catch {
      warnings.push('Could not parse origin URL');
    }

    if (subprotocols && subprotocols.length > 0) {
      const allowedSubprotocols = ['graphql-ws', 'graphql-transport-ws', 'json-rpc', 'msgpack', 'protobuf'];
      const requested = subprotocols.filter(sp => allowedSubprotocols.includes(sp));
      if (requested.length === 0) {
        warnings.push(`No recognized subprotocols in request: ${subprotocols.join(', ')}`);
      } else {
        negotiatedProtocol = requested[0];
      }
    }

    const secure = errors.length === 0;
    const result: WsSecurityResult = {
      secure,
      errors,
      warnings,
      negotiatedProtocol,
    };

    metrics.incCounter('api.websocket.security', { secure: String(secure) });
    span.end();

    logger.debug({ secure, errorCount: errors.length, warningCount: warnings.length, negotiatedProtocol }, 'WebSocket security validation completed');
    return result;
  } catch (err) {
    metrics.incCounter('api.websocket.security.error');
    span.end(err);
    return { secure: false, errors: [`WebSocket security error: ${(err as Error).message}`], warnings: [] };
  }
}

// --- 17. websocketOriginValidation -----------------------------------------

/**
 * @description Validates WebSocket connection origin against allowed origins list
 * @param origin - The origin header value from the WebSocket handshake
 * @param allowedOrigins - Array of allowed origin strings or regex patterns
 * @returns boolean indicating if the origin is allowed
 * @example
 * ```ts
 * const allowed = websocketOriginValidation('https://app.example.com', ['https://*.example.com', 'https://admin.example.com']);
 * ```
 */
export function websocketOriginValidation(
  origin: string,
  allowedOrigins: string[]
): boolean {
  const span = createSpan('api.websocketOriginValidation');
  const metrics = getMetrics();

  try {
    if (!origin) {
      metrics.incCounter('api.websocket.origin.missing');
      span.end();
      return false;
    }

    for (const allowed of allowedOrigins) {
      if (allowed === '*') {
        metrics.incCounter('api.websocket.origin.allowed', { pattern: 'wildcard' });
        span.end();
        return true;
      }

      if (allowed.includes('*')) {
        const regexPattern = allowed
          .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
          .replace(/\*/g, '.*');
        const regex = new RegExp(`^${regexPattern}$`);
        if (regex.test(origin)) {
          metrics.incCounter('api.websocket.origin.allowed', { pattern: allowed });
          span.end();
          return true;
        }
      } else if (origin === allowed) {
        metrics.incCounter('api.websocket.origin.allowed', { pattern: 'exact' });
        span.end();
        return true;
      }
    }

    metrics.incCounter('api.websocket.origin.rejected');
    span.end();

    logger.warn({ origin, allowedOrigins }, 'WebSocket origin rejected');
    return false;
  } catch (err) {
    metrics.incCounter('api.websocket.origin.error');
    span.end(err);
    return false;
  }
}

// --- 18. websocketFloodProtection ------------------------------------------

/**
 * @description Protects against WebSocket connection flooding per client
 * @param clientId - Unique identifier for the client
 * @param connections - Current active connections for this client
 * @param maxConnections - Maximum allowed concurrent connections
 * @param window - Time window in milliseconds for connection tracking
 * @returns FloodResult with connection status and flood protection state
 * @example
 * ```ts
 * const result = websocketFloodProtection('user-123', ['conn-1', 'conn-2', 'conn-3'], 5, 60000);
 * console.log(result.allowed); // true - under limit
 * ```
 */
export async function websocketFloodProtection(
  clientId: string,
  connections: string[],
  maxConnections: number,
  window: number
): Promise<FloodResult> {
  const span = createSpan('api.websocketFloodProtection');
  const metrics = getMetrics();
  const cache = getCache();
  const now = Date.now();

  try {
    const connectionKey = `ws:connections:${clientId}:${Math.floor(now / window)}`;
    const recentConnections = await cache.get<number>(connectionKey);
    const currentCount = connections.length;

    if (currentCount >= maxConnections) {
      metrics.incCounter('api.websocket.flood.blocked', { clientId });
      span.end();

      logger.warn({ clientId, currentConnections: currentCount, maxConnections }, 'WebSocket flood protection: connection blocked');
      return {
        allowed: false,
        currentConnections: currentCount,
        maxConnections,
        blocked: true,
        retryAfter: window - (now % window),
      };
    }

    if (recentConnections !== undefined && recentConnections > maxConnections * 2) {
      metrics.incCounter('api.websocket.flood.rate_limited', { clientId });
      return {
        allowed: false,
        currentConnections: currentCount,
        maxConnections,
        blocked: true,
        retryAfter: window - (now % window),
      };
    }

    await cache.set(connectionKey, (recentConnections ?? 0) + 1, { ttl: window / 1000 });

    metrics.setGauge('api.websocket.connections', currentCount);
    span.end();

    return {
      allowed: true,
      currentConnections: currentCount,
      maxConnections,
      blocked: false,
    };
  } catch (err) {
    metrics.incCounter('api.websocket.flood.error');
    span.end(err);
    return {
      allowed: true,
      currentConnections: connections.length,
      maxConnections,
      blocked: false,
    };
  }
}

// --- 19. apiKeyRotation ----------------------------------------------------

/**
 * @description Generates a new API key with secure rotation and hashing of the old key
 * @param currentKey - The current API key being rotated (for hash generation)
 * @param algorithm - Hash algorithm for key generation (default: 'sha3-256')
 * @param expiryDays - Number of days until the new key expires (default: 90)
 * @returns KeyRotationResult with new key, old key hash, and metadata
 * @example
 * ```ts
 * const result = apiKeyRotation('old-key-123', 'sha3-256', 90);
 * console.log(result.newKey); // newly generated secure key
 * ```
 */
export function apiKeyRotation(
  currentKey: string,
  algorithm = 'sha3-256',
  expiryDays = 90
): KeyRotationResult {
  const span = createSpan('api.apiKeyRotation');
  const metrics = getMetrics();

  try {
    const oldKeyHash = createHash('sha256').update(currentKey).digest('hex');

    const randomPart = randomBytes(32).toString('hex');
    const timestamp = Date.now().toString(36);
    const rotationId = randomBytes(8).toString('hex');

    let newKey: string;
    if (algorithm === 'sha3-256') {
      const hashBytes = sha3_256(Buffer.from(`${randomPart}:${timestamp}:${rotationId}`));
      newKey = `sk_${Buffer.from(hashBytes).toString('base64url')}`;
    } else {
      const hmac = createHmac('sha256', randomPart);
      hmac.update(`${timestamp}:${rotationId}`);
      newKey = `sk_${hmac.digest('base64url')}`;
    }

    const expiresAt = new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000);

    const result: KeyRotationResult = {
      newKey,
      oldKeyHash,
      expiresAt,
      algorithm,
      rotationId,
    };

    metrics.incCounter('api.key_rotation.completed', { algorithm });
    span.end();

    logger.info({ rotationId, algorithm, expiryDays }, 'API key rotation completed');
    return result;
  } catch (err) {
    metrics.incCounter('api.key_rotation.error');
    span.end(err);
    throw new SecurityError(`Key rotation failed: ${(err as Error).message}`);
  }
}

// --- 20. apiKeyValidation --------------------------------------------------

/**
 * @description Validates an API key against a set of valid keys with scope checking
 * @param apiKey - The API key to validate
 * @param validKeys - Map of valid API keys to their metadata
 * @param scopes - Available scopes for the validated key
 * @param requiredScope - The scope required for the requested operation
 * @returns KeyValidationResult with validation status and scope information
 * @example
 * ```ts
 * const result = apiKeyValidation('sk_valid_key', { 'sk_valid_key': { scopes: ['read', 'write'], expiresAt: new Date(Date.now() + 86400000) } }, ['read', 'write'], 'read');
 * ```
 */
export function apiKeyValidation(
  apiKey: string,
  validKeys: Record<string, { scopes: string[]; expiresAt?: Date; createdAt?: Date; rateLimit?: number }>,
  scopes: string[],
  requiredScope?: string
): KeyValidationResult {
  const span = createSpan('api.apiKeyValidation');
  const metrics = getMetrics();
  const errors: string[] = [];
  let riskScore = 0;

  try {
    if (!apiKey) {
      errors.push('API key is empty');
      riskScore += 0.5;
    }

    if (apiKey && !apiKey.startsWith('sk_')) {
      errors.push('Invalid API key format');
      riskScore += 0.3;
    }

    const keyData = validKeys[apiKey];
    if (!keyData) {
      errors.push('API key not found');
      riskScore += 0.5;

      for (const [key, data] of Object.entries(validKeys)) {
        try {
          if (apiKey.length === key.length) {
            const keyBuffer = Buffer.from(apiKey);
            const validBuffer = Buffer.from(key);
            if (keyBuffer.length === validBuffer.length) {
              const match = timingSafeEqual(keyBuffer, validBuffer);
              if (match) {
                errors.pop();
                errors.push('API key matched but timing check failed');
                riskScore = Math.max(riskScore, 0.8);
              }
            }
          }
        } catch {
          continue;
        }
      }

      const result: KeyValidationResult = {
        valid: false,
        scopes: [],
        errors,
        riskScore: Math.min(1, riskScore),
      };

      metrics.incCounter('api.key_validation.failed', { reason: 'key_not_found' });
      span.end();
      return result;
    }

    if (keyData.expiresAt && keyData.expiresAt < new Date()) {
      errors.push('API key has expired');
      riskScore += 0.5;
    }

    const keyScopes = keyData.scopes || [];
    const availableScopes = scopes.filter(s => keyScopes.includes(s));

    if (requiredScope && !keyScopes.includes(requiredScope)) {
      errors.push(`API key does not have required scope: ${requiredScope}`);
      riskScore += 0.3;
    }

    const valid = errors.length === 0;
    const result: KeyValidationResult = {
      valid,
      scopes: availableScopes,
      expiresAt: keyData.expiresAt,
      errors,
      riskScore: Math.min(1, riskScore),
    };

    metrics.incCounter('api.key_validation', { valid: String(valid) });
    span.end();

    logger.debug({ valid, scopeCount: availableScopes.length, riskScore }, 'API key validation completed');
    return result;
  } catch (err) {
    metrics.incCounter('api.key_validation.error');
    span.end(err);
    return { valid: false, scopes: [], errors: [`Key validation error: ${(err as Error).message}`], riskScore: 1 };
  }
}
