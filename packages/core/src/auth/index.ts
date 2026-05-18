import { createHash, createHmac, randomBytes, timingSafeEqual } from 'crypto';
import { sha3_256 } from '@noble/hashes/sha3';
import { getLogger, getMetrics, createSpan, getCache, getEventBus, SecurityEvent } from '../core/index.js';
import { AuthenticationError, ValidationError } from '../core/exceptions.js';
import pino from 'pino';

const logger = pino().child({ module: 'msf.auth' });

// --- Type Definitions ---

export interface JwtPayload {
  sub: string;
  iss?: string;
  aud?: string | string[];
  exp: number;
  iat: number;
  nbf?: number;
  jti?: string;
  scope?: string[];
  roles?: string[];
  [key: string]: unknown;
}

export interface JwtOptions {
  issuer?: string;
  audience?: string | string[];
  expiresIn?: number;
  notBefore?: number;
  algorithm?: string;
  tokenId?: string;
  scope?: string[];
  roles?: string[];
}

export interface RefreshTokenPayload {
  sub: string;
  jti: string;
  exp: number;
  iat: number;
  userId: string;
  deviceId?: string;
}

export interface Session {
  id: string;
  userId: string;
  ip: string;
  userAgent: string;
  deviceId: string;
  createdAt: number;
  expiresAt: number;
  lastAccessedAt: number;
  riskScore: number;
  status: 'active' | 'suspended' | 'revoked';
}

export interface AuthResult {
  authenticated: boolean;
  riskScore: number;
  requiresMfa: boolean;
  mfaMethod?: string;
  session?: Session;
  reason?: string;
}

export interface RiskContext {
  ip: string;
  userAgent: string;
  location?: { lat: number; lon: number };
  deviceFingerprint?: string;
  timestamp: number;
  requestCount?: number;
}

export interface RiskFactors {
  geoRisk?: number;
  deviceRisk?: number;
  behaviorRisk?: number;
  networkRisk?: number;
  reputationRisk?: number;
}

export interface BehaviorData {
  typingSpeed?: number;
  mouseMovement?: { x: number; y: number; timestamp: number }[];
  clickPatterns?: { x: number; y: number; timestamp: number }[];
  navigationPatterns?: string[];
  sessionDuration?: number;
  interactionCount?: number;
}

export interface BehaviorBaseline {
  avgTypingSpeed: number;
  avgMouseSpeed: number;
  commonPaths: string[];
  typicalSessionDuration: number;
  typicalInteractionCount: number;
}

export interface Location {
  lat: number;
  lon: number;
  timestamp: number;
}

// --- Revocation Store ---

const revokedTokens = new Map<string, { reason: string; revokedAt: number }>();
const tokenAccessLog = new Map<string, { ip: string; timestamp: number }[]>();

// --- Utility Functions ---

function base64UrlEncode(buffer: Buffer): string {
  return buffer.toString('base64url').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function base64UrlDecode(str: string): Buffer {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) base64 += '=';
  return Buffer.from(base64, 'base64');
}

function constantTimeCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

function hmacSha256(key: string, data: string): string {
  return createHmac('sha256', key).update(data).digest('base64url');
}

function haversineDistance(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const R = 6371;
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos((lat1 * Math.PI) / 180) *
      Math.cos((lat2 * Math.PI) / 180) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

// 1. validateJwt
/**
 * @description Validates a JWT token's signature, expiration, and claims.
 * @param token - The JWT token string to validate.
 * @param secret - The secret key used to verify the HMAC signature.
 * @param options - Optional validation options (issuer, audience, etc.).
 * @returns The decoded and validated JWT payload.
 * @example
 * const payload = await validateJwt(token, 'my-secret', { issuer: 'my-app' });
 */
export async function validateJwt(
  token: string,
  secret: string,
  options?: { issuer?: string; audience?: string | string[]; requireNotBefore?: boolean }
): Promise<JwtPayload> {
  const span = createSpan('auth.validateJwt');
  const startTime = Date.now();
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      getMetrics().incCounter('auth.jwt.validation.error', { reason: 'invalid_format' });
      throw new AuthenticationError('Invalid JWT format');
    }

    const [headerB64, payloadB64, signatureB64] = parts;
    const signingInput = `${headerB64}.${payloadB64}`;
    const expectedSig = hmacSha256(secret, signingInput);

    if (!constantTimeCompare(signatureB64, expectedSig)) {
      getMetrics().incCounter('auth.jwt.validation.error', { reason: 'invalid_signature' });
      throw new AuthenticationError('Invalid JWT signature');
    }

    const payload: JwtPayload = JSON.parse(base64UrlDecode(payloadB64).toString('utf-8'));

    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      getMetrics().incCounter('auth.jwt.validation.error', { reason: 'expired' });
      throw new AuthenticationError('JWT has expired');
    }

    if (options?.requireNotBefore && payload.nbf && payload.nbf > Math.floor(Date.now() / 1000)) {
      getMetrics().incCounter('auth.jwt.validation.error', { reason: 'not_yet_valid' });
      throw new AuthenticationError('JWT is not yet valid');
    }

    if (options?.issuer && payload.iss !== options.issuer) {
      getMetrics().incCounter('auth.jwt.validation.error', { reason: 'invalid_issuer' });
      throw new AuthenticationError('Invalid JWT issuer');
    }

    if (options?.audience) {
      const audiences = Array.isArray(options.audience) ? options.audience : [options.audience];
      const tokenAud = Array.isArray(payload.aud) ? payload.aud : payload.aud ? [payload.aud] : [];
      if (!audiences.some((a) => tokenAud.includes(a))) {
        getMetrics().incCounter('auth.jwt.validation.error', { reason: 'invalid_audience' });
        throw new AuthenticationError('Invalid JWT audience');
      }
    }

    if (payload.jti && revokedTokens.has(payload.jti)) {
      getMetrics().incCounter('auth.jwt.validation.error', { reason: 'revoked' });
      throw new AuthenticationError('JWT has been revoked');
    }

    const duration = Date.now() - startTime;
    getMetrics().observeHistogram('auth.jwt.validation.duration_ms', duration);
    getMetrics().incCounter('auth.jwt.validation.success');
    logger.info({ sub: payload.sub, jti: payload.jti, duration }, 'JWT validated successfully');
    span.end();
    return payload;
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    throw error;
  }
}

// 2. generateJwt
/**
 * @description Generates a signed JWT token with the given subject and options.
 * @param subject - The subject (user ID) for the token.
 * @param secret - The secret key used to sign the token.
 * @param options - Optional JWT claims and configuration.
 * @returns A signed JWT token string.
 * @example
 * const token = await generateJwt('user-123', 'my-secret', { expiresIn: 3600 });
 */
export async function generateJwt(
  subject: string,
  secret: string,
  options?: JwtOptions
): Promise<string> {
  const span = createSpan('auth.generateJwt');
  const startTime = Date.now();
  try {
    const now = Math.floor(Date.now() / 1000);
    const header = { alg: 'HS256', typ: 'JWT' };
    const payload: JwtPayload = {
      sub: subject,
      iss: options?.issuer,
      aud: options?.audience,
      iat: now,
      exp: now + (options?.expiresIn ?? 3600),
      jti: options?.tokenId ?? randomBytes(16).toString('hex'),
      scope: options?.scope,
      roles: options?.roles,
    };

    if (options?.notBefore) {
      payload.nbf = now + options.notBefore;
    }

    const headerB64 = base64UrlEncode(Buffer.from(JSON.stringify(header)));
    const payloadB64 = base64UrlEncode(Buffer.from(JSON.stringify(payload)));
    const signingInput = `${headerB64}.${payloadB64}`;
    const signature = hmacSha256(secret, signingInput);
    const token = `${signingInput}.${signature}`;

    const duration = Date.now() - startTime;
    getMetrics().observeHistogram('auth.jwt.generation.duration_ms', duration);
    getMetrics().incCounter('auth.jwt.generation.success');
    logger.info({ sub: subject, jti: payload.jti, duration }, 'JWT generated');
    span.end();
    return token;
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    throw error;
  }
}

// 3. revokeJwt
/**
 * @description Revokes a JWT token by its token ID, preventing further use.
 * @param tokenId - The unique identifier (jti) of the token to revoke.
 * @param reason - The reason for revocation.
 * @returns True if the token was successfully revoked.
 * @example
 * const revoked = await revokeJwt('token-id-123', 'user_logout');
 */
export async function revokeJwt(tokenId: string, reason: string): Promise<boolean> {
  const span = createSpan('auth.revokeJwt');
  const startTime = Date.now();
  try {
    revokedTokens.set(tokenId, { reason, revokedAt: Date.now() });
    const eventBus = getEventBus();
    await eventBus.publish('auth:token_revoked', {
      type: 'token_revoked',
      tokenId,
      reason,
      timestamp: Date.now(),
    } as SecurityEvent);

    getMetrics().incCounter('auth.jwt.revocation.success');
    logger.info({ tokenId, reason }, 'JWT revoked');
    span.end();
    return true;
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    throw error;
  }
}

// 4. rotateJwt
/**
 * @description Rotates an existing JWT by validating it and issuing a new one.
 * @param oldToken - The existing JWT token to rotate.
 * @param secret - The secret key for signing the new token.
 * @param options - Optional configuration for the new token.
 * @returns A newly generated JWT token string.
 * @example
 * const newToken = await rotateJwt(oldToken, 'my-secret', { expiresIn: 7200 });
 */
export async function rotateJwt(
  oldToken: string,
  secret: string,
  options?: JwtOptions
): Promise<string> {
  const span = createSpan('auth.rotateJwt');
  const startTime = Date.now();
  try {
    const payload = await validateJwt(oldToken, secret, options);

    if (payload.jti) {
      await revokeJwt(payload.jti, 'token_rotation');
    }

    const newToken = await generateJwt(payload.sub, secret, {
      ...options,
      tokenId: randomBytes(16).toString('hex'),
      scope: payload.scope as string[] | undefined,
      roles: payload.roles as string[] | undefined,
    });

    const duration = Date.now() - startTime;
    getMetrics().observeHistogram('auth.jwt.rotation.duration_ms', duration);
    getMetrics().incCounter('auth.jwt.rotation.success');
    logger.info({ oldJti: payload.jti, duration }, 'JWT rotated');
    span.end();
    return newToken;
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    throw error;
  }
}

// 5. validateRefreshToken
/**
 * @description Validates a refresh token and returns its payload.
 * @param token - The refresh token string to validate.
 * @param secret - The secret key used to verify the token signature.
 * @param userId - The expected user ID associated with the token.
 * @returns The validated refresh token payload.
 * @example
 * const payload = await validateRefreshToken(refreshToken, 'secret', 'user-123');
 */
export async function validateRefreshToken(
  token: string,
  secret: string,
  userId: string
): Promise<RefreshTokenPayload> {
  const span = createSpan('auth.validateRefreshToken');
  const startTime = Date.now();
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new AuthenticationError('Invalid refresh token format');
    }

    const [, payloadB64, signatureB64] = parts;
    const signingInput = `${parts[0]}.`;
    const expectedSig = hmacSha256(secret, signingInput);

    if (!constantTimeCompare(signatureB64, expectedSig)) {
      getMetrics().incCounter('auth.refresh_token.validation.error', { reason: 'invalid_signature' });
      throw new AuthenticationError('Invalid refresh token signature');
    }

    const payload: RefreshTokenPayload = JSON.parse(base64UrlDecode(payloadB64).toString('utf-8'));

    if (payload.exp < Math.floor(Date.now() / 1000)) {
      getMetrics().incCounter('auth.refresh_token.validation.error', { reason: 'expired' });
      throw new AuthenticationError('Refresh token has expired');
    }

    if (payload.userId !== userId) {
      getMetrics().incCounter('auth.refresh_token.validation.error', { reason: 'user_mismatch' });
      throw new AuthenticationError('Refresh token user mismatch');
    }

    if (revokedTokens.has(payload.jti)) {
      throw new AuthenticationError('Refresh token has been revoked');
    }

    const duration = Date.now() - startTime;
    getMetrics().observeHistogram('auth.refresh_token.validation.duration_ms', duration);
    getMetrics().incCounter('auth.refresh_token.validation.success');
    logger.info({ userId, jti: payload.jti, duration }, 'Refresh token validated');
    span.end();
    return payload;
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    throw error;
  }
}

// 6. secureSession
/**
 * @description Creates a new secure session with device and context tracking.
 * @param userId - The authenticated user ID.
 * @param ip - The client IP address.
 * @param userAgent - The client User-Agent string.
 * @param deviceId - The unique device identifier.
 * @returns A newly created session object.
 * @example
 * const session = await secureSession('user-123', '192.168.1.1', ua, 'device-abc');
 */
export async function secureSession(
  userId: string,
  ip: string,
  userAgent: string,
  deviceId: string
): Promise<Session> {
  const span = createSpan('auth.secureSession');
  const startTime = Date.now();
  try {
    const sessionId = randomBytes(32).toString('hex');
    const now = Date.now();
    const session: Session = {
      id: sessionId,
      userId,
      ip,
      userAgent,
      deviceId,
      createdAt: now,
      expiresAt: now + 86400000,
      lastAccessedAt: now,
      riskScore: 0,
      status: 'active',
    };

    const cache = getCache();
    await cache.set(`session:${sessionId}`, JSON.stringify(session), 86400);

    const eventBus = getEventBus();
    await eventBus.publish('auth:session_created', {
      type: 'session_created',
      userId,
      sessionId,
      deviceId,
      ip,
      timestamp: now,
    } as SecurityEvent);

    const duration = Date.now() - startTime;
    getMetrics().observeHistogram('auth.session.creation.duration_ms', duration);
    getMetrics().incCounter('auth.session.creation.success');
    logger.info({ userId, sessionId, deviceId, duration }, 'Session created');
    span.end();
    return session;
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    throw error;
  }
}

// 7. validateSession
/**
 * @description Validates an active session against user ID and IP constraints.
 * @param sessionId - The session ID to validate.
 * @param userId - The expected user ID for the session.
 * @param ip - The current client IP to verify against the session.
 * @returns True if the session is valid and active.
 * @example
 * const isValid = await validateSession(sessionId, 'user-123', '192.168.1.1');
 */
export async function validateSession(
  sessionId: string,
  userId: string,
  ip: string
): Promise<boolean> {
  const span = createSpan('auth.validateSession');
  const startTime = Date.now();
  try {
    const cache = getCache();
    const sessionData = await cache.get(`session:${sessionId}`);
    if (!sessionData) {
      getMetrics().incCounter('auth.session.validation.error', { reason: 'not_found' });
      return false;
    }

    const session: Session = JSON.parse(sessionData);

    if (session.status !== 'active') {
      getMetrics().incCounter('auth.session.validation.error', { reason: 'inactive' });
      return false;
    }

    if (session.userId !== userId) {
      getMetrics().incCounter('auth.session.validation.error', { reason: 'user_mismatch' });
      return false;
    }

    if (Date.now() > session.expiresAt) {
      getMetrics().incCounter('auth.session.validation.error', { reason: 'expired' });
      session.status = 'revoked';
      await cache.set(`session:${sessionId}`, JSON.stringify(session), 0);
      return false;
    }

    session.lastAccessedAt = Date.now();
    await cache.set(`session:${sessionId}`, JSON.stringify(session), 86400);

    const duration = Date.now() - startTime;
    getMetrics().observeHistogram('auth.session.validation.duration_ms', duration);
    getMetrics().incCounter('auth.session.validation.success');
    logger.debug({ sessionId, userId, duration }, 'Session validated');
    span.end();
    return true;
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    throw error;
  }
}

// 8. detectSessionHijack
/**
 * @description Detects potential session hijacking by comparing current request
 * characteristics against historical session data.
 * @param sessionId - The session ID to check.
 * @param currentIp - The current request IP address.
 * @param currentUa - The current request User-Agent string.
 * @param historical - Historical session data for comparison.
 * @returns True if session hijacking is suspected.
 * @example
 * const hijacked = await detectSessionHijack(sessionId, ip, ua, historicalSessions);
 */
export async function detectSessionHijack(
  sessionId: string,
  currentIp: string,
  currentUa: string,
  historical: { ip: string; userAgent: string; timestamp: number }[]
): Promise<boolean> {
  const span = createSpan('auth.detectSessionHijack');
  const startTime = Date.now();
  try {
    if (historical.length === 0) {
      span.end();
      return false;
    }

    const lastSession = historical[historical.length - 1];
    let riskScore = 0;

    if (currentIp !== lastSession.ip) {
      riskScore += 0.4;
      const ipParts = currentIp.split('.');
      const lastIpParts = lastSession.ip.split('.');
      if (ipParts[0] !== lastIpParts[0] || ipParts[1] !== lastIpParts[1]) {
        riskScore += 0.3;
      }
    }

    if (currentUa !== lastSession.userAgent) {
      riskScore += 0.5;
    }

    const timeSinceLastAccess = Date.now() - lastSession.timestamp;
    if (timeSinceLastAccess < 1000 && currentIp !== lastSession.ip) {
      riskScore += 0.3;
    }

    const hijacked = riskScore >= 0.7;

    if (hijacked) {
      getMetrics().incCounter('auth.session.hijack_detected');
      logger.warn({ sessionId, currentIp, riskScore, duration: Date.now() - startTime }, 'Potential session hijack detected');

      const eventBus = getEventBus();
      await eventBus.publish('auth:session_hijack_detected', {
        type: 'session_hijack_detected',
        sessionId,
        currentIp,
        riskScore,
        timestamp: Date.now(),
      } as SecurityEvent);
    }

    getMetrics().observeHistogram('auth.session.hijack_check.duration_ms', Date.now() - startTime);
    span.end();
    return hijacked;
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    throw error;
  }
}

// 9. detectTokenReplay
/**
 * @description Detects token replay attacks by tracking token usage patterns.
 * @param tokenId - The unique token identifier.
 * @param timestamp - The timestamp of the current token use.
 * @param ip - The IP address making the request.
 * @returns True if a token replay attack is suspected.
 * @example
 * const replayed = await detectTokenReplay(tokenId, Date.now(), '192.168.1.1');
 */
export async function detectTokenReplay(
  tokenId: string,
  timestamp: number,
  ip: string
): Promise<boolean> {
  const span = createSpan('auth.detectTokenReplay');
  const startTime = Date.now();
  try {
    const accessLog = tokenAccessLog.get(tokenId) || [];
    const recentAccesses = accessLog.filter((a) => timestamp - a.timestamp < 5000);

    if (recentAccesses.length > 0) {
      const differentIps = new Set(recentAccesses.map((a) => a.ip));
      differentIps.add(ip);

      if (differentIps.size > 1) {
        getMetrics().incCounter('auth.token.replay_detected');
        logger.warn({ tokenId, ip, accessCount: recentAccesses.length, duration: Date.now() - startTime }, 'Token replay detected');

        const eventBus = getEventBus();
        await eventBus.publish('auth:token_replay_detected', {
          type: 'token_replay_detected',
          tokenId,
          ip,
          timestamp,
        } as SecurityEvent);

        span.end();
        return true;
      }

      if (recentAccesses.length > 3) {
        getMetrics().incCounter('auth.token.replay_suspected');
        span.end();
        return true;
      }
    }

    accessLog.push({ ip, timestamp });
    if (accessLog.length > 100) accessLog.splice(0, 50);
    tokenAccessLog.set(tokenId, accessLog);

    getMetrics().observeHistogram('auth.token.replay_check.duration_ms', Date.now() - startTime);
    span.end();
    return false;
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    throw error;
  }
}

// 10. detectCredentialStuffing
/**
 * @description Detects credential stuffing attacks by analyzing login attempt patterns.
 * @param ip - The source IP address of login attempts.
 * @param username - The username being attempted.
 * @param attempts - Number of recent failed attempts.
 * @param window - Time window in milliseconds for the attempt count.
 * @returns True if credential stuffing is suspected.
 * @example
 * const stuffing = await detectCredentialStuffing(ip, 'admin', 15, 60000);
 */
export async function detectCredentialStuffing(
  ip: string,
  username: string,
  attempts: number,
  window: number
): Promise<boolean> {
  const span = createSpan('auth.detectCredentialStuffing');
  const startTime = Date.now();
  try {
    const cache = getCache();
    const key = `cred_stuff:${ip}`;
    const existing = await cache.get(key);
    const records: { username: string; timestamp: number }[] = existing ? JSON.parse(existing) : [];

    const now = Date.now();
    const windowRecords = records.filter((r) => now - r.timestamp < window);
    windowRecords.push({ username, timestamp: now });
    await cache.set(key, JSON.stringify(windowRecords), Math.ceil(window / 1000));

    const uniqueUsernames = new Set(windowRecords.map((r) => r.username));
    const stuffingDetected = windowRecords.length > 10 && uniqueUsernames.size > 5;

    if (stuffingDetected) {
      getMetrics().incCounter('auth.credential_stuffing.detected');
      logger.warn({ ip, attempts, uniqueUsernames: uniqueUsernames.size, duration: Date.now() - startTime }, 'Credential stuffing detected');

      const eventBus = getEventBus();
      await eventBus.publish('auth:credential_stuffing_detected', {
        type: 'credential_stuffing_detected',
        ip,
        uniqueUsernames: uniqueUsernames.size,
        attemptCount: windowRecords.length,
        timestamp: now,
      } as SecurityEvent);
    }

    getMetrics().observeHistogram('auth.credential_stuffing.check.duration_ms', Date.now() - startTime);
    span.end();
    return stuffingDetected;
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    throw error;
  }
}

// 11. detectBruteforce
/**
 * @description Detects brute force login attempts from a specific IP.
 * @param ip - The source IP address.
 * @param attempts - Number of recent failed login attempts.
 * @param window - Time window in milliseconds for counting attempts.
 * @param threshold - Maximum allowed attempts before flagging.
 * @returns True if brute force attack is detected.
 * @example
 * const bruteforce = await detectBruteforce(ip, 20, 300000, 10);
 */
export async function detectBruteforce(
  ip: string,
  attempts: number,
  window: number,
  threshold: number
): Promise<boolean> {
  const span = createSpan('auth.detectBruteforce');
  const startTime = Date.now();
  try {
    const cache = getCache();
    const key = `bruteforce:${ip}`;
    const count = await cache.get(key);
    const currentAttempts = count ? parseInt(count, 10) : attempts;

    if (currentAttempts >= threshold) {
      getMetrics().incCounter('auth.bruteforce.detected', { ip, attempts: currentAttempts });
      logger.warn({ ip, attempts: currentAttempts, threshold, duration: Date.now() - startTime }, 'Brute force attack detected');

      const eventBus = getEventBus();
      await eventBus.publish('auth:bruteforce_detected', {
        type: 'bruteforce_detected',
        ip,
        attempts: currentAttempts,
        threshold,
        timestamp: Date.now(),
      } as SecurityEvent);

      span.end();
      return true;
    }

    await cache.set(key, String(currentAttempts + 1), Math.ceil(window / 1000));
    getMetrics().observeHistogram('auth.bruteforce.check.duration_ms', Date.now() - startTime);
    span.end();
    return false;
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    throw error;
  }
}

// 12. adaptiveAuth
/**
 * @description Performs adaptive authentication based on risk score and context.
 * @param userId - The user attempting authentication.
 * @param riskScore - Pre-computed risk score (0-1).
 * @param context - Authentication context information.
 * @returns Authentication result with MFA requirements.
 * @example
 * const result = await adaptiveAuth('user-123', 0.7, { ip: '1.2.3.4', userAgent: ua });
 */
export async function adaptiveAuth(
  userId: string,
  riskScore: number,
  context: RiskContext
): Promise<AuthResult> {
  const span = createSpan('auth.adaptiveAuth');
  const startTime = Date.now();
  try {
    let requiresMfa = false;
    let mfaMethod: string | undefined;
    let authenticated = true;
    let reason: string | undefined;

    if (riskScore >= 0.8) {
      authenticated = false;
      requiresMfa = true;
      mfaMethod = 'webauthn';
      reason = 'High risk score requires hardware key authentication';
    } else if (riskScore >= 0.5) {
      requiresMfa = true;
      mfaMethod = 'totp';
      reason = 'Elevated risk score requires TOTP verification';
    } else if (riskScore >= 0.3) {
      requiresMfa = true;
      mfaMethod = 'sms';
      reason = 'Moderate risk score requires SMS verification';
    }

    const result: AuthResult = {
      authenticated,
      riskScore,
      requiresMfa,
      mfaMethod,
      reason,
    };

    const duration = Date.now() - startTime;
    getMetrics().observeHistogram('auth.adaptive.duration_ms', duration);
    getMetrics().incCounter('auth.adaptive.evaluated', { risk_level: riskScore >= 0.5 ? 'high' : 'low' });
    logger.info({ userId, riskScore, requiresMfa, mfaMethod, duration }, 'Adaptive auth evaluated');
    span.end();
    return result;
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    throw error;
  }
}

// 13. behavioralAuth
/**
 * @description Authenticates a user based on behavioral biometrics analysis.
 * @param userId - The user to authenticate.
 * @param behaviorData - Current behavioral data from the session.
 * @param baseline - The user's established behavioral baseline.
 * @returns A confidence score (0-1) matching the user's behavior.
 * @example
 * const confidence = await behavioralAuth('user-123', behaviorData, baseline);
 */
export async function behavioralAuth(
  userId: string,
  behaviorData: BehaviorData,
  baseline: BehaviorBaseline
): Promise<number> {
  const span = createSpan('auth.behavioralAuth');
  const startTime = Date.now();
  try {
    let confidence = 1.0;

    if (behaviorData.typingSpeed !== undefined && baseline.avgTypingSpeed > 0) {
      const typingDiff = Math.abs(behaviorData.typingSpeed - baseline.avgTypingSpeed) / baseline.avgTypingSpeed;
      confidence -= Math.min(typingDiff * 0.3, 0.3);
    }

    if (behaviorData.mouseMovement && behaviorData.mouseMovement.length > 1) {
      const speeds = behaviorData.mouseMovement
        .slice(1)
        .map((m, i) => {
          const prev = behaviorData.mouseMovement![i];
          const dx = m.x - prev.x;
          const dy = m.y - prev.y;
          const dt = m.timestamp - prev.timestamp;
          return dt > 0 ? Math.sqrt(dx * dx + dy * dy) / dt : 0;
        });
      const avgMouseSpeed = speeds.reduce((a, b) => a + b, 0) / speeds.length;
      const mouseDiff = Math.abs(avgMouseSpeed - baseline.avgMouseSpeed) / (baseline.avgMouseSpeed || 1);
      confidence -= Math.min(mouseDiff * 0.2, 0.2);
    }

    if (behaviorData.sessionDuration !== undefined && baseline.typicalSessionDuration > 0) {
      const durationDiff = Math.abs(behaviorData.sessionDuration - baseline.typicalSessionDuration) / baseline.typicalSessionDuration;
      confidence -= Math.min(durationDiff * 0.1, 0.1);
    }

    if (behaviorData.navigationPatterns && baseline.commonPaths.length > 0) {
      const commonMatches = behaviorData.navigationPatterns.filter((p) =>
        baseline.commonPaths.some((bp) => p.includes(bp))
      ).length;
      const pathRatio = commonMatches / behaviorData.navigationPatterns.length;
      confidence -= (1 - pathRatio) * 0.2;
    }

    const finalConfidence = Math.max(0, Math.min(1, confidence));

    const duration = Date.now() - startTime;
    getMetrics().observeHistogram('auth.behavioral.confidence', finalConfidence);
    getMetrics().observeHistogram('auth.behavioral.duration_ms', duration);
    logger.debug({ userId, confidence: finalConfidence, duration }, 'Behavioral auth evaluated');
    span.end();
    return finalConfidence;
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    throw error;
  }
}

// 14. impossibleTravel
/**
 * @description Detects impossible travel scenarios between two locations.
 * @param userId - The user whose travel is being checked.
 * @param currentLocation - Current login location (lat/lon).
 * @param lastLocation - Previous login location (lat/lon).
 * @param timeDelta - Time difference in milliseconds between logins.
 * @returns True if the travel between locations is physically impossible.
 * @example
 * const impossible = await impossibleTravel('user-123', currentLoc, lastLoc, 3600000);
 */
export async function impossibleTravel(
  userId: string,
  currentLocation: { lat: number; lon: number },
  lastLocation: { lat: number; lon: number },
  timeDelta: number
): Promise<boolean> {
  const span = createSpan('auth.impossibleTravel');
  const startTime = Date.now();
  try {
    const distanceKm = haversineDistance(
      currentLocation.lat,
      currentLocation.lon,
      lastLocation.lat,
      lastLocation.lon
    );

    const timeHours = timeDelta / (1000 * 60 * 60);
    if (timeHours <= 0) {
      span.end();
      return distanceKm > 0;
    }

    const requiredSpeedKmh = distanceKm / timeHours;
    const maxCommercialSpeed = 900;
    const impossible = requiredSpeedKmh > maxCommercialSpeed;

    if (impossible) {
      getMetrics().incCounter('auth.impossible_travel.detected');
      logger.warn(
        { userId, distanceKm, requiredSpeedKmh, timeDelta, duration: Date.now() - startTime },
        'Impossible travel detected'
      );

      const eventBus = getEventBus();
      await eventBus.publish('auth:impossible_travel', {
        type: 'impossible_travel',
        userId,
        distanceKm,
        requiredSpeedKmh,
        timestamp: Date.now(),
      } as SecurityEvent);
    }

    getMetrics().observeHistogram('auth.impossible_travel.duration_ms', Date.now() - startTime);
    span.end();
    return impossible;
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    throw error;
  }
}

// 15. geoVelocityCheck
/**
 * @description Checks geographic velocity across multiple login locations.
 * @param userId - The user whose locations are being checked.
 * @param locations - Array of login locations with timestamps.
 * @param maxSpeedKmh - Maximum allowed speed in km/h (default: 900).
 * @returns True if any location pair exceeds the maximum speed.
 * @example
 * const exceeded = await geoVelocityCheck('user-123', locations, 900);
 */
export async function geoVelocityCheck(
  userId: string,
  locations: Location[],
  maxSpeedKmh: number = 900
): Promise<boolean> {
  const span = createSpan('auth.geoVelocityCheck');
  const startTime = Date.now();
  try {
    if (locations.length < 2) {
      span.end();
      return false;
    }

    const sorted = [...locations].sort((a, b) => a.timestamp - b.timestamp);

    for (let i = 1; i < sorted.length; i++) {
      const prev = sorted[i - 1];
      const curr = sorted[i];
      const distanceKm = haversineDistance(prev.lat, prev.lon, curr.lat, curr.lon);
      const timeHours = (curr.timestamp - prev.timestamp) / (1000 * 60 * 60);

      if (timeHours > 0) {
        const speedKmh = distanceKm / timeHours;
        if (speedKmh > maxSpeedKmh) {
          getMetrics().incCounter('auth.geo_velocity.exceeded');
          logger.warn(
            { userId, speedKmh, maxSpeedKmh, distanceKm, duration: Date.now() - startTime },
            'Geo velocity check exceeded'
          );
          span.end();
          return true;
        }
      }
    }

    getMetrics().observeHistogram('auth.geo_velocity.duration_ms', Date.now() - startTime);
    span.end();
    return false;
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    throw error;
  }
}

// 16. riskBasedAuth
/**
 * @description Performs risk-based authentication using multiple risk factors.
 * @param userId - The user attempting authentication.
 * @param context - Authentication context (IP, location, device, etc.).
 * @param riskFactors - Individual risk factor scores.
 * @returns Authentication result with composite risk assessment.
 * @example
 * const result = await riskBasedAuth('user-123', context, { geoRisk: 0.3, deviceRisk: 0.1 });
 */
export async function riskBasedAuth(
  userId: string,
  context: RiskContext,
  riskFactors: RiskFactors
): Promise<AuthResult> {
  const span = createSpan('auth.riskBasedAuth');
  const startTime = Date.now();
  try {
    const weights = {
      geoRisk: 0.25,
      deviceRisk: 0.2,
      behaviorRisk: 0.2,
      networkRisk: 0.15,
      reputationRisk: 0.2,
    };

    const compositeRisk =
      (riskFactors.geoRisk ?? 0) * weights.geoRisk +
      (riskFactors.deviceRisk ?? 0) * weights.deviceRisk +
      (riskFactors.behaviorRisk ?? 0) * weights.behaviorRisk +
      (riskFactors.networkRisk ?? 0) * weights.networkRisk +
      (riskFactors.reputationRisk ?? 0) * weights.reputationRisk;

    const normalizedRisk = Math.max(0, Math.min(1, compositeRisk));

    let requiresMfa = false;
    let mfaMethod: string | undefined;
    let authenticated = true;
    let reason: string | undefined;

    if (normalizedRisk >= 0.75) {
      authenticated = false;
      requiresMfa = true;
      mfaMethod = 'webauthn';
      reason = 'Composite risk score too high';
    } else if (normalizedRisk >= 0.5) {
      requiresMfa = true;
      mfaMethod = 'totp';
      reason = 'Elevated composite risk requires MFA';
    } else if (normalizedRisk >= 0.3) {
      requiresMfa = true;
      mfaMethod = 'email';
      reason = 'Moderate composite risk requires email verification';
    }

    const result: AuthResult = {
      authenticated,
      riskScore: normalizedRisk,
      requiresMfa,
      mfaMethod,
      reason,
    };

    const duration = Date.now() - startTime;
    getMetrics().observeHistogram('auth.risk_based.score', normalizedRisk);
    getMetrics().observeHistogram('auth.risk_based.duration_ms', duration);
    logger.info({ userId, riskScore: normalizedRisk, riskFactors, duration }, 'Risk-based auth evaluated');
    span.end();
    return result;
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    throw error;
  }
}

// 17. passkeyAuth
/**
 * @description Authenticates using a passkey (FIDO2/WebAuthn) credential.
 * @param challenge - The authentication challenge sent to the client.
 * @param authenticatorData - Raw authenticator data from the response.
 * @param clientDataJson - Client data JSON from the WebAuthn response.
 * @param signature - Cryptographic signature from the authenticator.
 * @returns True if the passkey authentication is valid.
 * @example
 * const valid = await passkeyAuth(challenge, authData, clientDataJson, signature);
 */
export async function passkeyAuth(
  challenge: string,
  authenticatorData: Buffer,
  clientDataJson: Buffer,
  signature: Buffer
): Promise<boolean> {
  const span = createSpan('auth.passkeyAuth');
  const startTime = Date.now();
  try {
    const clientData = JSON.parse(clientDataJson.toString('utf-8'));

    if (clientData.type !== 'webauthn.get') {
      getMetrics().incCounter('auth.passkey.error', { reason: 'invalid_type' });
      throw new ValidationError('Invalid client data type');
    }

    const challengeHash = createHash('sha256').update(challenge).digest();
    if (!constantTimeCompare(clientData.challenge, challengeHash.toString('base64url'))) {
      getMetrics().incCounter('auth.passkey.error', { reason: 'challenge_mismatch' });
      throw new ValidationError('Challenge mismatch');
    }

    const message = Buffer.concat([authenticatorData, createHash('sha256').update(clientDataJson).digest()]);

    try {
      const crypto = await import('crypto');
      const publicKey = authenticatorData.slice(37);
      if (publicKey.length <= 0) {
        throw new Error('No public key in authenticator data');
      }

      const verify = crypto.createVerify('SHA256');
      verify.update(message);
      const isValid = verify.verify(publicKey, signature);

      const duration = Date.now() - startTime;
      getMetrics().observeHistogram('auth.passkey.duration_ms', duration);
      if (isValid) {
        getMetrics().incCounter('auth.passkey.success');
      } else {
        getMetrics().incCounter('auth.passkey.failure');
      }
      logger.info({ isValid, duration }, 'Passkey auth evaluated');
      span.end();
      return isValid;
    } catch {
      getMetrics().incCounter('auth.passkey.error', { reason: 'verification_failed' });
      span.end();
      return false;
    }
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    if (error instanceof ValidationError) throw error;
    return false;
  }
}

// 18. webauthnVerify
/**
 * @description Verifies a WebAuthn authentication response against a stored credential.
 * @param credentialId - The credential identifier.
 * @param challenge - The challenge that was sent to the client.
 * @param origin - The expected origin of the request.
 * @param rpId - The relying party ID.
 * @param publicKey - The stored public key for the credential.
 * @param signature - The signature from the authenticator.
 * @param authData - The authenticator data.
 * @param clientData - The client data JSON string.
 * @returns True if the WebAuthn verification succeeds.
 * @example
 * const valid = await webauthnVerify(credId, challenge, origin, rpId, pubKey, sig, authData, clientData);
 */
export async function webauthnVerify(
  credentialId: string,
  challenge: string,
  origin: string,
  rpId: string,
  publicKey: Buffer,
  signature: Buffer,
  authData: Buffer,
  clientData: string
): Promise<boolean> {
  const span = createSpan('auth.webauthnVerify');
  const startTime = Date.now();
  try {
    const clientDataObj = JSON.parse(clientData);

    if (clientDataObj.type !== 'webauthn.get') {
      getMetrics().incCounter('auth.webauthn.error', { reason: 'invalid_type' });
      return false;
    }

    if (!constantTimeCompare(clientDataObj.challenge, Buffer.from(challenge).toString('base64url'))) {
      getMetrics().incCounter('auth.webauthn.error', { reason: 'challenge_mismatch' });
      return false;
    }

    if (clientDataObj.origin !== origin) {
      getMetrics().incCounter('auth.webauthn.error', { reason: 'origin_mismatch' });
      return false;
    }

    const rpIdHash = createHash('sha256').update(rpId).digest();
    const authDataRpIdHash = authData.slice(0, 32);
    if (!timingSafeEqual(rpIdHash, authDataRpIdHash)) {
      getMetrics().incCounter('auth.webauthn.error', { reason: 'rp_id_mismatch' });
      return false;
    }

    const clientDataHash = createHash('sha256').update(Buffer.from(clientData)).digest();
    const verifyData = Buffer.concat([authData, clientDataHash]);

    try {
      const crypto = await import('crypto');
      const verify = crypto.createVerify('SHA256');
      verify.update(verifyData);
      const isValid = verify.verify(publicKey, signature);

      const duration = Date.now() - startTime;
      getMetrics().observeHistogram('auth.webauthn.duration_ms', duration);
      if (isValid) {
        getMetrics().incCounter('auth.webauthn.success');
      } else {
        getMetrics().incCounter('auth.webauthn.failure');
      }
      logger.info({ credentialId, isValid, duration }, 'WebAuthn verified');
      span.end();
      return isValid;
    } catch {
      getMetrics().incCounter('auth.webauthn.error', { reason: 'verification_failed' });
      span.end();
      return false;
    }
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    return false;
  }
}

// 19. generateTotp
/**
 * @description Generates a TOTP code from a shared secret.
 * @param secret - The base32-encoded shared secret.
 * @param digits - Number of digits in the TOTP code (default: 6).
 * @param period - Time step period in seconds (default: 30).
 * @param timeStep - Optional specific time step to use.
 * @returns The generated TOTP code as a zero-padded string.
 * @example
 * const code = generateTotp('JBSWY3DPEHPK3PXP', 6, 30);
 */
export function generateTotp(
  secret: string,
  digits: number = 6,
  period: number = 30,
  timeStep?: number
): string {
  const span = createSpan('auth.generateTotp');
  const startTime = Date.now();
  try {
    const key = base32ToBuffer(secret);
    const time = timeStep ?? Math.floor(Date.now() / 1000 / period);
    const timeBuffer = Buffer.alloc(8);
    timeBuffer.writeBigUInt64BE(BigInt(time));

    const hmac = createHmac('sha1', key);
    hmac.update(timeBuffer);
    const hmacResult = hmac.digest();

    const offset = hmacResult[hmacResult.length - 1] & 0x0f;
    const code =
      ((hmacResult[offset] & 0x7f) << 24) |
      ((hmacResult[offset + 1] & 0xff) << 16) |
      ((hmacResult[offset + 2] & 0xff) << 8) |
      (hmacResult[offset + 3] & 0xff);

    const totp = (code % 10 ** digits).toString().padStart(digits, '0');

    getMetrics().incCounter('auth.totp.generated');
    logger.debug({ digits, period, duration: Date.now() - startTime }, 'TOTP generated');
    span.end();
    return totp;
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    throw error;
  }
}

// 20. validateTotp
/**
 * @description Validates a TOTP code allowing for clock drift.
 * @param secret - The base32-encoded shared secret.
 * @param token - The TOTP code to validate.
 * @param digits - Number of digits expected (default: 6).
 * @param period - Time step period in seconds (default: 30).
 * @param drift - Allowed clock drift in steps (default: 1).
 * @returns True if the token is valid within the allowed drift window.
 * @example
 * const valid = validateTotp('JBSWY3DPEHPK3PXP', '123456', 6, 30, 1);
 */
export function validateTotp(
  secret: string,
  token: string,
  digits: number = 6,
  period: number = 30,
  drift: number = 1
): boolean {
  const span = createSpan('auth.validateTotp');
  const startTime = Date.now();
  try {
    const currentTimeStep = Math.floor(Date.now() / 1000 / period);

    for (let i = -drift; i <= drift; i++) {
      const expected = generateTotp(secret, digits, period, currentTimeStep + i);
      if (constantTimeCompare(token, expected)) {
        getMetrics().incCounter('auth.totp.validation.success');
        logger.debug({ drift: i, duration: Date.now() - startTime }, 'TOTP validated');
        span.end();
        return true;
      }
    }

    getMetrics().incCounter('auth.totp.validation.failure');
    span.end();
    return false;
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    return false;
  }
}

// 21. verifyBackupCode
/**
 * @description Verifies a backup/recovery code against a list of valid codes.
 * @param code - The backup code to verify.
 * @param validCodes - Array of valid backup codes.
 * @returns True if the code is valid (and consumed).
 * @example
 * const valid = verifyBackupCode('abcd-1234', ['abcd-1234', 'efgh-5678']);
 */
export function verifyBackupCode(code: string, validCodes: string[]): boolean {
  const span = createSpan('auth.verifyBackupCode');
  const startTime = Date.now();
  try {
    const normalizedCode = code.trim().toLowerCase();
    const index = validCodes.findIndex((c) => constantTimeCompare(c.toLowerCase(), normalizedCode));

    if (index !== -1) {
      validCodes.splice(index, 1);
      getMetrics().incCounter('auth.backup_code.success');
      logger.info({ duration: Date.now() - startTime }, 'Backup code verified');
      span.end();
      return true;
    }

    getMetrics().incCounter('auth.backup_code.failure');
    span.end();
    return false;
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    return false;
  }
}

// 22. passwordEntropy
/**
 * @description Calculates the Shannon entropy of a password in bits.
 * @param password - The password to analyze.
 * @returns The entropy value in bits per character.
 * @example
 * const entropy = passwordEntropy('MyP@ssw0rd!');
 */
export function passwordEntropy(password: string): number {
  const span = createSpan('auth.passwordEntropy');
  const startTime = Date.now();
  try {
    if (password.length === 0) {
      span.end();
      return 0;
    }

    const freq = new Map<string, number>();
    for (const char of password) {
      freq.set(char, (freq.get(char) || 0) + 1);
    }

    let entropy = 0;
    const len = password.length;
    for (const count of freq.values()) {
      const probability = count / len;
      entropy -= probability * Math.log2(probability);
    }

    const totalEntropy = entropy * len;
    logger.debug({ passwordLength: len, entropy: totalEntropy, duration: Date.now() - startTime }, 'Password entropy calculated');
    span.end();
    return totalEntropy;
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    return 0;
  }
}

// 23. detectWeakPassword
/**
 * @description Detects if a password is weak based on entropy and common password lists.
 * @param password - The password to check.
 * @param minEntropy - Minimum acceptable entropy (default: 28 bits).
 * @param commonPasswords - Set of common passwords to check against.
 * @returns True if the password is considered weak.
 * @example
 * const weak = detectWeakPassword('password123', 28, new Set(['password', '123456']));
 */
export function detectWeakPassword(
  password: string,
  minEntropy: number = 28,
  commonPasswords: Set<string> = new Set()
): boolean {
  const span = createSpan('auth.detectWeakPassword');
  const startTime = Date.now();
  try {
    if (password.length < 8) {
      getMetrics().incCounter('auth.password.weak', { reason: 'too_short' });
      span.end();
      return true;
    }

    const entropy = passwordEntropy(password);
    if (entropy < minEntropy) {
      getMetrics().incCounter('auth.password.weak', { reason: 'low_entropy', entropy });
      span.end();
      return true;
    }

    const lowerPassword = password.toLowerCase();
    for (const common of commonPasswords) {
      if (constantTimeCompare(lowerPassword, common.toLowerCase())) {
        getMetrics().incCounter('auth.password.weak', { reason: 'common_password' });
        span.end();
        return true;
      }
    }

    getMetrics().incCounter('auth.password.strength_check');
    logger.debug({ entropy, isWeak: false, duration: Date.now() - startTime }, 'Password strength check passed');
    span.end();
    return false;
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    return true;
  }
}

// 24. passwordBreachCheck
/**
 * @description Checks if a password hash exists in a known breach database.
 * @param passwordHash - The SHA-1 hash prefix of the password to check.
 * @param breachDb - The breach database (map of hash suffixes to counts).
 * @returns True if the password has been found in a breach.
 * @example
 * const breached = await passwordBreachCheck(hashPrefix, breachDatabase);
 */
export async function passwordBreachCheck(
  passwordHash: string,
  breachDb: Map<string, number>
): Promise<boolean> {
  const span = createSpan('auth.passwordBreachCheck');
  const startTime = Date.now();
  try {
    const hash = passwordHash.toUpperCase();
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);

    for (const [dbSuffix, count] of breachDb.entries()) {
      if (constantTimeCompare(dbSuffix.toUpperCase(), suffix) && count > 0) {
        getMetrics().incCounter('auth.password.breached');
        logger.warn({ breachCount: count, duration: Date.now() - startTime }, 'Password found in breach database');
        span.end();
        return true;
      }
    }

    getMetrics().incCounter('auth.password.breach_check.clean');
    span.end();
    return false;
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    throw error;
  }
}

// 25. securePasswordHash
/**
 * @description Creates a secure password hash using the specified algorithm.
 * @param password - The plaintext password to hash.
 * @param algorithm - Hashing algorithm ('pbkdf2-sha256', 'pbkdf2-sha3-256', 'hmac-sha256').
 * @param salt - Optional salt (generated if not provided).
 * @param iterations - Number of iterations (default: 100000).
 * @returns The hashed password string in format 'algorithm\\\'.
 * @example
 * const hash = await securePasswordHash('password', 'pbkdf2-sha256', undefined, 100000);
 */
export async function securePasswordHash(
  password: string,
  algorithm: string = 'pbkdf2-sha256',
  salt?: string,
  iterations: number = 100000
): Promise<string> {
  const span = createSpan('auth.securePasswordHash');
  const startTime = Date.now();
  try {
    const saltValue = salt || randomBytes(16).toString('hex');
    let hash: Buffer;

    switch (algorithm) {
      case 'pbkdf2-sha256':
        hash = await new Promise<Buffer>((resolve, reject) => {
          import('crypto').then((crypto) => {
            crypto.pbkdf2(password, saltValue, iterations, 32, 'sha256', (err, derivedKey) => {
              if (err) reject(err);
              else resolve(derivedKey);
            });
          });
        });
        break;

      case 'pbkdf2-sha3-256': {
        const saltedPassword = `${password}${saltValue}`;
        let derived = Buffer.from(saltedPassword);
        for (let i = 0; i < Math.min(iterations / 1000, 100); i++) {
          derived = Buffer.from(sha3_256(derived));
        }
        hash = derived;
        break;
      }

      case 'hmac-sha256':
        hash = createHmac('sha256', saltValue).update(password).digest();
        break;

      default:
        throw new ValidationError(`Unsupported algorithm: ${algorithm}`);
    }

    const hashString = `${algorithm}$${iterations}$${saltValue}$${hash.toString('hex')}`;

    const duration = Date.now() - startTime;
    getMetrics().observeHistogram('auth.password.hash.duration_ms', duration);
    getMetrics().incCounter('auth.password.hash.success');
    logger.debug({ algorithm, iterations, duration }, 'Password hashed');
    span.end();
    return hashString;
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    throw error;
  }
}

// 26. verifyPasswordHash
/**
 * @description Verifies a password against a stored hash.
 * @param password - The plaintext password to verify.
 * @param hashValue - The stored hash string in format 'algorithm\\\'.
 * @returns True if the password matches the stored hash.
 * @example
 * const valid = await verifyPasswordHash('password', 'pbkdf2-sha256\\\');
 */
export async function verifyPasswordHash(
  password: string,
  hashValue: string
): Promise<boolean> {
  const span = createSpan('auth.verifyPasswordHash');
  const startTime = Date.now();
  try {
    const parts = hashValue.split('$');
    if (parts.length !== 4) {
      throw new ValidationError('Invalid hash format');
    }

    const [algorithm, iterationsStr, salt, storedHash] = parts;
    const iterations = parseInt(iterationsStr, 10);

    const computedHash = await securePasswordHash(password, algorithm, salt, iterations);
    const computedParts = computedHash.split('$');
    const computedHashValue = computedParts[3];

    const isValid = constantTimeCompare(computedHashValue, storedHash);

    const duration = Date.now() - startTime;
    getMetrics().observeHistogram('auth.password.verify.duration_ms', duration);
    if (isValid) {
      getMetrics().incCounter('auth.password.verify.success');
    } else {
      getMetrics().incCounter('auth.password.verify.failure');
    }
    logger.debug({ isValid, duration }, 'Password hash verified');
    span.end();
    return isValid;
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    if (error instanceof ValidationError) throw error;
    return false;
  }
}

// 27. deviceFingerprint
/**
 * @description Generates a device fingerprint from client characteristics.
 * @param userAgent - The browser User-Agent string.
 * @param screen - Screen resolution (e.g., '1920x1080').
 * @param timezone - The browser timezone offset.
 * @param languages - Array of preferred languages.
 * @param platform - The OS platform string.
 * @returns A SHA3-256 hash representing the device fingerprint.
 * @example
 * const fingerprint = deviceFingerprint(ua, '1920x1080', '-300', ['en-US'], 'Win32');
 */
export function deviceFingerprint(
  userAgent: string,
  screen: string,
  timezone: string,
  languages: string[],
  platform: string
): string {
  const span = createSpan('auth.deviceFingerprint');
  const startTime = Date.now();
  try {
    const components = [
      userAgent.toLowerCase(),
      screen.toLowerCase(),
      timezone.toLowerCase(),
      languages.map((l) => l.toLowerCase()).join(','),
      platform.toLowerCase(),
    ].join('|');

    const hash = Buffer.from(sha3_256(Buffer.from(components))).toString('hex');

    getMetrics().incCounter('auth.device.fingerprint.generated');
    logger.debug({ hash: hash.slice(0, 16), duration: Date.now() - startTime }, 'Device fingerprint generated');
    span.end();
    return hash;
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    throw error;
  }
}

// 28. browserFingerprint
/**
 * @description Generates a browser fingerprint from canvas, WebGL, audio, and font data.
 * @param canvasHash - Hash of the canvas rendering.
 * @param webglHash - Hash of the WebGL renderer info.
 * @param audioHash - Hash of the AudioContext fingerprint.
 * @param fonts - Array of detected font hashes.
 * @returns A SHA3-256 hash representing the browser fingerprint.
 * @example
 * const fp = browserFingerprint(canvasHash, webglHash, audioHash, fontHashes);
 */
export function browserFingerprint(
  canvasHash: string,
  webglHash: string,
  audioHash: string,
  fonts: string[]
): string {
  const span = createSpan('auth.browserFingerprint');
  const startTime = Date.now();
  try {
    const components = [
      canvasHash.toLowerCase(),
      webglHash.toLowerCase(),
      audioHash.toLowerCase(),
      fonts.map((f) => f.toLowerCase()).sort().join(','),
    ].join('|');

    const hash = Buffer.from(sha3_256(Buffer.from(components))).toString('hex');

    getMetrics().incCounter('auth.browser.fingerprint.generated');
    logger.debug({ hash: hash.slice(0, 16), duration: Date.now() - startTime }, 'Browser fingerprint generated');
    span.end();
    return hash;
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    throw error;
  }
}

// 29. biometricValidation
/**
 * @description Validates biometric data against a stored template.
 * @param biometricData - The biometric sample to validate.
 * @param storedTemplate - The stored biometric template.
 * @param threshold - Similarity threshold for matching (0-1, default: 0.85).
 * @returns True if the biometric sample matches the stored template.
 * @example
 * const valid = await biometricValidation(sample, template, 0.85);
 */
export async function biometricValidation(
  biometricData: Buffer,
  storedTemplate: Buffer,
  threshold: number = 0.85
): Promise<boolean> {
  const span = createSpan('auth.biometricValidation');
  const startTime = Date.now();
  try {
    if (biometricData.length !== storedTemplate.length) {
      getMetrics().incCounter('auth.biometric.error', { reason: 'length_mismatch' });
      span.end();
      return false;
    }

    let matchingBits = 0;
    const totalBits = biometricData.length * 8;

    for (let i = 0; i < biometricData.length; i++) {
      const xor = biometricData[i] ^ storedTemplate[i];
      matchingBits += 8 - popcount(xor);
    }

    const similarity = matchingBits / totalBits;
    const isValid = similarity >= threshold;

    const duration = Date.now() - startTime;
    getMetrics().observeHistogram('auth.biometric.similarity', similarity);
    getMetrics().observeHistogram('auth.biometric.duration_ms', duration);
    if (isValid) {
      getMetrics().incCounter('auth.biometric.success');
    } else {
      getMetrics().incCounter('auth.biometric.failure');
    }
    logger.info({ similarity, threshold, isValid, duration }, 'Biometric validation completed');
    span.end();
    return isValid;
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    return false;
  }
}

// 30. phishingResistantAuth
/**
 * @description Evaluates if an authentication method is phishing-resistant.
 * @param authMethod - The authentication method identifier.
 * @param fidoLevel - FIDO certification level (0-3).
 * @param attestation - The attestation type ('none', 'self', 'basic', 'attested').
 * @returns True if the authentication method is considered phishing-resistant.
 * @example
 * const isResistant = phishingResistantAuth('webauthn', 2, 'attested');
 */
export function phishingResistantAuth(
  authMethod: string,
  fidoLevel: number,
  attestation: string
): boolean {
  const span = createSpan('auth.phishingResistantAuth');
  const startTime = Date.now();
  try {
    const phishingResistantMethods = new Set([
      'webauthn',
      'fido2',
      'passkey',
      'smartcard',
      'pkcs11',
      'hardware-token',
    ]);

    const isResistantMethod = phishingResistantMethods.has(authMethod.toLowerCase());
    const hasSufficientFido = fidoLevel >= 2;
    const hasStrongAttestation = ['basic', 'attested', 'attestation'].includes(attestation.toLowerCase());

    const isPhishingResistant = isResistantMethod && hasSufficientFido && hasStrongAttestation;

    getMetrics().incCounter('auth.phishing_resistant.check', {
      method: authMethod,
      resistant: isPhishingResistant,
    });
    logger.debug(
      { authMethod, fidoLevel, attestation, isPhishingResistant, duration: Date.now() - startTime },
      'Phishing resistance evaluated'
    );
    span.end();
    return isPhishingResistant;
  } catch (error) {
    span.end(error instanceof Error ? error.message : 'unknown');
    return false;
  }
}

// --- Helper: Base32 decoding ---

function base32ToBuffer(base32: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  const cleaned = base32.toUpperCase().replace(/=+$/, '');

  for (const char of cleaned) {
    const val = alphabet.indexOf(char);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }

  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }

  return Buffer.from(bytes);
}

// --- Helper: Population count ---

function popcount(byte: number): number {
  let count = 0;
  let n = byte;
  while (n > 0) {
    count += n & 1;
    n >>= 1;
  }
  return count;
}
