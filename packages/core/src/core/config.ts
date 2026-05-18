/**
 * Hot-reload security configuration engine
 * @module core/config
 */

/**
 * Security level for the system
 */
export enum SecurityLevel {
  /** Minimal security, suitable for development */
  LOW = 'low',
  /** Standard security with basic protections */
  MEDIUM = 'medium',
  /** High security with strict controls */
  HIGH = 'high',
  /** Maximum security with zero-trust architecture */
  CRITICAL = 'critical',
}

/**
 * Environment type for configuration
 */
export enum Environment {
  /** Development environment with relaxed security */
  DEVELOPMENT = 'development',
  /** Staging environment for testing */
  STAGING = 'staging',
  /** Production environment with full security */
  PRODUCTION = 'production',
  /** Testing environment for automated tests */
  TESTING = 'testing',
}

/**
 * Rate limiting configuration
 */
export interface RateLimitConfig {
  /** Maximum requests per window */
  maxRequests: number;
  /** Time window in milliseconds */
  windowMs: number;
  /** Block duration after rate limit exceeded (ms) */
  blockDurationMs: number;
  /** Enable IP-based rate limiting */
  ipBased: boolean;
  /** Enable user-based rate limiting */
  userBased: boolean;
  /** Custom rate limit key generator */
  keyGenerator?: (req: unknown) => string;
}

/**
 * Cryptographic configuration
 */
export interface CryptoConfig {
  /** Primary encryption algorithm */
  encryptionAlgorithm: string;
  /** Hash algorithm for integrity checks */
  hashAlgorithm: string;
  /** Key rotation interval in milliseconds */
  keyRotationIntervalMs: number;
  /** Minimum key length in bits */
  minKeyLength: number;
  /** Enable hardware security module */
  enableHSM: boolean;
  /** HSM provider name */
  hsmProvider?: string;
  /** Salt length for password hashing */
  saltLength: number;
  /** PBKDF2 iterations */
  pbkdf2Iterations: number;
}

/**
 * Authentication configuration
 */
export interface AuthConfig {
  /** JWT secret key */
  jwtSecret: string;
  /** JWT expiration time in seconds */
  jwtExpirationSec: number;
  /** Refresh token expiration in seconds */
  refreshTokenExpirationSec: number;
  /** Maximum concurrent sessions per user */
  maxSessionsPerUser: number;
  /** Enable multi-factor authentication */
  enableMFA: boolean;
  /** MFA methods allowed */
  allowedMFAMethods: string[];
  /** Session timeout in milliseconds */
  sessionTimeoutMs: number;
  /** Password minimum length */
  passwordMinLength: number;
  /** Password complexity requirements */
  passwordComplexity: {
    requireUppercase: boolean;
    requireLowercase: boolean;
    requireNumbers: boolean;
    requireSpecialChars: boolean;
  };
}

/**
 * Web security configuration
 */
export interface WebSecurityConfig {
  /** Content Security Policy directives */
  contentSecurityPolicy: Record<string, string>;
  /** HTTP Strict Transport Security max age */
  hstsMaxAge: number;
  /** Enable CORS */
  enableCORS: boolean;
  /** Allowed CORS origins */
  allowedOrigins: string[];
  /** CORS methods */
  allowedMethods: string[];
  /** CORS headers */
  allowedHeaders: string[];
  /** Enable XSS protection */
  enableXSSProtection: boolean;
  /** Enable frame protection (X-Frame-Options) */
  enableFrameProtection: boolean;
  /** Maximum request body size in bytes */
  maxBodySizeBytes: number;
  /** Enable request validation */
  enableRequestValidation: boolean;
}

/**
 * AI security configuration
 */
export interface AISecurityConfig {
  /** Enable prompt injection detection */
  enablePromptInjectionDetection: boolean;
  /** Enable output sanitization */
  enableOutputSanitization: boolean;
  /** Maximum tokens per request */
  maxTokensPerRequest: number;
  /** Allowed AI models */
  allowedModels: string[];
  /** Enable content filtering */
  enableContentFiltering: boolean;
  /** Content filter sensitivity (0-1) */
  contentFilterSensitivity: number;
  /** Enable jailbreak detection */
  enableJailbreakDetection: boolean;
  /** Maximum context window size */
  maxContextWindowSize: number;
  /** Enable rate limiting per AI user */
  enableAIRateLimiting: boolean;
  /** AI rate limit requests per minute */
  aiRateLimitRPM: number;
}

/**
 * Monitoring configuration
 */
export interface MonitoringConfig {
  /** Enable metrics collection */
  enableMetrics: boolean;
  /** Enable distributed tracing */
  enableTracing: boolean;
  /** Metrics collection interval in milliseconds */
  metricsIntervalMs: number;
  /** Enable alerting */
  enableAlerting: boolean;
  /** Alert webhook URLs */
  alertWebhooks: string[];
  /** Log level for security events */
  securityLogLevel: string;
  /** Enable audit logging */
  enableAuditLogging: boolean;
  /** Audit log retention days */
  auditLogRetentionDays: number;
  /** Enable anomaly detection */
  enableAnomalyDetection: boolean;
  /** Anomaly detection sensitivity (0-1) */
  anomalySensitivity: number;
}

/**
 * Main configuration class for the MSF framework
 * Supports hot-reloading and environment-based defaults
 */
export class MSFConfig {
  /** Current security level */
  public securityLevel: SecurityLevel;
  /** Current environment */
  public environment: Environment;
  /** Rate limiting configuration */
  public rateLimit: RateLimitConfig;
  /** Cryptographic configuration */
  public crypto: CryptoConfig;
  /** Authentication configuration */
  public auth: AuthConfig;
  /** Web security configuration */
  public webSecurity: WebSecurityConfig;
  /** AI security configuration */
  public aiSecurity: AISecurityConfig;
  /** Monitoring configuration */
  public monitoring: MonitoringConfig;
  /** Application name */
  public appName: string;
  /** Application version */
  public appVersion: string;
  /** Configuration last reload timestamp */
  public lastReloaded: Date;

  /**
   * Create a new MSFConfig instance
   * @param options - Partial configuration options
   */
  constructor(options: Partial<MSFConfig> = {}) {
    this.securityLevel = options.securityLevel ?? SecurityLevel.MEDIUM;
    this.environment = options.environment ?? Environment.DEVELOPMENT;
    this.rateLimit = options.rateLimit ?? this.getDefaultRateLimit();
    this.crypto = options.crypto ?? this.getDefaultCrypto();
    this.auth = options.auth ?? this.getDefaultAuth();
    this.webSecurity = options.webSecurity ?? this.getDefaultWebSecurity();
    this.aiSecurity = options.aiSecurity ?? this.getDefaultAISecurity();
    this.monitoring = options.monitoring ?? this.getDefaultMonitoring();
    this.appName = options.appName ?? 'msf-framework';
    this.appVersion = options.appVersion ?? '1.0.0';
    this.lastReloaded = new Date();
  }

  /**
   * Get default rate limit configuration
   * @returns Default RateLimitConfig
   */
  private getDefaultRateLimit(): RateLimitConfig {
    return {
      maxRequests: 100,
      windowMs: 60000,
      blockDurationMs: 300000,
      ipBased: true,
      userBased: true,
    };
  }

  /**
   * Get default crypto configuration
   * @returns Default CryptoConfig
   */
  private getDefaultCrypto(): CryptoConfig {
    return {
      encryptionAlgorithm: 'aes-256-gcm',
      hashAlgorithm: 'sha3-256',
      keyRotationIntervalMs: 86400000,
      minKeyLength: 256,
      enableHSM: false,
      saltLength: 16,
      pbkdf2Iterations: 100000,
    };
  }

  /**
   * Get default auth configuration
   * @returns Default AuthConfig
   */
  private getDefaultAuth(): AuthConfig {
    return {
      jwtSecret: process.env.JWT_SECRET || 'change-me-in-production',
      jwtExpirationSec: 3600,
      refreshTokenExpirationSec: 604800,
      maxSessionsPerUser: 5,
      enableMFA: false,
      allowedMFAMethods: ['totp', 'sms', 'email'],
      sessionTimeoutMs: 1800000,
      passwordMinLength: 12,
      passwordComplexity: {
        requireUppercase: true,
        requireLowercase: true,
        requireNumbers: true,
        requireSpecialChars: true,
      },
    };
  }

  /**
   * Get default web security configuration
   * @returns Default WebSecurityConfig
   */
  private getDefaultWebSecurity(): WebSecurityConfig {
    return {
      contentSecurityPolicy: {
        'default-src': "'self'",
        'script-src': "'self'",
        'style-src': "'self'",
        'img-src': "'self' data:",
        'connect-src': "'self'",
      },
      hstsMaxAge: 31536000,
      enableCORS: false,
      allowedOrigins: [],
      allowedMethods: ['GET', 'POST', 'PUT', 'DELETE'],
      allowedHeaders: ['Content-Type', 'Authorization'],
      enableXSSProtection: true,
      enableFrameProtection: true,
      maxBodySizeBytes: 1048576,
      enableRequestValidation: true,
    };
  }

  /**
   * Get default AI security configuration
   * @returns Default AISecurityConfig
   */
  private getDefaultAISecurity(): AISecurityConfig {
    return {
      enablePromptInjectionDetection: true,
      enableOutputSanitization: true,
      maxTokensPerRequest: 4096,
      allowedModels: [],
      enableContentFiltering: true,
      contentFilterSensitivity: 0.7,
      enableJailbreakDetection: true,
      maxContextWindowSize: 8192,
      enableAIRateLimiting: true,
      aiRateLimitRPM: 60,
    };
  }

  /**
   * Get default monitoring configuration
   * @returns Default MonitoringConfig
   */
  private getDefaultMonitoring(): MonitoringConfig {
    return {
      enableMetrics: true,
      enableTracing: true,
      metricsIntervalMs: 15000,
      enableAlerting: false,
      alertWebhooks: [],
      securityLogLevel: 'info',
      enableAuditLogging: true,
      auditLogRetentionDays: 90,
      enableAnomalyDetection: true,
      anomalySensitivity: 0.5,
    };
  }

  /**
   * Create configuration from environment variables
   * @returns MSFConfig instance populated from environment
   * @example
   * ```typescript
   * const config = MSFConfig.fromEnv();
   * ```
   */
  static fromEnv(): MSFConfig {
    const env = (process.env.NODE_ENV || 'development') as Environment;
    const securityLevel = (process.env.MSF_SECURITY_LEVEL || 'medium') as SecurityLevel;

    return new MSFConfig({
      environment: env,
      securityLevel,
      appName: process.env.MSF_APP_NAME,
      appVersion: process.env.MSF_APP_VERSION,
      auth: {
        jwtSecret: process.env.JWT_SECRET || '',
        jwtExpirationSec: parseInt(process.env.JWT_EXPIRATION_SEC || '3600', 10),
        refreshTokenExpirationSec: parseInt(process.env.REFRESH_TOKEN_EXPIRATION_SEC || '604800', 10),
        maxSessionsPerUser: parseInt(process.env.MAX_SESSIONS_PER_USER || '5', 10),
        enableMFA: process.env.ENABLE_MFA === 'true',
        allowedMFAMethods: process.env.ALLOWED_MFA_METHODS?.split(',') || ['totp'],
        sessionTimeoutMs: parseInt(process.env.SESSION_TIMEOUT_MS || '1800000', 10),
        passwordMinLength: parseInt(process.env.PASSWORD_MIN_LENGTH || '12', 10),
        passwordComplexity: {
          requireUppercase: process.env.PASSWORD_REQUIRE_UPPER !== 'false',
          requireLowercase: process.env.PASSWORD_REQUIRE_LOWER !== 'false',
          requireNumbers: process.env.PASSWORD_REQUIRE_NUMBERS !== 'false',
          requireSpecialChars: process.env.PASSWORD_REQUIRE_SPECIAL !== 'false',
        },
      },
      monitoring: {
        enableMetrics: process.env.ENABLE_METRICS !== 'false',
        enableTracing: process.env.ENABLE_TRACING !== 'false',
        enableAlerting: process.env.ENABLE_ALERTING === 'true',
        alertWebhooks: process.env.ALERT_WEBHOOKS?.split(',') || [],
        enableAuditLogging: process.env.ENABLE_AUDIT_LOGGING !== 'false',
        auditLogRetentionDays: parseInt(process.env.AUDIT_LOG_RETENTION_DAYS || '90', 10),
        enableAnomalyDetection: process.env.ENABLE_ANOMALY_DETECTION !== 'false',
        anomalySensitivity: parseFloat(process.env.ANOMALY_SENSITIVITY || '0.5'),
      },
      aiSecurity: {
        enablePromptInjectionDetection: process.env.ENABLE_PROMPT_INJECTION_DETECTION !== 'false',
        enableOutputSanitization: process.env.ENABLE_OUTPUT_SANITIZATION !== 'false',
        maxTokensPerRequest: parseInt(process.env.MAX_TOKENS_PER_REQUEST || '4096', 10),
        allowedModels: process.env.ALLOWED_AI_MODELS?.split(',') || [],
        enableContentFiltering: process.env.ENABLE_CONTENT_FILTERING !== 'false',
        contentFilterSensitivity: parseFloat(process.env.CONTENT_FILTER_SENSITIVITY || '0.7'),
        enableJailbreakDetection: process.env.ENABLE_JAILBREAK_DETECTION !== 'false',
        maxContextWindowSize: parseInt(process.env.MAX_CONTEXT_WINDOW_SIZE || '8192', 10),
        enableAIRateLimiting: process.env.ENABLE_AI_RATE_LIMITING !== 'false',
        aiRateLimitRPM: parseInt(process.env.AI_RATE_LIMIT_RPM || '60', 10),
      },
    });
  }

  /**
   * Convert configuration to JSON-serializable object
   * @returns Configuration as plain object (secrets redacted)
   * @example
   * ```typescript
   * const json = config.toJSON();
   * console.log(JSON.stringify(json, null, 2));
   * ```
   */
  toJSON(): Record<string, unknown> {
    return {
      securityLevel: this.securityLevel,
      environment: this.environment,
      appName: this.appName,
      appVersion: this.appVersion,
      lastReloaded: this.lastReloaded.toISOString(),
      rateLimit: this.rateLimit,
      crypto: {
        ...this.crypto,
        hsmProvider: this.crypto.hsmProvider,
      },
      auth: {
        ...this.auth,
        jwtSecret: this.auth.jwtSecret ? '***REDACTED***' : undefined,
      },
      webSecurity: this.webSecurity,
      aiSecurity: this.aiSecurity,
      monitoring: this.monitoring,
    };
  }

  /**
   * Reload configuration from environment variables
   * Updates the current instance in place
   * @returns This instance for chaining
   * @example
   * ```typescript
   * config.reload();
   * console.log(config.lastReloaded);
   * ```
   */
  reload(): this {
    const fresh = MSFConfig.fromEnv();
    Object.assign(this, fresh);
    this.lastReloaded = new Date();
    return this;
  }
}

let _config: MSFConfig | null = null;

/**
 * Get the current global configuration instance
 * Creates a default instance if none exists
 * @returns The global MSFConfig instance
 * @example
 * ```typescript
 * const config = getConfig();
 * console.log(config.securityLevel);
 * ```
 */
export function getConfig(): MSFConfig {
  if (!_config) {
    _config = new MSFConfig();
  }
  return _config;
}

/**
 * Set the global configuration instance
 * @param config - The configuration to set
 * @example
 * ```typescript
 * setConfig(new MSFConfig({ securityLevel: SecurityLevel.HIGH }));
 * ```
 */
export function setConfig(config: MSFConfig): void {
  _config = config;
}

/**
 * Reload the global configuration from environment variables
 * @returns The reloaded configuration instance
 * @example
 * ```typescript
 * const newConfig = reloadConfig();
 * ```
 */
export function reloadConfig(): MSFConfig {
  if (!_config) {
    _config = MSFConfig.fromEnv();
  } else {
    _config.reload();
  }
  return _config;
}
