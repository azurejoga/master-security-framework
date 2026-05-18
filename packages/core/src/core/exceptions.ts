/**
 * Hierarchical exception classes for the MSF framework
 * @module core/exceptions
 */

/**
 * Severity levels for exceptions
 */
export enum SeverityLevel {
  /** Low severity, informational */
  LOW = 'low',
  /** Medium severity, requires attention */
  MEDIUM = 'medium',
  /** High severity, requires immediate action */
  HIGH = 'high',
  /** Critical severity, system-threatening */
  CRITICAL = 'critical',
}

/**
 * Base exception dictionary interface
 */
export interface ExceptionDict {
  /** Exception name */
  name: string;
  /** Error message */
  message: string;
  /** Error code */
  code: string;
  /** Severity level */
  severity: SeverityLevel;
  /** Stack trace */
  stack?: string;
  /** Additional context */
  context?: Record<string, unknown>;
  /** Timestamp */
  timestamp: string;
  /** Cause of the error */
  cause?: string;
}

/**
 * Base MSF error class with structured error information
 */
export class MSFError extends Error {
  /** Unique error code */
  public readonly code: string;
  /** Severity level */
  public readonly severity: SeverityLevel;
  /** Additional context data */
  public readonly context: Record<string, unknown>;
  /** Timestamp when error was created */
  public readonly timestamp: Date;

  /**
   * Create a new MSFError
   * @param message - Error message
   * @param code - Error code
   * @param severity - Severity level
   * @param context - Additional context
   * @param options - Error options including cause
   */
  constructor(
    message: string,
    code: string = 'MSF_ERROR',
    severity: SeverityLevel = SeverityLevel.MEDIUM,
    context: Record<string, unknown> = {},
    options?: { cause?: Error }
  ) {
    super(message, options);
    this.name = 'MSFError';
    this.code = code;
    this.severity = severity;
    this.context = context;
    this.timestamp = new Date();
  }

  /**
   * Convert error to dictionary representation
   * @returns Serializable error dictionary
   * @example
   * ```typescript
   * const dict = error.toDict();
   * console.log(dict.code, dict.message);
   * ```
   */
  toDict(): ExceptionDict {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      severity: this.severity,
      stack: this.stack,
      context: this.context,
      timestamp: this.timestamp.toISOString(),
      cause: this.cause?.toString(),
    };
  }
}

/**
 * Security-related error
 */
export class SecurityError extends MSFError {
  /**
   * Create a new SecurityError
   * @param message - Error message
   * @param context - Additional context
   * @param options - Error options
   */
  constructor(message: string, context: Record<string, unknown> = {}, options?: { cause?: Error }) {
    super(message, 'SECURITY_ERROR', SeverityLevel.HIGH, context, options);
    this.name = 'SecurityError';
  }
}

/**
 * Authentication failure error
 */
export class AuthenticationError extends MSFError {
  /**
   * Create a new AuthenticationError
   * @param message - Error message
   * @param context - Additional context
   * @param options - Error options
   */
  constructor(message: string, context: Record<string, unknown> = {}, options?: { cause?: Error }) {
    super(message, 'AUTHENTICATION_ERROR', SeverityLevel.HIGH, context, options);
    this.name = 'AuthenticationError';
  }
}

/**
 * Authorization failure error
 */
export class AuthorizationError extends MSFError {
  /**
   * Create a new AuthorizationError
   * @param message - Error message
   * @param context - Additional context
   * @param options - Error options
   */
  constructor(message: string, context: Record<string, unknown> = {}, options?: { cause?: Error }) {
    super(message, 'AUTHORIZATION_ERROR', SeverityLevel.HIGH, context, options);
    this.name = 'AuthorizationError';
  }
}

/**
 * Validation failure error
 */
export class ValidationError extends MSFError {
  /**
   * Create a new ValidationError
   * @param message - Error message
   * @param context - Additional context
   * @param options - Error options
   */
  constructor(message: string, context: Record<string, unknown> = {}, options?: { cause?: Error }) {
    super(message, 'VALIDATION_ERROR', SeverityLevel.MEDIUM, context, options);
    this.name = 'ValidationError';
  }
}

/**
 * Cryptography operation error
 */
export class CryptographyError extends MSFError {
  /**
   * Create a new CryptographyError
   * @param message - Error message
   * @param context - Additional context
   * @param options - Error options
   */
  constructor(message: string, context: Record<string, unknown> = {}, options?: { cause?: Error }) {
    super(message, 'CRYPTOGRAPHY_ERROR', SeverityLevel.CRITICAL, context, options);
    this.name = 'CryptographyError';
  }
}

/**
 * Rate limit exceeded error
 */
export class RateLimitError extends MSFError {
  /** Retry-after duration in seconds */
  public readonly retryAfter: number;

  /**
   * Create a new RateLimitError
   * @param message - Error message
   * @param retryAfter - Seconds until retry is allowed
   * @param context - Additional context
   */
  constructor(message: string, retryAfter: number = 60, context: Record<string, unknown> = {}) {
    super(message, 'RATE_LIMIT_ERROR', SeverityLevel.MEDIUM, { retryAfter, ...context });
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
  }
}

/**
 * Operation timeout error
 */
export class TimeoutError extends MSFError {
  /** Timeout duration in milliseconds */
  public readonly timeoutMs: number;

  /**
   * Create a new TimeoutError
   * @param message - Error message
   * @param timeoutMs - Timeout duration
   * @param context - Additional context
   */
  constructor(message: string, timeoutMs: number, context: Record<string, unknown> = {}) {
    super(message, 'TIMEOUT_ERROR', SeverityLevel.HIGH, { timeoutMs, ...context });
    this.name = 'TimeoutError';
    this.timeoutMs = timeoutMs;
  }
}

/**
 * Policy violation error
 */
export class PolicyViolationError extends MSFError {
  /** Policy rule that was violated */
  public readonly policyRule: string;

  /**
   * Create a new PolicyViolationError
   * @param message - Error message
   * @param policyRule - The violated policy rule
   * @param context - Additional context
   */
  constructor(message: string, policyRule: string, context: Record<string, unknown> = {}) {
    super(message, 'POLICY_VIOLATION', SeverityLevel.HIGH, { policyRule, ...context });
    this.name = 'PolicyViolationError';
    this.policyRule = policyRule;
  }
}

/**
 * Threat detection error
 */
export class ThreatDetectedError extends MSFError {
  /** Threat type identifier */
  public readonly threatType: string;
  /** MITRE ATT&CK technique ID if applicable */
  public readonly mitreTechnique?: string;

  /**
   * Create a new ThreatDetectedError
   * @param message - Error message
   * @param threatType - Type of threat detected
   * @param mitreTechnique - MITRE ATT&CK technique ID
   * @param context - Additional context
   */
  constructor(
    message: string,
    threatType: string,
    mitreTechnique?: string,
    context: Record<string, unknown> = {}
  ) {
    super(message, 'THREAT_DETECTED', SeverityLevel.CRITICAL, { threatType, mitreTechnique, ...context });
    this.name = 'ThreatDetectedError';
    this.threatType = threatType;
    this.mitreTechnique = mitreTechnique;
  }
}

/**
 * Configuration error
 */
export class ConfigurationError extends MSFError {
  /**
   * Create a new ConfigurationError
   * @param message - Error message
   * @param context - Additional context
   * @param options - Error options
   */
  constructor(message: string, context: Record<string, unknown> = {}, options?: { cause?: Error }) {
    super(message, 'CONFIGURATION_ERROR', SeverityLevel.HIGH, context, options);
    this.name = 'ConfigurationError';
  }
}

/**
 * Plugin-related error
 */
export class PluginError extends MSFError {
  /** Plugin name */
  public readonly pluginName: string;

  /**
   * Create a new PluginError
   * @param message - Error message
   * @param pluginName - Name of the plugin
   * @param context - Additional context
   * @param options - Error options
   */
  constructor(
    message: string,
    pluginName: string,
    context: Record<string, unknown> = {},
    options?: { cause?: Error }
  ) {
    super(message, 'PLUGIN_ERROR', SeverityLevel.HIGH, { pluginName, ...context }, options);
    this.name = 'PluginError';
    this.pluginName = pluginName;
  }
}
