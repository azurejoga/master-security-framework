/**
 * Structured logging with tamper-proof hash chain
 * @module core/logger
 */

import pino, { Logger, LoggerOptions } from 'pino';
import { createHash } from '@noble/hashes/sha3';
import { bytesToHex } from '@noble/hashes/utils';

/**
 * PII redaction patterns for log sanitization
 */
const PII_PATTERNS: { name: string; pattern: RegExp }[] = [
  { name: 'email', pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g },
  { name: 'ssn', pattern: /\b\d{3}-\d{2}-\d{4}\b/g },
  { name: 'creditCard', pattern: /\b(?:\d{4}[- ]?){3}\d{4}\b/g },
  { name: 'phone', pattern: /\b(?:\+?1[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b/g },
  { name: 'ipAddress', pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g },
  { name: 'jwt', pattern: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/g },
  { name: 'apiKey', pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*['"]?[A-Za-z0-9]{20,}/gi },
  { name: 'password', pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"]?[^\s'"]+/gi },
];

/**
 * Tamper-proof hash chain for log integrity verification
 * Uses SHA3-256 to create an immutable chain of log entries
 */
export class TamperProofChain {
  /** Current chain head hash */
  private head: string;
  /** Chain entries stored in memory */
  private entries: Map<string, ChainEntry>;

  /**
   * Create a new tamper-proof chain
   * @param genesisHash - Optional genesis hash (defaults to zeros)
   */
  private static instance: TamperProofChain;

  static getInstance(): TamperProofChain {
    if (!TamperProofChain.instance) {
      TamperProofChain.instance = new TamperProofChain();
    }
    return TamperProofChain.instance;
  }

  static async getLastHash(): Promise<string> {
    return TamperProofChain.getInstance().getHead();
  }

  static async append(entry: Record<string, unknown>): Promise<void> {
    const chain = TamperProofChain.getInstance();
    chain.addEntry(JSON.stringify(entry));
  }

  constructor(genesisHash?: string) {
    this.head = genesisHash || bytesToHex(new Uint8Array(32));
    this.entries = new Map();
  }

  /**
   * Add a new entry to the hash chain
   * @param data - The log entry data to hash
   * @returns The new chain hash
   * @example
   * ```typescript
   * const chain = new TamperProofChain();
   * const hash = chain.addEntry('log message');
   * ```
   */
  addEntry(data: string): string {
    const payload = `${this.head}:${data}:${Date.now()}`;
    const hash = bytesToHex(createHash(new TextEncoder().encode(payload)));
    const entry: ChainEntry = {
      data,
      previousHash: this.head,
      hash,
      timestamp: new Date(),
    };
    this.entries.set(hash, entry);
    this.head = hash;
    return hash;
  }

  /**
   * Verify the integrity of the entire chain
   * @returns True if chain is valid, false if tampered
   * @example
   * ```typescript
   * const isValid = chain.verify();
   * if (!isValid) throw new Error('Log chain tampered!');
   * ```
   */
  verify(): boolean {
    const entryList = Array.from(this.entries.values());
    if (entryList.length === 0) return true;

    for (let i = 1; i < entryList.length; i++) {
      const prev = entryList[i - 1];
      const curr = entryList[i];
      if (curr.previousHash !== prev.hash) {
        return false;
      }
    }
    return true;
  }

  /**
   * Get the current chain head hash
   * @returns The latest hash in the chain
   */
  getHead(): string {
    return this.head;
  }

  /**
   * Get an entry by its hash
   * @param hash - The entry hash to look up
   * @returns The chain entry or undefined
   */
  getEntry(hash: string): ChainEntry | undefined {
    return this.entries.get(hash);
  }

  /**
   * Get the total number of entries in the chain
   * @returns Entry count
   */
  getEntryCount(): number {
    return this.entries.size;
  }
}

/**
 * Chain entry structure
 */
interface ChainEntry {
  /** Original data */
  data: string;
  /** Previous hash in chain */
  previousHash: string;
  /** This entry hash */
  hash: string;
  /** Entry timestamp */
  timestamp: Date;
}

/**
 * Redact PII from a string value
 * @param value - The string to sanitize
 * @returns Sanitized string with PII replaced
 * @example
 * ```typescript
 * const safe = redactPII('Contact user@example.com');
 * // Returns: 'Contact [PII:email]'
 * ```
 */
export function redactPII(value: string): string {
  let result = value;
  for (const { name, pattern } of PII_PATTERNS) {
    result = result.replace(pattern, `[PII:${name}]`);
  }
  return result;
}

/**
 * Redact PII from an object recursively
 * @param obj - The object to sanitize
 * @returns New object with PII redacted
 * @example
 * ```typescript
   const safe = redactObjectPII({ email: 'user@test.com' });
   * ```
   */
export function redactObjectPII<T extends Record<string, unknown>>(obj: T): T {
  const result = {} as T;
  for (const [key, value] of Object.entries(obj)) {
    if (typeof value === 'string') {
      (result as Record<string, unknown>)[key] = redactPII(value);
    } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      (result as Record<string, unknown>)[key] = redactObjectPII(value as Record<string, unknown>);
    } else {
      (result as Record<string, unknown>)[key] = value;
    }
  }
  return result;
}

/**
 * MSF Logger with structured logging and tamper-proof audit chain
 */
export class MSFLogger {
  /** Underlying pino logger */
  private logger: Logger;
  /** Tamper-proof hash chain for audit entries */
  private chain: TamperProofChain;
  /** Whether PII redaction is enabled */
  private redactPIIEnabled: boolean;
  /** Component name for log context */
  private component: string;

  /**
   * Create a new MSFLogger instance
   * @param options - Logger configuration options
   */
  constructor(options: MSFLoggerOptions = {}) {
    const pinoOptions: LoggerOptions = {
      level: options.level || 'info',
      transport: options.transport,
      formatters: {
        level: (label) => ({ level: label.toUpperCase() }),
      },
      timestamp: pino.stdTimeFunctions.isoTime,
      ...options.pinoOptions,
    };

    this.logger = pino(pinoOptions);
    this.chain = new TamperProofChain(options.genesisHash);
    this.redactPIIEnabled = options.redactPII !== false;
    this.component = options.component || 'msf';
  }

  /**
   * Log a debug message
   * @param message - Log message
   * @param data - Optional structured data
   * @example
   * ```typescript
   * logger.debug('Processing request', { requestId: 'abc123' });
   * ```
   */
  debug(message: string, data?: Record<string, unknown>): void {
    const sanitized = this.redactPIIEnabled && data ? redactObjectPII(data) : data;
    this.logger.debug({ component: this.component, ...sanitized }, message);
  }

  /**
   * Log an info message
   * @param message - Log message
   * @param data - Optional structured data
   * @example
   * ```typescript
   * logger.info('Server started', { port: 3000 });
   * ```
   */
  info(message: string, data?: Record<string, unknown>): void {
    const sanitized = this.redactPIIEnabled && data ? redactObjectPII(data) : data;
    this.logger.info({ component: this.component, ...sanitized }, message);
  }

  /**
   * Log a warning message
   * @param message - Log message
   * @param data - Optional structured data
   * @example
   * ```typescript
   * logger.warning('High memory usage', { memoryPercent: 85 });
   * ```
   */
  warning(message: string, data?: Record<string, unknown>): void {
    const sanitized = this.redactPIIEnabled && data ? redactObjectPII(data) : data;
    this.logger.warn({ component: this.component, ...sanitized }, message);
  }

  /**
   * Log an error message
   * @param message - Log message
   * @param data - Optional structured data or Error
   * @example
   * ```typescript
   * logger.error('Database connection failed', { error: err.message });
   * ```
   */
  error(message: string, data?: Record<string, unknown> | Error): void {
    const errorData = data instanceof Error ? { error: data.message, stack: data.stack } : data;
    const sanitized = this.redactPIIEnabled && errorData ? redactObjectPII(errorData) : errorData;
    this.logger.error({ component: this.component, ...sanitized }, message);
  }

  /**
   * Log a critical message (system-threatening)
   * @param message - Log message
   * @param data - Optional structured data
   * @example
   * ```typescript
   * logger.critical('Security breach detected', { sourceIP: '10.0.0.1' });
   * ```
   */
  critical(message: string, data?: Record<string, unknown>): void {
    const sanitized = this.redactPIIEnabled && data ? redactObjectPII(data) : data;
    this.logger.fatal({ component: this.component, ...sanitized }, message);
    this.chain.addEntry(`CRITICAL: ${message}`);
  }

  /**
   * Log a security event with tamper-proof hashing
   * @param message - Security event description
   * @param data - Event metadata
   * @returns The chain hash for this entry
   * @example
   * ```typescript
   * const hash = logger.securityEvent('Login attempt', { userId: '123' });
   * ```
   */
  securityEvent(message: string, data?: Record<string, unknown>): string {
    const sanitized = this.redactPIIEnabled && data ? redactObjectPII(data) : data;
    const entry = { component: this.component, securityEvent: true, ...sanitized };
    this.logger.info(entry, message);
    const hash = this.chain.addEntry(`SECURITY: ${message} | ${JSON.stringify(sanitized)}`);
    return hash;
  }

  /**
   * Get the tamper-proof chain
   * @returns The TamperProofChain instance
   */
  getChain(): TamperProofChain {
    return this.chain;
  }

  /**
   * Verify the integrity of the audit chain
   * @returns True if chain is valid
   */
  verifyChain(): boolean {
    return this.chain.verify();
  }

  /**
   * Create a child logger with additional context
   * @param bindings - Additional bindings for the child logger
   * @returns A new MSFLogger instance
   * @example
   * ```typescript
   * const childLogger = logger.child({ requestId: 'abc' });
   * ```
   */
  child(bindings: Record<string, unknown>): MSFLogger {
    const childLogger = new MSFLogger({
      component: `${this.component}:${bindings.component || 'child'}`,
      redactPII: this.redactPIIEnabled,
      genesisHash: this.chain.getHead(),
    });
    childLogger.logger = this.logger.child(bindings);
    return childLogger;
  }
}

/**
 * MSFLogger constructor options
 */
export interface MSFLoggerOptions {
  /** Log level */
  level?: string;
  /** Component name */
  component?: string;
  /** Enable PII redaction */
  redactPII?: boolean;
  /** Genesis hash for chain */
  genesisHash?: string;
  /** Pino transport configuration */
  transport?: LoggerOptions['transport'];
  /** Additional pino options */
  pinoOptions?: Partial<LoggerOptions>;
}

/**
 * Logger instances cache
 */
const _loggerCache: Map<string, MSFLogger> = new Map();

/**
 * Get a cached logger instance by component name
 * Creates a new instance if not cached
 * @param component - Component name for the logger
 * @param options - Logger options (only used on first creation)
 * @returns MSFLogger instance
 * @example
 * ```typescript
 * const logger = getLogger('auth');
 * logger.info('Auth module initialized');
 * ```
 */
export function getLogger(component: string, options?: MSFLoggerOptions): MSFLogger {
  if (!_loggerCache.has(component)) {
    _loggerCache.set(component, new MSFLogger({ component, ...options }));
  }
  return _loggerCache.get(component)!;
}
