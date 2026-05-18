/**
 * Core module exports
 * @module core
 */

// Configuration
export {
  SecurityLevel,
  Environment,
  MSFConfig,
  getConfig,
  setConfig,
  reloadConfig,
} from './config';
export type {
  RateLimitConfig,
  CryptoConfig,
  AuthConfig,
  WebSecurityConfig,
  AISecurityConfig,
  MonitoringConfig,
} from './config';

// Logging
export {
  TamperProofChain,
  MSFLogger,
  redactPII,
  redactObjectPII,
  getLogger,
} from './logger';
export type { MSFLoggerOptions } from './logger';

// Exceptions
export {
  SeverityLevel,
  MSFError,
  SecurityError,
  AuthenticationError,
  AuthorizationError,
  ValidationError,
  CryptographyError,
  RateLimitError,
  TimeoutError,
  PolicyViolationError,
  ThreatDetectedError,
  ConfigurationError,
  PluginError,
} from './exceptions';
export type { ExceptionDict } from './exceptions';

// Metrics
export { MetricType, getMetrics } from './metrics';
export { MetricsRegistry } from './metrics';
export type { CounterMetric, HistogramMetric, GaugeMetric } from './metrics';

// Telemetry
export {
  TelemetryManager,
  getTelemetry,
  createSpan,
} from './telemetry';
export type { SecuritySpanAttributes, SpanOptions } from './telemetry';

// Events
export {
  EventSeverity,
  EventType,
  EventBus,
  getEventBus,
} from './events';
export type { SecurityEvent, EventHandler, Subscription } from './events';

// Policy
export {
  PolicyAction,
  PolicyEngine,
  getPolicyEngine,
} from './policy';
export type {
  PolicyRule,
  PolicyContext,
  PolicyEvaluation,
} from './policy';

// Cache
export {
  LRUCache,
  CacheManager,
  getCache,
} from './cache';
export type { CacheOptions } from './cache';
