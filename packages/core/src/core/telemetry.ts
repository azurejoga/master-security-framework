/**
 * Telemetry manager with OpenTelemetry integration
 * @module core/telemetry
 */

import * as otel from '@opentelemetry/api';

/**
 * Span attributes specific to security operations
 */
export interface SecuritySpanAttributes {
  /** MITRE ATT&CK technique ID (e.g., T1059) */
  mitreTechnique?: string;
  /** MITRE ATT&CK tactic name */
  mitreTactic?: string;
  /** Security event type */
  securityEventType?: string;
  /** Threat severity */
  threatSeverity?: string;
  /** Actor identifier */
  actorId?: string;
  /** Resource identifier */
  resourceId?: string;
  /** Action performed */
  action?: string;
  /** Result of the action */
  result?: string;
}

/**
 * Span creation options
 */
export interface SpanOptions {
  /** Span name */
  name: string;
  /** Span kind */
  kind?: otel.SpanKind;
  /** Span attributes */
  attributes?: Record<string, string | number | boolean>;
  /** Parent span context */
  parentContext?: otel.Context;
  /** Security-specific attributes */
  security?: SecuritySpanAttributes;
}

/**
 * Telemetry manager for distributed tracing
 */
export class TelemetryManager {
  /** OpenTelemetry tracer instance */
  private tracer: otel.Tracer;
  /** Whether telemetry is enabled */
  private enabled: boolean;

  /**
   * Create a new TelemetryManager
   * @param serviceName - OpenTelemetry service name
   * @param serviceVersion - Service version
   * @param enabled - Whether telemetry is enabled
   */
  constructor(serviceName: string = 'msf-framework', serviceVersion: string = '1.0.0', enabled: boolean = true) {
    this.tracer = otel.trace.getTracer(serviceName, serviceVersion);
    this.enabled = enabled;
  }

  /**
   * Start a new span with context management
   * @param options - Span creation options
   * @returns The created span
   * @example
   * ```typescript
   * const span = telemetry.startSpan({ name: 'process-request', kind: SpanKind.SERVER });
   * try {
   *   // do work
   *   span.end();
   * } catch (err) {
   *   span.recordException(err);
   *   span.setStatus({ code: SpanStatusCode.ERROR });
   *   throw err;
   * }
   * ```
   */
  startSpan(options: SpanOptions): otel.Span {
    if (!this.enabled) {
      return new NoopSpan();
    }

    const attributes: Record<string, string | number | boolean> = { ...options.attributes };
    if (options.security) {
      const sec = options.security;
      if (sec.mitreTechnique) attributes['security.mitre.technique'] = sec.mitreTechnique;
      if (sec.mitreTactic) attributes['security.mitre.tactic'] = sec.mitreTactic;
      if (sec.securityEventType) attributes['security.event.type'] = sec.securityEventType;
      if (sec.threatSeverity) attributes['security.threat.severity'] = sec.threatSeverity;
      if (sec.actorId) attributes['security.actor.id'] = sec.actorId;
      if (sec.resourceId) attributes['security.resource.id'] = sec.resourceId;
      if (sec.action) attributes['security.action'] = sec.action;
      if (sec.result) attributes['security.result'] = sec.result;
    }

    const spanOptions: otel.SpanOptions = {
      kind: options.kind,
      attributes,
    };

    const parentContext = options.parentContext;
    if (parentContext) {
      return this.tracer.startSpan(options.name, spanOptions, parentContext);
    }
    return this.tracer.startSpan(options.name, spanOptions);
  }

  /**
   * Create a security-focused span with MITRE ATT&CK tagging
   * @param name - Span name
   * @param mitreTechnique - MITRE ATT&CK technique ID
   * @param attributes - Additional attributes
   * @returns The created span
   * @example
   * ```typescript
   * const span = telemetry.createSecuritySpan('detect-injection', 'T1059.001', {
   *   severity: 'high',
   *   action: 'scan',
   * });
   * ```
   */
  createSecuritySpan(
    name: string,
    mitreTechnique: string,
    attributes: Record<string, string | number | boolean> = {}
  ): otel.Span {
    return this.startSpan({
      name,
      kind: otel.SpanKind.INTERNAL,
      attributes,
      security: {
        mitreTechnique,
        securityEventType: name,
      },
    });
  }

  /**
   * Execute a function within a span context
   * @param options - Span options
   * @param fn - Function to execute
   * @returns Function result
   * @example
   * ```typescript
   * const result = await telemetry.withSpan({ name: 'auth' }, async (span) => {
   *   return await authenticate(credentials);
   * });
   * ```
   */
  async withSpan<T>(options: SpanOptions, fn: (span: otel.Span) => Promise<T>): Promise<T> {
    const span = this.startSpan(options);
    try {
      const result = await fn(span);
      span.setStatus({ code: otel.SpanStatusCode.OK });
      return result;
    } catch (error) {
      span.recordException(error as Error);
      span.setStatus({ code: otel.SpanStatusCode.ERROR, message: (error as Error).message });
      throw error;
    } finally {
      span.end();
    }
  }

  /**
   * Get the current active span
   * @returns Current span or undefined
   */
  getActiveSpan(): otel.Span | undefined {
    const span = otel.trace.getActiveSpan();
    return span && span.spanContext().traceId ? span : undefined;
  }

  /**
   * Get the current trace context for propagation
   * @returns Trace context headers
   * @example
   * ```typescript
   * const headers = telemetry.getTraceContext();
   * fetch('http://api', { headers });
   * ```
   */
  getTraceContext(): Record<string, string> {
    const headers: Record<string, string> = {};
    const propagator = otel.propagation;
    propagator.inject(otel.context.active(), headers, {
      set(carrier, key, value) {
        carrier[key] = value as string;
      },
    });
    return headers;
  }

  /**
   * Enable or disable telemetry
   * @param enabled - Whether telemetry should be enabled
   */
  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
  }

  /**
   * Check if telemetry is enabled
   * @returns True if enabled
   */
  isEnabled(): boolean {
    return this.enabled;
  }
}

/**
 * Noop span implementation for when telemetry is disabled
 */
class NoopSpan implements otel.Span {
  spanContext(): otel.SpanContext {
    return { traceId: '00000000000000000000000000000000', spanId: '0000000000000000', traceFlags: 0 };
  }
  updateName(): this { return this; }
  setAttribute(): this { return this; }
  setAttributes(): this { return this; }
  addEvent(): this { return this; }
  setStatus(): this { return this; }
  end(): void {}
  isRecording(): boolean { return false; }
  recordException(): void {}
}

let _telemetry: TelemetryManager | null = null;

/**
 * Get the global telemetry manager singleton
 * @param serviceName - Service name (only on first call)
 * @param serviceVersion - Service version (only on first call)
 * @param enabled - Whether telemetry is enabled (only on first call)
 * @returns TelemetryManager instance
 * @example
 * ```typescript
   const telemetry = getTelemetry();
   * const span = telemetry.startSpan({ name: 'my-operation' });
   * ```
   */
export function getTelemetry(
  serviceName?: string,
  serviceVersion?: string,
  enabled?: boolean
): TelemetryManager {
  if (!_telemetry) {
    _telemetry = new TelemetryManager(serviceName, serviceVersion, enabled);
  }
  return _telemetry;
}

/**
 * Convenience function to create a span
 * @param name - Span name
 * @param attributes - Optional attributes
 * @returns The created span
 * @example
 * ```typescript
   const span = createSpan('process-request');
   * span.end();
   * ```
   */
export function createSpan(
  name: string,
  attributes: Record<string, string | number | boolean> = {}
): otel.Span {
  return getTelemetry().startSpan({ name, attributes });
}
