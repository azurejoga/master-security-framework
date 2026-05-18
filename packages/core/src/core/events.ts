/**
 * Event bus for security event distribution
 * @module core/events
 */

/**
 * Event severity levels
 */
export enum EventSeverity {
  /** Informational event */
  INFO = 'info',
  /** Warning event */
  WARNING = 'warning',
  /** Error event */
  ERROR = 'error',
  /** Critical event */
  CRITICAL = 'critical',
}

/**
 * Event type classification
 */
export enum EventType {
  /** Authentication event */
  AUTHENTICATION = 'authentication',
  /** Authorization event */
  AUTHORIZATION = 'authorization',
  /** Security policy event */
  POLICY = 'policy',
  /** Threat detection event */
  THREAT = 'threat',
  /** System event */
  SYSTEM = 'system',
  /** Audit event */
  AUDIT = 'audit',
  /** Configuration change event */
  CONFIG = 'config',
  /** Rate limiting event */
  RATE_LIMIT = 'rate_limit',
  /** Data access event */
  DATA_ACCESS = 'data_access',
  /** Network event */
  NETWORK = 'network',
}

/**
 * Security event structure
 */
export interface SecurityEvent {
  /** Unique event ID */
  id: string;
  /** Event type */
  type: EventType;
  /** Event severity */
  severity: EventSeverity;
  /** Event timestamp */
  timestamp: Date;
  /** Event source */
  source: string;
  /** Event message */
  message: string;
  /** Event metadata */
  metadata: Record<string, unknown>;
  /** Actor identifier */
  actorId?: string;
  /** Target resource */
  target?: string;
  /** MITRE ATT&CK technique ID */
  mitreTechnique?: string;
  /** Event correlation ID */
  correlationId?: string;
}

/**
 * Event handler function type
 */
export type EventHandler = (event: SecurityEvent) => void | Promise<void>;

/**
 * Event subscription handle
 */
export interface Subscription {
  /** Unsubscribe function */
  unsubscribe: () => void;
}

/**
 * EventBus for publishing and subscribing to security events
 */
export class EventBus {
  /** Event handlers by event type */
  private handlers: Map<EventType, Set<EventHandler>>;
  /** Global handlers for all events */
  private globalHandlers: Set<EventHandler>;
  /** Event history buffer */
  private history: SecurityEvent[];
  /** Maximum history size */
  private maxHistory: number;
  /** Dead letter queue for failed deliveries */
  private deadLetter: SecurityEvent[];
  /** Maximum dead letter size */
  private maxDeadLetter: number;

  /**
   * Create a new EventBus
   * @param maxHistory - Maximum events to keep in history
   * @param maxDeadLetter - Maximum failed events to keep
   */
  constructor(maxHistory: number = 1000, maxDeadLetter: number = 500) {
    this.handlers = new Map();
    this.globalHandlers = new Set();
    this.history = [];
    this.maxHistory = maxHistory;
    this.deadLetter = [];
    this.maxDeadLetter = maxDeadLetter;
  }

  /**
   * Subscribe to events of a specific type
   * @param type - Event type to subscribe to
   * @param handler - Event handler function
   * @returns Subscription handle
   * @example
   * ```typescript
   * const sub = eventBus.subscribe(EventType.AUTHENTICATION, (event) => {
   *   console.log('Auth event:', event.message);
   * });
   * ```
   */
  subscribe(type: EventType, handler: EventHandler): Subscription {
    if (!this.handlers.has(type)) {
      this.handlers.set(type, new Set());
    }
    this.handlers.get(type)!.add(handler);
    return {
      unsubscribe: () => {
        this.unsubscribe(type, handler);
      },
    };
  }

  /**
   * Subscribe to all events
   * @param handler - Event handler function
   * @returns Subscription handle
   * @example
   * ```typescript
   * eventBus.subscribeAll((event) => {
   *   logger.info('Event received', { type: event.type });
   * });
   * ```
   */
  subscribeAll(handler: EventHandler): Subscription {
    this.globalHandlers.add(handler);
    return {
      unsubscribe: () => {
        this.globalHandlers.delete(handler);
      },
    };
  }

  /**
   * Unsubscribe from events of a specific type
   * @param type - Event type
   * @param handler - Handler to remove
   * @example
   * ```typescript
   * eventBus.unsubscribe(EventType.AUTHENTICATION, handler);
   * ```
   */
  unsubscribe(type: EventType, handler: EventHandler): void {
    const typeHandlers = this.handlers.get(type);
    if (typeHandlers) {
      typeHandlers.delete(handler);
    }
  }

  /**
   * Publish an event to all subscribers
   * @param event - Event to publish
   * @example
   * ```typescript
   * eventBus.publish({
   *   id: crypto.randomUUID(),
   *   type: EventType.AUTHENTICATION,
   *   severity: EventSeverity.INFO,
   *   timestamp: new Date(),
   *   source: 'auth-service',
   *   message: 'User logged in',
   *   metadata: { userId: '123' },
   * });
   * ```
   */
  async publish(event: SecurityEvent): Promise<void> {
    this.addToHistory(event);

    const typeHandlers = this.handlers.get(event.type) || new Set();
    const allHandlers = [...this.globalHandlers, ...typeHandlers];

    for (const handler of allHandlers) {
      try {
        await handler(event);
      } catch (error) {
        this.deadLetter.push(event);
        if (this.deadLetter.length > this.maxDeadLetter) {
          this.deadLetter.shift();
        }
      }
    }
  }

  /**
   * Get event history
   * @param type - Optional filter by event type
   * @param limit - Maximum number of events to return
   * @returns Array of security events
   * @example
   * ```typescript
   * const authEvents = eventBus.getHistory(EventType.AUTHENTICATION, 10);
   * ```
   */
  getHistory(type?: EventType, limit: number = 100): SecurityEvent[] {
    let events = this.history;
    if (type) {
      events = events.filter((e) => e.type === type);
    }
    return events.slice(-limit);
  }

  /**
   * Get dead letter queue (failed event deliveries)
   * @param limit - Maximum number of events to return
   * @returns Array of failed events
   * @example
   * ```typescript
   * const failed = eventBus.getDeadLetter();
   * ```
   */
  getDeadLetter(limit: number = 100): SecurityEvent[] {
    return this.deadLetter.slice(-limit);
  }

  /**
   * Get the number of subscribers for an event type
   * @param type - Event type
   * @returns Subscriber count
   */
  getSubscriberCount(type: EventType): number {
    return (this.handlers.get(type)?.size || 0) + this.globalHandlers.size;
  }

  /**
   * Clear event history
   */
  clearHistory(): void {
    this.history = [];
  }

  /**
   * Clear dead letter queue
   */
  clearDeadLetter(): void {
    this.deadLetter = [];
  }

  /**
   * Add event to history buffer
   * @param event - Event to add
   */
  private addToHistory(event: SecurityEvent): void {
    this.history.push(event);
    if (this.history.length > this.maxHistory) {
      this.history.shift();
    }
  }
}

let _eventBus: EventBus | null = null;

/**
 * Get the global event bus singleton
 * @param maxHistory - Max history size (only on first call)
 * @param maxDeadLetter - Max dead letter size (only on first call)
 * @returns EventBus instance
 * @example
 * ```typescript
   const eventBus = getEventBus();
   * eventBus.publish(myEvent);
   * ```
   */
export function getEventBus(maxHistory?: number, maxDeadLetter?: number): EventBus {
  if (!_eventBus) {
    _eventBus = new EventBus(maxHistory, maxDeadLetter);
  }
  return _eventBus;
}
