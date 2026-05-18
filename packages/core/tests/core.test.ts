import { describe, it, expect, beforeEach, afterEach } from 'vitest';

// Core module tests - no external dependencies needed for these

describe('Core: Exceptions', () => {
  let MSFError: any, SecurityError: any, AuthenticationError: any, ValidationError: any, SeverityLevel: any;

  beforeEach(async () => {
    const mod = await import('./src/core/exceptions.js');
    MSFError = mod.MSFError;
    SecurityError = mod.SecurityError;
    AuthenticationError = mod.AuthenticationError;
    ValidationError = mod.ValidationError;
    SeverityLevel = mod.SeverityLevel;
  });

  it('MSFError has correct properties', () => {
    const err = new MSFError('test error', 'TEST_CODE', SeverityLevel.HIGH, { key: 'value' });
    expect(err.name).toBe('MSFError');
    expect(err.message).toBe('test error');
    expect(err.code).toBe('TEST_CODE');
    expect(err.severity).toBe(SeverityLevel.HIGH);
    expect(err.context).toEqual({ key: 'value' });
    expect(err.timestamp).toBeInstanceOf(Date);
  });

  it('MSFError.toDict returns serializable object', () => {
    const err = new MSFError('test', 'CODE', SeverityLevel.MEDIUM);
    const dict = err.toDict();
    expect(dict.name).toBe('MSFError');
    expect(dict.message).toBe('test');
    expect(dict.code).toBe('CODE');
    expect(dict.severity).toBe(SeverityLevel.MEDIUM);
    expect(dict.timestamp).toBeDefined();
  });

  it('SecurityError has correct defaults', () => {
    const err = new SecurityError('security breach');
    expect(err.name).toBe('SecurityError');
    expect(err.code).toBe('SECURITY_ERROR');
    expect(err.severity).toBe(SeverityLevel.HIGH);
  });

  it('AuthenticationError has correct defaults', () => {
    const err = new AuthenticationError('invalid credentials');
    expect(err.name).toBe('AuthenticationError');
    expect(err.code).toBe('AUTHENTICATION_ERROR');
  });

  it('ValidationError has correct defaults', () => {
    const err = new ValidationError('bad input');
    expect(err.name).toBe('ValidationError');
    expect(err.code).toBe('VALIDATION_ERROR');
    expect(err.severity).toBe(SeverityLevel.MEDIUM);
  });
});

describe('Core: Metrics', () => {
  let MetricsRegistry: any, getMetrics: any;

  beforeEach(async () => {
    const mod = await import('./src/core/metrics.js');
    MetricsRegistry = mod.MetricsRegistry;
    getMetrics = mod.getMetrics;
  });

  it('registerCounter and incCounter work', () => {
    const registry = new MetricsRegistry();
    registry.registerCounter('requests', 'Total requests');
    registry.incCounter('requests');
    registry.incCounter('requests', 5);
    const metrics = registry.getMetrics();
    expect(metrics.counters.get('requests')!.value).toBe(6);
  });

  it('incCounter auto-registers if not found', () => {
    const registry = new MetricsRegistry();
    registry.incCounter('auto_counter', 3);
    const metrics = registry.getMetrics();
    expect(metrics.counters.has('auto_counter')).toBe(true);
    expect(metrics.counters.get('auto_counter')!.value).toBe(3);
  });

  it('observeHistogram works', () => {
    const registry = new MetricsRegistry();
    registry.registerHistogram('latency', 'Request latency', [10, 50, 100]);
    registry.observeHistogram('latency', 25);
    registry.observeHistogram('latency', 75);
    const metrics = registry.getMetrics();
    const h = metrics.histograms.get('latency')!;
    expect(h.sum).toBe(100);
    expect(h.count).toBe(2);
  });

  it('setGauge works', () => {
    const registry = new MetricsRegistry();
    registry.registerGauge('connections', 'Active connections');
    registry.setGauge('connections', 42);
    const metrics = registry.getMetrics();
    expect(metrics.gauges.get('connections')!.value).toBe(42);
  });

  it('incGauge and decGauge work', () => {
    const registry = new MetricsRegistry();
    registry.registerGauge('connections', 'Active connections');
    registry.incGauge('connections', 10);
    registry.decGauge('connections', 3);
    const metrics = registry.getMetrics();
    expect(metrics.gauges.get('connections')!.value).toBe(7);
  });

  it('clear removes all metrics', () => {
    const registry = new MetricsRegistry();
    registry.registerCounter('c1', 'c1');
    registry.registerGauge('g1', 'g1');
    registry.clear();
    const metrics = registry.getMetrics();
    expect(metrics.counters.size).toBe(0);
    expect(metrics.gauges.size).toBe(0);
    expect(metrics.histograms.size).toBe(0);
  });
});

describe('Core: Cache (LRU)', () => {
  let LRUCache: any, CacheManager: any, getCache: any;

  beforeEach(async () => {
    const mod = await import('./src/core/cache.js');
    LRUCache = mod.LRUCache;
    CacheManager = mod.CacheManager;
    getCache = mod.getCache;
  });

  it('set and get work', () => {
    const cache = new LRUCache(100);
    cache.set('key1', 'value1', 60000);
    expect(cache.get('key1')).toBe('value1');
  });

  it('get returns undefined for missing key', () => {
    const cache = new LRUCache(100);
    expect(cache.get('nonexistent')).toBeUndefined();
  });

  it('delete removes entry', () => {
    const cache = new LRUCache(100);
    cache.set('key1', 'value1');
    expect(cache.delete('key1')).toBe(true);
    expect(cache.get('key1')).toBeUndefined();
  });

  it('exists checks validity', () => {
    const cache = new LRUCache(100);
    cache.set('key1', 'value1', 60000);
    expect(cache.exists('key1')).toBe(true);
    expect(cache.exists('nonexistent')).toBe(false);
  });

  it('size returns correct count', () => {
    const cache = new LRUCache(100);
    cache.set('a', 1);
    cache.set('b', 2);
    expect(cache.size()).toBe(2);
  });

  it('clear removes all entries', () => {
    const cache = new LRUCache(100);
    cache.set('a', 1);
    cache.set('b', 2);
    cache.clear();
    expect(cache.size()).toBe(0);
  });

  it('LRU eviction works', () => {
    const cache = new LRUCache(2);
    cache.set('a', 1);
    cache.set('b', 2);
    cache.set('c', 3); // should evict 'a'
    expect(cache.get('a')).toBeUndefined();
    expect(cache.get('b')).toBe(2);
    expect(cache.get('c')).toBe(3);
  });

  it('evictExpired removes expired entries', () => {
    const cache = new LRUCache(100);
    cache.set('key1', 'value1', 1); // 1ms TTL
    // Wait for expiry
    const start = Date.now();
    while (Date.now() - start < 5) {} // busy wait 5ms
    const evicted = cache.evictExpired();
    expect(evicted).toBe(1);
    expect(cache.get('key1')).toBeUndefined();
  });
});

describe('Core: Policy Engine', () => {
  let PolicyEngine: any, PolicyAction: any, getPolicyEngine: any;

  beforeEach(async () => {
    const mod = await import('./src/core/policy.js');
    PolicyEngine = mod.PolicyEngine;
    PolicyAction = mod.PolicyAction;
    getPolicyEngine = mod.getPolicyEngine;
  });

  it('addRule and evaluate work', () => {
    const engine = new PolicyEngine();
    engine.addRule({
      id: 'deny-admin',
      name: 'Deny admin',
      description: 'Deny admin actions',
      condition: (ctx: any) => ctx.roles?.includes('admin'),
      action: PolicyAction.DENY,
      priority: 1,
      enabled: true,
      tags: [],
      metadata: {},
    });
    const result = engine.evaluate('deny-admin', { roles: ['admin'] });
    expect(result.allowed).toBe(false);
    expect(result.matchedRules).toContain('deny-admin');
  });

  it('evaluate returns allow for non-matching rule', () => {
    const engine = new PolicyEngine();
    engine.addRule({
      id: 'deny-admin',
      name: 'Deny admin',
      description: 'Deny admin actions',
      condition: (ctx: any) => ctx.roles?.includes('admin'),
      action: PolicyAction.DENY,
      priority: 1,
      enabled: true,
      tags: [],
      metadata: {},
    });
    const result = engine.evaluate('deny-admin', { roles: ['user'] });
    expect(result.allowed).toBe(true);
  });

  it('evaluateAll evaluates all enabled rules', () => {
    const engine = new PolicyEngine();
    engine.addRule({
      id: 'allow-user',
      name: 'Allow user',
      description: 'Allow user actions',
      condition: (ctx: any) => ctx.roles?.includes('user'),
      action: PolicyAction.ALLOW,
      priority: 1,
      enabled: true,
      tags: [],
      metadata: {},
    });
    const result = engine.evaluateAll({ roles: ['user'] });
    expect(result.allowed).toBe(true);
    expect(result.evaluatedRules).toContain('allow-user');
  });

  it('evaluateAll denies on first deny rule', () => {
    const engine = new PolicyEngine();
    engine.addRule({
      id: 'deny-all',
      name: 'Deny all',
      description: 'Deny everything',
      condition: () => true,
      action: PolicyAction.DENY,
      priority: 1,
      enabled: true,
      tags: [],
      metadata: {},
    });
    engine.addRule({
      id: 'allow-specific',
      name: 'Allow specific',
      description: 'Allow specific actions',
      condition: () => true,
      action: PolicyAction.ALLOW,
      priority: 2,
      enabled: true,
      tags: [],
      metadata: {},
    });
    const result = engine.evaluateAll({});
    expect(result.allowed).toBe(false);
  });

  it('enableRule and disableRule work', () => {
    const engine = new PolicyEngine();
    engine.addRule({
      id: 'test-rule',
      name: 'Test',
      description: 'Test rule',
      condition: () => true,
      action: PolicyAction.DENY,
      priority: 1,
      enabled: true,
      tags: [],
      metadata: {},
    });
    expect(engine.disableRule('test-rule')).toBe(true);
    const result = engine.evaluate('test-rule', {});
    expect(result.allowed).toBe(true); // disabled rules allow
  });

  it('removeRule works', () => {
    const engine = new PolicyEngine();
    engine.addRule({
      id: 'temp-rule',
      name: 'Temp',
      description: 'Temporary rule',
      condition: () => true,
      action: PolicyAction.DENY,
      priority: 1,
      enabled: true,
      tags: [],
      metadata: {},
    });
    expect(engine.removeRule('temp-rule')).toBe(true);
    expect(engine.getRuleCount()).toBe(0);
  });
});

describe('Core: Events', () => {
  let EventBus: any, EventType: any, EventSeverity: any, getEventBus: any;

  beforeEach(async () => {
    const mod = await import('./src/core/events.js');
    EventBus = mod.EventBus;
    EventType = mod.EventType;
    EventSeverity = mod.EventSeverity;
    getEventBus = mod.getEventBus;
  });

  it('subscribe and publish work', async () => {
    const bus = new EventBus();
    let received: any = null;
    bus.subscribe(EventType.AUTHENTICATION, (event: any) => {
      received = event;
    });
    await bus.publish({
      id: '1',
      type: EventType.AUTHENTICATION,
      severity: EventSeverity.INFO,
      timestamp: new Date(),
      source: 'test',
      message: 'test event',
      metadata: {},
    });
    expect(received).not.toBeNull();
    expect(received.message).toBe('test event');
  });

  it('subscribeAll receives all events', async () => {
    const bus = new EventBus();
    const received: any[] = [];
    bus.subscribeAll((event: any) => {
      received.push(event);
    });
    await bus.publish({
      id: '1',
      type: EventType.AUTHENTICATION,
      severity: EventSeverity.INFO,
      timestamp: new Date(),
      source: 'test',
      message: 'auth event',
      metadata: {},
    });
    await bus.publish({
      id: '2',
      type: EventType.THREAT,
      severity: EventSeverity.CRITICAL,
      timestamp: new Date(),
      source: 'test',
      message: 'threat event',
      metadata: {},
    });
    expect(received.length).toBe(2);
  });

  it('unsubscribe removes handler', async () => {
    const bus = new EventBus();
    let received = 0;
    const handler = () => { received++; };
    bus.subscribe(EventType.AUTHENTICATION, handler);
    await bus.publish({
      id: '1',
      type: EventType.AUTHENTICATION,
      severity: EventSeverity.INFO,
      timestamp: new Date(),
      source: 'test',
      message: 'test',
      metadata: {},
    });
    expect(received).toBe(1);
    bus.unsubscribe(EventType.AUTHENTICATION, handler);
    await bus.publish({
      id: '2',
      type: EventType.AUTHENTICATION,
      severity: EventSeverity.INFO,
      timestamp: new Date(),
      source: 'test',
      message: 'test',
      metadata: {},
    });
    expect(received).toBe(1); // still 1
  });

  it('getHistory returns published events', async () => {
    const bus = new EventBus();
    await bus.publish({
      id: '1',
      type: EventType.AUTHENTICATION,
      severity: EventSeverity.INFO,
      timestamp: new Date(),
      source: 'test',
      message: 'event1',
      metadata: {},
    });
    const history = bus.getHistory();
    expect(history.length).toBe(1);
    expect(history[0].message).toBe('event1');
  });

  it('getDeadLetter captures failed deliveries', async () => {
    const bus = new EventBus();
    bus.subscribe(EventType.THREAT, () => {
      throw new Error('handler failed');
    });
    await bus.publish({
      id: '1',
      type: EventType.THREAT,
      severity: EventSeverity.ERROR,
      timestamp: new Date(),
      source: 'test',
      message: 'fail',
      metadata: {},
    });
    const dead = bus.getDeadLetter();
    expect(dead.length).toBe(1);
  });

  it('getSubscriberCount returns correct count', () => {
    const bus = new EventBus();
    expect(bus.getSubscriberCount(EventType.AUTHENTICATION)).toBe(0);
    bus.subscribe(EventType.AUTHENTICATION, () => {});
    expect(bus.getSubscriberCount(EventType.AUTHENTICATION)).toBe(1);
  });
});
