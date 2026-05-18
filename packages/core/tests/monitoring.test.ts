import { describe, it, expect } from 'vitest';

describe('Monitoring: Anomaly score', () => {
  it('anomalyScore returns score', async () => {
    const { anomalyScore } = await import('./src/monitoring/index.js');
    const metrics = { cpu: 80, memory: 70, network: 50 };
    const baseline = { cpu: { mean: 50, std: 10 }, memory: { mean: 50, std: 10 }, network: { mean: 50, std: 10 } };
    const result = anomalyScore(metrics as any, baseline as any);
    expect(typeof result).toBe('number');
  });

  it('anomalyScore detects outlier', async () => {
    const { anomalyScore } = await import('./src/monitoring/index.js');
    const metrics = { cpu: 99, memory: 95, network: 90 };
    const baseline = { cpu: { mean: 50, std: 10 }, memory: { mean: 50, std: 10 }, network: { mean: 50, std: 10 } };
    const result = anomalyScore(metrics as any, baseline as any);
    expect(result).toBeGreaterThan(0);
  });
});

describe('Monitoring: Threat score', () => {
  it('threatScore returns score', async () => {
    const { threatScore } = await import('./src/monitoring/index.js');
    const events = [{ type: 'port_scan', severity: 'high', timestamp: Date.now(), source: '10.0.0.1' }];
    const threatIntel = { port_scan: { severity: 0.8, confidence: 0.9 } };
    const result = threatScore(events as any, threatIntel as any, {});
    expect(typeof result).toBe('number');
  });
});

describe('Monitoring: Risk score', () => {
  it('riskScore returns score', async () => {
    const { riskScore } = await import('./src/monitoring/index.js');
    const events = [{ type: 'login', severity: 'medium', timestamp: Date.now(), source: 'user1' }];
    const result = riskScore('user1', events as any, {}, { avgRisk: 0.5, incidentCount: 1, lastIncidentDays: 30 });
    expect(typeof result).toBe('number');
  });
});

describe('Monitoring: Event correlation', () => {
  it('correlateEvents returns correlated events', async () => {
    const { correlateEvents } = await import('./src/monitoring/index.js');
    const events = [
      { type: 'login', timestamp: Date.now(), source: '10.0.0.1' },
      { type: 'access', timestamp: Date.now() + 1000, source: '10.0.0.1' },
    ];
    const result = correlateEvents(events as any);
    expect(result).toBeDefined();
  });
});

describe('Monitoring: Secure logging', () => {
  it('secureLog logs securely', async () => {
    const { secureLog } = await import('./src/monitoring/index.js');
    const result = await secureLog('test_event', 'info', { sensitive: 'secret' }, false);
    expect(result).toBeDefined();
    expect(result).toHaveProperty('id');
    expect(result).toHaveProperty('hash');
  });
});

describe('Monitoring: Behavioral analysis', () => {
  it('behavioralAnalysis returns analysis', async () => {
    const { behavioralAnalysis } = await import('./src/monitoring/index.js');
    const events = [{ type: 'login', timestamp: new Date().toISOString(), source: 'user1' }];
    const baseline = { loginHours: { mean: 9, std: 2 }, locations: ['office'], avgEventsPerHour: 5 };
    const result = behavioralAnalysis(events as any, baseline);
    expect(result).toBeDefined();
    expect(result).toHaveProperty('userId');
  });
});
