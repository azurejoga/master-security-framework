import { describe, it, expect } from 'vitest';

describe('Enterprise: Compliance checks', () => {
  it('lgpdCheck returns compliance result', async () => {
    const { lgpdCheck } = await import('./src/enterprise/index.js');
    const result = lgpdCheck(
      { dataCategories: ['personal'], retentionDays: 365 },
      [{ source: 'web', destination: 'db', dataType: 'personal' }],
      [
        { name: 'encryption', implemented: true },
        { name: 'consent', implemented: true },
        { name: 'dpo', implemented: true },
        { name: 'data subject rights', implemented: true },
        { name: 'access control', implemented: true },
      ]
    );
    expect(result).toHaveProperty('compliant');
  });

  it('gdprCheck returns compliance result', async () => {
    const { gdprCheck } = await import('./src/enterprise/index.js');
    const result = gdprCheck(
      { dataCategories: ['personal'], retentionDays: 365 },
      [{ source: 'web', destination: 'db', dataType: 'personal' }],
      [
        { name: 'encryption', implemented: true },
        { name: 'consent', implemented: true },
        { name: 'dpo', implemented: true },
        { name: 'data subject rights', implemented: true },
        { name: 'breach notification', implemented: true },
        { name: 'dpia', implemented: true },
        { name: 'erasure', implemented: true },
      ]
    );
    expect(result).toHaveProperty('compliant');
  });

  it('hipaaCheck returns compliance result', async () => {
    const { hipaaCheck } = await import('./src/enterprise/index.js');
    const result = hipaaCheck(
      { dataCategories: ['phi'], retentionDays: 365 },
      [{ source: 'ehr', destination: 'db', dataType: 'phi' }],
      [
        { name: 'encryption', implemented: true },
        { name: 'access control', implemented: true },
        { name: 'audit', implemented: true },
        { name: 'risk assessment', implemented: true },
        { name: 'secure config', implemented: true },
        { name: 'malware protection', implemented: true },
        { name: 'physical access', implemented: true },
      ]
    );
    expect(result).toHaveProperty('compliant');
  });

  it('pciCheck returns compliance result', async () => {
    const { pciCheck } = await import('./src/enterprise/index.js');
    const result = pciCheck(
      { dataCategories: ['card'], retentionDays: 30 },
      [{ source: 'checkout', destination: 'db', dataType: 'card' }],
      [
        { name: 'encryption', implemented: true },
        { name: 'network seg', implemented: true },
        { name: 'logging', implemented: true },
        { name: 'policy', implemented: true },
      ]
    );
    expect(result).toHaveProperty('compliant');
  });
});

describe('Enterprise: Audit trail', () => {
  it('auditTrail returns audit result', async () => {
    const { auditTrail } = await import('./src/enterprise/index.js');
    const result = auditTrail(
      [{ type: 'login', user: 'admin', timestamp: new Date().toISOString(), result: 'success' }],
      [{ userId: 'admin', action: 'login', timestamp: new Date().toISOString() }],
      [{ changedBy: 'admin', changeType: 'update', timestamp: new Date().toISOString() }]
    );
    expect(result).toBeDefined();
  });
});
