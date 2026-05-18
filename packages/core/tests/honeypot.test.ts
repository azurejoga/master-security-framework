import { describe, it, expect } from 'vitest';

describe('Honeypot: Adaptive honeypot', () => {
  it('adaptiveHoneypot returns honeypot config', async () => {
    const { adaptiveHoneypot } = await import('./src/honeypot/index.js');
    const result = await adaptiveHoneypot(
      { type: 'web', services: ['http'] },
      { attackSignatures: [], requestRate: 10 },
      5
    );
    expect(result).toBeDefined();
  });
});

describe('Honeypot: Fake admin panel', () => {
  it('fakeAdminPanel returns panel config', async () => {
    const { fakeAdminPanel } = await import('./src/honeypot/index.js');
    const result = await fakeAdminPanel();
    expect(result).toBeDefined();
    expect(result).toHaveProperty('id');
  });
});

describe('Honeypot: Fake database', () => {
  it('fakeDatabase returns database config', async () => {
    const { fakeDatabase } = await import('./src/honeypot/index.js');
    const result = await fakeDatabase();
    expect(result).toBeDefined();
  });
});

describe('Honeypot: Honeytoken generation', () => {
  it('honeytokenGeneration returns token', async () => {
    const { honeytokenGeneration } = await import('./src/honeypot/index.js');
    const result = await honeytokenGeneration(
      'api-key',
      { endpoint: '/api/test' },
      { alerts: [] }
    );
    expect(result).toBeDefined();
    expect(result).toHaveProperty('value');
  });
});

describe('Honeypot: Decoy endpoints', () => {
  it('decoyEndpoints returns endpoints', async () => {
    const { decoyEndpoints } = await import('./src/honeypot/index.js');
    const result = await decoyEndpoints(['/api/fake', '/admin/hidden']);
    expect(result).toBeDefined();
  });
});
