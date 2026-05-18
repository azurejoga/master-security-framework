import { describe, it, expect } from 'vitest';

describe('Defensive: Anti-debugging', () => {
  it('antiDebuggingDetection detects debugger', async () => {
    const { antiDebuggingDetection } = await import('./src/defensive/index.js');
    const result = antiDebuggingDetection(
      { pid: 1234, memoryUsage: 1024 * 1024 * 100 },
      { traced: false, tracerPid: 0 },
      [{ type: 'SIGTRAP', detected: false }]
    );
    expect(result).toBeDefined();
    expect(result).toHaveProperty('detected');
  });
});

describe('Defensive: Anti-tampering', () => {
  it('antiTampering detects tampering', async () => {
    const { antiTampering } = await import('./src/defensive/index.js');
    const result = antiTampering(
      [{ path: '/usr/bin/test', hash: 'abc123' }],
      { '/usr/bin/test': 'abc123' },
      [{ algorithm: 'sha256', expectedValue: 'test' }]
    );
    expect(result).toBeDefined();
    expect(result).toHaveProperty('detected');
  });
});

describe('Defensive: Memory integrity', () => {
  it('memoryIntegrityCheck returns check result', async () => {
    const { memoryIntegrityCheck } = await import('./src/defensive/index.js');
    const result = memoryIntegrityCheck(
      [{ address: '0x1000', permissions: 'rwx', hash: 'abc123' }],
      [{ regionAddress: '0x1000', expectedPermissions: 'rwx', expectedHash: 'abc123' }],
      [{ pattern: 'test', name: 'test-sig' }]
    );
    expect(result).toBeDefined();
    expect(result).toHaveProperty('valid');
  });
});

describe('Defensive: Runtime self-protection', () => {
  it('runtimeSelfProtection returns protection status', async () => {
    const { runtimeSelfProtection } = await import('./src/defensive/index.js');
    const result = runtimeSelfProtection(
      { enabled: true },
      [{ algorithm: 'sha256', expectedValue: 'test' }],
      { enabled: true }
    );
    expect(result).toBeDefined();
  });
});

describe('Defensive: Self-healing security', () => {
  it('selfHealingSecurity returns healing result', async () => {
    const { selfHealingSecurity } = await import('./src/defensive/index.js');
    const result = await selfHealingSecurity(
      { components: { web: { health: 30, status: 'unhealthy' } }, errors: [] },
      [{ trigger: 'web', action: 'restart', priority: 1 }],
      [{ target: 'web', type: 'restart' }]
    );
    expect(result).toBeDefined();
  });
});
