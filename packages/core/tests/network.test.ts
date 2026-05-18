import { describe, it, expect } from 'vitest';

describe('Network: IP validation', () => {
  it('validateIp accepts valid IPv4', async () => {
    const { validateIp } = await import('./src/network/index.js');
    const result = validateIp('192.168.1.1');
    expect(result.valid).toBe(true);
  });

  it('validateIp rejects IPv6 (not supported)', async () => {
    const { validateIp } = await import('./src/network/index.js');
    const result = validateIp('::1');
    expect(result.valid).toBe(false);
  });

  it('validateIp rejects invalid IP', async () => {
    const { validateIp } = await import('./src/network/index.js');
    const result = validateIp('999.999.999.999');
    expect(result.valid).toBe(false);
  });
});

describe('Network: Domain validation', () => {
  it('validateDomain accepts valid domain', async () => {
    const { validateDomain } = await import('./src/network/index.js');
    const result = validateDomain('example.com', ['.com']);
    expect(result.valid).toBe(true);
  });

  it('validateDomain rejects disallowed TLD', async () => {
    const { validateDomain } = await import('./src/network/index.js');
    const result = validateDomain('example.ru', ['.com']);
    expect(result.valid).toBe(false);
  });
});

describe('Network: Port scan detection', () => {
  it('detectPortScan detects scan', async () => {
    const { detectPortScan } = await import('./src/network/index.js');
    const now = Date.now();
    const connections = Array.from({ length: 20 }, (_, i) => ({
      sourceIp: '192.168.1.100',
      destinationPort: i + 1,
      destinationIp: '10.0.0.1',
      timestamp: now,
    }));
    const result = detectPortScan('192.168.1.100', connections, 60, 10);
    expect(result.detected).toBe(true);
  });

  it('detectPortScan allows normal traffic', async () => {
    const { detectPortScan } = await import('./src/network/index.js');
    const now = Date.now();
    const connections = [{
      sourceIp: '192.168.1.100',
      destinationPort: 443,
      destinationIp: '10.0.0.1',
      timestamp: now,
    }];
    const result = detectPortScan('192.168.1.100', connections, 60, 10);
    expect(result.detected).toBe(false);
  });
});

describe('Network: DNS tunneling detection', () => {
  it('detectDnsTunneling detects tunneling', async () => {
    const { detectDnsTunneling } = await import('./src/network/index.js');
    const queries = Array.from({ length: 60 }, (_, i) => ({
      domain: `a${i}.very-long-subdomain-that-looks-suspicious.example.com`,
      queryType: 'TXT',
      responseSize: 4000 + i * 100,
    }));
    const result = detectDnsTunneling(queries, 'example.com', 50);
    expect(result.detected).toBe(true);
  });
});

describe('Network: DDoS detection', () => {
  it('detectDdos detects attack', async () => {
    const { detectDdos } = await import('./src/network/index.js');
    const trafficData = {
      bytesPerSecond: 1000000,
      packetsPerSecond: 50000,
      connectionsPerSecond: 10000,
      sourceDistribution: { '10.0.0.1': 1000, '10.0.0.2': 500 },
    };
    const baseline = {
      bytesPerSecond: 10000,
      packetsPerSecond: 500,
      connectionsPerSecond: 100,
    };
    const result = detectDdos(trafficData, baseline, 5.0, 60);
    expect(result.detected).toBe(true);
  });
});
