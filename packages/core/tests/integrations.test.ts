import { describe, it, expect } from 'vitest';

describe('Integrations: Express middleware', () => {
  it('expressSecurityMiddleware returns middleware', async () => {
    const { expressSecurityMiddleware } = await import('./src/integrations/index.js');
    const middleware = expressSecurityMiddleware(null, {}, {});
    expect(typeof middleware).toBe('object');
    expect(middleware).toHaveProperty('headers');
  });
});

describe('Integrations: Next.js security headers', () => {
  it('nextjsSecurityHeaders returns headers config', async () => {
    const { nextjsSecurityHeaders } = await import('./src/integrations/index.js');
    const result = nextjsSecurityHeaders();
    expect(result).toBeDefined();
  });
});

describe('Integrations: Cloudflare edge protection', () => {
  it('cloudflareEdgeProtection returns config', async () => {
    const { cloudflareEdgeProtection } = await import('./src/integrations/index.js');
    const result = cloudflareEdgeProtection({ zoneId: 'test-zone', apiToken: 'test-token' });
    expect(result).toBeDefined();
  });
});

describe('Integrations: Deno security plugin', () => {
  it('denoSecurityPlugin returns plugin config', async () => {
    const { denoSecurityPlugin } = await import('./src/integrations/index.js');
    const result = denoSecurityPlugin();
    expect(result).toBeDefined();
  });
});

describe('Integrations: Bun security plugin', () => {
  it('bunSecurityPlugin returns plugin config', async () => {
    const { bunSecurityPlugin } = await import('./src/integrations/index.js');
    const result = bunSecurityPlugin();
    expect(result).toBeDefined();
  });
});

describe('Integrations: WASM security runtime', () => {
  it('wasmSecurityRuntime returns runtime config', async () => {
    const { wasmSecurityRuntime } = await import('./src/integrations/index.js');
    const result = wasmSecurityRuntime();
    expect(result).toBeDefined();
  });
});
