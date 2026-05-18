import { describe, it, expect } from 'vitest';

describe('Web: XSS detection', () => {
  it('detectXss finds script injection', async () => {
    const { detectXss } = await import('./src/web/index.js');
    const result = detectXss('<script>alert(1)</script>');
    expect(result.detected).toBe(true);
  });

  it('detectXss finds event handler', async () => {
    const { detectXss } = await import('./src/web/index.js');
    const result = detectXss('<img onerror="alert(1)">');
    expect(result.detected).toBe(true);
  });

  it('detectXss allows clean input', async () => {
    const { detectXss } = await import('./src/web/index.js');
    const result = detectXss('Hello world');
    expect(result.detected).toBe(false);
  });
});

describe('Web: HTML sanitization', () => {
  it('sanitizeHtml removes script tags', async () => {
    const { sanitizeHtml } = await import('./src/web/index.js');
    const result = sanitizeHtml('<script>alert(1)</script>');
    expect(result).not.toContain('<script>');
  });

  it('sanitizeHtml preserves clean text', async () => {
    const { sanitizeHtml } = await import('./src/web/index.js');
    const result = sanitizeHtml('Hello world');
    expect(result).toContain('Hello world');
  });
});

describe('Web: SQL injection detection', () => {
  it('detectSqli finds UNION injection', async () => {
    const { detectSqli } = await import('./src/web/index.js');
    const result = detectSqli("1' UNION SELECT * FROM users--");
    expect(result.detected).toBe(true);
  });

  it('detectSqli finds OR injection', async () => {
    const { detectSqli } = await import('./src/web/index.js');
    const result = detectSqli("' OR 1=1--");
    expect(result.detected).toBe(true);
  });

  it('detectSqli allows clean input', async () => {
    const { detectSqli } = await import('./src/web/index.js');
    const result = detectSqli('Hello world, this is a normal string');
    expect(result.detected).toBe(false);
  });
});

describe('Web: CSRF protection', () => {
  it('csrfProtect allows safe methods', async () => {
    const { csrfProtect } = await import('./src/web/index.js');
    const result = csrfProtect({ method: 'GET', url: '/test' }, 'token123', 'session456');
    expect(result).toBe(true);
  });

  it('validateCsrf accepts valid token', async () => {
    const { validateCsrf } = await import('./src/web/index.js');
    const token = 'valid-token-123';
    expect(validateCsrf(token, token)).toBe(true);
  });

  it('validateCsrf rejects invalid token', async () => {
    const { validateCsrf } = await import('./src/web/index.js');
    expect(validateCsrf('invalid-token', 'secret')).toBe(false);
  });
});

describe('Web: CORS validation', () => {
  it('validateCors accepts allowed origin', async () => {
    const { validateCors } = await import('./src/web/index.js');
    const result = validateCors('https://example.com', ['https://example.com']);
    expect(result.allowed).toBe(true);
  });

  it('validateCors rejects disallowed origin', async () => {
    const { validateCors } = await import('./src/web/index.js');
    const result = validateCors('https://evil.com', ['https://example.com']);
    expect(result.allowed).toBe(false);
  });
});

describe('Web: Secure headers', () => {
  it('secureHeaders returns headers object', async () => {
    const { secureHeaders } = await import('./src/web/index.js');
    const headers = secureHeaders({ method: 'GET', url: '/test' });
    expect(typeof headers).toBe('object');
    expect(Object.keys(headers).length).toBeGreaterThan(0);
  });
});

describe('Web: Secure cookies', () => {
  it('secureCookie generates secure cookie string', async () => {
    const { secureCookie } = await import('./src/web/index.js');
    const result = secureCookie('session', 'abc123');
    expect(typeof result).toBe('string');
    expect(result).toContain('session=abc123');
    expect(result).toContain('HttpOnly');
    expect(result).toContain('Secure');
  });
});
