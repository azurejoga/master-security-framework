import { describe, it, expect } from 'vitest';

describe('File: Malware scan', () => {
  it('malwareScan returns scan result', async () => {
    const { malwareScan } = await import('./src/file/index.js');
    const fileData = Buffer.from('hello world');
    const result = malwareScan(fileData, []);
    expect(result).toHaveProperty('threats');
  });
});

describe('File: Extension validation', () => {
  it('validateExtension accepts allowed extension', async () => {
    const { validateExtension } = await import('./src/file/index.js');
    expect(validateExtension('test.txt', ['.txt', '.pdf'])).toBe(true);
  });

  it('validateExtension rejects disallowed extension', async () => {
    const { validateExtension } = await import('./src/file/index.js');
    expect(validateExtension('test.exe', ['.txt', '.pdf'])).toBe(false);
  });
});

describe('File: Filename sanitization', () => {
  it('sanitizeFilename removes dangerous characters', async () => {
    const { sanitizeFilename } = await import('./src/file/index.js');
    const result = sanitizeFilename('test/../evil.txt');
    expect(result).not.toContain('../');
  });
});

describe('File: Entropy analysis', () => {
  it('entropyAnalysis returns entropy result', async () => {
    const { entropyAnalysis } = await import('./src/file/index.js');
    const fileData = Buffer.from('hello world hello world');
    const result = entropyAnalysis(fileData);
    expect(result).toHaveProperty('entropy');
  });
});

describe('File: Secure tempfile', () => {
  it('secureTempfile returns temp file path', async () => {
    const { secureTempfile } = await import('./src/file/index.js');
    const result = secureTempfile('test');
    expect(typeof result).toBe('string');
    expect(result.length).toBeGreaterThan(0);
  });
});
