import { describe, it, expect } from 'vitest';

describe('Crypto: encrypt/decrypt', () => {
  it('encryptData returns encrypted string', async () => {
    const { encryptData, decryptData } = await import('./src/crypto/index.js');
    const plaintext = new TextEncoder().encode('hello world');
    const encrypted = await encryptData(plaintext, 'test-key-12345678901234567890');
    expect(encrypted).toHaveProperty('ciphertext');
    expect(encrypted).toHaveProperty('iv');
    const decrypted = await decryptData(encrypted, 'test-key-12345678901234567890');
    expect(new TextDecoder().decode(decrypted)).toBe('hello world');
  });

  it('decryptData fails with wrong key', async () => {
    const { encryptData, decryptData } = await import('./src/crypto/index.js');
    const plaintext = new TextEncoder().encode('hello world');
    const encrypted = await encryptData(plaintext, 'correct-key-123456789012345');
    await expect(decryptData(encrypted, 'wrong-key-1234567890123456')).rejects.toThrow();
  });
});

describe('Crypto: secureRandom', () => {
  it('secureRandom returns Uint8Array', async () => {
    const { secureRandom } = await import('./src/crypto/index.js');
    const random = secureRandom(32);
    expect(random instanceof Uint8Array).toBe(true);
    expect(random.length).toBe(32);
  });
});

describe('Crypto: HMAC', () => {
  it('generateHmac returns hex string', async () => {
    const { generateHmac } = await import('./src/crypto/index.js');
    const hmac = generateHmac('hello', 'secret-key');
    expect(typeof hmac).toBe('string');
    expect(hmac.length).toBeGreaterThan(0);
  });

  it('verifyHmac returns true for valid hmac', async () => {
    const { generateHmac, verifyHmac } = await import('./src/crypto/index.js');
    const hmac = generateHmac('hello', 'secret-key');
    expect(verifyHmac('hello', hmac, 'secret-key')).toBe(true);
  });

  it('verifyHmac returns false for tampered data', async () => {
    const { generateHmac, verifyHmac } = await import('./src/crypto/index.js');
    const hmac = generateHmac('hello', 'secret-key');
    expect(verifyHmac('tampered', hmac, 'secret-key')).toBe(false);
  });
});

describe('Crypto: anti-timing compare', () => {
  it('antiTimingCompare returns true for equal arrays', async () => {
    const { antiTimingCompare } = await import('./src/crypto/index.js');
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3]);
    expect(antiTimingCompare(a, b)).toBe(true);
  });

  it('antiTimingCompare returns false for different arrays', async () => {
    const { antiTimingCompare } = await import('./src/crypto/index.js');
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 4]);
    expect(antiTimingCompare(a, b)).toBe(false);
  });
});

describe('Crypto: key rotation', () => {
  it('rotateKeys returns new keys', async () => {
    const { rotateKeys, secureRandom } = await import('./src/crypto/index.js');
    const oldKey = secureRandom(32);
    const newKey = secureRandom(32);
    const result = await rotateKeys(oldKey, newKey);
    expect(result).toBeDefined();
    expect(result).toHaveProperty('status');
  });
});
