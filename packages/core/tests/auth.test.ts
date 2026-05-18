import { describe, it, expect, beforeEach, afterEach } from 'vitest';

// Auth module tests
describe('Auth: generateJwt + validateJwt', () => {
  let generateJwt: any, validateJwt: any, revokeJwt: any, rotateJwt: any;

  beforeEach(async () => {
    const mod = await import('./src/auth/index.js');
    generateJwt = mod.generateJwt;
    validateJwt = mod.validateJwt;
    revokeJwt = mod.revokeJwt;
    rotateJwt = mod.rotateJwt;
  });

  it('generateJwt returns a token string', async () => {
    const token = await generateJwt('user-123', 'test-secret', { expiresIn: 3600 });
    expect(typeof token).toBe('string');
    expect(token.split('.').length).toBe(3);
  });

  it('validateJwt returns payload for valid token', async () => {
    const token = await generateJwt('user-123', 'test-secret');
    const payload = await validateJwt(token, 'test-secret');
    expect(payload.sub).toBe('user-123');
  });

  it('validateJwt throws for wrong secret', async () => {
    const token = await generateJwt('user-123', 'correct-secret');
    await expect(validateJwt(token, 'wrong-secret')).rejects.toThrow();
  });

  it('validateJwt throws for expired token', async () => {
    const token = await generateJwt('user-123', 'test-secret', { expiresIn: -100 });
    await expect(validateJwt(token, 'test-secret')).rejects.toThrow('expired');
  });

  it('validateJwt checks issuer', async () => {
    const token = await generateJwt('user-123', 'test-secret', { issuer: 'my-app' });
    const payload = await validateJwt(token, 'test-secret', { issuer: 'my-app' });
    expect(payload.iss).toBe('my-app');
  });

  it('validateJwt rejects wrong issuer', async () => {
    const token = await generateJwt('user-123', 'test-secret', { issuer: 'my-app' });
    await expect(validateJwt(token, 'test-secret', { issuer: 'other-app' })).rejects.toThrow('issuer');
  });

  it('revokeJwt works', async () => {
    const token = await generateJwt('user-123', 'test-secret', { tokenId: 'test-token-1' });
    const result = await revokeJwt('test-token-1', 'logout');
    expect(result).toBe(true);
  });

  it('validateJwt rejects revoked token', async () => {
    const token = await generateJwt('user-123', 'test-secret', { tokenId: 'test-token-2' });
    await revokeJwt('test-token-2', 'logout');
    await expect(validateJwt(token, 'test-secret')).rejects.toThrow('revoked');
  });

  it('rotateJwt returns new token', async () => {
    const oldToken = await generateJwt('user-123', 'test-secret', { tokenId: 'test-token-3' });
    const newToken = await rotateJwt(oldToken, 'test-secret', { expiresIn: 7200 });
    expect(typeof newToken).toBe('string');
    expect(newToken.split('.').length).toBe(3);
  });

  it('validateJwt rejects invalid format', async () => {
    await expect(validateJwt('not-a-jwt', 'test-secret')).rejects.toThrow('Invalid JWT format');
  });
});

describe('Auth: TOTP', () => {
  let generateTotp: any, validateTotp: any;

  beforeEach(async () => {
    const mod = await import('./src/auth/index.js');
    generateTotp = mod.generateTotp;
    validateTotp = mod.validateTotp;
  });

  it('generateTotp returns a code string', () => {
    const code = generateTotp('JBSWY3DPEHPK3PXP');
    expect(typeof code).toBe('string');
    expect(code.length).toBe(6);
  });

  it('validateTotp accepts valid code', () => {
    const code = generateTotp('JBSWY3DPEHPK3PXP');
    expect(validateTotp('JBSWY3DPEHPK3PXP', code)).toBe(true);
  });

  it('validateTotp rejects wrong code', () => {
    expect(validateTotp('JBSWY3DPEHPK3PXP', '000000')).toBe(false);
  });
});

describe('Auth: Session', () => {
  let secureSession: any, validateSession: any, detectSessionHijack: any;

  beforeEach(async () => {
    const mod = await import('./src/auth/index.js');
    secureSession = mod.secureSession;
    validateSession = mod.validateSession;
    detectSessionHijack = mod.detectSessionHijack;
  });

  it('secureSession creates a session', async () => {
    const session = await secureSession('user-123', '192.168.1.1', 'Mozilla/5.0', 'device-abc');
    expect(session.userId).toBe('user-123');
    expect(session.ip).toBe('192.168.1.1');
    expect(session.status).toBe('active');
    expect(session.id).toBeDefined();
  });

  it('detectSessionHijack detects IP change', async () => {
    const historical = [{ ip: '192.168.1.1', userAgent: 'Mozilla/5.0', timestamp: Date.now() - 500 }];
    const hijacked = await detectSessionHijack('session-1', '10.0.0.1', 'Mozilla/5.0', historical);
    expect(hijacked).toBe(true);
  });

  it('detectSessionHijack returns false for same IP', async () => {
    const historical = [{ ip: '192.168.1.1', userAgent: 'Mozilla/5.0', timestamp: Date.now() - 500 }];
    const hijacked = await detectSessionHijack('session-1', '192.168.1.1', 'Mozilla/5.0', historical);
    expect(hijacked).toBe(false);
  });

  it('detectSessionHijack detects UA change', async () => {
    const historical = [{ ip: '192.168.1.1', userAgent: 'Mozilla/5.0', timestamp: Date.now() - 500 }];
    const hijacked = await detectSessionHijack('session-1', '10.0.0.1', 'Chrome/100', historical);
    expect(hijacked).toBe(true);
  });

  it('detectSessionHijack returns false for empty history', async () => {
    const hijacked = await detectSessionHijack('session-1', '10.0.0.1', 'Mozilla/5.0', []);
    expect(hijacked).toBe(false);
  });
});

describe('Auth: Adaptive Auth', () => {
  let adaptiveAuth: any, riskBasedAuth: any, behavioralAuth: any;

  beforeEach(async () => {
    const mod = await import('./src/auth/index.js');
    adaptiveAuth = mod.adaptiveAuth;
    riskBasedAuth = mod.riskBasedAuth;
    behavioralAuth = mod.behavioralAuth;
  });

  it('adaptiveAuth requires MFA for high risk', async () => {
    const result = await adaptiveAuth('user-123', 0.9, {
      ip: '10.0.0.1',
      userAgent: 'Mozilla/5.0',
      timestamp: Date.now(),
    });
    expect(result.requiresMfa).toBe(true);
    expect(result.authenticated).toBe(false);
  });

  it('adaptiveAuth allows low risk', async () => {
    const result = await adaptiveAuth('user-123', 0.1, {
      ip: '192.168.1.1',
      userAgent: 'Mozilla/5.0',
      timestamp: Date.now(),
    });
    expect(result.requiresMfa).toBe(false);
    expect(result.authenticated).toBe(true);
  });

  it('riskBasedAuth calculates composite risk', async () => {
    const result = await riskBasedAuth('user-123', {
      ip: '10.0.0.1',
      userAgent: 'Mozilla/5.0',
      timestamp: Date.now(),
    }, {
      geoRisk: 0.8,
      deviceRisk: 0.1,
      behaviorRisk: 0.1,
      networkRisk: 0.1,
      reputationRisk: 0.1,
    });
    expect(result.riskScore).toBeGreaterThan(0);
  });

  it('behavioralAuth returns confidence score', async () => {
    const confidence = await behavioralAuth('user-123', {
      typingSpeed: 50,
      mouseMovement: [{ x: 0, y: 0, timestamp: 1 }, { x: 10, y: 10, timestamp: 2 }],
      sessionDuration: 300,
      navigationPatterns: ['/home', '/profile'],
    }, {
      avgTypingSpeed: 50,
      avgMouseSpeed: 10,
      commonPaths: ['/home', '/profile'],
      typicalSessionDuration: 300,
      typicalInteractionCount: 10,
    });
    expect(confidence).toBeGreaterThanOrEqual(0);
    expect(confidence).toBeLessThanOrEqual(1);
  });
});

describe('Auth: Password', () => {
  let passwordEntropy: any, detectWeakPassword: any, verifyBackupCode: any;

  beforeEach(async () => {
    const mod = await import('./src/auth/index.js');
    passwordEntropy = mod.passwordEntropy;
    detectWeakPassword = mod.detectWeakPassword;
    verifyBackupCode = mod.verifyBackupCode;
  });

  it('passwordEntropy returns positive value', () => {
    const entropy = passwordEntropy('MyP@ssw0rd!');
    expect(entropy).toBeGreaterThan(0);
  });

  it('passwordEntropy returns 0 for empty string', () => {
    expect(passwordEntropy('')).toBe(0);
  });

  it('detectWeakPassword identifies short password', () => {
    expect(detectWeakPassword('short')).toBe(true);
  });

  it('detectWeakPassword identifies common password', () => {
    expect(detectWeakPassword('password123456', 28, new Set(['password123456']))).toBe(true);
  });

  it('detectWeakPassword allows strong password', () => {
    expect(detectWeakPassword('X9#kL2$mP7@qR4!v', 28, new Set())).toBe(false);
  });

  it('verifyBackupCode validates correct code', () => {
    const codes = ['abcd-1234', 'efgh-5678'];
    expect(verifyBackupCode('abcd-1234', codes)).toBe(true);
  });

  it('verifyBackupCode rejects wrong code', () => {
    const codes = ['abcd-1234', 'efgh-5678'];
    expect(verifyBackupCode('wrong-code', codes)).toBe(false);
  });

  it('verifyBackupCode consumes code (removes from list)', () => {
    const codes = ['abcd-1234', 'efgh-5678'];
    verifyBackupCode('abcd-1234', codes);
    expect(codes).not.toContain('abcd-1234');
  });
});

describe('Auth: Impossible Travel', () => {
  let impossibleTravel: any, geoVelocityCheck: any;

  beforeEach(async () => {
    const mod = await import('./src/auth/index.js');
    impossibleTravel = mod.impossibleTravel;
    geoVelocityCheck = mod.geoVelocityCheck;
  });

  it('impossibleTravel detects impossible travel', async () => {
    const result = await impossibleTravel('user-123',
      { lat: 40.7128, lon: -74.0060 }, // New York
      { lat: 51.5074, lon: -0.1278 },  // London
      3600000 // 1 hour
    );
    expect(result).toBe(true);
  });

  it('impossibleTravel allows reasonable travel', async () => {
    const result = await impossibleTravel('user-123',
      { lat: 40.7128, lon: -74.0060 }, // New York
      { lat: 40.7580, lon: -73.9855 }, // Times Square
      3600000 // 1 hour
    );
    expect(result).toBe(false);
  });

  it('geoVelocityCheck detects exceeded speed', async () => {
    const locations = [
      { lat: 40.7128, lon: -74.0060, timestamp: Date.now() - 7200000 },
      { lat: 51.5074, lon: -0.1278, timestamp: Date.now() },
    ];
    const result = await geoVelocityCheck('user-123', locations, 900);
    expect(result).toBe(true);
  });

  it('geoVelocityCheck allows reasonable speed', async () => {
    const locations = [
      { lat: 40.7128, lon: -74.0060, timestamp: Date.now() - 86400000 },
      { lat: 51.5074, lon: -0.1278, timestamp: Date.now() },
    ];
    const result = await geoVelocityCheck('user-123', locations, 900);
    expect(result).toBe(false);
  });
});

describe('Auth: Token Replay & Credential Stuffing', () => {
  let detectTokenReplay: any, detectCredentialStuffing: any, detectBruteforce: any;

  beforeEach(async () => {
    const mod = await import('./src/auth/index.js');
    detectTokenReplay = mod.detectTokenReplay;
    detectCredentialStuffing = mod.detectCredentialStuffing;
    detectBruteforce = mod.detectBruteforce;
  });

  it('detectTokenReplay returns false for first use', async () => {
    const result = await detectTokenReplay('token-1', Date.now(), '192.168.1.1');
    expect(result).toBe(false);
  });

  it('detectBruteforce detects attack', async () => {
    const result = await detectBruteforce('10.0.0.1', 15, 300000, 10);
    expect(result).toBe(true);
  });

  it('detectBruteforce allows under threshold', async () => {
    const result = await detectBruteforce('192.168.1.1', 3, 300000, 10);
    expect(result).toBe(false);
  });
});

describe('Auth: WebAuthn', () => {
  let passkeyAuth: any, webauthnVerify: any;

  beforeEach(async () => {
    const mod = await import('./src/auth/index.js');
    passkeyAuth = mod.passkeyAuth;
    webauthnVerify = mod.webauthnVerify;
  });

  it('passkeyAuth throws for invalid type', async () => {
    await expect(passkeyAuth(
      'challenge',
      Buffer.alloc(37),
      Buffer.from('{"type":"webauthn.create","challenge":"abc"}'),
      Buffer.alloc(0)
    )).rejects.toThrow();
  });

  it('webauthnVerify returns false for invalid type', async () => {
    const result = await webauthnVerify(
      'cred-1', 'challenge', 'https://example.com', 'example.com',
      Buffer.alloc(0), Buffer.alloc(0), Buffer.alloc(0),
      '{"type":"webauthn.create","challenge":"abc","origin":"https://example.com"}'
    );
    expect(result).toBe(false);
  });
});
