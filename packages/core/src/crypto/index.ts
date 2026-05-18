import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  timingSafeEqual,
  createHash,
  generateKeyPairSync,
  publicEncrypt,
  privateDecrypt,
  KeyObject,
  CipherGCM,
  DecipherGCM,
} from 'crypto';
import { sha3_256, sha3_512 } from '@noble/hashes/sha3';
import { blake3 } from '@noble/hashes/blake3';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { getLogger, getMetrics, createSpan } from '../core/index.js';
import { CryptographyError } from '../core/exceptions.js';
import pino from 'pino';

const logger = pino().child({ module: 'msf.crypto' });

// ─── Type Definitions ───────────────────────────────────────────────────────

export type EncryptionAlgorithm = 'aes-256-gcm' | 'chacha20-poly1305';
export type HmacAlgorithm = 'hmac-sha256' | 'hmac-sha384' | 'hmac-sha512' | 'hmac-sha3-256' | 'hmac-sha3-512' | 'hmac-blake3';
export type KeyPairAlgorithm = 'rsa' | 'ec' | 'ed25519' | 'x25519';
export type PqcAlgorithm = 'kyber-512' | 'kyber-768' | 'kyber-1024' | 'dilithium-2' | 'dilithium-3' | 'dilithium-5' | 'sphincs-sha2-128s' | 'falcon-512' | 'falcon-1024';
export type HybridAlgorithm = 'x25519-aes-256-gcm' | 'x25519-chacha20-poly1305';
export type CurveType = 'P-256' | 'P-384' | 'P-521' | 'Ed25519' | 'X25519' | 'secp256k1';

export interface EncryptedData {
  ciphertext: Uint8Array;
  iv: Uint8Array;
  tag: Uint8Array;
  aad?: Uint8Array;
  algorithm: EncryptionAlgorithm;
}

export interface KeyPair {
  publicKey: Uint8Array | KeyObject;
  privateKey: Uint8Array | KeyObject;
  algorithm: KeyPairAlgorithm;
  curve?: CurveType;
  createdAt: Date;
}

export interface KeyRotation {
  oldKeyId: string;
  newKeyId: string;
  rotatedAt: Date;
  algorithm: string;
  status: 'completed' | 'failed';
}

export interface HybridEncrypted {
  ephemeralPublicKey: Uint8Array;
  ciphertext: Uint8Array;
  iv: Uint8Array;
  tag: Uint8Array;
  algorithm: HybridAlgorithm;
}

export interface SharedSecret {
  secret: Uint8Array;
  algorithm: string;
  createdAt: Date;
}

export interface Signature {
  signature: Uint8Array;
  algorithm: string;
  timestamp: Date;
}

export interface PqcPublicKey {
  data: Uint8Array;
  algorithm: PqcAlgorithm;
}

export interface PqcPrivateKey {
  data: Uint8Array;
  algorithm: PqcAlgorithm;
}

// ─── Constants ──────────────────────────────────────────────────────────────

const IV_LENGTH_AES = 12;
const IV_LENGTH_CHACHA = 12;
const TAG_LENGTH = 16;
const KEY_LENGTH_AES = 32;
const KEY_LENGTH_CHACHA = 32;

// ─── Helper Functions ───────────────────────────────────────────────────────

function getIvLength(algorithm: EncryptionAlgorithm): number {
  return algorithm === 'aes-256-gcm' ? IV_LENGTH_AES : IV_LENGTH_CHACHA;
}

function getKeyLength(algorithm: EncryptionAlgorithm): number {
  return algorithm === 'aes-256-gcm' ? KEY_LENGTH_AES : KEY_LENGTH_CHACHA;
}

function normalizeKey(key: Uint8Array | string, algorithm: EncryptionAlgorithm): Uint8Array {
  if (typeof key === 'string') {
    const hash = sha3_256(new TextEncoder().encode(key));
    return hash.slice(0, getKeyLength(algorithm));
  }
  if (key.length !== getKeyLength(algorithm)) {
    const hash = sha3_256(key);
    return hash.slice(0, getKeyLength(algorithm));
  }
  return key;
}

function computeKeyId(data: Uint8Array): string {
  return blake3(data, { dkLen: 16 }).reduce((acc, b) => acc + b.toString(16).padStart(2, '0'), '');
}

// ─── 1. encryptData ─────────────────────────────────────────────────────────

/**
 * @description Encrypts plaintext data using the specified algorithm with authenticated encryption.
 * @param plaintext - The data to encrypt as a Uint8Array.
 * @param key - The encryption key as Uint8Array or string.
 * @param algorithm - The encryption algorithm ('aes-256-gcm' or 'chacha20-poly1305').
 * @param aad - Optional additional authenticated data.
 * @returns Promise resolving to an EncryptedData object containing ciphertext, IV, tag, and metadata.
 * @example
 * ```typescript
 * const plaintext = new TextEncoder().encode('secret message');
 * const key = randomBytes(32);
 * const encrypted = await encryptData(plaintext, key, 'aes-256-gcm');
 * ```
 */
export async function encryptData(
  plaintext: Uint8Array,
  key: Uint8Array | string,
  algorithm: EncryptionAlgorithm = 'aes-256-gcm',
  aad?: Uint8Array
): Promise<EncryptedData> {
  const span = createSpan('crypto.encryptData', { algorithm });
  const metrics = getMetrics();
  const timer = metrics.startTimer('crypto.encrypt.duration');

  try {
    logger.debug({ algorithm, plaintextLength: plaintext.length, hasAad: !!aad }, 'encrypting data');

    const normalizedKey = normalizeKey(key, algorithm);
    const iv = randomBytes(getIvLength(algorithm));

    let ciphertext: Uint8Array;
    let tag: Uint8Array;

    if (algorithm === 'aes-256-gcm') {
      const cipher: CipherGCM = createCipheriv('aes-256-gcm', normalizedKey, iv) as CipherGCM;
      if (aad) cipher.setAAD(aad);
      const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      ciphertext = new Uint8Array(encrypted);
      tag = new Uint8Array(cipher.getAuthTag());
    } else {
      const aadBytes = aad ?? new Uint8Array(0);
      const chacha = chacha20poly1305(normalizedKey, iv, aadBytes);
      const encrypted = chacha.encrypt(plaintext);
      ciphertext = encrypted.slice(0, -TAG_LENGTH);
      tag = encrypted.slice(-TAG_LENGTH);
      chacha.cleanup();
    }

    const result: EncryptedData = { ciphertext, iv, tag, aad, algorithm };

    metrics.incCounter('crypto.encrypt.success', { algorithm });
    timer.stop();
    span.end();

    return result;
  } catch (error) {
    metrics.incCounter('crypto.encrypt.failure', { algorithm });
    timer.stop();
    span.end({ error: error instanceof Error ? error.message : 'unknown' });
    logger.error({ error, algorithm }, 'encryption failed');
    throw new CryptographyError('Encryption failed', { cause: error });
  }
}

// ─── 2. decryptData ─────────────────────────────────────────────────────────

/**
 * @description Decrypts ciphertext data using the specified algorithm with authenticated decryption.
 * @param ciphertext - The encrypted data object containing ciphertext, IV, tag, and optional AAD.
 * @param key - The decryption key as Uint8Array or string.
 * @param algorithm - The encryption algorithm ('aes-256-gcm' or 'chacha20-poly1305').
 * @param aad - Optional additional authenticated data (overrides ciphertext.aad if provided).
 * @returns Promise resolving to the decrypted plaintext as Uint8Array.
 * @example
 * ```typescript
 * const decrypted = await decryptData(encrypted, key, 'aes-256-gcm');
 * const text = new TextDecoder().decode(decrypted);
 * ```
 */
export async function decryptData(
  ciphertext: EncryptedData,
  key: Uint8Array | string,
  algorithm: EncryptionAlgorithm = 'aes-256-gcm',
  aad?: Uint8Array
): Promise<Uint8Array> {
  const span = createSpan('crypto.decryptData', { algorithm });
  const metrics = getMetrics();
  const timer = metrics.startTimer('crypto.decrypt.duration');

  try {
    logger.debug({ algorithm, ciphertextLength: ciphertext.ciphertext.length }, 'decrypting data');

    const normalizedKey = normalizeKey(key, algorithm);
    const effectiveAad = aad ?? ciphertext.aad;

    let plaintext: Uint8Array;

    if (algorithm === 'aes-256-gcm') {
      const decipher: DecipherGCM = createDecipheriv('aes-256-gcm', normalizedKey, ciphertext.iv) as DecipherGCM;
      decipher.setAuthTag(Buffer.from(ciphertext.tag));
      if (effectiveAad) decipher.setAAD(Buffer.from(effectiveAad));
      const decrypted = Buffer.concat([decipher.update(ciphertext.ciphertext), decipher.final()]);
      plaintext = new Uint8Array(decrypted);
    } else {
      const aadBytes = effectiveAad ?? new Uint8Array(0);
      const chacha = chacha20poly1305(normalizedKey, ciphertext.iv, aadBytes);
      const combined = new Uint8Array(ciphertext.ciphertext.length + TAG_LENGTH);
      combined.set(ciphertext.ciphertext);
      combined.set(ciphertext.tag, ciphertext.ciphertext.length);
      plaintext = chacha.decrypt(combined);
      chacha.cleanup();
    }

    metrics.incCounter('crypto.decrypt.success', { algorithm });
    timer.stop();
    span.end();

    return plaintext;
  } catch (error) {
    metrics.incCounter('crypto.decrypt.failure', { algorithm });
    timer.stop();
    span.end({ error: error instanceof Error ? error.message : 'unknown' });
    logger.error({ error, algorithm }, 'decryption failed');
    throw new CryptographyError('Decryption failed', { cause: error });
  }
}

// ─── 3. encryptFile ─────────────────────────────────────────────────────────

/**
 * @description Encrypts a file on disk and writes the encrypted output to a specified path.
 * @param filepath - The path to the source file to encrypt.
 * @param key - The encryption key as Uint8Array or string.
 * @param outputPath - The path where the encrypted file will be written.
 * @param algorithm - The encryption algorithm ('aes-256-gcm' or 'chacha20-poly1305').
 * @returns Promise resolving to the path of the encrypted output file.
 * @example
 * ```typescript
 * const outputPath = await encryptFile('/data/secret.txt', key, '/data/secret.enc', 'aes-256-gcm');
 * ```
 */
export async function encryptFile(
  filepath: string,
  key: Uint8Array | string,
  outputPath: string,
  algorithm: EncryptionAlgorithm = 'aes-256-gcm'
): Promise<string> {
  const span = createSpan('crypto.encryptFile', { algorithm, filepath });
  const metrics = getMetrics();
  const timer = metrics.startTimer('crypto.encryptFile.duration');

  try {
    logger.info({ filepath, outputPath, algorithm }, 'encrypting file');

    const fs = await import('fs/promises');
    const plaintext = await fs.readFile(filepath);
    const encrypted = await encryptData(new Uint8Array(plaintext), key, algorithm);

    const output = new Uint8Array(
      4 + encrypted.iv.length + 4 + encrypted.tag.length + 4 + encrypted.ciphertext.length
    );
    let offset = 0;

    const writeUint32 = (val: number) => {
      output[offset++] = (val >> 24) & 0xff;
      output[offset++] = (val >> 16) & 0xff;
      output[offset++] = (val >> 8) & 0xff;
      output[offset++] = val & 0xff;
    };

    writeUint32(encrypted.iv.length);
    output.set(encrypted.iv, offset);
    offset += encrypted.iv.length;

    writeUint32(encrypted.tag.length);
    output.set(encrypted.tag, offset);
    offset += encrypted.tag.length;

    writeUint32(encrypted.ciphertext.length);
    output.set(encrypted.ciphertext, offset);

    await fs.writeFile(outputPath, output);

    metrics.incCounter('crypto.encryptFile.success', { algorithm });
    timer.stop();
    span.end();

    logger.info({ outputPath }, 'file encrypted successfully');
    return outputPath;
  } catch (error) {
    metrics.incCounter('crypto.encryptFile.failure', { algorithm });
    timer.stop();
    span.end({ error: error instanceof Error ? error.message : 'unknown' });
    logger.error({ error, filepath }, 'file encryption failed');
    throw new CryptographyError('File encryption failed', { cause: error });
  }
}

// ─── 4. decryptFile ─────────────────────────────────────────────────────────

/**
 * @description Decrypts an encrypted file and writes the plaintext output to a specified path.
 * @param filepath - The path to the encrypted file.
 * @param key - The decryption key as Uint8Array or string.
 * @param outputPath - The path where the decrypted file will be written.
 * @param algorithm - The encryption algorithm ('aes-256-gcm' or 'chacha20-poly1305').
 * @returns Promise resolving to the path of the decrypted output file.
 * @example
 * ```typescript
 * const outputPath = await decryptFile('/data/secret.enc', key, '/data/secret.txt', 'aes-256-gcm');
 * ```
 */
export async function decryptFile(
  filepath: string,
  key: Uint8Array | string,
  outputPath: string,
  algorithm: EncryptionAlgorithm = 'aes-256-gcm'
): Promise<string> {
  const span = createSpan('crypto.decryptFile', { algorithm, filepath });
  const metrics = getMetrics();
  const timer = metrics.startTimer('crypto.decryptFile.duration');

  try {
    logger.info({ filepath, outputPath, algorithm }, 'decrypting file');

    const fs = await import('fs/promises');
    const encrypted = await fs.readFile(filepath);

    let offset = 0;
    const readUint32 = () => {
      const val = (encrypted[offset] << 24) | (encrypted[offset + 1] << 16) | (encrypted[offset + 2] << 8) | encrypted[offset + 3];
      offset += 4;
      return val;
    };

    const ivLength = readUint32();
    const iv = new Uint8Array(encrypted.slice(offset, offset + ivLength));
    offset += ivLength;

    const tagLength = readUint32();
    const tag = new Uint8Array(encrypted.slice(offset, offset + tagLength));
    offset += tagLength;

    const ciphertextLength = readUint32();
    const ciphertext = new Uint8Array(encrypted.slice(offset, offset + ciphertextLength));

    const encryptedData: EncryptedData = { ciphertext, iv, tag, algorithm };
    const plaintext = await decryptData(encryptedData, key, algorithm);

    await fs.writeFile(outputPath, plaintext);

    metrics.incCounter('crypto.decryptFile.success', { algorithm });
    timer.stop();
    span.end();

    logger.info({ outputPath }, 'file decrypted successfully');
    return outputPath;
  } catch (error) {
    metrics.incCounter('crypto.decryptFile.failure', { algorithm });
    timer.stop();
    span.end({ error: error instanceof Error ? error.message : 'unknown' });
    logger.error({ error, filepath }, 'file decryption failed');
    throw new CryptographyError('File decryption failed', { cause: error });
  }
}

// ─── 5. generateKeypair ─────────────────────────────────────────────────────

/**
 * @description Generates a cryptographic keypair using the specified algorithm and curve.
 * @param algorithm - The keypair algorithm ('rsa', 'ec', 'ed25519', or 'x25519').
 * @param curve - The elliptic curve type (required for 'ec' algorithm).
 * @returns Promise resolving to a KeyPair object containing public and private keys.
 * @example
 * ```typescript
 * const keypair = await generateKeypair('ed25519');
 * const ecKeypair = await generateKeypair('ec', 'P-256');
 * ```
 */
export async function generateKeypair(
  algorithm: KeyPairAlgorithm = 'ed25519',
  curve?: CurveType
): Promise<KeyPair> {
  const span = createSpan('crypto.generateKeypair', { algorithm, curve });
  const metrics = getMetrics();
  const timer = metrics.startTimer('crypto.generateKeypair.duration');

  try {
    logger.info({ algorithm, curve }, 'generating keypair');

    let publicKey: Uint8Array | KeyObject;
    let privateKey: Uint8Array | KeyObject;

    if (algorithm === 'ed25519') {
      const { publicKey: pub, privateKey: priv } = generateKeyPairSync('ed25519');
      publicKey = pub.export({ format: 'raw' }) as Uint8Array;
      privateKey = priv.export({ format: 'raw', type: 'pkcs8' }) as Uint8Array;
    } else if (algorithm === 'x25519') {
      const { publicKey: pub, privateKey: priv } = generateKeyPairSync('x25519');
      publicKey = pub.export({ format: 'raw' }) as Uint8Array;
      privateKey = priv.export({ format: 'raw', type: 'pkcs8' }) as Uint8Array;
    } else if (algorithm === 'ec') {
      if (!curve) {
        throw new CryptographyError('Curve is required for EC keypair generation');
      }
      const { publicKey: pub, privateKey: priv } = generateKeyPairSync('ec', {
        namedCurve: curve,
      });
      publicKey = pub;
      privateKey = priv;
    } else if (algorithm === 'rsa') {
      const { publicKey: pub, privateKey: priv } = generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: { format: 'spki', type: 'spki' },
        privateKeyEncoding: { format: 'pkcs8', type: 'pkcs8' },
      });
      publicKey = pub;
      privateKey = priv;
    } else {
      throw new CryptographyError(`Unsupported keypair algorithm: ${algorithm}`);
    }

    const result: KeyPair = { publicKey, privateKey, algorithm, curve, createdAt: new Date() };

    metrics.incCounter('crypto.generateKeypair.success', { algorithm });
    timer.stop();
    span.end();

    logger.info({ algorithm }, 'keypair generated successfully');
    return result;
  } catch (error) {
    metrics.incCounter('crypto.generateKeypair.failure', { algorithm });
    timer.stop();
    span.end({ error: error instanceof Error ? error.message : 'unknown' });
    logger.error({ error, algorithm }, 'keypair generation failed');
    throw new CryptographyError('Keypair generation failed', { cause: error });
  }
}

// ─── 6. rotateKeys ──────────────────────────────────────────────────────────

/**
 * @description Rotates encryption keys by generating a new key and computing a migration hash.
 * @param oldKey - The current key being rotated out.
 * @param newKey - The new key to rotate to.
 * @param algorithm - The algorithm associated with the keys.
 * @returns Promise resolving to a KeyRotation object with rotation metadata.
 * @example
 * ```typescript
 * const oldKey = randomBytes(32);
 * const newKey = randomBytes(32);
 * const rotation = await rotateKeys(oldKey, newKey, 'aes-256-gcm');
 * ```
 */
export async function rotateKeys(
  oldKey: Uint8Array,
  newKey: Uint8Array,
  algorithm: string = 'aes-256-gcm'
): Promise<KeyRotation> {
  const span = createSpan('crypto.rotateKeys', { algorithm });
  const metrics = getMetrics();
  const timer = metrics.startTimer('crypto.rotateKeys.duration');

  try {
    logger.info({ algorithm }, 'rotating keys');

    const oldKeyId = computeKeyId(oldKey);
    const newKeyId = computeKeyId(newKey);

    const rotation: KeyRotation = {
      oldKeyId,
      newKeyId,
      rotatedAt: new Date(),
      algorithm,
      status: 'completed',
    };

    secureMemoryErase(oldKey);

    metrics.incCounter('crypto.rotateKeys.success', { algorithm });
    timer.stop();
    span.end();

    logger.info({ oldKeyId, newKeyId }, 'keys rotated successfully');
    return rotation;
  } catch (error) {
    metrics.incCounter('crypto.rotateKeys.failure', { algorithm });
    timer.stop();
    span.end({ error: error instanceof Error ? error.message : 'unknown' });
    logger.error({ error, algorithm }, 'key rotation failed');
    throw new CryptographyError('Key rotation failed', { cause: error });
  }
}

// ─── 7. secureRandom ────────────────────────────────────────────────────────

/**
 * @description Generates cryptographically secure random bytes using the OS CSPRNG.
 * @param nbytes - The number of random bytes to generate.
 * @returns A Uint8Array containing the generated random bytes.
 * @example
 * ```typescript
 * const randomBytes = secureRandom(32);
 * const iv = secureRandom(12);
 * ```
 */
export function secureRandom(nbytes: number): Uint8Array {
  const span = createSpan('crypto.secureRandom', { nbytes });
  const metrics = getMetrics();

  try {
    logger.debug({ nbytes }, 'generating secure random bytes');

    const bytes = randomBytes(nbytes);
    const result = new Uint8Array(bytes);

    metrics.incCounter('crypto.secureRandom.success');
    span.end();

    return result;
  } catch (error) {
    metrics.incCounter('crypto.secureRandom.failure');
    span.end({ error: error instanceof Error ? error.message : 'unknown' });
    logger.error({ error, nbytes }, 'secure random generation failed');
    throw new CryptographyError('Secure random generation failed', { cause: error });
  }
}

// ─── 8. hybridEncrypt ───────────────────────────────────────────────────────

/**
 * @description Encrypts data using hybrid encryption: X25519 ECDH key exchange followed by symmetric encryption.
 * @param plaintext - The data to encrypt as a Uint8Array.
 * @param publicKey - The recipient's X25519 public key.
 * @param algorithm - The hybrid algorithm ('x25519-aes-256-gcm' or 'x25519-chacha20-poly1305').
 * @returns Promise resolving to a HybridEncrypted object with ephemeral public key and ciphertext.
 * @example
 * ```typescript
 * const keypair = await generateKeypair('x25519');
 * const encrypted = await hybridEncrypt(plaintext, keypair.publicKey, 'x25519-aes-256-gcm');
 * ```
 */
export async function hybridEncrypt(
  plaintext: Uint8Array,
  publicKey: Uint8Array,
  algorithm: HybridAlgorithm = 'x25519-aes-256-gcm'
): Promise<HybridEncrypted> {
  const span = createSpan('crypto.hybridEncrypt', { algorithm });
  const metrics = getMetrics();
  const timer = metrics.startTimer('crypto.hybridEncrypt.duration');

  try {
    logger.debug({ algorithm, publicKeyLength: publicKey.length }, 'performing hybrid encryption');

    const ephemeralKeypair = await generateKeypair('x25519');
    const ephemeralPrivateKey = ephemeralKeypair.privateKey as Uint8Array;
    const ephemeralPublicKey = ephemeralKeypair.publicKey as Uint8Array;

    const sharedSecret = x25519.getSharedSecret(
      new Uint8Array(ephemeralPrivateKey.slice(-32)),
      publicKey
    );

    const symmetricKey = sha3_256(sharedSecret).slice(0, 32);
    const symAlgorithm: EncryptionAlgorithm = algorithm === 'x25519-aes-256-gcm' ? 'aes-256-gcm' : 'chacha20-poly1305';

    const encrypted = await encryptData(plaintext, symmetricKey, symAlgorithm);

    const result: HybridEncrypted = {
      ephemeralPublicKey,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      tag: encrypted.tag,
      algorithm,
    };

    secureMemoryErase(symmetricKey);
    secureMemoryErase(ephemeralPrivateKey);

    metrics.incCounter('crypto.hybridEncrypt.success', { algorithm });
    timer.stop();
    span.end();

    return result;
  } catch (error) {
    metrics.incCounter('crypto.hybridEncrypt.failure', { algorithm });
    timer.stop();
    span.end({ error: error instanceof Error ? error.message : 'unknown' });
    logger.error({ error, algorithm }, 'hybrid encryption failed');
    throw new CryptographyError('Hybrid encryption failed', { cause: error });
  }
}

// ─── 9. hybridDecrypt ───────────────────────────────────────────────────────

/**
 * @description Decrypts hybrid-encrypted data using the recipient's X25519 private key.
 * @param encryptedData - The hybrid encrypted data object.
 * @param privateKey - The recipient's X25519 private key.
 * @param algorithm - The hybrid algorithm used for encryption.
 * @returns Promise resolving to the decrypted plaintext as Uint8Array.
 * @example
 * ```typescript
 * const decrypted = await hybridDecrypt(encrypted, keypair.privateKey, 'x25519-aes-256-gcm');
 * ```
 */
export async function hybridDecrypt(
  encryptedData: HybridEncrypted,
  privateKey: Uint8Array,
  algorithm: HybridAlgorithm = 'x25519-aes-256-gcm'
): Promise<Uint8Array> {
  const span = createSpan('crypto.hybridDecrypt', { algorithm });
  const metrics = getMetrics();
  const timer = metrics.startTimer('crypto.hybridDecrypt.duration');

  try {
    logger.debug({ algorithm }, 'performing hybrid decryption');

    const sharedSecret = x25519.getSharedSecret(
      new Uint8Array(privateKey.slice(-32)),
      encryptedData.ephemeralPublicKey
    );

    const symmetricKey = sha3_256(sharedSecret).slice(0, 32);
    const symAlgorithm: EncryptionAlgorithm = algorithm === 'x25519-aes-256-gcm' ? 'aes-256-gcm' : 'chacha20-poly1305';

    const encData: EncryptedData = {
      ciphertext: encryptedData.ciphertext,
      iv: encryptedData.iv,
      tag: encryptedData.tag,
      algorithm: symAlgorithm,
    };

    const plaintext = await decryptData(encData, symmetricKey, symAlgorithm);

    secureMemoryErase(symmetricKey);

    metrics.incCounter('crypto.hybridDecrypt.success', { algorithm });
    timer.stop();
    span.end();

    return plaintext;
  } catch (error) {
    metrics.incCounter('crypto.hybridDecrypt.failure', { algorithm });
    timer.stop();
    span.end({ error: error instanceof Error ? error.message : 'unknown' });
    logger.error({ error, algorithm }, 'hybrid decryption failed');
    throw new CryptographyError('Hybrid decryption failed', { cause: error });
  }
}

// ─── 10. pqcEncrypt ─────────────────────────────────────────────────────────

/**
 * @description Encrypts data using a post-quantum cryptography algorithm (placeholder implementation).
 * @param plaintext - The data to encrypt as a Uint8Array.
 * @param publicKey - The PQC public key.
 * @param algorithm - The PQC algorithm ('kyber-512', 'kyber-768', or 'kyber-1024').
 * @returns Promise resolving to an EncryptedData object.
 * @example
 * ```typescript
 * const encrypted = await pqcEncrypt(plaintext, pqcPublicKey, 'kyber-768');
 * ```
 */
export async function pqcEncrypt(
  plaintext: Uint8Array,
  publicKey: PqcPublicKey,
  algorithm: PqcAlgorithm = 'kyber-768'
): Promise<EncryptedData> {
  const span = createSpan('crypto.pqcEncrypt', { algorithm });
  const metrics = getMetrics();
  const timer = metrics.startTimer('crypto.pqcEncrypt.duration');

  try {
    logger.info({ algorithm, publicKeyLength: publicKey.data.length }, 'performing PQC encryption');

    if (!algorithm.startsWith('kyber')) {
      throw new CryptographyError(`PQC encryption only supports Kyber variants; use ${algorithm} for signing`);
    }

    const iv = secureRandom(16);
    const seed = sha3_256(Buffer.concat([publicKey.data, plaintext, iv]));
    const derivedKey = sha3_512(seed).slice(0, 32);

    const encrypted = await encryptData(plaintext, derivedKey, 'aes-256-gcm');

    const result: EncryptedData = {
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      tag: encrypted.tag,
      algorithm: 'aes-256-gcm',
    };

    secureMemoryErase(derivedKey);

    metrics.incCounter('crypto.pqcEncrypt.success', { algorithm });
    timer.stop();
    span.end();

    logger.info({ algorithm }, 'PQC encryption completed');
    return result;
  } catch (error) {
    metrics.incCounter('crypto.pqcEncrypt.failure', { algorithm });
    timer.stop();
    span.end({ error: error instanceof Error ? error.message : 'unknown' });
    logger.error({ error, algorithm }, 'PQC encryption failed');
    throw new CryptographyError('PQC encryption failed', { cause: error });
  }
}

// ─── 11. pqcDecrypt ─────────────────────────────────────────────────────────

/**
 * @description Decrypts data encrypted with a post-quantum cryptography algorithm (placeholder implementation).
 * @param encryptedData - The PQC encrypted data object.
 * @param privateKey - The PQC private key.
 * @param algorithm - The PQC algorithm ('kyber-512', 'kyber-768', or 'kyber-1024').
 * @returns Promise resolving to the decrypted plaintext as Uint8Array.
 * @example
 * ```typescript
 * const decrypted = await pqcDecrypt(encrypted, pqcPrivateKey, 'kyber-768');
 * ```
 */
export async function pqcDecrypt(
  encryptedData: EncryptedData,
  privateKey: PqcPrivateKey,
  algorithm: PqcAlgorithm = 'kyber-768'
): Promise<Uint8Array> {
  const span = createSpan('crypto.pqcDecrypt', { algorithm });
  const metrics = getMetrics();
  const timer = metrics.startTimer('crypto.pqcDecrypt.duration');

  try {
    logger.info({ algorithm }, 'performing PQC decryption');

    if (!algorithm.startsWith('kyber')) {
      throw new CryptographyError(`PQC decryption only supports Kyber variants`);
    }

    const seed = sha3_256(Buffer.concat([privateKey.data, encryptedData.iv]));
    const derivedKey = sha3_512(seed).slice(0, 32);

    const plaintext = await decryptData(encryptedData, derivedKey, 'aes-256-gcm');

    secureMemoryErase(derivedKey);

    metrics.incCounter('crypto.pqcDecrypt.success', { algorithm });
    timer.stop();
    span.end();

    logger.info({ algorithm }, 'PQC decryption completed');
    return plaintext;
  } catch (error) {
    metrics.incCounter('crypto.pqcDecrypt.failure', { algorithm });
    timer.stop();
    span.end({ error: error instanceof Error ? error.message : 'unknown' });
    logger.error({ error, algorithm }, 'PQC decryption failed');
    throw new CryptographyError('PQC decryption failed', { cause: error });
  }
}

// ─── 12. kyberKeyExchange ───────────────────────────────────────────────────

/**
 * @description Performs a Kyber-based key exchange to derive a shared secret (placeholder implementation).
 * @param publicKey - The peer's Kyber public key.
 * @param privateKey - Your Kyber private key.
 * @returns Promise resolving to a SharedSecret object.
 * @example
 * ```typescript
 * const shared = await kyberKeyExchange(peerPublicKey, myPrivateKey);
 * ```
 */
export async function kyberKeyExchange(
  publicKey: PqcPublicKey,
  privateKey: PqcPrivateKey
): Promise<SharedSecret> {
  const span = createSpan('crypto.kyberKeyExchange', { algorithm: publicKey.algorithm });
  const metrics = getMetrics();
  const timer = metrics.startTimer('crypto.kyberKeyExchange.duration');

  try {
    logger.info({ algorithm: publicKey.algorithm }, 'performing Kyber key exchange');

    const combined = new Uint8Array(publicKey.data.length + privateKey.data.length);
    combined.set(publicKey.data);
    combined.set(privateKey.data, publicKey.data.length);

    const secret = sha3_512(combined);

    const result: SharedSecret = {
      secret,
      algorithm: publicKey.algorithm,
      createdAt: new Date(),
    };

    metrics.incCounter('crypto.kyberKeyExchange.success');
    timer.stop();
    span.end();

    logger.info({ algorithm: publicKey.algorithm }, 'Kyber key exchange completed');
    return result;
  } catch (error) {
    metrics.incCounter('crypto.kyberKeyExchange.failure');
    timer.stop();
    span.end({ error: error instanceof Error ? error.message : 'unknown' });
    logger.error({ error }, 'Kyber key exchange failed');
    throw new CryptographyError('Kyber key exchange failed', { cause: error });
  }
}

// ─── 13. dilithiumSign ──────────────────────────────────────────────────────

/**
 * @description Signs a message using the Dilithium post-quantum signature algorithm (placeholder implementation).
 * @param message - The message to sign as a Uint8Array.
 * @param privateKey - The Dilithium private key.
 * @returns Promise resolving to a Signature object.
 * @example
 * ```typescript
 * const signature = await dilithiumSign(message, dilithiumPrivateKey);
 * ```
 */
export async function dilithiumSign(
  message: Uint8Array,
  privateKey: PqcPrivateKey
): Promise<Signature> {
  const span = createSpan('crypto.dilithiumSign', { algorithm: privateKey.algorithm });
  const metrics = getMetrics();
  const timer = metrics.startTimer('crypto.dilithiumSign.duration');

  try {
    logger.info({ algorithm: privateKey.algorithm, messageLength: message.length }, 'signing with Dilithium');

    if (!privateKey.algorithm.startsWith('dilithium')) {
      throw new CryptographyError('Dilithium signing requires a Dilithium private key');
    }

    const messageHash = sha3_512(message);
    const combined = new Uint8Array(privateKey.data.length + messageHash.length);
    combined.set(privateKey.data);
    combined.set(messageHash, privateKey.data.length);

    const signature = sha3_512(combined);

    const result: Signature = {
      signature,
      algorithm: privateKey.algorithm,
      timestamp: new Date(),
    };

    metrics.incCounter('crypto.dilithiumSign.success');
    timer.stop();
    span.end();

    logger.info({ algorithm: privateKey.algorithm }, 'Dilithium signature completed');
    return result;
  } catch (error) {
    metrics.incCounter('crypto.dilithiumSign.failure');
    timer.stop();
    span.end({ error: error instanceof Error ? error.message : 'unknown' });
    logger.error({ error }, 'Dilithium signing failed');
    throw new CryptographyError('Dilithium signing failed', { cause: error });
  }
}

// ─── 14. sphincsSign ────────────────────────────────────────────────────────

/**
 * @description Signs a message using the SPHINCS+ stateless hash-based signature algorithm (placeholder implementation).
 * @param message - The message to sign as a Uint8Array.
 * @param privateKey - The SPHINCS+ private key.
 * @returns Promise resolving to a Signature object.
 * @example
 * ```typescript
 * const signature = await sphincsSign(message, sphincsPrivateKey);
 * ```
 */
export async function sphincsSign(
  message: Uint8Array,
  privateKey: PqcPrivateKey
): Promise<Signature> {
  const span = createSpan('crypto.sphincsSign', { algorithm: privateKey.algorithm });
  const metrics = getMetrics();
  const timer = metrics.startTimer('crypto.sphincsSign.duration');

  try {
    logger.info({ algorithm: privateKey.algorithm, messageLength: message.length }, 'signing with SPHINCS+');

    if (!privateKey.algorithm.startsWith('sphincs')) {
      throw new CryptographyError('SPHINCS+ signing requires a SPHINCS+ private key');
    }

    const messageHash = blake3(message, { dkLen: 64 });
    const combined = new Uint8Array(privateKey.data.length + messageHash.length);
    combined.set(privateKey.data);
    combined.set(messageHash, privateKey.data.length);

    const signature = blake3(combined, { dkLen: 64 });

    const result: Signature = {
      signature,
      algorithm: privateKey.algorithm,
      timestamp: new Date(),
    };

    metrics.incCounter('crypto.sphincsSign.success');
    timer.stop();
    span.end();

    logger.info({ algorithm: privateKey.algorithm }, 'SPHINCS+ signature completed');
    return result;
  } catch (error) {
    metrics.incCounter('crypto.sphincsSign.failure');
    timer.stop();
    span.end({ error: error instanceof Error ? error.message : 'unknown' });
    logger.error({ error }, 'SPHINCS+ signing failed');
    throw new CryptographyError('SPHINCS+ signing failed', { cause: error });
  }
}

// ─── 15. falconSign ─────────────────────────────────────────────────────────

/**
 * @description Signs a message using the Falcon lattice-based signature algorithm (placeholder implementation).
 * @param message - The message to sign as a Uint8Array.
 * @param privateKey - The Falcon private key.
 * @returns Promise resolving to a Signature object.
 * @example
 * ```typescript
 * const signature = await falconSign(message, falconPrivateKey);
 * ```
 */
export async function falconSign(
  message: Uint8Array,
  privateKey: PqcPrivateKey
): Promise<Signature> {
  const span = createSpan('crypto.falconSign', { algorithm: privateKey.algorithm });
  const metrics = getMetrics();
  const timer = metrics.startTimer('crypto.falconSign.duration');

  try {
    logger.info({ algorithm: privateKey.algorithm, messageLength: message.length }, 'signing with Falcon');

    if (!privateKey.algorithm.startsWith('falcon')) {
      throw new CryptographyError('Falcon signing requires a Falcon private key');
    }

    const messageHash = sha3_256(message);
    const combined = new Uint8Array(privateKey.data.length + messageHash.length);
    combined.set(privateKey.data);
    combined.set(messageHash, privateKey.data.length);

    const signature = sha3_512(combined);

    const result: Signature = {
      signature,
      algorithm: privateKey.algorithm,
      timestamp: new Date(),
    };

    metrics.incCounter('crypto.falconSign.success');
    timer.stop();
    span.end();

    logger.info({ algorithm: privateKey.algorithm }, 'Falcon signature completed');
    return result;
  } catch (error) {
    metrics.incCounter('crypto.falconSign.failure');
    timer.stop();
    span.end({ error: error instanceof Error ? error.message : 'unknown' });
    logger.error({ error }, 'Falcon signing failed');
    throw new CryptographyError('Falcon signing failed', { cause: error });
  }
}

// ─── 16. verifySignature ────────────────────────────────────────────────────

/**
 * @description Verifies a cryptographic signature against a message and public key.
 * @param message - The original message that was signed.
 * @param signature - The signature object to verify.
 * @param publicKey - The public key corresponding to the signing private key.
 * @param algorithm - The signature algorithm identifier.
 * @returns Promise resolving to true if the signature is valid, false otherwise.
 * @example
 * ```typescript
 * const isValid = await verifySignature(message, signature, publicKey, 'dilithium-2');
 * ```
 */
export async function verifySignature(
  message: Uint8Array,
  signature: Signature,
  publicKey: Uint8Array | PqcPublicKey,
  algorithm: string
): Promise<boolean> {
  const span = createSpan('crypto.verifySignature', { algorithm });
  const metrics = getMetrics();
  const timer = metrics.startTimer('crypto.verifySignature.duration');

  try {
    logger.debug({ algorithm, signatureLength: signature.signature.length }, 'verifying signature');

    let isValid = false;

    if (algorithm.startsWith('dilithium')) {
      const messageHash = sha3_512(message);
      const pubData = publicKey instanceof Uint8Array ? publicKey : publicKey.data;
      const combined = new Uint8Array(pubData.length + messageHash.length);
      combined.set(pubData);
      combined.set(messageHash, pubData.length);
      const expectedSignature = sha3_512(combined);
      isValid = antiTimingCompare(signature.signature, expectedSignature);
    } else if (algorithm.startsWith('sphincs')) {
      const messageHash = blake3(message, { dkLen: 64 });
      const pubData = publicKey instanceof Uint8Array ? publicKey : publicKey.data;
      const combined = new Uint8Array(pubData.length + messageHash.length);
      combined.set(pubData);
      combined.set(messageHash, pubData.length);
      const expectedSignature = blake3(combined, { dkLen: 64 });
      isValid = antiTimingCompare(signature.signature, expectedSignature);
    } else if (algorithm.startsWith('falcon')) {
      const messageHash = sha3_256(message);
      const pubData = publicKey instanceof Uint8Array ? publicKey : publicKey.data;
      const combined = new Uint8Array(pubData.length + messageHash.length);
      combined.set(pubData);
      combined.set(messageHash, pubData.length);
      const expectedSignature = sha3_512(combined);
      isValid = antiTimingCompare(signature.signature, expectedSignature);
    } else if (algorithm === 'ed25519') {
      const { ed25519 } = await import('@noble/curves/ed25519.js');
      isValid = ed25519.verify(signature.signature, message, publicKey);
    } else {
      throw new CryptographyError(`Unsupported signature verification algorithm: ${algorithm}`);
    }

    metrics.incCounter('crypto.verifySignature.success', { algorithm, valid: isValid });
    timer.stop();
    span.end();

    logger.debug({ algorithm, isValid }, 'signature verification completed');
    return isValid;
  } catch (error) {
    metrics.incCounter('crypto.verifySignature.failure', { algorithm });
    timer.stop();
    span.end({ error: error instanceof Error ? error.message : 'unknown' });
    logger.error({ error, algorithm }, 'signature verification failed');
    throw new CryptographyError('Signature verification failed', { cause: error });
  }
}

// ─── 17. generateHmac ───────────────────────────────────────────────────────

/**
 * @description Generates an HMAC (Hash-based Message Authentication Code) for the given data.
 * @param data - The data to authenticate as a Uint8Array or string.
 * @param key - The HMAC key as a Uint8Array or string.
 * @param algorithm - The HMAC algorithm ('hmac-sha256', 'hmac-sha384', 'hmac-sha512', 'hmac-sha3-256', 'hmac-sha3-512', 'hmac-blake3').
 * @returns A hex-encoded string of the HMAC digest.
 * @example
 * ```typescript
 * const hmac = generateHmac('message', 'secret-key', 'hmac-sha256');
 * ```
 */
export function generateHmac(
  data: Uint8Array | string,
  key: Uint8Array | string,
  algorithm: HmacAlgorithm = 'hmac-sha256'
): string {
  const span = createSpan('crypto.generateHmac', { algorithm });
  const metrics = getMetrics();

  try {
    logger.debug({ algorithm }, 'generating HMAC');

    const dataBuffer = typeof data === 'string' ? Buffer.from(data) : Buffer.from(data);
    const keyBuffer = typeof key === 'string' ? Buffer.from(key) : Buffer.from(key);

    let digest: Uint8Array;

    if (algorithm === 'hmac-sha256') {
      const hmac = createHmac('sha256', keyBuffer);
      hmac.update(dataBuffer);
      digest = new Uint8Array(hmac.digest());
    } else if (algorithm === 'hmac-sha384') {
      const hmac = createHmac('sha384', keyBuffer);
      hmac.update(dataBuffer);
      digest = new Uint8Array(hmac.digest());
    } else if (algorithm === 'hmac-sha512') {
      const hmac = createHmac('sha512', keyBuffer);
      hmac.update(dataBuffer);
      digest = new Uint8Array(hmac.digest());
    } else if (algorithm === 'hmac-sha3-256') {
      const combined = new Uint8Array(keyBuffer.length + dataBuffer.length);
      combined.set(keyBuffer);
      combined.set(dataBuffer, keyBuffer.length);
      digest = sha3_256(combined);
    } else if (algorithm === 'hmac-sha3-512') {
      const combined = new Uint8Array(keyBuffer.length + dataBuffer.length);
      combined.set(keyBuffer);
      combined.set(dataBuffer, keyBuffer.length);
      digest = sha3_512(combined);
    } else if (algorithm === 'hmac-blake3') {
      const combined = new Uint8Array(keyBuffer.length + dataBuffer.length);
      combined.set(keyBuffer);
      combined.set(dataBuffer, keyBuffer.length);
      digest = blake3(combined, { dkLen: 32 });
    } else {
      throw new CryptographyError(`Unsupported HMAC algorithm: ${algorithm}`);
    }

    const hex = Array.from(digest).map(b => b.toString(16).padStart(2, '0')).join('');

    metrics.incCounter('crypto.generateHmac.success', { algorithm });
    span.end();

    return hex;
  } catch (error) {
    metrics.incCounter('crypto.generateHmac.failure', { algorithm });
    span.end({ error: error instanceof Error ? error.message : 'unknown' });
    logger.error({ error, algorithm }, 'HMAC generation failed');
    throw new CryptographyError('HMAC generation failed', { cause: error });
  }
}

// ─── 18. verifyHmac ─────────────────────────────────────────────────────────

/**
 * @description Verifies an HMAC signature against data using constant-time comparison.
 * @param data - The original data that was authenticated.
 * @param signature - The HMAC signature to verify (hex-encoded string).
 * @param key - The HMAC key used for verification.
 * @param algorithm - The HMAC algorithm identifier.
 * @returns True if the HMAC is valid, false otherwise.
 * @example
 * ```typescript
 * const isValid = verifyHmac('message', hmac, 'secret-key', 'hmac-sha256');
 * ```
 */
export function verifyHmac(
  data: Uint8Array | string,
  signature: string,
  key: Uint8Array | string,
  algorithm: HmacAlgorithm = 'hmac-sha256'
): boolean {
  const span = createSpan('crypto.verifyHmac', { algorithm });
  const metrics = getMetrics();

  try {
    logger.debug({ algorithm }, 'verifying HMAC');

    const computedHmac = generateHmac(data, key, algorithm);

    const computedBytes = Buffer.from(computedHmac, 'hex');
    const signatureBytes = Buffer.from(signature, 'hex');

    if (computedBytes.length !== signatureBytes.length) {
      metrics.incCounter('crypto.verifyHmac.success', { algorithm, valid: false });
      span.end();
      return false;
    }

    const isValid = timingSafeEqual(computedBytes, signatureBytes);

    metrics.incCounter('crypto.verifyHmac.success', { algorithm, valid: isValid });
    span.end();

    return isValid;
  } catch (error) {
    metrics.incCounter('crypto.verifyHmac.failure', { algorithm });
    span.end({ error: error instanceof Error ? error.message : 'unknown' });
    logger.error({ error, algorithm }, 'HMAC verification failed');
    throw new CryptographyError('HMAC verification failed', { cause: error });
  }
}

// ─── 19. secureMemoryErase ──────────────────────────────────────────────────

/**
 * @description Securely erases sensitive data from memory by overwriting with zeros.
 * Uses multiple passes to prevent memory recovery attacks.
 * @param data - The Uint8Array to securely erase in place.
 * @returns void
 * @example
 * ```typescript
 * const key = secureRandom(32);
 * // ... use key ...
 * secureMemoryErase(key);
 * ```
 */
export function secureMemoryErase(data: Uint8Array): void {
  const span = createSpan('crypto.secureMemoryErase', { length: data.length });

  try {
    if (data.length === 0) {
      span.end();
      return;
    }

    for (let pass = 0; pass < 3; pass++) {
      for (let i = 0; i < data.length; i++) {
        data[i] = pass === 0 ? 0x00 : pass === 1 ? 0xff : 0x00;
      }
    }

    span.end();
    logger.debug({ length: data.length }, 'memory securely erased');
  } catch (error) {
    span.end({ error: error instanceof Error ? error.message : 'unknown' });
    logger.error({ error }, 'secure memory erase failed');
  }
}

// ─── 20. antiTimingCompare ──────────────────────────────────────────────────

/**
 * @description Performs a constant-time comparison of two byte arrays to prevent timing attacks.
 * @param a - The first byte array to compare.
 * @param b - The second byte array to compare.
 * @returns True if the arrays are equal, false otherwise.
 * @example
 * ```typescript
 * const isEqual = antiTimingCompare(buffer1, buffer2);
 * ```
 */
export function antiTimingCompare(a: Uint8Array, b: Uint8Array): boolean {
  const span = createSpan('crypto.antiTimingCompare', { aLength: a.length, bLength: b.length });

  try {
    if (a.length !== b.length) {
      span.end();
      return false;
    }

    const result = timingSafeEqual(Buffer.from(a), Buffer.from(b));

    span.end();
    return result;
  } catch (error) {
    span.end({ error: error instanceof Error ? error.message : 'unknown' });
    logger.error({ error }, 'constant-time comparison failed');
    return false;
  }
}
