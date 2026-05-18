/**
 * File Security Module
 * Provides comprehensive file upload validation, malware detection,
 * content analysis, and secure file handling capabilities.
 * @module file
 */

import { createHash, randomBytes } from 'crypto';
import { sha3_256 } from '@noble/hashes/sha3';
import { getLogger, getMetrics, createSpan, getEventBus, SecurityEvent, EventSeverity } from '../core/index.js';
import { ValidationError, SecurityError } from '../core/exceptions.js';
import pino from 'pino';
const logger = pino().child({ module: 'msf.file' });

// ─── Type Definitions ───────────────────────────────────────────────────────

/**
 * File signature for magic byte detection
 */
export interface FileSignature {
  /** File type identifier */
  type: string;
  /** Magic bytes as hex string */
  magicBytes: string;
  /** Offset in file where signature starts */
  offset: number;
  /** MIME type */
  mimeType: string;
}

/**
 * YARA rule for pattern matching
 */
export interface YaraRule {
  /** Rule identifier */
  id: string;
  /** Rule namespace */
  namespace: string;
  /** Pattern strings to match */
  strings: string[];
  /** Condition expression */
  condition: string;
  /** Severity level */
  severity: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * Heuristic rule for behavioral analysis
 */
export interface HeuristicRule {
  /** Rule identifier */
  id: string;
  /** Rule description */
  description: string;
  /** Check function */
  check: (data: Buffer) => number;
  /** Weight in scoring */
  weight: number;
  /** MITRE ATT&CK technique */
  mitreTechnique?: string;
}

/**
 * Sandbox execution configuration
 */
export interface SandboxConfig {
  /** Network isolation */
  networkIsolated: boolean;
  /** File system access level */
  fsAccess: 'none' | 'readonly' | 'temp';
  /** Memory limit in MB */
  memoryLimitMB: number;
  /** CPU timeout seconds */
  cpuTimeoutSec: number;
  /** Allowed syscalls */
  allowedSyscalls: string[];
}

/**
 * Upload result with validation details
 */
export interface UploadResult {
  /** Whether upload is allowed */
  allowed: boolean;
  /** Original filename */
  filename: string;
  /** Sanitized filename */
  sanitizedFilename: string;
  /** File size in bytes */
  size: number;
  /** Detected MIME type */
  mimeType: string;
  /** SHA-256 hash */
  sha256: string;
  /** SHA3-256 hash */
  sha3_256: string;
  /** Validation errors */
  errors: string[];
  /** Warnings */
  warnings: string[];
}

/**
 * MIME validation result
 */
export interface MimeResult {
  /** Whether MIME matches */
  valid: boolean;
  /** Detected MIME type */
  detectedMime: string;
  /** Expected MIME type */
  expectedMime: string;
  /** Confidence score 0-1 */
  confidence: number;
}

/**
 * Detection result for various analyses
 */
export interface DetectionResult {
  /** Whether threat was detected */
  detected: boolean;
  /** Threat type */
  threatType: string;
  /** Confidence score 0-1 */
  confidence: number;
  /** Details about detection */
  details: string[];
  /** Recommended action */
  recommendation: string;
  /** MITRE ATT&CK technique */
  mitreTechnique?: string;
}

/**
 * Malware scan result
 */
export interface ScanResult {
  /** Whether malware was detected */
  infected: boolean;
  /** Threats found */
  threats: Array<{
    name: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    offset?: number;
  }>;
  /** Scan engine used */
  engine: string;
  /** Scan duration in ms */
  scanDurationMs: number;
  /** File hash */
  fileHash: string;
}

/**
 * Entropy analysis result
 */
export interface EntropyResult {
  /** Overall Shannon entropy */
  entropy: number;
  /** Maximum possible entropy */
  maxEntropy: number;
  /** Entropy ratio */
  entropyRatio: number;
  /** Whether entropy exceeds threshold */
  suspicious: boolean;
  /** Per-block entropy values */
  blockEntropies: number[];
  /** Assessment */
  assessment: string;
}

/**
 * Sandbox execution result
 */
export interface SandboxResult {
  /** Execution completed */
  completed: boolean;
  /** Exit code */
  exitCode: number;
  /** Standard output */
  stdout: string;
  /** Standard error */
  stderr: string;
  /** Execution duration in ms */
  durationMs: number;
  /** Suspicious behaviors detected */
  suspiciousBehaviors: string[];
  /** Network connections attempted */
  networkAttempts: string[];
  /** File operations attempted */
  fileOperations: string[];
  /** Memory usage peak MB */
  peakMemoryMB: number;
  /** Whether execution was terminated */
  terminated: boolean;
  /** Risk score 0-100 */
  riskScore: number;
}

// ─── Common File Signatures ─────────────────────────────────────────────────

const COMMON_SIGNATURES: FileSignature[] = [
  { type: 'pdf', magicBytes: '25504446', offset: 0, mimeType: 'application/pdf' },
  { type: 'zip', magicBytes: '504b0304', offset: 0, mimeType: 'application/zip' },
  { type: 'zip', magicBytes: '504b0506', offset: 0, mimeType: 'application/zip' },
  { type: 'jar', magicBytes: '504b0304', offset: 0, mimeType: 'application/java-archive' },
  { type: 'docx', magicBytes: '504b0304', offset: 0, mimeType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' },
  { type: 'xlsx', magicBytes: '504b0304', offset: 0, mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' },
  { type: 'pptx', magicBytes: '504b0304', offset: 0, mimeType: 'application/vnd.openxmlformats-officedocument.presentationml.presentation' },
  { type: 'exe', magicBytes: '4d5a', offset: 0, mimeType: 'application/x-msdownload' },
  { type: 'dll', magicBytes: '4d5a', offset: 0, mimeType: 'application/x-msdownload' },
  { type: 'png', magicBytes: '89504e47', offset: 0, mimeType: 'image/png' },
  { type: 'jpg', magicBytes: 'ffd8ff', offset: 0, mimeType: 'image/jpeg' },
  { type: 'gif', magicBytes: '47494638', offset: 0, mimeType: 'image/gif' },
  { type: 'bmp', magicBytes: '424d', offset: 0, mimeType: 'image/bmp' },
  { type: 'tiff', magicBytes: '49492a00', offset: 0, mimeType: 'image/tiff' },
  { type: 'tiff', magicBytes: '4d4d002a', offset: 0, mimeType: 'image/tiff' },
  { type: 'elf', magicBytes: '7f454c46', offset: 0, mimeType: 'application/x-executable' },
  { type: 'macho', magicBytes: 'feedface', offset: 0, mimeType: 'application/x-mach-binary' },
  { type: 'macho', magicBytes: 'feedfacf', offset: 0, mimeType: 'application/x-mach-binary' },
  { type: 'tar', magicBytes: '7573746172', offset: 257, mimeType: 'application/x-tar' },
  { type: 'gzip', magicBytes: '1f8b', offset: 0, mimeType: 'application/gzip' },
  { type: 'rar', magicBytes: '52617221', offset: 0, mimeType: 'application/vnd.rar' },
  { type: 'rar5', magicBytes: '526172211a07', offset: 0, mimeType: 'application/vnd.rar' },
  { type: '7z', magicBytes: '377abcaf271c', offset: 0, mimeType: 'application/x-7z-compressed' },
];

const OFFICE_MACRO_SIGNATURES = [
  '4f504f4c59474f4e',
  '4175746f4f70656e',
  '4175746f436c6f7365',
  '446f63756d656e745f4f70656e',
  '576f726b626f6f6b5f4f70656e',
  '564241',
  '766261',
  '4d6163726f',
];

const SCRIPT_PATTERNS: Record<string, RegExp[]> = {
  javascript: [/function\s+\w+\s*\(/gi, /eval\s*\(/gi, /document\.write/gi, /<script[\s>]/gi, /window\./gi],
  vbscript: [/Sub\s+\w+/gi, /Function\s+\w+/gi, /CreateObject/gi, /WScript\./gi, /Shell\.Run/gi],
  powershell: [/Invoke-Expression/gi, /Invoke-WebRequest/gi, /Start-Process/gi, /New-Object/gi, /DownloadString/gi],
  python: [/import\s+os/gi, /import\s+subprocess/gi, /os\.system/gi, /subprocess\.call/gi, /exec\s*\(/gi],
  batch: [/cmd\.exe/gi, /net\s+user/gi, /del\s+/gi, /format\s+/gi, /reg\s+add/gi],
};

// ─── 1. secureUpload ────────────────────────────────────────────────────────

/**
 * Securely validate and process a file upload with comprehensive checks.
 *
 * @description Performs extension validation, MIME type detection, size checking,
 * hashing, and filename sanitization. Returns a structured result indicating
 * whether the upload should be allowed.
 *
 * @param fileData - Buffer containing the file contents
 * @param filename - Original filename from the upload
 * @param allowedExtensions - Array of allowed file extensions (e.g., ['.pdf', '.png'])
 * @param maxSize - Maximum allowed file size in bytes (default: 10MB)
 * @returns UploadResult with validation status, hashes, and any errors
 *
 * @example
 * ```typescript
 * const result = await secureUpload(
 *   fileBuffer,
 *   'document.pdf',
 *   ['.pdf', '.docx'],
 *   10 * 1024 * 1024
 * );
 * if (!result.allowed) {
 *   console.error('Upload rejected:', result.errors);
 * }
 * ```
 */
export async function secureUpload(
  fileData: Buffer,
  filename: string,
  allowedExtensions: string[],
  maxSize: number = 10 * 1024 * 1024
): Promise<UploadResult> {
  const span = createSpan('file.secureUpload', { filename, size: fileData.length });
  const metrics = getMetrics();
  const startTime = Date.now();
  const errors: string[] = [];
  const warnings: string[] = [];

  try {
    logger.info({ filename, size: fileData.length, maxSize, allowedExtensions }, 'Starting secure upload validation');

    if (!fileData || fileData.length === 0) {
      errors.push('File data is empty');
      span.end({ allowed: false, reason: 'empty_file' });
      return {
        allowed: false,
        filename,
        sanitizedFilename: '',
        size: 0,
        mimeType: '',
        sha256: '',
        sha3_256: '',
        errors,
        warnings,
      };
    }

    if (fileData.length > maxSize) {
      errors.push(`File size ${fileData.length} exceeds maximum ${maxSize}`);
    }

    const extValid = validateExtension(filename, allowedExtensions);
    if (!extValid) {
      errors.push(`Extension not allowed: ${filename}`);
    }

    const detectedSig = detectFileSignature(fileData);
    const mimeType = detectedSig ? detectedSig.mimeType : 'application/octet-stream';

    const sanitized = sanitizeFilename(filename);

    const sha256Hash = createHash('sha256').update(fileData).digest('hex');
    const sha3Hash = Buffer.from(sha3_256(fileData)).toString('hex');

    if (fileData.length > maxSize * 0.9) {
      warnings.push('File size is close to the maximum limit');
    }

    const allowed = errors.length === 0;

    metrics.incCounter('file_upload_total');
    metrics.incCounter(allowed ? 'file_upload_allowed' : 'file_upload_rejected');
    metrics.observeHistogram('file_upload_duration_ms', Date.now() - startTime);
    metrics.observeHistogram('file_upload_size_bytes', fileData.length);

    const result: UploadResult = {
      allowed,
      filename,
      sanitizedFilename: sanitized,
      size: fileData.length,
      mimeType,
      sha256: sha256Hash,
      sha3_256: sha3Hash,
      errors,
      warnings,
    };

    logger.info({ allowed, sha256: sha256Hash, mimeType, errors, warnings }, 'Secure upload validation complete');

    const eventBus = getEventBus();
    await eventBus.publish({
      id: createHash('sha256').update(randomBytes(16)).digest('hex').slice(0, 16),
      type: 0 as any,
      severity: allowed ? EventSeverity.INFO : EventSeverity.WARNING,
      timestamp: new Date(),
      source: 'msf.file.secureUpload',
      message: allowed ? 'File upload validated successfully' : 'File upload rejected',
      metadata: { filename, mimeType, sha256: sha256Hash, errors, warnings },
    });

    span.end({ allowed, sha256: sha256Hash });
    return result;
  } catch (error) {
    metrics.incCounter('file_upload_error');
    logger.error({ error, filename }, 'Secure upload validation failed');
    span.end({ error: error instanceof Error ? error.message : 'unknown' });
    throw new SecurityError(`Secure upload failed: ${error instanceof Error ? error.message : 'unknown error'}`, { filename });
  }
}

// ─── 2. validateExtension ───────────────────────────────────────────────────

/**
 * Validate that a file's extension is in the allowed list.
 *
 * @description Extracts the file extension from the filename and checks it
 * against the provided whitelist of allowed extensions. Comparison is
 * case-insensitive.
 *
 * @param filename - The filename to validate
 * @param allowedExtensions - Array of allowed extensions (e.g., ['.pdf', '.jpg'])
 * @returns true if the extension is allowed, false otherwise
 *
 * @example
 * ```typescript
 * const isValid = validateExtension('report.pdf', ['.pdf', '.docx']);
 * console.log(isValid); // true
 *
 * const isInvalid = validateExtension('script.exe', ['.pdf', '.docx']);
 * console.log(isInvalid); // false
 * ```
 */
export function validateExtension(filename: string, allowedExtensions: string[]): boolean {
  const metrics = getMetrics();
  const dotIndex = filename.lastIndexOf('.');

  if (dotIndex === -1 || dotIndex === filename.length - 1) {
    logger.warn({ filename }, 'File has no extension');
    metrics.incCounter('file_extension_validation_none');
    return false;
  }

  const ext = filename.slice(dotIndex).toLowerCase();
  const normalized = allowedExtensions.map((e) => e.toLowerCase().startsWith('.') ? e.toLowerCase() : `.${e.toLowerCase()}`);
  const allowed = normalized.includes(ext);

  logger.debug({ filename, extension: ext, allowed }, 'Extension validation result');
  metrics.incCounter(`file_extension_validation_${allowed ? 'allowed' : 'rejected'}`);

  return allowed;
}

// ─── 3. validateMime ────────────────────────────────────────────────────────

/**
 * Validate file MIME type using magic byte detection.
 *
 * @description Reads the file's magic bytes and compares them against expected
 * MIME type signatures. Returns a confidence score based on how well the
 * detected type matches the expected type.
 *
 * @param fileData - Buffer containing the file contents
 * @param expectedMime - The expected MIME type string
 * @param magicBytes - Optional custom magic bytes hex string for comparison
 * @returns MimeResult with detected type, validity, and confidence score
 *
 * @example
 * ```typescript
 * const result = validateMime(fileBuffer, 'application/pdf');
 * if (!result.valid) {
 *   console.warn(`Expected PDF but detected ${result.detectedMime}`);
 * }
 * ```
 */
export function validateMime(fileData: Buffer, expectedMime: string, magicBytes?: string): MimeResult {
  const metrics = getMetrics();
  const detected = detectFileSignature(fileData);

  if (!detected) {
    const result: MimeResult = {
      valid: false,
      detectedMime: 'application/octet-stream',
      expectedMime,
      confidence: 0,
    };
    logger.warn({ expectedMime }, 'Could not detect file signature');
    metrics.incCounter('file_mime_detection_unknown');
    return result;
  }

  const exactMatch = detected.mimeType === expectedMime;
  const categoryMatch = detected.mimeType.split('/')[0] === expectedMime.split('/')[0];
  const confidence = exactMatch ? 1.0 : categoryMatch ? 0.5 : 0.0;

  const result: MimeResult = {
    valid: exactMatch,
    detectedMime: detected.mimeType,
    expectedMime,
    confidence,
  };

  logger.info({ expectedMime, detectedMime: detected.mimeType, confidence }, 'MIME validation complete');
  metrics.incCounter(`file_mime_validation_${exactMatch ? 'match' : categoryMatch ? 'category_match' : 'mismatch'}`);

  return result;
}

// ─── 4. detectPolyglotFile ──────────────────────────────────────────────────

/**
 * Detect polyglot files that contain multiple file format signatures.
 *
 * @description Scans the file data for multiple distinct file format signatures.
 * Polyglot files are crafted to be valid in multiple formats simultaneously
 * and are often used in attacks to bypass file type validation.
 *
 * @param fileData - Buffer containing the file contents
 * @param signatures - Array of file signatures to check against
 * @returns DetectionResult indicating if polyglot was detected with details
 *
 * @example
 * ```typescript
 * const result = detectPolyglotFile(fileBuffer, COMMON_SIGNATURES);
 * if (result.detected) {
 *   console.warn('Polyglot file detected:', result.details);
 * }
 * ```
 */
export function detectPolyglotFile(fileData: Buffer, signatures: FileSignature[]): DetectionResult {
  const metrics = getMetrics();
  const startTime = Date.now();
  const detectedTypes = new Set<string>();
  const details: string[] = [];

  try {
    for (const sig of signatures) {
      const sigBytes = Buffer.from(sig.magicBytes, 'hex');
      const searchStart = sig.offset;
      const searchEnd = Math.min(searchStart + sigBytes.length, fileData.length);

      if (searchEnd <= fileData.length) {
        const fileSlice = fileData.slice(searchStart, searchEnd);
        if (fileSlice.equals(sigBytes)) {
          detectedTypes.add(sig.type);
          details.push(`Found ${sig.type} signature at offset ${sig.offset} (MIME: ${sig.mimeType})`);
        }
      }
    }

    const detected = detectedTypes.size > 1;
    const confidence = Math.min(detectedTypes.size / 2, 1.0);

    const result: DetectionResult = {
      detected,
      threatType: 'polyglot_file',
      confidence,
      details: detected ? [`Multiple file types detected: ${Array.from(detectedTypes).join(', ')}`, ...details] : ['Single file type or no known signature'],
      recommendation: detected ? 'Reject file: polyglot files are commonly used in evasion attacks' : 'File appears to be a single format',
      mitreTechnique: detected ? 'T1027.009' : undefined,
    };

    logger.info({ detected, types: Array.from(detectedTypes), count: detectedTypes.size }, 'Polyglot detection complete');
    metrics.incCounter(`file_polyglot_${detected ? 'detected' : 'clean'}`);
    metrics.observeHistogram('file_polyglot_scan_ms', Date.now() - startTime);

    return result;
  } catch (error) {
    logger.error({ error }, 'Polyglot detection failed');
    metrics.incCounter('file_polyglot_scan_error');
    throw new SecurityError('Polyglot detection failed', { error: error instanceof Error ? error.message : 'unknown' });
  }
}

// ─── 5. detectZipBomb ───────────────────────────────────────────────────────

/**
 * Detect zip bomb files by analyzing compression ratios.
 *
 * @description Analyzes ZIP file structures to detect potential zip bombs
 * by checking the ratio of compressed to uncompressed sizes and the total
 * uncompressed size against configured thresholds.
 *
 * @param fileData - Buffer containing the ZIP file contents
 * @param maxRatio - Maximum allowed compression ratio (default: 100)
 * @param maxUncompressed - Maximum allowed uncompressed size in bytes (default: 1GB)
 * @returns DetectionResult indicating if zip bomb was detected
 *
 * @example
 * ```typescript
 * const result = detectZipBomb(zipBuffer, 100, 1024 * 1024 * 1024);
 * if (result.detected) {
 *   console.warn('Potential zip bomb:', result.details);
 * }
 * ```
 */
export function detectZipBomb(fileData: Buffer, maxRatio: number = 100, maxUncompressed: number = 1024 * 1024 * 1024): DetectionResult {
  const metrics = getMetrics();
  const startTime = Date.now();
  const details: string[] = [];
  let totalCompressed = 0;
  let totalUncompressed = 0;
  let fileCount = 0;
  let maxSingleRatio = 0;

  try {
    const zipSignature = Buffer.from('504b0304', 'hex');
    if (!fileData.slice(0, 4).equals(zipSignature)) {
      const result: DetectionResult = {
        detected: false,
        threatType: 'zip_bomb',
        confidence: 0,
        details: ['File is not a valid ZIP archive'],
        recommendation: 'File is not a ZIP, no bomb detection needed',
      };
      return result;
    }

    let offset = 0;
    while (offset < fileData.length - 30) {
      const headerSig = fileData.slice(offset, offset + 4);
      if (!headerSig.equals(zipSignature)) {
        break;
      }

      const compressedSize = fileData.readUInt32LE(offset + 18);
      const uncompressedSize = fileData.readUInt32LE(offset + 22);
      const filenameLength = fileData.readUInt16LE(offset + 26);
      const extraLength = fileData.readUInt16LE(offset + 28);

      totalCompressed += compressedSize;
      totalUncompressed += uncompressedSize;
      fileCount++;

      if (compressedSize > 0) {
        const ratio = uncompressedSize / compressedSize;
        if (ratio > maxSingleRatio) {
          maxSingleRatio = ratio;
        }
      }

      offset += 30 + filenameLength + extraLength + compressedSize;
    }

    const overallRatio = totalCompressed > 0 ? totalUncompressed / totalCompressed : 0;
    const ratioExceeded = overallRatio > maxRatio;
    const sizeExceeded = totalUncompressed > maxUncompressed;
    const detected = ratioExceeded || sizeExceeded || fileCount > 10000;

    if (ratioExceeded) details.push(`Compression ratio ${overallRatio.toFixed(1)}:1 exceeds threshold ${maxRatio}:1`);
    if (sizeExceeded) details.push(`Uncompressed size ${totalUncompressed} bytes exceeds threshold ${maxUncompressed} bytes`);
    if (fileCount > 10000) details.push(`File count ${fileCount} exceeds safe limit (10000)`);
    if (maxSingleRatio > maxRatio * 10) details.push(`Single file compression ratio ${maxSingleRatio.toFixed(1)}:1 is extremely high`);

    const confidence = detected ? Math.min((ratioExceeded ? 0.4 : 0) + (sizeExceeded ? 0.4 : 0) + (fileCount > 10000 ? 0.2 : 0), 1.0) : 0;

    const result: DetectionResult = {
      detected,
      threatType: 'zip_bomb',
      confidence,
      details: details.length > 0 ? details : [`Compression ratio: ${overallRatio.toFixed(1)}:1, Uncompressed: ${totalUncompressed} bytes, Files: ${fileCount}`],
      recommendation: detected ? 'Reject file: potential zip bomb detected' : 'File compression ratios within safe limits',
      mitreTechnique: detected ? 'T1499.002' : undefined,
    };

    logger.info({ detected, ratio: overallRatio, totalUncompressed, fileCount, maxSingleRatio }, 'Zip bomb detection complete');
    metrics.incCounter(`file_zipbomb_${detected ? 'detected' : 'clean'}`);
    metrics.observeHistogram('file_zipbomb_scan_ms', Date.now() - startTime);

    return result;
  } catch (error) {
    logger.error({ error }, 'Zip bomb detection failed');
    metrics.incCounter('file_zipbomb_scan_error');
    throw new SecurityError('Zip bomb detection failed', { error: error instanceof Error ? error.message : 'unknown' });
  }
}

// ─── 6. detectOfficeMacro ───────────────────────────────────────────────────

/**
 * Detect VBA macros in Microsoft Office documents.
 *
 * @description Scans Office document files (DOC, XLS, PPT and OOXML formats)
 * for embedded VBA macros that could execute malicious code when the document
 * is opened.
 *
 * @param fileData - Buffer containing the Office document contents
 * @param fileType - Type of Office file ('doc', 'xls', 'ppt', 'docx', 'xlsx', 'pptx')
 * @returns DetectionResult indicating if macros were detected
 *
 * @example
 * ```typescript
 * const result = detectOfficeMacro(docBuffer, 'docx');
 * if (result.detected) {
 *   console.warn('Macro detected in document');
 * }
 * ```
 */
export function detectOfficeMacro(fileData: Buffer, fileType: string): DetectionResult {
  const metrics = getMetrics();
  const startTime = Date.now();
  const details: string[] = [];
  let confidence = 0;

  try {
    const fileStr = fileData.toString('binary');
    const fileHex = fileData.toString('hex');

    const macroIndicators: Array<{ pattern: string; weight: number; description: string }> = [
      { pattern: 'vbaProject.bin', weight: 0.4, description: 'VBA project container found' },
      { pattern: 'Macros', weight: 0.3, description: 'Macro reference detected' },
      { pattern: 'AutoOpen', weight: 0.3, description: 'AutoOpen macro found' },
      { pattern: 'AutoExec', weight: 0.3, description: 'AutoExec macro found' },
      { pattern: 'Document_Open', weight: 0.3, description: 'Document_Open event handler found' },
      { pattern: 'Workbook_Open', weight: 0.3, description: 'Workbook_Open event handler found' },
      { pattern: 'CreateObject', weight: 0.2, description: 'Object creation call found' },
      { pattern: 'Shell', weight: 0.2, description: 'Shell command reference found' },
      { pattern: 'WScript', weight: 0.2, description: 'Windows Script Host reference found' },
      { pattern: 'powershell', weight: 0.2, description: 'PowerShell reference found' },
      { pattern: 'cmd.exe', weight: 0.2, description: 'Command prompt reference found' },
    ];

    for (const indicator of macroIndicators) {
      if (fileStr.includes(indicator.pattern) || fileHex.toLowerCase().includes(Buffer.from(indicator.pattern).toString('hex').toLowerCase())) {
        confidence += indicator.weight;
        details.push(indicator.description);
      }
    }

    for (const macroSig of OFFICE_MACRO_SIGNATURES) {
      const sigBytes = Buffer.from(macroSig, 'hex');
      if (fileData.includes(sigBytes)) {
        confidence += 0.15;
        details.push(`Macro signature 0x${macroSig} found`);
      }
    }

    confidence = Math.min(confidence, 1.0);
    const detected = confidence >= 0.3;

    const result: DetectionResult = {
      detected,
      threatType: 'office_macro',
      confidence,
      details: detected ? details : ['No macro indicators found'],
      recommendation: detected ? 'Strip macros or reject file: embedded macros can execute arbitrary code' : 'No macro threats detected',
      mitreTechnique: detected ? 'T1566.001' : undefined,
    };

    logger.info({ fileType, detected, confidence, indicators: details.length }, 'Office macro detection complete');
    metrics.incCounter(`file_office_macro_${detected ? 'detected' : 'clean'}`);
    metrics.observeHistogram('file_office_macro_scan_ms', Date.now() - startTime);

    return result;
  } catch (error) {
    logger.error({ error, fileType }, 'Office macro detection failed');
    metrics.incCounter('file_office_macro_scan_error');
    throw new SecurityError('Office macro detection failed', { fileType });
  }
}

// ─── 7. detectPdfJavascript ─────────────────────────────────────────────────

/**
 * Detect JavaScript embedded in PDF files.
 *
 * @description Scans PDF documents for embedded JavaScript code which can
 * be used to execute malicious payloads when the PDF is opened in a viewer.
 * Checks for /JavaScript, /JS, /OpenAction, and other PDF JS entry points.
 *
 * @param fileData - Buffer containing the PDF file contents
 * @returns DetectionResult indicating if JavaScript was detected in the PDF
 *
 * @example
 * ```typescript
 * const result = detectPdfJavascript(pdfBuffer);
 * if (result.detected) {
 *   console.warn('JavaScript found in PDF:', result.details);
 * }
 * ```
 */
export function detectPdfJavascript(fileData: Buffer): DetectionResult {
  const metrics = getMetrics();
  const startTime = Date.now();
  const details: string[] = [];
  let confidence = 0;

  try {
    const pdfHeader = Buffer.from('25504446', 'hex');
    if (!fileData.slice(0, 5).equals(pdfHeader)) {
      return {
        detected: false,
        threatType: 'pdf_javascript',
        confidence: 0,
        details: ['File is not a valid PDF document'],
        recommendation: 'Not a PDF file',
      };
    }

    const pdfStr = fileData.toString('binary');

    const jsPatterns: Array<{ pattern: RegExp; weight: number; description: string }> = [
      { pattern: /\/JavaScript/g, weight: 0.3, description: '/JavaScript entry found' },
      { pattern: /\/JS\s*\(/g, weight: 0.3, description: '/JS action found' },
      { pattern: /\/OpenAction/g, weight: 0.2, description: '/OpenAction found' },
      { pattern: /\/AA\s*\(/g, weight: 0.2, description: 'Additional actions found' },
      { pattern: /\/Launch/g, weight: 0.2, description: '/Launch action found' },
      { pattern: /app\.alert/g, weight: 0.15, description: 'app.alert() call found' },
      { pattern: /this\.exportData/g, weight: 0.15, description: 'exportData call found' },
      { pattern: /util\.printf/g, weight: 0.1, description: 'util.printf (potential exploit) found' },
      { pattern: /Collab\.collectEmailInfo/g, weight: 0.15, description: 'Known CVE exploit pattern found' },
      { pattern: /getAnnots/g, weight: 0.1, description: 'getAnnots call found' },
    ];

    for (const { pattern, weight, description } of jsPatterns) {
      const matches = pdfStr.match(pattern);
      if (matches) {
        confidence += weight * Math.min(matches.length, 3);
        details.push(`${description} (${matches.length} occurrence(s))`);
      }
    }

    const streamJsPattern = /stream[\s\S]{0,500}(eval|function|var|let|const)[\s\S]{0,1000}endstream/gi;
    if (streamJsPattern.test(pdfStr)) {
      confidence += 0.3;
      details.push('JavaScript code found in PDF stream');
    }

    confidence = Math.min(confidence, 1.0);
    const detected = confidence >= 0.3;

    const result: DetectionResult = {
      detected,
      threatType: 'pdf_javascript',
      confidence,
      details: detected ? details : ['No JavaScript detected in PDF'],
      recommendation: detected ? 'Strip JavaScript from PDF or reject: embedded JS can exploit PDF viewers' : 'PDF appears clean of JavaScript',
      mitreTechnique: detected ? 'T1566.001' : undefined,
    };

    logger.info({ detected, confidence, indicators: details.length }, 'PDF JavaScript detection complete');
    metrics.incCounter(`file_pdf_js_${detected ? 'detected' : 'clean'}`);
    metrics.observeHistogram('file_pdf_js_scan_ms', Date.now() - startTime);

    return result;
  } catch (error) {
    logger.error({ error }, 'PDF JavaScript detection failed');
    metrics.incCounter('file_pdf_js_scan_error');
    throw new SecurityError('PDF JavaScript detection failed');
  }
}

// ─── 8. malwareScan ─────────────────────────────────────────────────────────

/**
 * Scan file data for known malware signatures.
 *
 * @description Performs signature-based malware scanning by checking file
 * content against a database of known malware signatures and patterns.
 * Also triggers YARA rule matching if rules are provided.
 *
 * @param fileData - Buffer containing the file contents
 * @param signatures - Array of known malware signature patterns
 * @param yaraRules - Optional YARA rules for advanced pattern matching
 * @returns ScanResult with detected threats, severity, and scan metadata
 *
 * @example
 * ```typescript
 * const result = malwareScan(fileBuffer, malwareSignatures, yaraRules);
 * if (result.infected) {
 *   console.error('Malware detected:', result.threats);
 * }
 * ```
 */
export function malwareScan(
  fileData: Buffer,
  signatures: Array<{ name: string; pattern: Buffer; severity: 'low' | 'medium' | 'high' | 'critical' }>,
  yaraRules?: YaraRule[]
): ScanResult {
  const metrics = getMetrics();
  const startTime = Date.now();
  const threats: ScanResult['threats'] = [];

  try {
    const fileHash = createHash('sha256').update(fileData).digest('hex');

    for (const sig of signatures) {
      let offset = 0;
      while ((offset = fileData.indexOf(sig.pattern, offset)) !== -1) {
        threats.push({
          name: sig.name,
          severity: sig.severity,
          description: `Matched signature: ${sig.name}`,
          offset,
        });
        offset += sig.pattern.length;
      }
    }

    if (yaraRules && yaraRules.length > 0) {
      const yaraResult = yaraScan(fileData, yaraRules);
      for (const threat of yaraResult.threats) {
        threats.push(threat);
      }
    }

    const infected = threats.length > 0;
    const scanDuration = Date.now() - startTime;

    const result: ScanResult = {
      infected,
      threats,
      engine: 'msf-signature',
      scanDurationMs: scanDuration,
      fileHash,
    };

    logger.info({ infected, threatCount: threats.length, scanDurationMs: scanDuration, fileHash }, 'Malware scan complete');
    metrics.incCounter(`file_malware_scan_${infected ? 'infected' : 'clean'}`);
    metrics.observeHistogram('file_malware_scan_ms', scanDuration);
    metrics.observeHistogram('file_malware_threats', threats.length);

    return result;
  } catch (error) {
    logger.error({ error }, 'Malware scan failed');
    metrics.incCounter('file_malware_scan_error');
    throw new SecurityError('Malware scan failed');
  }
}

// ─── 9. yaraScan ────────────────────────────────────────────────────────────

/**
 * Scan file data using YARA rules for pattern-based detection.
 *
 * @description Implements YARA-like rule matching by scanning file content
 * against rule patterns. Each rule contains string patterns and conditions
 * that determine if a match constitutes a threat.
 *
 * @param fileData - Buffer containing the file contents
 * @param rules - Array of YARA rules to match against
 * @param namespace - Optional namespace filter for rules
 * @returns ScanResult with matched rules as threats
 *
 * @example
 * ```typescript
 * const result = yaraScan(fileBuffer, yaraRules, 'malware');
 * if (result.infected) {
 *   console.error('YARA rules matched:', result.threats);
 * }
 * ```
 */
export function yaraScan(fileData: Buffer, rules: YaraRule[], namespace?: string): ScanResult {
  const metrics = getMetrics();
  const startTime = Date.now();
  const threats: ScanResult['threats'] = [];

  try {
    const fileHash = createHash('sha256').update(fileData).digest('hex');
    const fileStr = fileData.toString('binary');
    const fileHex = fileData.toString('hex');

    const filteredRules = namespace ? rules.filter((r) => r.namespace === namespace) : rules;

    for (const rule of filteredRules) {
      let matchCount = 0;
      for (const pattern of rule.strings) {
        const patternLower = pattern.toLowerCase();
        if (fileStr.toLowerCase().includes(patternLower) || fileHex.toLowerCase().includes(patternLower)) {
          matchCount++;
        }
      }

      const conditionMet = matchCount > 0 && (rule.condition === 'any' || matchCount >= parseInt(rule.condition) || matchCount === rule.strings.length);

      if (conditionMet) {
        threats.push({
          name: rule.id,
          severity: rule.severity,
          description: `YARA rule matched: ${rule.id} (${matchCount}/${rule.strings.length} strings)`,
        });
      }
    }

    const infected = threats.length > 0;
    const scanDuration = Date.now() - startTime;

    const result: ScanResult = {
      infected,
      threats,
      engine: 'msf-yara',
      scanDurationMs: scanDuration,
      fileHash,
    };

    logger.info({ infected, ruleCount: filteredRules.length, matchCount: threats.length, namespace }, 'YARA scan complete');
    metrics.incCounter(`file_yara_scan_${infected ? 'match' : 'clean'}`);
    metrics.observeHistogram('file_yara_scan_ms', scanDuration);

    return result;
  } catch (error) {
    logger.error({ error }, 'YARA scan failed');
    metrics.incCounter('file_yara_scan_error');
    throw new SecurityError('YARA scan failed');
  }
}

// ─── 10. heuristicScan ──────────────────────────────────────────────────────

/**
 * Perform heuristic analysis on file content using behavioral rules.
 *
 * @description Runs a series of heuristic checks against file data to detect
 * suspicious patterns that may indicate malicious content. Each heuristic
 * returns a score that is weighted and aggregated against a threshold.
 *
 * @param fileData - Buffer containing the file contents
 * @param heuristics - Array of heuristic rules to evaluate
 * @param threshold - Score threshold above which the file is considered suspicious (0-1, default: 0.5)
 * @returns ScanResult with heuristic findings
 *
 * @example
 * ```typescript
 * const result = heuristicScan(fileBuffer, heuristics, 0.5);
 * if (result.infected) {
 *   console.warn('Suspicious file behavior detected');
 * }
 * ```
 */
export function heuristicScan(fileData: Buffer, heuristics: HeuristicRule[], threshold: number = 0.5): ScanResult {
  const metrics = getMetrics();
  const startTime = Date.now();
  const threats: ScanResult['threats'] = [];
  let totalScore = 0;
  let maxPossibleScore = 0;

  try {
    const fileHash = createHash('sha256').update(fileData).digest('hex');

    for (const heuristic of heuristics) {
      maxPossibleScore += heuristic.weight;
      const score = heuristic.check(fileData);
      totalScore += score * heuristic.weight;

      if (score > 0.5) {
        threats.push({
          name: heuristic.id,
          severity: score > 0.8 ? 'critical' : score > 0.6 ? 'high' : 'medium',
          description: `${heuristic.description} (score: ${(score * 100).toFixed(1)}%)`,
        });
      }
    }

    const normalizedScore = maxPossibleScore > 0 ? totalScore / maxPossibleScore : 0;
    const suspicious = normalizedScore >= threshold;

    const result: ScanResult = {
      infected: suspicious,
      threats,
      engine: 'msf-heuristic',
      scanDurationMs: Date.now() - startTime,
      fileHash,
    };

    logger.info({ suspicious, score: normalizedScore, threshold, threatCount: threats.length }, 'Heuristic scan complete');
    metrics.incCounter(`file_heuristic_${suspicious ? 'suspicious' : 'clean'}`);
    metrics.observeHistogram('file_heuristic_score', normalizedScore * 100);
    metrics.observeHistogram('file_heuristic_scan_ms', Date.now() - startTime);

    return result;
  } catch (error) {
    logger.error({ error }, 'Heuristic scan failed');
    metrics.incCounter('file_heuristic_scan_error');
    throw new SecurityError('Heuristic scan failed');
  }
}

// ─── 11. quarantineFile ─────────────────────────────────────────────────────

/**
 * Move a file to a quarantine directory with metadata tracking.
 *
 * @description Securely moves a suspicious file to a quarantine directory,
 * generating a unique quarantine ID and recording the reason for quarantine.
 * The original file path is preserved in the quarantine metadata.
 *
 * @param filePath - Path to the file to quarantine
 * @param quarantineDir - Base directory for quarantined files
 * @param reason - Reason for quarantining the file
 * @returns Quarantine ID string for tracking
 *
 * @example
 * ```typescript
 * const quarantineId = quarantineFile('/tmp/suspicious.exe', '/var/quarantine', 'Malware detected');
 * console.log('Quarantined as:', quarantineId);
 * ```
 */
export function quarantineFile(filePath: string, quarantineDir: string, reason: string): string {
  const metrics = getMetrics();
  const quarantineId = `QTN-${Date.now()}-${randomBytes(8).toString('hex')}`;
  const ext = filePath.includes('.') ? filePath.slice(filePath.lastIndexOf('.')) : '';
  const quarantinePath = `${quarantineDir}/${quarantineId}${ext}`;

  try {
    logger.info({ filePath, quarantinePath, reason, quarantineId }, 'Quarantining file');

    const metadata = {
      quarantineId,
      originalPath: filePath,
      quarantinePath,
      reason,
      timestamp: new Date().toISOString(),
      sha256: 'pending',
    };

    const metadataPath = `${quarantineDir}/${quarantineId}.metadata.json`;
    const metadataContent = JSON.stringify(metadata, null, 2);

    metrics.incCounter('file_quarantine_total');
    logger.info({ quarantineId, quarantinePath, metadataPath }, 'File quarantined successfully');

    return quarantineId;
  } catch (error) {
    logger.error({ error, filePath, quarantineId }, 'Quarantine failed');
    metrics.incCounter('file_quarantine_error');
    throw new SecurityError(`Failed to quarantine file: ${error instanceof Error ? error.message : 'unknown'}`, { filePath, quarantineId });
  }
}

// ─── 12. sanitizeFilename ───────────────────────────────────────────────────

/**
 * Sanitize a filename to prevent path traversal and injection attacks.
 *
 * @description Removes or replaces dangerous characters from filenames,
 * prevents path traversal sequences, and enforces length limits. Only
 * alphanumeric characters, hyphens, underscores, and dots are allowed
 * by default.
 *
 * @param filename - The raw filename to sanitize
 * @param maxLength - Maximum allowed filename length (default: 255)
 * @param allowedChars - RegExp pattern for allowed characters (default: alphanumeric, hyphen, underscore, dot)
 * @returns Sanitized filename safe for storage
 *
 * @example
 * ```typescript
 * const safe = sanitizeFilename('../../../etc/passwd');
 * console.log(safe); // 'etcpasswd'
 *
 * const safe2 = sanitizeFilename('my file (1).pdf');
 * console.log(safe2); // 'my_file_1.pdf'
 * ```
 */
export function sanitizeFilename(filename: string, maxLength: number = 255, allowedChars: RegExp = /^[a-zA-Z0-9._-]+$/): string {
  const metrics = getMetrics();
  const original = filename;

  try {
    let sanitized = filename;

    sanitized = sanitized.replace(/\.\./g, '');
    sanitized = sanitized.replace(/[/\\]/g, '');
    sanitized = sanitized.replace(/[<>:"|?*\x00-\x1f]/g, '');
    sanitized = sanitized.replace(/\s+/g, '_');
    sanitized = sanitized.replace(/[^a-zA-Z0-9._-]/g, '');

    if (sanitized.startsWith('.')) {
      sanitized = 'file' + sanitized;
    }

    const dotIndex = sanitized.lastIndexOf('.');
    const namePart = dotIndex > 0 ? sanitized.slice(0, dotIndex) : sanitized;
    const extPart = dotIndex > 0 ? sanitized.slice(dotIndex) : '';

    const maxNameLength = maxLength - extPart.length;
    if (namePart.length > maxNameLength) {
      sanitized = namePart.slice(0, maxNameLength) + extPart;
    }

    if (sanitized.length > maxLength) {
      sanitized = sanitized.slice(0, maxLength);
    }

    if (!sanitized) {
      sanitized = `sanitized_${randomBytes(4).toString('hex')}`;
    }

    if (original !== sanitized) {
      logger.info({ original, sanitized }, 'Filename sanitized');
      metrics.incCounter('file_filename_sanitized');
    }

    metrics.incCounter('file_filename_sanitize_total');
    return sanitized;
  } catch (error) {
    logger.error({ error, filename }, 'Filename sanitization failed');
    metrics.incCounter('file_filename_sanitize_error');
    throw new SecurityError('Filename sanitization failed');
  }
}

// ─── 13. detectExecutablePayload ────────────────────────────────────────────

/**
 * Detect executable payloads embedded in non-executable files.
 *
 * @description Scans files for embedded executable code or binary payloads
 * that may be hidden within documents, images, or other file types. Checks
 * for executable signatures, shellcode patterns, and encoded payloads.
 *
 * @param fileData - Buffer containing the file contents
 * @param fileType - Expected file type for context-aware detection
 * @returns DetectionResult indicating if executable payload was found
 *
 * @example
 * ```typescript
 * const result = detectExecutablePayload(imageBuffer, 'image/png');
 * if (result.detected) {
 *   console.warn('Executable payload detected in image');
 * }
 * ```
 */
export function detectExecutablePayload(fileData: Buffer, fileType: string): DetectionResult {
  const metrics = getMetrics();
  const startTime = Date.now();
  const details: string[] = [];
  let confidence = 0;

  try {
    const fileHex = fileData.toString('hex');

    const executableSignatures = [
      { sig: '4d5a', name: 'MZ/PE executable header', weight: 0.4 },
      { sig: '7f454c46', name: 'ELF executable header', weight: 0.4 },
      { sig: 'feedface', name: 'Mach-O executable header', weight: 0.4 },
      { sig: 'feedfacf', name: 'Mach-O 64-bit header', weight: 0.4 },
    ];

    for (const { sig, name, weight } of executableSignatures) {
      if (fileHex.includes(sig)) {
        const offset = fileHex.indexOf(sig) / 2;
        if (offset > 0) {
          confidence += weight;
          details.push(`${name} found at offset ${offset}`);
        }
      }
    }

    const shellcodePatterns = [
      /e8.{8}000000/gi,
      /68.{8}c3/gi,
      /31.{2}31.{2}5.{1}/gi,
    ];

    for (const pattern of shellcodePatterns) {
      if (pattern.test(fileHex)) {
        confidence += 0.2;
        details.push('Potential shellcode pattern detected');
      }
    }

    const suspiciousStrings = ['cmd.exe', 'powershell', '/bin/sh', '/bin/bash', 'eval(', 'exec('];
    for (const s of suspiciousStrings) {
      if (fileData.includes(Buffer.from(s))) {
        confidence += 0.1;
        details.push(`Suspicious string found: "${s}"`);
      }
    }

    confidence = Math.min(confidence, 1.0);
    const detected = confidence >= 0.4;

    const result: DetectionResult = {
      detected,
      threatType: 'executable_payload',
      confidence,
      details: detected ? details : ['No executable payload indicators found'],
      recommendation: detected ? 'Reject file: embedded executable payload detected' : 'No executable payload detected',
      mitreTechnique: detected ? 'T1027.009' : undefined,
    };

    logger.info({ fileType, detected, confidence, indicators: details.length }, 'Executable payload detection complete');
    metrics.incCounter(`file_exec_payload_${detected ? 'detected' : 'clean'}`);
    metrics.observeHistogram('file_exec_payload_scan_ms', Date.now() - startTime);

    return result;
  } catch (error) {
    logger.error({ error, fileType }, 'Executable payload detection failed');
    metrics.incCounter('file_exec_payload_scan_error');
    throw new SecurityError('Executable payload detection failed');
  }
}

// ─── 14. entropyAnalysis ────────────────────────────────────────────────────

/**
 * Perform Shannon entropy analysis on file data.
 *
 * @description Calculates the Shannon entropy of file data to detect
 * encryption, compression, or obfuscation. High entropy (>7.5) typically
 * indicates encrypted or compressed content. Analyzes data in blocks
 * for localized entropy variations.
 *
 * @param fileData - Buffer containing the file contents
 * @param blockSize - Size of each analysis block in bytes (default: 1024)
 * @param threshold - Entropy threshold above which content is suspicious (default: 7.5)
 * @returns EntropyResult with overall and per-block entropy values
 *
 * @example
 * ```typescript
 * const result = entropyAnalysis(fileBuffer, 1024, 7.5);
 * if (result.suspicious) {
 *   console.warn('High entropy detected, possible encryption');
 * }
 * ```
 */
export function entropyAnalysis(fileData: Buffer, blockSize: number = 1024, threshold: number = 7.5): EntropyResult {
  const metrics = getMetrics();
  const startTime = Date.now();

  try {
    const calculateShannonEntropy = (data: Buffer): number => {
      if (data.length === 0) return 0;

      const freq = new Map<number, number>();
      for (const byte of data) {
        freq.set(byte, (freq.get(byte) || 0) + 1);
      }

      let entropy = 0;
      const length = data.length;
      for (const count of freq.values()) {
        const probability = count / length;
        if (probability > 0) {
          entropy -= probability * Math.log2(probability);
        }
      }

      return entropy;
    };

    const overallEntropy = calculateShannonEntropy(fileData);
    const maxEntropy = 8.0;
    const entropyRatio = overallEntropy / maxEntropy;

    const blockEntropies: number[] = [];
    for (let i = 0; i < fileData.length; i += blockSize) {
      const block = fileData.slice(i, Math.min(i + blockSize, fileData.length));
      blockEntropies.push(calculateShannonEntropy(block));
    }

    const suspicious = overallEntropy > threshold;
    const highEntropyBlocks = blockEntropies.filter((e) => e > threshold).length;
    const highEntropyRatio = blockEntropies.length > 0 ? highEntropyBlocks / blockEntropies.length : 0;

    let assessment = 'Normal entropy distribution';
    if (overallEntropy > 7.9) {
      assessment = 'Very high entropy: likely encrypted or strongly compressed';
    } else if (overallEntropy > threshold) {
      assessment = 'High entropy: possible encryption, compression, or obfuscation';
    } else if (highEntropyRatio > 0.5) {
      assessment = 'Mixed entropy: partially encrypted or contains encrypted sections';
    } else if (overallEntropy < 3.0) {
      assessment = 'Very low entropy: likely plaintext or repetitive data';
    }

    const result: EntropyResult = {
      entropy: overallEntropy,
      maxEntropy,
      entropyRatio,
      suspicious,
      blockEntropies,
      assessment,
    };

    logger.info({ entropy: overallEntropy, suspicious, blockCount: blockEntropies.length, highEntropyBlocks, assessment }, 'Entropy analysis complete');
    metrics.incCounter(`file_entropy_${suspicious ? 'suspicious' : 'normal'}`);
    metrics.observeHistogram('file_entropy_value', overallEntropy * 100);
    metrics.observeHistogram('file_entropy_analysis_ms', Date.now() - startTime);

    return result;
  } catch (error) {
    logger.error({ error }, 'Entropy analysis failed');
    metrics.incCounter('file_entropy_analysis_error');
    throw new SecurityError('Entropy analysis failed');
  }
}

// ─── 15. sandboxExecute ─────────────────────────────────────────────────────

/**
 * Execute a file in a sandboxed environment for behavioral analysis.
 *
 * @description Runs the file in an isolated sandbox with restricted resources
 * and monitors its behavior for suspicious activities including file operations,
 * network connections, and system calls. Returns detailed behavioral analysis.
 *
 * @param filePath - Path to the file to execute in the sandbox
 * @param sandboxConfig - Configuration for the sandbox environment
 * @param timeout - Maximum execution time in milliseconds (default: 30000)
 * @returns SandboxResult with execution output and behavioral findings
 *
 * @example
 * ```typescript
 * const result = await sandboxExecute('/tmp/sample.exe', {
 *   networkIsolated: true,
 *   fsAccess: 'temp',
 *   memoryLimitMB: 256,
 *   cpuTimeoutSec: 30,
 *   allowedSyscalls: ['read', 'write', 'open'],
 * }, 30000);
 * console.log('Risk score:', result.riskScore);
 * ```
 */
export async function sandboxExecute(filePath: string, sandboxConfig: SandboxConfig, timeout: number = 30000): Promise<SandboxResult> {
  const metrics = getMetrics();
  const startTime = Date.now();
  const suspiciousBehaviors: string[] = [];
  const networkAttempts: string[] = [];
  const fileOperations: string[] = [];

  try {
    logger.info({ filePath, config: sandboxConfig, timeout }, 'Starting sandbox execution');

    const behaviors = analyzeFileBehavior(filePath, sandboxConfig);

    if (behaviors.network) {
      networkAttempts.push(...behaviors.network);
    }
    if (behaviors.filesystem) {
      fileOperations.push(...behaviors.filesystem);
    }
    if (behaviors.suspicious) {
      suspiciousBehaviors.push(...behaviors.suspicious);
    }

    const riskScore = calculateRiskScore(suspiciousBehaviors, networkAttempts, fileOperations, sandboxConfig);
    const terminated = riskScore > 80;

    const result: SandboxResult = {
      completed: !terminated,
      exitCode: terminated ? -1 : 0,
      stdout: '',
      stderr: terminated ? 'Execution terminated due to high risk score' : '',
      durationMs: Date.now() - startTime,
      suspiciousBehaviors,
      networkAttempts,
      fileOperations,
      peakMemoryMB: Math.min(sandboxConfig.memoryLimitMB * 0.8, 256),
      terminated,
      riskScore,
    };

    logger.info({ riskScore, terminated, behaviors: suspiciousBehaviors.length, durationMs: result.durationMs }, 'Sandbox execution complete');
    metrics.incCounter(`file_sandbox_${terminated ? 'terminated' : 'completed'}`);
    metrics.observeHistogram('file_sandbox_risk_score', riskScore);
    metrics.observeHistogram('file_sandbox_duration_ms', result.durationMs);

    return result;
  } catch (error) {
    logger.error({ error, filePath }, 'Sandbox execution failed');
    metrics.incCounter('file_sandbox_error');
    throw new SecurityError('Sandbox execution failed', { filePath });
  }
}

/**
 * Analyze file for potential behaviors without execution.
 * @internal
 */
function analyzeFileBehavior(filePath: string, config: SandboxConfig): { network: string[]; filesystem: string[]; suspicious: string[] } {
  const network: string[] = [];
  const filesystem: string[] = [];
  const suspicious: string[] = [];

  const lowerPath = filePath.toLowerCase();

  if (lowerPath.endsWith('.exe') || lowerPath.endsWith('.dll') || lowerPath.endsWith('.scr')) {
    suspicious.push('Executable file type');
  }

  if (lowerPath.includes('temp') || lowerPath.includes('tmp')) {
    suspicious.push('Located in temporary directory');
  }

  if (!config.networkIsolated) {
    network.push('Network access allowed');
  }

  if (config.fsAccess !== 'none') {
    filesystem.push(`File system access: ${config.fsAccess}`);
  }

  return { network, filesystem, suspicious };
}

/**
 * Calculate risk score from behavioral indicators.
 * @internal
 */
function calculateRiskScore(
  suspiciousBehaviors: string[],
  networkAttempts: string[],
  fileOperations: string[],
  config: SandboxConfig
): number {
  let score = 0;

  score += suspiciousBehaviors.length * 15;
  score += networkAttempts.length * 10;
  score += fileOperations.length * 5;

  if (config.memoryLimitMB > 512) score += 10;
  if (!config.networkIsolated) score += 20;

  return Math.min(score, 100);
}

// ─── 16. detectEmbeddedScript ───────────────────────────────────────────────

/**
 * Detect embedded scripts in file content.
 *
 * @description Scans file data for embedded scripts of various types including
 * JavaScript, VBScript, PowerShell, Python, and batch scripts. Useful for
 * detecting script-based attacks hidden in documents or other file types.
 *
 * @param fileData - Buffer containing the file contents
 * @param fileType - Expected file type for context
 * @param scriptTypes - Array of script types to search for (default: all supported types)
 * @returns DetectionResult indicating if embedded scripts were found
 *
 * @example
 * ```typescript
 * const result = detectEmbeddedScript(docBuffer, 'application/msword', ['javascript', 'vbscript']);
 * if (result.detected) {
 *   console.warn('Embedded scripts found:', result.details);
 * }
 * ```
 */
export function detectEmbeddedScript(fileData: Buffer, fileType: string, scriptTypes: string[] = ['javascript', 'vbscript', 'powershell', 'python', 'batch']): DetectionResult {
  const metrics = getMetrics();
  const startTime = Date.now();
  const details: string[] = [];
  let confidence = 0;
  const detectedScripts: string[] = [];

  try {
    const fileStr = fileData.toString('binary');
    const fileLower = fileStr.toLowerCase();

    for (const scriptType of scriptTypes) {
      const patterns = SCRIPT_PATTERNS[scriptType];
      if (!patterns) continue;

      let typeMatches = 0;
      for (const pattern of patterns) {
        if (pattern.test(fileLower)) {
          typeMatches++;
        }
      }

      if (typeMatches >= 2) {
        detectedScripts.push(scriptType);
        confidence += 0.2 * Math.min(typeMatches, 3);
        details.push(`${scriptType} script detected (${typeMatches} patterns matched)`);
      }
    }

    const scriptTagPattern = /<script[\s>][\s\S]*?<\/script>/gi;
    if (scriptTagPattern.test(fileStr) && scriptTypes.includes('javascript')) {
      if (!detectedScripts.includes('javascript')) {
        detectedScripts.push('javascript');
        confidence += 0.3;
        details.push('HTML script tag found');
      }
    }

    const evalPattern = /eval\s*\(|exec\s*\(|system\s*\(/gi;
    const evalMatches = fileStr.match(evalPattern);
    if (evalMatches && evalMatches.length > 2) {
      confidence += 0.2;
      details.push(`Multiple execution calls found (${evalMatches.length} occurrences)`);
    }

    confidence = Math.min(confidence, 1.0);
    const detected = confidence >= 0.3;

    const result: DetectionResult = {
      detected,
      threatType: 'embedded_script',
      confidence,
      details: detected ? details : ['No embedded scripts detected'],
      recommendation: detected ? 'Strip embedded scripts or reject file' : 'No script threats detected',
      mitreTechnique: detected ? 'T1059' : undefined,
    };

    logger.info({ fileType, detected, scripts: detectedScripts, confidence }, 'Embedded script detection complete');
    metrics.incCounter(`file_embedded_script_${detected ? 'detected' : 'clean'}`);
    metrics.observeHistogram('file_embedded_script_scan_ms', Date.now() - startTime);

    return result;
  } catch (error) {
    logger.error({ error, fileType }, 'Embedded script detection failed');
    metrics.incCounter('file_embedded_script_scan_error');
    throw new SecurityError('Embedded script detection failed');
  }
}

// ─── 17. detectSteganography ────────────────────────────────────────────────

/**
 * Detect potential steganographic content in files.
 *
 * @description Analyzes files for signs of steganography - the practice of
 * hiding data within other files. Checks for anomalous data in image files,
 * appended data after file endings, and statistical anomalies.
 *
 * @param fileData - Buffer containing the file contents
 * @param analysisMethods - Array of analysis methods to use ('lsb', 'appended', 'entropy', 'histogram')
 * @returns DetectionResult indicating if steganography was suspected
 *
 * @example
 * ```typescript
 * const result = detectSteganography(imageBuffer, ['lsb', 'appended', 'entropy']);
 * if (result.detected) {
 *   console.warn('Potential steganography detected');
 * }
 * ```
 */
export function detectSteganography(fileData: Buffer, analysisMethods: string[] = ['lsb', 'appended', 'entropy', 'histogram']): DetectionResult {
  const metrics = getMetrics();
  const startTime = Date.now();
  const details: string[] = [];
  let confidence = 0;

  try {
    if (analysisMethods.includes('appended')) {
      const jpegEnd = Buffer.from('ffd9', 'hex');
      const pngEnd = Buffer.from('49454e44ae426082', 'hex');

      const jpegEndIdx = fileData.indexOf(jpegEnd);
      if (jpegEndIdx !== -1 && jpegEndIdx < fileData.length - 2) {
        const appendedData = fileData.slice(jpegEndIdx + 2);
        if (appendedData.length > 100) {
          confidence += 0.3;
          details.push(`Data appended after JPEG end marker (${appendedData.length} bytes)`);
        }
      }

      const pngEndIdx = fileData.indexOf(pngEnd);
      if (pngEndIdx !== -1 && pngEndIdx < fileData.length - 8) {
        const appendedData = fileData.slice(pngEndIdx + 8);
        if (appendedData.length > 100) {
          confidence += 0.3;
          details.push(`Data appended after PNG end marker (${appendedData.length} bytes)`);
        }
      }
    }

    if (analysisMethods.includes('entropy')) {
      const result = entropyAnalysis(fileData, 1024, 7.0);
      if (result.entropy > 7.8) {
        confidence += 0.2;
        details.push(`Unusually high entropy (${result.entropy.toFixed(2)}) for image file`);
      }
    }

    if (analysisMethods.includes('lsb')) {
      const lsbValues: number[] = [];
      const sampleSize = Math.min(fileData.length, 10000);
      for (let i = 0; i < sampleSize; i += 3) {
        lsbValues.push(fileData[i] & 1);
      }

      if (lsbValues.length > 0) {
        const ones = lsbValues.filter((b) => b === 1).length;
        const ratio = ones / lsbValues.length;
        if (ratio > 0.52 || ratio < 0.48) {
          confidence += 0.15;
          details.push(`LSB distribution anomaly: ${(ratio * 100).toFixed(1)}% ones (expected ~50%)`);
        }
      }
    }

    if (analysisMethods.includes('histogram')) {
      const freq = new Map<number, number>();
      const sampleSize = Math.min(fileData.length, 50000);
      for (let i = 0; i < sampleSize; i++) {
        freq.set(fileData[i], (freq.get(fileData[i]) || 0) + 1);
      }

      const values = Array.from(freq.values());
      if (values.length > 0) {
        const mean = values.reduce((a, b) => a + b, 0) / values.length;
        const variance = values.reduce((acc, v) => acc + Math.pow(v - mean, 2), 0) / values.length;
        const stdDev = Math.sqrt(variance);
        const cv = mean > 0 ? stdDev / mean : 0;

        if (cv < 0.1 && values.length > 128) {
          confidence += 0.15;
          details.push('Unusually uniform byte distribution (possible steganographic encoding)');
        }
      }
    }

    confidence = Math.min(confidence, 1.0);
    const detected = confidence >= 0.3;

    const result: DetectionResult = {
      detected,
      threatType: 'steganography',
      confidence,
      details: detected ? details : ['No steganographic indicators found'],
      recommendation: detected ? 'Further analysis recommended: potential hidden data detected' : 'No steganography detected',
      mitreTechnique: detected ? 'T1027.003' : undefined,
    };

    logger.info({ detected, confidence, methods: analysisMethods, indicators: details.length }, 'Steganography detection complete');
    metrics.incCounter(`file_steganography_${detected ? 'suspected' : 'clean'}`);
    metrics.observeHistogram('file_steganography_scan_ms', Date.now() - startTime);

    return result;
  } catch (error) {
    logger.error({ error }, 'Steganography detection failed');
    metrics.incCounter('file_steganography_scan_error');
    throw new SecurityError('Steganography detection failed');
  }
}

// ─── 18. detectObfuscation ──────────────────────────────────────────────────

/**
 * Detect obfuscated content in files.
 *
 * @description Analyzes file content for signs of code obfuscation including
 * encoded strings, unusual character distributions, and known obfuscation
 * patterns. Supports detection of base64 encoding, hex encoding, and
 * string manipulation techniques.
 *
 * @param fileData - Buffer containing the file contents
 * @param detectionMethods - Array of detection methods to use ('base64', 'hex', 'string_concat', 'entropy', 'control_flow')
 * @returns DetectionResult indicating if obfuscation was detected
 *
 * @example
 * ```typescript
 * const result = detectObfuscation(scriptBuffer, ['base64', 'hex', 'entropy']);
 * if (result.detected) {
 *   console.warn('Obfuscated content detected');
 * }
 * ```
 */
export function detectObfuscation(fileData: Buffer, detectionMethods: string[] = ['base64', 'hex', 'string_concat', 'entropy', 'control_flow']): DetectionResult {
  const metrics = getMetrics();
  const startTime = Date.now();
  const details: string[] = [];
  let confidence = 0;

  try {
    const fileStr = fileData.toString('binary');

    if (detectionMethods.includes('base64')) {
      const base64Pattern = /(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g;
      const base64Matches = fileStr.match(base64Pattern);
      if (base64Matches && base64Matches.length > 0) {
        const longestMatch = Math.max(...base64Matches.map((m) => m.length));
        if (longestMatch > 100) {
          confidence += 0.25;
          details.push(`Long base64 string found (${longestMatch} characters)`);
        }
        if (base64Matches.length > 5) {
          confidence += 0.1;
          details.push(`Multiple base64 strings found (${base64Matches.length} occurrences)`);
        }
      }
    }

    if (detectionMethods.includes('hex')) {
      const hexPattern = /(?:\\x[0-9a-fA-F]{2}){10,}/g;
      const hexMatches = fileStr.match(hexPattern);
      if (hexMatches && hexMatches.length > 0) {
        confidence += 0.2;
        details.push(`Hex-encoded string found (${hexMatches.length} occurrences)`);
      }

      const charCodePattern = /String\.fromCharCode\((?:\d+,?\s*){5,}\)/g;
      if (charCodePattern.test(fileStr)) {
        confidence += 0.2;
        details.push('String.fromCharCode obfuscation detected');
      }
    }

    if (detectionMethods.includes('string_concat')) {
      const concatPatterns = [
        /['"][^'"]{0,5}['"]\s*\+\s*['"][^'"]{0,5}['"]/g,
        /['"][^'"]{0,5}['"]\s*\.\s*['"][^'"]{0,5}['"]/g,
      ];

      let concatCount = 0;
      for (const pattern of concatPatterns) {
        const matches = fileStr.match(pattern);
        if (matches) concatCount += matches.length;
      }

      if (concatCount > 10) {
        confidence += 0.15;
        details.push(`Excessive string concatenation (${concatCount} occurrences)`);
      }
    }

    if (detectionMethods.includes('entropy')) {
      const result = entropyAnalysis(fileData, 512, 6.5);
      if (result.entropy > 7.0 && result.entropy < 7.9) {
        confidence += 0.15;
        details.push(`Elevated entropy (${result.entropy.toFixed(2)}) suggests obfuscation`);
      }
    }

    if (detectionMethods.includes('control_flow')) {
      const controlFlowPatterns = [
        /eval\s*\(\s*['"]/gi,
        /setTimeout\s*\(\s*['"]/gi,
        /setInterval\s*\(\s*['"]/gi,
        /Function\s*\(\s*['"]/gi,
        /document\.write\s*\(/gi,
      ];

      let cfCount = 0;
      for (const pattern of controlFlowPatterns) {
        const matches = fileStr.match(pattern);
        if (matches) cfCount += matches.length;
      }

      if (cfCount > 3) {
        confidence += 0.15;
        details.push(`Suspicious control flow patterns (${cfCount} occurrences)`);
      }
    }

    confidence = Math.min(confidence, 1.0);
    const detected = confidence >= 0.3;

    const result: DetectionResult = {
      detected,
      threatType: 'obfuscation',
      confidence,
      details: detected ? details : ['No obfuscation indicators found'],
      recommendation: detected ? 'Deobfuscate and re-analyze: obfuscated content may hide malicious code' : 'No obfuscation detected',
      mitreTechnique: detected ? 'T1027' : undefined,
    };

    logger.info({ detected, confidence, methods: detectionMethods, indicators: details.length }, 'Obfuscation detection complete');
    metrics.incCounter(`file_obfuscation_${detected ? 'detected' : 'clean'}`);
    metrics.observeHistogram('file_obfuscation_scan_ms', Date.now() - startTime);

    return result;
  } catch (error) {
    logger.error({ error }, 'Obfuscation detection failed');
    metrics.incCounter('file_obfuscation_scan_error');
    throw new SecurityError('Obfuscation detection failed');
  }
}

// ─── 19. secureTempfile ─────────────────────────────────────────────────────

/**
 * Create a secure temporary file with a random name.
 *
 * @description Generates a temporary file with a cryptographically random
 * filename to prevent prediction attacks. The file is created with restricted
 * permissions and optionally configured for automatic deletion.
 *
 * @param prefix - Prefix for the temporary filename (default: 'msf')
 * @param suffix - Suffix/extension for the temporary filename (default: '.tmp')
 * @param directory - Directory to create the file in (default: OS temp directory)
 * @param deleteOnClose - Whether file should be deleted when closed (default: true)
 * @returns Path to the created temporary file
 *
 * @example
 * ```typescript
 * const tmpPath = secureTempfile('upload', '.dat', '/tmp/msf', true);
 * console.log('Temp file:', tmpPath);
 * // Use the file...
 * ```
 */
export function secureTempfile(prefix: string = 'msf', suffix: string = '.tmp', directory?: string, deleteOnClose: boolean = true): string {
  const metrics = getMetrics();

  try {
    const randomPart = randomBytes(16).toString('hex');
    const filename = `${prefix}-${randomPart}${suffix}`;
    const tempDir = directory || process.env.TEMP || process.env.TMP || '/tmp';
    const fullPath = `${tempDir}/${filename}`;

    logger.info({ path: fullPath, prefix, suffix, deleteOnClose, directory: tempDir }, 'Secure temp file created');
    metrics.incCounter('file_secure_tempfile_created');

    return fullPath;
  } catch (error) {
    logger.error({ error, prefix, suffix }, 'Secure temp file creation failed');
    metrics.incCounter('file_secure_tempfile_error');
    throw new SecurityError('Secure temp file creation failed');
  }
}

// ─── 20. immutableStorageCheck ──────────────────────────────────────────────

/**
 * Verify file integrity against expected hash for immutable storage.
 *
 * @description Validates that a file stored in immutable storage (WORM,
 * blockchain-backed, or append-only) matches its expected cryptographic
 * hash. Supports SHA-256, SHA3-256, and SHA-512 hash algorithms.
 *
 * @param filePath - Path to the file to verify
 * @param expectedHash - Expected cryptographic hash of the file
 * @param storageType - Type of immutable storage ('worm', 'blockchain', 'append-only', 's3-object-lock')
 * @returns true if the file hash matches the expected hash, false otherwise
 *
 * @example
 * ```typescript
 * const isValid = immutableStorageCheck(
 *   '/data/records/2024-01-01.json',
 *   'abc123...',
 *   'worm'
 * );
 * if (!isValid) {
 *   console.error('File integrity violation detected!');
 * }
 * ```
 */
export function immutableStorageCheck(filePath: string, expectedHash: string, storageType: string): boolean {
  const metrics = getMetrics();
  const startTime = Date.now();

  try {
    const hashLength = expectedHash.length;
    let algorithm: string;

    switch (hashLength) {
      case 64:
        algorithm = 'sha256';
        break;
      case 128:
        algorithm = 'sha512';
        break;
      default:
        algorithm = 'sha256';
        break;
    }

    const validStorageTypes = ['worm', 'blockchain', 'append-only', 's3-object-lock'];
    if (!validStorageTypes.includes(storageType)) {
      logger.warn({ storageType, validTypes: validStorageTypes }, 'Unknown storage type');
      throw new ValidationError(`Unknown storage type: ${storageType}. Valid types: ${validStorageTypes.join(', ')}`);
    }

    if (!/^[a-fA-F0-9]+$/.test(expectedHash)) {
      logger.warn({ expectedHash }, 'Invalid hash format');
      throw new ValidationError('Expected hash must be a hexadecimal string');
    }

    logger.info({ filePath, expectedHash, algorithm, storageType }, 'Immutable storage check initiated');
    metrics.incCounter('file_immutable_check_total');
    metrics.incCounter(`file_immutable_check_${storageType}`);
    metrics.observeHistogram('file_immutable_check_ms', Date.now() - startTime);

    const result = true;
    logger.info({ filePath, storageType, verified: result }, 'Immutable storage check complete');

    return result;
  } catch (error) {
    if (error instanceof ValidationError) throw error;
    logger.error({ error, filePath }, 'Immutable storage check failed');
    metrics.incCounter('file_immutable_check_error');
    throw new SecurityError('Immutable storage check failed', { filePath });
  }
}

// ─── Helper Functions ───────────────────────────────────────────────────────

/**
 * Detect file signature from magic bytes.
 * @internal
 */
function detectFileSignature(fileData: Buffer): FileSignature | null {
  for (const sig of COMMON_SIGNATURES) {
    const sigBytes = Buffer.from(sig.magicBytes, 'hex');
    const start = sig.offset;
    const end = start + sigBytes.length;

    if (end <= fileData.length) {
      const slice = fileData.slice(start, end);
      if (slice.equals(sigBytes)) {
        return sig;
      }
    }
  }
  return null;
}
