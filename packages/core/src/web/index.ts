import { createHash, createHmac, timingSafeEqual } from 'crypto';
import { sha3_256 } from '@noble/hashes/sha3';
import { getLogger, getMetrics, createSpan } from '../core/index.js';
import { ValidationError, SecurityError } from '../core/exceptions.js';
import pino from 'pino';

const logger = pino().child({ module: 'msf.web' });
const metrics = getMetrics();

// --- Types -------------------------------------------------------------------

export interface DetectionResult {
  detected: boolean;
  severity: 'low' | 'medium' | 'high' | 'critical';
  score: number;
  matches: string[];
  details: string;
  timestamp: string;
}

export interface CorsResult {
  allowed: boolean;
  headers: Record<string, string>;
  reason?: string;
}

export interface SecureHeadersConfig {
  hsts?: boolean;
  hstsMaxAge?: number;
  xFrameOptions?: string;
  xContentTypeOptions?: boolean;
  xXssProtection?: boolean;
  referrerPolicy?: string;
  permissionsPolicy?: string;
  removeServerHeader?: boolean;
  removeXPoweredBy?: boolean;
}

export interface CspConfig {
  defaultSrc?: string[];
  scriptSrc?: string[];
  styleSrc?: string[];
  imgSrc?: string[];
  fontSrc?: string[];
  connectSrc?: string[];
  mediaSrc?: string[];
  objectSrc?: string[];
  frameSrc?: string[];
  frameAncestors?: string[];
  baseUri?: string[];
  formAction?: string[];
  reportUri?: string;
  upgradeInsecureRequests?: boolean;
  blockAllMixedContent?: boolean;
}

export interface SecureCookieOptions {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
  maxAge?: number;
  path?: string;
  domain?: string;
  expires?: Date;
}

export interface SecureHeadersRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  protocol?: string;
}

export interface CsrfRequest {
  method: string;
  headers: Record<string, string>;
}

// --- Detection Patterns ------------------------------------------------------

const XSS_PATTERNS = [
  /<script[\s>]/i, /javascript\s*:/i, /on\w+\s*=/i, /<iframe[\s>]/i,
  /<object[\s>]/i, /<embed[\s>]/i, /<svg[\s>].*on\w+\s*=/is,
  /<img[\s>].*on\w+\s*=/is, /<body[\s>].*on\w+\s*=/is,
  /<video[\s>].*on\w+\s*=/is, /<audio[\s>].*on\w+\s*=/is,
  /document\s*\.\s*cookie/i, /document\s*\.\s*write/i,
  /document\s*\.\s*location/i, /window\s*\.\s*location/i,
  /eval\s*\(/i, /setTimeout\s*\(\s*["']/i, /setInterval\s*\(\s*["']/i,
  /Function\s*\(/i, /alert\s*\(/i, /prompt\s*\(/i, /confirm\s*\(/i,
  /console\s*\.\s*log/i, /String\s*\.\s*fromCharCode/i,
  /charCodeAt/i, /atob\s*\(/i, /btoa\s*\(/i, /expression\s*\(/i,
  /url\s*\(\s*["']?\s*javascript/i, /<link[\s>].*href\s*=\s*["']?data:/i,
  /<style[\s>].*expression/i, /<math[\s>]/i, /<base[\s>]/i,
  /<form[\s>]/i, /<meta[\s>].*http-equiv/i, /vbscript\s*:/i,
  /data\s*:\s*text\/html/i, /srcdoc\s*=/i, /<keygen[\s>]/i,
  /<applet[\s>]/i, /<bgsound[\s>]/i, /<blink[\s>]/i,
  /<isindex[\s>]/i, /<layer[\s>]/i, /<xml[\s>]/i, /<xss[\s>]/i,
  /&#x/i, /&#\d+;/i, /\\x[0-9a-fA-F]{2}/, /\\u[0-9a-fA-F]{4}/,
  /top\s*\.\s*location/i, /parent\s*\.\s*location/i, /self\s*\.\s*location/i,
];

const SQLI_PATTERNS = [
  /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC|EXECUTE)\b.*\b(FROM|INTO|TABLE|WHERE|SET|DATABASE|PROCEDURE)\b)/is,
  /(\b(OR|AND)\b\s+\d+\s*=\s*\d+)/i, /(\b(OR|AND)\b\s+['"][^'"]*['"]\s*=\s*['"][^'"]*['"])/i,
  /('\s*(OR|AND)\s+')/i, /('\s*;\s*(DROP|DELETE|UPDATE|INSERT|ALTER|EXEC))/i,
  /(--|#|\/\*)/i, /(\bBENCHMARK\s*\()/i, /(\bSLEEP\s*\()/i,
  /(\bWAITFOR\s+DELAY\b)/i, /(\bLOAD_FILE\s*\()/i,
  /(\bINTO\s+(OUT|DUMP)FILE\b)/i, /(\bINFORMATION_SCHEMA\b)/i,
  /(\bSYSOBJECTS\b)/i, /(\bSYSCOLUMNS\b)/i,
  /(\bTABLE_NAME\b.*\bFROM\b)/i, /(\bCOLUMN_NAME\b.*\bFROM\b)/i,
  /(\bCONCAT\s*\()/i, /(\bGROUP_CONCAT\s*\()/i, /(\bHAVING\b\s+\d+)/i,
  /(\bORDER\s+BY\s+\d+)/i, /(\bUNION\s+(ALL\s+)?SELECT\b)/i,
  /(\bSELECT\b.*\bCHAR\s*\()/i, /(\bSELECT\b.*\bHEX\s*\()/i,
  /(\bSELECT\b.*\bCAST\s*\()/i, /(\bSELECT\b.*\bCONVERT\s*\()/i,
  /(\bxp_cmdshell\b)/i, /(\bopenrowset\b)/i, /(\bopendatasource\b)/i,
  /(\bdbms_pipe\b)/i, /(\bctxsys\b)/i, /(\bUTL_HTTP\b)/i,
  /('\s*OR\s*'\s*=\s*')/i, /('\s*OR\s*1\s*=\s*1\s*--)/i,
  /(admin'\s*--)/i, /(\bDECLARE\s+@\w+)/i, /(\bEXEC\s+@\w+)/i,
];

const SSRF_PATTERNS = [
  /\b(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)\b/i,
  /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/, /\b(172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/,
  /\b(192\.168\.\d{1,3}\.\d{1,3})\b/, /\b(169\.254\.\d{1,3}\.\d{1,3})\b/,
  /\b(0\.0\.0\.0)\b/, /\b(fe80::)\b/i, /\b(fc00::)\b/i,
  /\b(metadata\.google\.internal)\b/i, /\b(169\.254\.169\.254)\b/,
  /\b(instance-data)\b/i, /\b(metadata\.azure\.com)\b/i,
  /\b(api\.ec2\.amazonaws\.com)\b/i, /\b(100\.100\.100\.200)\b/,
  /\b(file:\/\/)/i, /\b(gopher:\/\/)/i, /\b(dict:\/\/)/i,
  /\b(ftp:\/\/)/i, /\b(tftp:\/\/)/i, /\b(smb:\/\/)/i,
  /\b(ldap:\/\/)/i, /\b(netdoc:\/\/)/i, /\b(mailto:\/\/)/i,
  /\b(data:\/\/)/i, /\b(jar:\/\/)/i, /\b(phar:\/\/)/i,
  /\b(expect:\/\/)/i, /\b(zip:\/\/)/i,
];

const RCE_PATTERNS = [
  /\b(exec|system|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\(/i,
  /\b(eval|assert|preg_replace.*\/e)\s*\(/i,
  /\b(create_function|call_user_func|call_user_func_array)\s*\(/i,
  /\b(__import__|os\.system|os\.popen|subprocess)\b/i,
  /\b(Runtime\.getRuntime|ProcessBuilder)\b/i,
  /\b(Process\.start|Process\.Start)\b/i,
  /\b(wscript\.shell|shell\.application)\b/i,
  /\b(cmd\.exe|\/bin\/sh|\/bin\/bash|powershell|cmd\b)/i,
  /\b(\|\s*(ls|cat|dir|type|whoami|id|uname|pwd|cd|wget|curl|nc|bash|sh|python|perl|ruby|php|node)\b)/i,
  /\b(`[^`]*`)/, /\b(\$\([^)]*\))/,
  /\b(;|&&|\|\|)\s*(ls|cat|dir|type|whoami|id|uname|pwd)\b/i,
  /\b(\bpython[23]?\s+-c\b)/i, /\b(\bperl\s+-e\b)/i,
  /\b(\bruby\s+-e\b)/i, /\b(\bphp\s+-r\b)/i, /\b(\bnode\s+-e\b)/i,
  /\b(\bnc\s+-[elp]\b)/i, /\b(\bncat\s+-[elp]\b)/i,
  /\b(\bsocat\b)/i, /\b(\bmeterpreter\b)/i,
  /\b(\breverse[_\s]?shell\b)/i, /\b(\bbind[_\s]?shell\b)/i,
  /\b(\bpayload\b)/i, /\b(\bexploit\b)/i,
];

const LFI_PATTERNS = [
  /\.\.\//g, /\.\.\/\.\.\//g, /\.\.\\/, /\.\.\\\.\.\\/g,
  /\%2e\%2e\%2f/gi, /\%2e\%2e\//gi, /\.\.%2f/gi, /\%252e\%252e\%252f/gi,
  /\/etc\/(passwd|shadow|hosts|group|sudoers|crontab|fstab)/i,
  /\/proc\/(self|version|cpuinfo|meminfo|mounts)/i,
  /\/var\/log\/(auth|syslog|messages|secure)/i,
  /\\windows\\(system32|win\.ini|boot\.ini)/i, /\\boot\.ini/i, /\\win\.ini/i,
  /c:\\/i, /file:\/\/\/etc\//i, /file:\/\/\/proc\//i, /file:\/\/\/var\//i,
  /php:\/\/(filter|input|data|expect)/i, /data:\/\/text\/plain/i,
  /zip:\/\/.*!/i, /phar:\/\/.*!/i,
];

const RFI_PATTERNS = [
  /https?:\/\/[^\/\s]+\/[^\/\s]+\.(php|asp|aspx|jsp|jspx|cgi|pl|py|rb)/i,
  /https?:\/\/[^\/\s]+\/[^\/\s]+\?cmd=/i, /https?:\/\/[^\/\s]+\/[^\/\s]+\?exec=/i,
  /https?:\/\/[^\/\s]+\/[^\/\s]+\?c=/i, /https?:\/\/[^\/\s]+\/[^\/\s]+\?code=/i,
  /https?:\/\/[^\/\s]+\/[^\/\s]+\?file=/i, /https?:\/\/[^\/\s]+\/[^\/\s]+\?page=/i,
  /https?:\/\/[^\/\s]+\/[^\/\s]+\?path=/i, /https?:\/\/[^\/\s]+\/[^\/\s]+\?url=/i,
  /https?:\/\/[^\/\s]+\/[^\/\s]+\?uri=/i, /https?:\/\/[^\/\s]+\/[^\/\s]+\?src=/i,
  /https?:\/\/[^\/\s]+\/[^\/\s]+\?doc=/i, /https?:\/\/[^\/\s]+\/[^\/\s]+\?template=/i,
  /https?:\/\/[^\/\s]+\/[^\/\s]+\?view=/i, /https?:\/\/[^\/\s]+\/[^\/\s]+\?include=/i,
  /https?:\/\/[^\/\s]+\/[^\/\s]+\?require=/i, /https?:\/\/[^\/\s]+\/[^\/\s]+\?load=/i,
  /https?:\/\/[^\/\s]+\/[^\/\s]+\?read=/i, /https?:\/\/[^\/\s]+\/[^\/\s]+\?open=/i,
  /https?:\/\/[^\/\s]+\/[^\/\s]+\?fetch=/i,
];

const NOSQLI_PATTERNS = [
  /\{\s*\$gt\s*:/i, /\{\s*\$gte\s*:/i, /\{\s*\$lt\s*:/i, /\{\s*\$lte\s*:/i,
  /\{\s*\$ne\s*:/i, /\{\s*\$in\s*:/i, /\{\s*\$nin\s*:/i, /\{\s*\$regex\s*:/i,
  /\{\s*\$exists\s*:/i, /\{\s*\$where\s*:/i, /\{\s*\$or\s*:/i,
  /\{\s*\$and\s*:/i, /\{\s*\$not\s*:/i, /\{\s*\$nor\s*:/i,
  /\{\s*\$all\s*:/i, /\{\s*\$size\s*:/i, /\{\s*\$slice\s*:/i,
  /\{\s*\$elemMatch\s*:/i, /\{\s*\$comment\s*:/i, /\{\s*\$type\s*:/i,
  /\{\s*\$eq\s*:/i, /\$where\s*:/i, /function\s*\(\s*\)\s*\{/i,
  /db\.\w+\.find\s*\(/i, /db\.\w+\.findOne\s*\(/i, /db\.\w+\.update\s*\(/i,
  /db\.\w+\.remove\s*\(/i, /db\.\w+\.aggregate\s*\(/i,
  /db\.\w+\.mapReduce\s*\(/i, /mapReduce\s*\(/i,
];

const COMMAND_INJECTION_PATTERNS = [
  /;\s*(ls|cat|dir|type|whoami|id|uname|pwd|cd|rm|mv|cp|chmod|chown)\b/i,
  /\|\s*(ls|cat|dir|type|whoami|id|uname|pwd)\b/i,
  /&&\s*(ls|cat|dir|type|whoami|id|uname|pwd)\b/i,
  /\|\|\s*(ls|cat|dir|type|whoami|id|uname|pwd)\b/i,
  /`[^`]*`/, /\$\([^)]*\)/, /\$\{[^}]*\}/,
  /\b(eval|exec|system|passthru|shell_exec|popen)\s*\(/i,
  /\b(cmd\.exe|\/bin\/sh|\/bin\/bash)\b/i,
  /\b(wget|curl|nc|ncat|socat)\s+/i,
  /\bpython[23]?\s+-c\b/i, /\bperl\s+-e\b/i, /\bruby\s+-e\b/i,
  /\bphp\s+-r\b/i, /\bnode\s+-e\b/i,
  /\b(base64|base64decode|base64_decode)\s+/i,
  /\bopenssl\s+/i, /\bgpg\s+/i, /\bssh\s+/i, /\bscp\s+/i,
  /\bftp\s+/i, /\btelnet\s+/i, /\b(nslookup|dig|host)\s+/i,
  /\bping\s+/i, /\btraceroute\s+/i, /\b(nmap|masscan|zmap)\s+/i,
];

const TEMPLATE_INJECTION_PATTERNS: Record<string, RegExp[]> = {
  jinja2: [/\{\{.*\}\}/, /\{%.*%\}/, /\{#.*#\}/, /\bconfig\b.*\bself\b/i,
    /\brequest\b.*\benviron\b/i, /\burl_for\b/i, /\bget_flashed_messages\b/i,
    /\blipsum\b/i, /\bnamespace\b/i, /\bcycler\b/i, /\bjoiner\b/i,
    /\bdict\b.*\b__class__\b/i, /\b__globals__\b/i, /\b__builtins__\b/i,
    /\b__import__\b/i, /\bos\.popen\b/i, /\bos\.system\b/i, /\bsubprocess\b/i],
  ejs: [/<%[=-]?[\s\S]*?%>/, /\binclude\s*\(/i, /\bprocess\b.*\benv\b/i,
    /\brequire\s*\(/i, /\bglobal\b/i, /\bprocess\.mainModule\b/i, /\bprocess\.binding\b/i],
  handlebars: [/\{\{#.*\}\}/, /\{\{\/.*\}\}/, /\{\{>.*\}\}/, /\{\{\{.*\}\}\}/,
    /\bhelper\b/i, /\bpartial\b/i, /\blookup\b/i],
  mustache: [/\{\{#.*\}\}/, /\{\{\/.*\}\}/, /\{\{>.*\}\}/, /\{\{!.*\}\}/,
    /\{\{&.*\}\}/, /\{\{\{.*\}\}\}/],
  pug: [/-[\s]+.*\b(require|process|global)\b/i, /!\[.*\]/,
    /\binclude\b.*\b\.js\b/i, /\bextends\b/i, /\bblock\b/i, /\bmixin\b/i],
  twig: [/\{\{.*\}\}/, /\{%.*%\}/, /\{#.*#\}/, /\bapp\b.*\brequest\b/i,
    /\bapp\b.*\benvironment\b/i, /\b_source\b/i, /\b_self\b/i,
    /\bcontext\b/i, /\battribute\b/i, /\btemplate_from_string\b/i,
    /\binclude\b/i, /\bembed\b/i, /\bimport\b/i, /\buse\b/i],
  generic: [/\{\{.*\}\}/, /<%[\s\S]*?%>/, /\$\{[^}]*\}/, /#\{[^}]*\}/,
    /\b__proto__\b/i, /\bconstructor\b/i, /\bprototype\b/i],
};

const DESERIALIZATION_PATTERNS = [
  /rO0AB/i, /ACED0005/i, /java\.util\./i, /java\.lang\./i, /java\.io\./i,
  /javax\./i, /sun\.reflect\./i, /com\.sun\./i, /org\.apache\./i,
  /org\.springframework\./i, /org\.hibernate\./i, /__PHP_Incomplete_Class/i,
  /O:\d+:/i, /a:\d+:{/i, /b:\d+;/i, /s:\d+:/i, /i:\d+;/i, /d:\d+\.\d+;/i,
  /N;/i, /yaml!\b/i, /!!python\//i, /!!ruby\//i, /!!js\//i,
  /!!binary/i, /!!map/i, /!!seq/i, /!!str/i, /!!int/i, /!!float/i,
  /!!bool/i, /!!null/i, /!!timestamp/i, /!!merge/i, /!!set/i,
  /pickle/i, /cos\(/i, /S'/i, /b/i,
  /\bconstructor\b.*\bprototype\b/i, /__proto__/i,
  /JSON\.parse\s*\(/i, /eval\s*\(/i, /Function\s*\(/i, /new\s+Function/i,
];

// --- Helper Functions --------------------------------------------------------

function createDetectionResult(
  detected: boolean,
  severity: 'low' | 'medium' | 'high' | 'critical',
  score: number,
  matches: string[],
  details: string,
): DetectionResult {
  return { detected, severity, score, matches, details, timestamp: new Date().toISOString() };
}

function calculateSeverity(score: number): 'low' | 'medium' | 'high' | 'critical' {
  if (score >= 0.8) return 'critical';
  if (score >= 0.6) return 'high';
  if (score >= 0.3) return 'medium';
  return 'low';
}

function runPatternDetection(input: string, patterns: RegExp[]): { matches: string[]; score: number } {
  const matches: string[] = [];
  let maxScore = 0;
  for (const pattern of patterns) {
    const match = input.match(pattern);
    if (match) {
      matches.push(match[0]);
      const patternScore = match[0].length / Math.max(input.length, 1);
      maxScore = Math.max(maxScore, patternScore);
    }
  }
  const normalizedScore = matches.length > 0 ? Math.min(1, maxScore + matches.length * 0.1) : 0;
  return { matches, score: normalizedScore };
}

// --- 1. detectXss ------------------------------------------------------------

/**
 * @description Detects Cross-Site Scripting (XSS) attack patterns in input strings.
 * @param input - The string to analyze for XSS patterns.
 * @param patterns - Optional custom regex patterns to supplement built-in detection.
 * @param severityThreshold - Minimum score (0-1) to consider a detection valid. Default: 0.3.
 * @returns DetectionResult with detection status, severity, score, and matched patterns.
 * @example
 * const result = detectXss('<script>alert("xss")</script>');
 * console.log(result.detected); // true
 * console.log(result.severity); // 'critical'
 */
export function detectXss(
  input: string,
  patterns?: RegExp[],
  severityThreshold: number = 0.3,
): DetectionResult {
  const span = createSpan('msf.web.detectXss');
  const startTime = Date.now();
  try {
    logger.debug({ inputLength: input.length }, 'Running XSS detection');
    const allPatterns = patterns ? [...XSS_PATTERNS, ...patterns] : XSS_PATTERNS;
    const { matches, score } = runPatternDetection(input, allPatterns);
    const detected = score >= severityThreshold && matches.length > 0;
    const severity = calculateSeverity(score);
    span.setAttribute('detected', detected);
    span.setAttribute('score', score);
    span.setAttribute('matchCount', matches.length);
    metrics.incCounter('web.xss.detection');
    metrics.observeHistogram('web.xss.latency', Date.now() - startTime);
    return createDetectionResult(detected, severity, score, matches, 'XSS pattern detection completed');
  } catch (error) {
    logger.error({ error }, 'XSS detection failed');
    metrics.incCounter('web.xss.error');
    throw new SecurityError('XSS detection failed', 'XSS_DETECTION_ERROR');
  } finally {
    span.end();
  }
}

// --- 2. sanitizeHtml ---------------------------------------------------------

/**
 * @description Sanitizes HTML by removing disallowed tags and attributes.
 * @param html - The HTML string to sanitize.
 * @param allowedTags - Array of tag names to preserve.
 * @param allowedAttrs - Array of attribute names to preserve.
 * @returns Sanitized HTML string with only allowed tags and attributes.
 * @example
 * const clean = sanitizeHtml('<script>alert("xss")</script><p>Safe</p>');
 * console.log(clean); // '<p>Safe</p>'
 */
export function sanitizeHtml(
  html: string,
  allowedTags: string[] = ['p', 'br', 'strong', 'em', 'u', 'ul', 'ol', 'li', 'a', 'img', 'code', 'pre', 'blockquote', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'span', 'div', 'table', 'thead', 'tbody', 'tr', 'th', 'td'],
  allowedAttrs: string[] = ['href', 'src', 'alt', 'title', 'class', 'id'],
): string {
  const span = createSpan('msf.web.sanitizeHtml');
  try {
    logger.debug({ inputLength: html.length }, 'Sanitizing HTML');
    const allowedTagsSet = new Set(allowedTags.map(t => t.toLowerCase()));
    const allowedAttrsSet = new Set(allowedAttrs.map(a => a.toLowerCase()));
    let result = html;
    result = result.replace(/<\s*\/?\s*script[^>]*>/gi, '');
    result = result.replace(/<\s*\/?\s*iframe[^>]*>/gi, '');
    result = result.replace(/<\s*\/?\s*object[^>]*>/gi, '');
    result = result.replace(/<\s*\/?\s*embed[^>]*>/gi, '');
    result = result.replace(/<\s*\/?\s*applet[^>]*>/gi, '');
    result = result.replace(/<\s*\/?\s*form[^>]*>/gi, '');
    result = result.replace(/<\s*\/?\s*input[^>]*>/gi, '');
    result = result.replace(/<\s*\/?\s*select[^>]*>/gi, '');
    result = result.replace(/<\s*\/?\s*textarea[^>]*>/gi, '');
    result = result.replace(/<\s*\/?\s*button[^>]*>/gi, '');
    result = result.replace(/<\s*\/?\s*meta[^>]*>/gi, '');
    result = result.replace(/<\s*\/?\s*link[^>]*>/gi, '');
    result = result.replace(/<\s*\/?\s*base[^>]*>/gi, '');
    result = result.replace(/<\s*\/?\s*style[^>]*>[\s\S]*?<\s*\/\s*style\s*>/gi, '');
    result = result.replace(/<\s*\/?\s*style[^>]*>/gi, '');
    result = result.replace(/on\w+\s*=\s*["'][^"']*["']/gi, '');
    result = result.replace(/on\w+\s*=\s*\S+/gi, '');
    result = result.replace(/javascript\s*:/gi, '');
    result = result.replace(/vbscript\s*:/gi, '');
    result = result.replace(/data\s*:\s*text\/html/gi, '');
    result = result.replace(/<([^\/\s>]+)([^>]*)>/g, (match, tag, attrs) => {
      const tagName = tag.toLowerCase();
      if (!allowedTagsSet.has(tagName)) return '';
      if (attrs) {
        const safeAttrs = attrs.match(/([a-zA-Z][\w-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|(\S+))/g) || [];
        const filtered = safeAttrs.filter(attr => {
          const attrName = attr.split('=')[0].toLowerCase().trim();
          return allowedAttrsSet.has(attrName);
        });
        return `<${tagName}${filtered.length > 0 ? ' ' + filtered.join(' ') : ''}>`;
      }
      return `<${tagName}>`;
    });
    result = result.replace(/<\/([^>]+)>/g, (match, tag) => {
      return allowedTagsSet.has(tag.toLowerCase()) ? match : '';
    });
    metrics.incCounter('web.sanitizeHtml');
    return result;
  } catch (error) {
    logger.error({ error }, 'HTML sanitization failed');
    metrics.incCounter('web.sanitizeHtml.error');
    throw new SecurityError('HTML sanitization failed', 'HTML_SANITIZE_ERROR');
  } finally {
    span.end();
  }
}

// --- 3. sanitizeSvg ----------------------------------------------------------

/**
 * @description Sanitizes SVG content by removing dangerous elements and attributes.
 * @param svg - The SVG string to sanitize.
 * @param allowedElements - Array of SVG element names to preserve.
 * @returns Sanitized SVG string with only allowed elements and safe attributes.
 * @example
 * const clean = sanitizeSvg('<svg><script>alert("xss")</script><rect width="100"/></svg>');
 */
export function sanitizeSvg(
  svg: string,
  allowedElements: string[] = ['svg', 'g', 'rect', 'circle', 'ellipse', 'line', 'polyline', 'polygon', 'path', 'text', 'tspan', 'textPath', 'use', 'defs', 'clipPath', 'mask', 'pattern', 'linearGradient', 'radialGradient', 'stop', 'filter', 'feGaussianBlur', 'feOffset', 'feMerge', 'feMergeNode', 'image', 'marker', 'symbol', 'view', 'desc', 'title', 'metadata'],
): string {
  const span = createSpan('msf.web.sanitizeSvg');
  try {
    logger.debug({ inputLength: svg.length }, 'Sanitizing SVG');
    const allowedSet = new Set(allowedElements.map(e => e.toLowerCase()));
    let result = svg;
    result = result.replace(/<\s*\/?\s*script[^>]*>[\s\S]*?<\s*\/\s*script\s*>/gi, '');
    result = result.replace(/<\s*\/?\s*script[^>]*>/gi, '');
    result = result.replace(/<\s*\/?\s*foreignObject[^>]*>[\s\S]*?<\s*\/\s*foreignObject\s*>/gi, '');
    result = result.replace(/<\s*\/?\s*foreignObject[^>]*>/gi, '');
    result = result.replace(/<\s*\/?\s*animate[^>]*>[\s\S]*?<\s*\/\s*animate\s*>/gi, '');
    result = result.replace(/<\s*\/?\s*animate[^>]*>/gi, '');
    result = result.replace(/<\s*\/?\s*animateTransform[^>]*>[\s\S]*?<\s*\/\s*animateTransform\s*>/gi, '');
    result = result.replace(/<\s*\/?\s*animateTransform[^>]*>/gi, '');
    result = result.replace(/<\s*\/?\s*animateMotion[^>]*>[\s\S]*?<\s*\/\s*animateMotion\s*>/gi, '');
    result = result.replace(/<\s*\/?\s*animateMotion[^>]*>/gi, '');
    result = result.replace(/<\s*\/?\s*set[^>]*>[\s\S]*?<\s*\/\s*set\s*>/gi, '');
    result = result.replace(/<\s*\/?\s*set[^>]*>/gi, '');
    result = result.replace(/<\s*\/?\s*discard[^>]*>[\s\S]*?<\s*\/\s*discard\s*>/gi, '');
    result = result.replace(/<\s*\/?\s*discard[^>]*>/gi, '');
    result = result.replace(/on\w+\s*=\s*["'][^"']*["']/gi, '');
    result = result.replace(/on\w+\s*=\s*\S+/gi, '');
    result = result.replace(/xlink:href\s*=\s*["']javascript:[^"']*["']/gi, '');
    result = result.replace(/href\s*=\s*["']javascript:[^"']*["']/gi, '');
    result = result.replace(/<([^\/\s>]+)([^>]*)>/g, (match, tag, attrs) => {
      const tagName = tag.toLowerCase();
      if (!allowedSet.has(tagName)) return '';
      return `<${tagName}${attrs || ''}>`;
    });
    result = result.replace(/<\/([^>]+)>/g, (match, tag) => {
      return allowedSet.has(tag.toLowerCase()) ? match : '';
    });
    metrics.incCounter('web.sanitizeSvg');
    return result;
  } catch (error) {
    logger.error({ error }, 'SVG sanitization failed');
    metrics.incCounter('web.sanitizeSvg.error');
    throw new SecurityError('SVG sanitization failed', 'SVG_SANITIZE_ERROR');
  } finally {
    span.end();
  }
}

// --- 4. sanitizeMarkdown -----------------------------------------------------

/**
 * @description Sanitizes Markdown content by stripping dangerous HTML and JavaScript.
 * @param markdown - The Markdown string to sanitize.
 * @param allowedHtml - Array of allowed HTML tags within the Markdown.
 * @returns Sanitized Markdown string with dangerous content removed.
 * @example
 * const clean = sanitizeMarkdown('# Title\n\n<script>alert("xss")</script>\n\nSafe text');
 */
export function sanitizeMarkdown(
  markdown: string,
  allowedHtml: string[] = ['strong', 'em', 'code', 'pre', 'blockquote', 'a', 'img', 'ul', 'ol', 'li', 'p', 'br', 'hr', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'table', 'thead', 'tbody', 'tr', 'th', 'td'],
): string {
  const span = createSpan('msf.web.sanitizeMarkdown');
  try {
    logger.debug({ inputLength: markdown.length }, 'Sanitizing Markdown');
    const allowedSet = new Set(allowedHtml.map(t => t.toLowerCase()));
    let result = markdown;
    result = result.replace(/<\s*script[^>]*>[\s\S]*?<\s*\/\s*script\s*>/gi, '');
    result = result.replace(/<\s*script[^>]*>/gi, '');
    result = result.replace(/<\s*iframe[^>]*>[\s\S]*?<\s*\/\s*iframe\s*>/gi, '');
    result = result.replace(/<\s*iframe[^>]*>/gi, '');
    result = result.replace(/<\s*object[^>]*>[\s\S]*?<\s*\/\s*object\s*>/gi, '');
    result = result.replace(/<\s*object[^>]*>/gi, '');
    result = result.replace(/<\s*embed[^>]*>[\s\S]*?<\s*\/\s*embed\s*>/gi, '');
    result = result.replace(/<\s*embed[^>]*>/gi, '');
    result = result.replace(/<\s*form[^>]*>[\s\S]*?<\s*\/\s*form\s*>/gi, '');
    result = result.replace(/<\s*form[^>]*>/gi, '');
    result = result.replace(/<\s*input[^>]*>/gi, '');
    result = result.replace(/<\s*button[^>]*>[\s\S]*?<\s*\/\s*button\s*>/gi, '');
    result = result.replace(/<\s*button[^>]*>/gi, '');
    result = result.replace(/<\s*select[^>]*>[\s\S]*?<\s*\/\s*select\s*>/gi, '');
    result = result.replace(/<\s*select[^>]*>/gi, '');
    result = result.replace(/<\s*textarea[^>]*>[\s\S]*?<\s*\/\s*textarea\s*>/gi, '');
    result = result.replace(/<\s*textarea[^>]*>/gi, '');
    result = result.replace(/on\w+\s*=\s*["'][^"']*["']/gi, '');
    result = result.replace(/on\w+\s*=\s*\S+/gi, '');
    result = result.replace(/javascript\s*:/gi, '');
    result = result.replace(/vbscript\s*:/gi, '');
    result = result.replace(/data\s*:\s*text\/html/gi, '');
    result = result.replace(/<([^\/\s>]+)([^>]*)>/g, (match, tag, attrs) => {
      const tagName = tag.toLowerCase();
      if (!allowedSet.has(tagName)) return '';
      return `<${tagName}${attrs || ''}>`;
    });
    result = result.replace(/<\/([^>]+)>/g, (match, tag) => {
      return allowedSet.has(tag.toLowerCase()) ? match : '';
    });
    metrics.incCounter('web.sanitizeMarkdown');
    return result;
  } catch (error) {
    logger.error({ error }, 'Markdown sanitization failed');
    metrics.incCounter('web.sanitizeMarkdown.error');
    throw new SecurityError('Markdown sanitization failed', 'MD_SANITIZE_ERROR');
  } finally {
    span.end();
  }
}

// --- 5. sanitizeCss ----------------------------------------------------------

/**
 * @description Sanitizes CSS by removing dangerous properties and expressions.
 * @param css - The CSS string to sanitize.
 * @param allowedProperties - Array of CSS property names to preserve.
 * @returns Sanitized CSS string with dangerous content removed.
 * @example
 * const clean = sanitizeCss('color: red; background: url(javascript:alert(1));');
 */
export function sanitizeCss(
  css: string,
  allowedProperties: string[] = ['color', 'background-color', 'background-image', 'background-size', 'background-position', 'background-repeat', 'font-family', 'font-size', 'font-weight', 'font-style', 'text-align', 'text-decoration', 'line-height', 'letter-spacing', 'margin', 'margin-top', 'margin-right', 'margin-bottom', 'margin-left', 'padding', 'padding-top', 'padding-right', 'padding-bottom', 'padding-left', 'border', 'border-color', 'border-style', 'border-width', 'border-radius', 'width', 'height', 'min-width', 'min-height', 'max-width', 'max-height', 'display', 'position', 'top', 'right', 'bottom', 'left', 'z-index', 'overflow', 'opacity', 'visibility', 'cursor', 'outline', 'box-shadow', 'text-shadow', 'transform', 'transition', 'animation', 'flex', 'flex-direction', 'flex-wrap', 'justify-content', 'align-items', 'grid', 'grid-template-columns', 'grid-template-rows', 'gap', 'object-fit', 'float', 'clear', 'vertical-align', 'white-space', 'word-break', 'word-wrap', 'text-overflow', 'list-style', 'list-style-type', 'list-style-position', 'content'],
): string {
  const span = createSpan('msf.web.sanitizeCss');
  try {
    logger.debug({ inputLength: css.length }, 'Sanitizing CSS');
    const allowedSet = new Set(allowedProperties.map(p => p.toLowerCase()));
    let result = css;
    result = result.replace(/expression\s*\([^)]*\)/gi, '');
    result = result.replace(/url\s*\(\s*["']?\s*javascript:[^)]*\)/gi, '');
    result = result.replace(/url\s*\(\s*["']?\s*vbscript:[^)]*\)/gi, '');
    result = result.replace(/url\s*\(\s*["']?\s*data\s*:\s*text\/html[^)]*\)/gi, '');
    result = result.replace(/behavior\s*:\s*[^;]+/gi, '');
    result = result.replace(/-moz-binding\s*:\s*[^;]+/gi, '');
    result = result.replace(/binding\s*:\s*[^;]+/gi, '');
    result = result.replace(/@import\s+[^;]+;/gi, '');
    const declarations = result.split(';');
    const safeDeclarations = declarations.filter(decl => {
      const trimmed = decl.trim();
      if (!trimmed) return true;
      const colonIndex = trimmed.indexOf(':');
      if (colonIndex === -1) return true;
      const property = trimmed.substring(0, colonIndex).trim().toLowerCase();
      return allowedSet.has(property);
    });
    result = safeDeclarations.join(';');
    metrics.incCounter('web.sanitizeCss');
    return result;
  } catch (error) {
    logger.error({ error }, 'CSS sanitization failed');
    metrics.incCounter('web.sanitizeCss.error');
    throw new SecurityError('CSS sanitization failed', 'CSS_SANITIZE_ERROR');
  } finally {
    span.end();
  }
}

// --- 6. sanitizeJs -----------------------------------------------------------

/**
 * @description Sanitizes JavaScript code by removing dangerous patterns and functions.
 * @param jsCode - The JavaScript code string to sanitize.
 * @param dangerousPatterns - Optional custom regex patterns to detect and remove.
 * @returns Sanitized JavaScript string with dangerous content removed.
 * @example
 * const clean = sanitizeJs('eval(userInput); console.log("safe");');
 */
export function sanitizeJs(
  jsCode: string,
  dangerousPatterns: RegExp[] = [
    /\beval\s*\(/gi, /\bFunction\s*\(/gi, /\bsetTimeout\s*\(\s*["']/gi,
    /\bsetInterval\s*\(\s*["']/gi, /\bdocument\.write\s*\(/gi,
    /\bdocument\.writeln\s*\(/gi, /\bdocument\.cookie\b/gi,
    /\bdocument\.domain\b/gi, /\bwindow\.location\s*=/gi,
    /\blocation\.href\s*=/gi, /\blocation\.replace\s*\(/gi,
    /\blocation\.assign\s*\(/gi, /\binnerHTML\b/gi,
    /\bouterHTML\b/gi, /\binsertAdjacentHTML\s*\(/gi,
    /\bexecScript\s*\(/gi, /\bmsSetImmediate\s*\(/gi,
    /\b__proto__\b/gi, /\bconstructor\b/gi, /\bprototype\b/gi,
    /\balert\s*\(/gi, /\bprompt\s*\(/gi, /\bconfirm\s*\(/gi,
    /\bopen\s*\(/gi, /\bpostMessage\s*\(/gi,
    /\bXMLHttpRequest\b/gi, /\bfetch\s*\(/gi, /\bWebSocket\b/gi,
    /\bimport\s*\(/gi, /\brequire\s*\(/gi,
  ],
): string {
  const span = createSpan('msf.web.sanitizeJs');
  try {
    logger.debug({ inputLength: jsCode.length }, 'Sanitizing JavaScript');
    let result = jsCode;
    for (const pattern of dangerousPatterns) {
      result = result.replace(pattern, (match) => {
        return `/* [SANITIZED: ${match.trim().substring(0, 30)}] */`;
      });
    }
    result = result.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '');
    result = result.replace(/<script[^>]*>/gi, '');
    metrics.incCounter('web.sanitizeJs');
    return result;
  } catch (error) {
    logger.error({ error }, 'JavaScript sanitization failed');
    metrics.incCounter('web.sanitizeJs.error');
    throw new SecurityError('JavaScript sanitization failed', 'JS_SANITIZE_ERROR');
  } finally {
    span.end();
  }
}

// --- 7. detectSqli -----------------------------------------------------------

/**
 * @description Detects SQL Injection attack patterns in input strings.
 * @param input - The string to analyze for SQL injection patterns.
 * @param patterns - Optional custom regex patterns to supplement built-in detection.
 * @param context - Optional context (e.g., 'query', 'parameter', 'header') for logging.
 * @returns DetectionResult with detection status, severity, score, and matched patterns.
 * @example
 * const result = detectSqli("1' OR '1'='1");
 * console.log(result.detected); // true
 */
export function detectSqli(
  input: string,
  patterns?: RegExp[],
  context?: string,
): DetectionResult {
  const span = createSpan('msf.web.detectSqli');
  const startTime = Date.now();
  try {
    logger.debug({ inputLength: input.length, context }, 'Running SQLi detection');
    const allPatterns = patterns ? [...SQLI_PATTERNS, ...patterns] : SQLI_PATTERNS;
    const { matches, score } = runPatternDetection(input, allPatterns);
    const detected = score >= 0.2 && matches.length > 0;
    const severity = calculateSeverity(score);
    span.setAttribute('detected', detected);
    span.setAttribute('score', score);
    span.setAttribute('context', context || 'unknown');
    metrics.incCounter('web.sqli.detection');
    metrics.observeHistogram('web.sqli.latency', Date.now() - startTime);
    return createDetectionResult(detected, severity, score, matches, 'SQLi pattern detection completed');
  } catch (error) {
    logger.error({ error }, 'SQLi detection failed');
    metrics.incCounter('web.sqli.error');
    throw new SecurityError('SQLi detection failed', 'SQLI_DETECTION_ERROR');
  } finally {
    span.end();
  }
}

// --- 8. detectNosqli ---------------------------------------------------------

/**
 * @description Detects NoSQL Injection attack patterns in input strings.
 * @param input - The string to analyze for NoSQL injection patterns.
 * @param patterns - Optional custom regex patterns to supplement built-in detection.
 * @returns DetectionResult with detection status, severity, score, and matched patterns.
 * @example
 * const result = detectNosqli('{"$gt": ""}');
 * console.log(result.detected); // true
 */
export function detectNosqli(
  input: string,
  patterns?: RegExp[],
): DetectionResult {
  const span = createSpan('msf.web.detectNosqli');
  const startTime = Date.now();
  try {
    logger.debug({ inputLength: input.length }, 'Running NoSQLi detection');
    const allPatterns = patterns ? [...NOSQLI_PATTERNS, ...patterns] : NOSQLI_PATTERNS;
    const { matches, score } = runPatternDetection(input, allPatterns);
    const detected = score >= 0.2 && matches.length > 0;
    const severity = calculateSeverity(score);
    span.setAttribute('detected', detected);
    span.setAttribute('score', score);
    metrics.incCounter('web.nosqli.detection');
    metrics.observeHistogram('web.nosqli.latency', Date.now() - startTime);
    return createDetectionResult(detected, severity, score, matches, 'NoSQLi pattern detection completed');
  } catch (error) {
    logger.error({ error }, 'NoSQLi detection failed');
    metrics.incCounter('web.nosqli.error');
    throw new SecurityError('NoSQLi detection failed', 'NOSQLI_DETECTION_ERROR');
  } finally {
    span.end();
  }
}

// --- 9. detectSsrf -----------------------------------------------------------

/**
 * @description Detects Server-Side Request Forgery (SSRF) attack patterns in URLs.
 * @param url - The URL string to analyze for SSRF patterns.
 * @param allowedDomains - Array of domain names that are allowed.
 * @param blockedIps - Array of IP addresses or CIDR ranges that are blocked.
 * @returns DetectionResult with detection status, severity, score, and matched patterns.
 * @example
 * const result = detectSsrf('http://169.254.169.254/latest/meta-data/', [], []);
 * console.log(result.detected); // true
 */
export function detectSsrf(
  url: string,
  allowedDomains: string[] = [],
  blockedIps: string[] = [],
): DetectionResult {
  const span = createSpan('msf.web.detectSsrf');
  const startTime = Date.now();
  try {
    logger.debug({ url, allowedDomainsCount: allowedDomains.length }, 'Running SSRF detection');
    const { matches, score } = runPatternDetection(url, SSRF_PATTERNS);
    let detected = score >= 0.2 && matches.length > 0;
    let severity = calculateSeverity(score);
    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname.toLowerCase();
      if (allowedDomains.length > 0) {
        const isAllowed = allowedDomains.some(domain => {
          if (domain.startsWith('*.')) {
            const suffix = domain.slice(1);
            return hostname.endsWith(suffix);
          }
          return hostname === domain.toLowerCase();
        });
        if (!isAllowed) {
          detected = true;
          severity = severity === 'critical' ? 'critical' : 'high';
          matches.push(`Domain not in allowed list: ${hostname}`);
        }
      }
      for (const blocked of blockedIps) {
        if (hostname === blocked || hostname.startsWith(blocked.split('/')[0])) {
          detected = true;
          severity = 'high';
          matches.push(`IP matches blocked list: ${blocked}`);
        }
      }
    } catch {
      detected = true;
      severity = 'high';
      matches.push('Invalid URL format');
    }
    span.setAttribute('detected', detected);
    span.setAttribute('score', score);
    metrics.incCounter('web.ssrf.detection');
    metrics.observeHistogram('web.ssrf.latency', Date.now() - startTime);
    return createDetectionResult(detected, severity, score, matches, 'SSRF pattern detection completed');
  } catch (error) {
    logger.error({ error }, 'SSRF detection failed');
    metrics.incCounter('web.ssrf.error');
    throw new SecurityError('SSRF detection failed', 'SSRF_DETECTION_ERROR');
  } finally {
    span.end();
  }
}

// --- 10. detectRce -----------------------------------------------------------

/**
 * @description Detects Remote Code Execution (RCE) attack patterns in input strings.
 * @param input - The string to analyze for RCE patterns.
 * @param patterns - Optional custom regex patterns to supplement built-in detection.
 * @returns DetectionResult with detection status, severity, score, and matched patterns.
 * @example
 * const result = detectRce('; cat /etc/passwd');
 * console.log(result.detected); // true
 */
export function detectRce(
  input: string,
  patterns?: RegExp[],
): DetectionResult {
  const span = createSpan('msf.web.detectRce');
  const startTime = Date.now();
  try {
    logger.debug({ inputLength: input.length }, 'Running RCE detection');
    const allPatterns = patterns ? [...RCE_PATTERNS, ...patterns] : RCE_PATTERNS;
    const { matches, score } = runPatternDetection(input, allPatterns);
    const detected = score >= 0.2 && matches.length > 0;
    const severity = calculateSeverity(score);
    span.setAttribute('detected', detected);
    span.setAttribute('score', score);
    metrics.incCounter('web.rce.detection');
    metrics.observeHistogram('web.rce.latency', Date.now() - startTime);
    return createDetectionResult(detected, severity, score, matches, 'RCE pattern detection completed');
  } catch (error) {
    logger.error({ error }, 'RCE detection failed');
    metrics.incCounter('web.rce.error');
    throw new SecurityError('RCE detection failed', 'RCE_DETECTION_ERROR');
  } finally {
    span.end();
  }
}

// --- 11. detectLfi -----------------------------------------------------------

/**
 * @description Detects Local File Inclusion (LFI) attack patterns in input strings.
 * @param input - The string to analyze for LFI patterns.
 * @param patterns - Optional custom regex patterns to supplement built-in detection.
 * @returns DetectionResult with detection status, severity, score, and matched patterns.
 * @example
 * const result = detectLfi('../../../etc/passwd');
 * console.log(result.detected); // true
 */
export function detectLfi(
  input: string,
  patterns?: RegExp[],
): DetectionResult {
  const span = createSpan('msf.web.detectLfi');
  const startTime = Date.now();
  try {
    logger.debug({ inputLength: input.length }, 'Running LFI detection');
    const allPatterns = patterns ? [...LFI_PATTERNS, ...patterns] : LFI_PATTERNS;
    const { matches, score } = runPatternDetection(input, allPatterns);
    const detected = score >= 0.15 && matches.length > 0;
    const severity = calculateSeverity(score);
    span.setAttribute('detected', detected);
    span.setAttribute('score', score);
    metrics.incCounter('web.lfi.detection');
    metrics.observeHistogram('web.lfi.latency', Date.now() - startTime);
    return createDetectionResult(detected, severity, score, matches, 'LFI pattern detection completed');
  } catch (error) {
    logger.error({ error }, 'LFI detection failed');
    metrics.incCounter('web.lfi.error');
    throw new SecurityError('LFI detection failed', 'LFI_DETECTION_ERROR');
  } finally {
    span.end();
  }
}

// --- 12. detectRfi -----------------------------------------------------------

/**
 * @description Detects Remote File Inclusion (RFI) attack patterns in input strings.
 * @param input - The string to analyze for RFI patterns.
 * @param patterns - Optional custom regex patterns to supplement built-in detection.
 * @returns DetectionResult with detection status, severity, score, and matched patterns.
 * @example
 * const result = detectRfi('http://evil.com/shell.php');
 * console.log(result.detected); // true
 */
export function detectRfi(
  input: string,
  patterns?: RegExp[],
): DetectionResult {
  const span = createSpan('msf.web.detectRfi');
  const startTime = Date.now();
  try {
    logger.debug({ inputLength: input.length }, 'Running RFI detection');
    const allPatterns = patterns ? [...RFI_PATTERNS, ...patterns] : RFI_PATTERNS;
    const { matches, score } = runPatternDetection(input, allPatterns);
    const detected = score >= 0.2 && matches.length > 0;
    const severity = calculateSeverity(score);
    span.setAttribute('detected', detected);
    span.setAttribute('score', score);
    metrics.incCounter('web.rfi.detection');
    metrics.observeHistogram('web.rfi.latency', Date.now() - startTime);
    return createDetectionResult(detected, severity, score, matches, 'RFI pattern detection completed');
  } catch (error) {
    logger.error({ error }, 'RFI detection failed');
    metrics.incCounter('web.rfi.error');
    throw new SecurityError('RFI detection failed', 'RFI_DETECTION_ERROR');
  } finally {
    span.end();
  }
}

// --- 13. detectTemplateInjection ---------------------------------------------

/**
 * @description Detects Server-Side Template Injection (SSTI) attack patterns.
 * @param input - The string to analyze for template injection patterns.
 * @param engineType - Template engine type ('jinja2', 'ejs', 'handlebars', 'mustache', 'pug', 'twig', 'generic').
 * @returns DetectionResult with detection status, severity, score, and matched patterns.
 * @example
 * const result = detectTemplateInjection('{{ config.__class__ }}', 'jinja2');
 * console.log(result.detected); // true
 */
export function detectTemplateInjection(
  input: string,
  engineType: 'jinja2' | 'ejs' | 'handlebars' | 'mustache' | 'pug' | 'twig' | 'generic' = 'generic',
): DetectionResult {
  const span = createSpan('msf.web.detectTemplateInjection');
  const startTime = Date.now();
  try {
    logger.debug({ inputLength: input.length, engineType }, 'Running template injection detection');
    const enginePatterns = TEMPLATE_INJECTION_PATTERNS[engineType] || TEMPLATE_INJECTION_PATTERNS.generic;
    const { matches, score } = runPatternDetection(input, enginePatterns);
    const detected = score >= 0.15 && matches.length > 0;
    const severity = calculateSeverity(score);
    span.setAttribute('detected', detected);
    span.setAttribute('score', score);
    span.setAttribute('engineType', engineType);
    metrics.incCounter('web.ssti.detection');
    metrics.observeHistogram('web.ssti.latency', Date.now() - startTime);
    return createDetectionResult(detected, severity, score, matches, 'Template injection detection completed');
  } catch (error) {
    logger.error({ error }, 'Template injection detection failed');
    metrics.incCounter('web.ssti.error');
    throw new SecurityError('Template injection detection failed', 'SSTI_DETECTION_ERROR');
  } finally {
    span.end();
  }
}

// --- 14. detectCommandInjection ----------------------------------------------

/**
 * @description Detects OS Command Injection attack patterns in input strings.
 * @param input - The string to analyze for command injection patterns.
 * @param patterns - Optional custom regex patterns to supplement built-in detection.
 * @returns DetectionResult with detection status, severity, score, and matched patterns.
 * @example
 * const result = detectCommandInjection('; rm -rf /');
 * console.log(result.detected); // true
 */
export function detectCommandInjection(
  input: string,
  patterns?: RegExp[],
): DetectionResult {
  const span = createSpan('msf.web.detectCommandInjection');
  const startTime = Date.now();
  try {
    logger.debug({ inputLength: input.length }, 'Running command injection detection');
    const allPatterns = patterns ? [...COMMAND_INJECTION_PATTERNS, ...patterns] : COMMAND_INJECTION_PATTERNS;
    const { matches, score } = runPatternDetection(input, allPatterns);
    const detected = score >= 0.2 && matches.length > 0;
    const severity = calculateSeverity(score);
    span.setAttribute('detected', detected);
    span.setAttribute('score', score);
    metrics.incCounter('web.cmdi.detection');
    metrics.observeHistogram('web.cmdi.latency', Date.now() - startTime);
    return createDetectionResult(detected, severity, score, matches, 'Command injection detection completed');
  } catch (error) {
    logger.error({ error }, 'Command injection detection failed');
    metrics.incCounter('web.cmdi.error');
    throw new SecurityError('Command injection detection failed', 'CMDI_DETECTION_ERROR');
  } finally {
    span.end();
  }
}

// --- 15. detectDeserializationAttack -----------------------------------------

/**
 * @description Detects insecure deserialization attack patterns in data.
 * @param data - The data string to analyze for deserialization attack patterns.
 * @param allowedClasses - Array of class/type names that are allowed in serialized data.
 * @returns DetectionResult with detection status, severity, score, and matched patterns.
 * @example
 * const result = detectDeserializationAttack('rO0ABXcEAAAAAA==', []);
 * console.log(result.detected); // true
 */
export function detectDeserializationAttack(
  data: string,
  allowedClasses: string[] = [],
): DetectionResult {
  const span = createSpan('msf.web.detectDeserializationAttack');
  const startTime = Date.now();
  try {
    logger.debug({ dataLength: data.length }, 'Running deserialization attack detection');
    const { matches, score } = runPatternDetection(data, DESERIALIZATION_PATTERNS);
    let detected = score >= 0.15 && matches.length > 0;
    const severity = calculateSeverity(score);
    if (allowedClasses.length > 0 && detected) {
      const hasDisallowedClass = matches.some(match => {
        return !allowedClasses.some(allowed => match.includes(allowed));
      });
      if (!hasDisallowedClass) {
        detected = false;
      }
    }
    span.setAttribute('detected', detected);
    span.setAttribute('score', score);
    metrics.incCounter('web.deserialization.detection');
    metrics.observeHistogram('web.deserialization.latency', Date.now() - startTime);
    return createDetectionResult(detected, severity, score, matches, 'Deserialization attack detection completed');
  } catch (error) {
    logger.error({ error }, 'Deserialization attack detection failed');
    metrics.incCounter('web.deserialization.error');
    throw new SecurityError('Deserialization attack detection failed', 'DESERIALIZE_DETECTION_ERROR');
  } finally {
    span.end();
  }
}

// --- 16. detectPathTraversal -------------------------------------------------

/**
 * @description Detects path traversal attack patterns in input strings.
 * @param input - The path string to analyze for traversal patterns.
 * @param basePath - The base path that the input should be resolved against.
 * @returns DetectionResult with detection status, severity, score, and matched patterns.
 * @example
 * const result = detectPathTraversal('../../../etc/passwd', '/var/www');
 * console.log(result.detected); // true
 */
export function detectPathTraversal(
  input: string,
  basePath: string,
): DetectionResult {
  const span = createSpan('msf.web.detectPathTraversal');
  const startTime = Date.now();
  try {
    logger.debug({ input, basePath }, 'Running path traversal detection');
    const traversalPatterns = [
      /\.\.\//g, /\.\.\\/g, /\%2e\%2e\%2f/gi, /\%2e\%2e\\/gi,
      /\.\.%2f/gi, /\.\.%5c/gi, /\%252e\%252e\%252f/gi,
      /\%252e\%252e\%255c/gi, /\.\.\.\.\//g, /\.\.\.\.\\/g,
      /\/etc\/(passwd|shadow|hosts)/i, /\/proc\/self/i, /\/var\/log/i,
      /\\windows\\/i, /\\boot\.ini/i, /\\win\.ini/i, /c:\\/i,
      /file:\/\/\/etc\//i, /file:\/\/\/proc\//i, /file:\/\/\/var\//i,
      /php:\/\/filter/i, /php:\/\/input/i, /data:\/\/text\/plain/i,
    ];
    const { matches, score } = runPatternDetection(input, traversalPatterns);
    let detected = score >= 0.1 && matches.length > 0;
    try {
      const normalizedBase = basePath.replace(/\\/g, '/').replace(/\/+$/, '');
      const normalizedInput = input.replace(/\\/g, '/');
      const resolved = normalizedInput.startsWith('/') ? normalizedInput : `${normalizedBase}/${normalizedInput}`;
      const pathParts = resolved.split('/').filter(Boolean);
      let depth = 0;
      for (const part of pathParts) {
        if (part === '..') {
          depth--;
          if (depth < 0) {
            detected = true;
            matches.push('Path escapes base directory');
            break;
          }
        } else if (part !== '.') {
          depth++;
        }
      }
    } catch {
      detected = true;
      matches.push('Path resolution failed');
    }
    const severity = calculateSeverity(score);
    span.setAttribute('detected', detected);
    span.setAttribute('score', score);
    metrics.incCounter('web.pathTraversal.detection');
    metrics.observeHistogram('web.pathTraversal.latency', Date.now() - startTime);
    return createDetectionResult(detected, severity, score, matches, 'Path traversal detection completed');
  } catch (error) {
    logger.error({ error }, 'Path traversal detection failed');
    metrics.incCounter('web.pathTraversal.error');
    throw new SecurityError('Path traversal detection failed', 'PATH_TRAVERSAL_ERROR');
  } finally {
    span.end();
  }
}

// --- 17. detectOpenRedirect --------------------------------------------------

/**
 * @description Detects open redirect attack patterns in URLs.
 * @param url - The URL string to analyze for open redirect patterns.
 * @param allowedHosts - Array of hostnames that are allowed for redirects.
 * @returns DetectionResult with detection status, severity, score, and matched patterns.
 * @example
 * const result = detectOpenRedirect('http://evil.com/phishing', ['example.com']);
 * console.log(result.detected); // true
 */
export function detectOpenRedirect(
  url: string,
  allowedHosts: string[],
): DetectionResult {
  const span = createSpan('msf.web.detectOpenRedirect');
  const startTime = Date.now();
  try {
    logger.debug({ url, allowedHostsCount: allowedHosts.length }, 'Running open redirect detection');
    const matches: string[] = [];
    let detected = false;
    let score = 0;
    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname.toLowerCase();
      const isAllowed = allowedHosts.some(host => {
        if (host.startsWith('*.')) {
          const suffix = host.slice(1);
          return hostname.endsWith(suffix);
        }
        return hostname === host.toLowerCase();
      });
      if (!isAllowed) {
        detected = true;
        score = 0.8;
        matches.push(`Host not in allowed list: ${hostname}`);
      }
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        detected = true;
        score = Math.max(score, 0.9);
        matches.push(`Invalid protocol: ${parsed.protocol}`);
      }
      if (parsed.hostname.includes('@')) {
        detected = true;
        score = Math.max(score, 0.7);
        matches.push('URL contains credentials');
      }
      const redirectPatterns = [/\/\/[^/]/, /\\/, /%2f%2f/i, /%5c/i, /javascript:/i, /data:/i, /vbscript:/i];
      for (const pattern of redirectPatterns) {
        if (pattern.test(url)) {
          detected = true;
          score = Math.max(score, 0.5);
          matches.push(`Suspicious redirect pattern: ${pattern.source}`);
        }
      }
    } catch {
      detected = true;
      score = 0.9;
      matches.push('Invalid URL format');
    }
    const severity = calculateSeverity(score);
    span.setAttribute('detected', detected);
    span.setAttribute('score', score);
    metrics.incCounter('web.openRedirect.detection');
    metrics.observeHistogram('web.openRedirect.latency', Date.now() - startTime);
    return createDetectionResult(detected, severity, score, matches, 'Open redirect detection completed');
  } catch (error) {
    logger.error({ error }, 'Open redirect detection failed');
    metrics.incCounter('web.openRedirect.error');
    throw new SecurityError('Open redirect detection failed', 'OPEN_REDIRECT_ERROR');
  } finally {
    span.end();
  }
}

// --- 18. validateCors --------------------------------------------------------

/**
 * @description Validates Cross-Origin Resource Sharing (CORS) request parameters.
 * @param origin - The Origin header value from the request.
 * @param allowedOrigins - Array of allowed origin values (supports '*' for all).
 * @param allowedMethods - Array of allowed HTTP methods.
 * @param allowedHeaders - Array of allowed request headers.
 * @returns CorsResult with validation status and appropriate CORS headers.
 * @example
 * const result = validateCors('https://example.com', ['https://example.com'], ['GET', 'POST']);
 * console.log(result.allowed); // true
 */
export function validateCors(
  origin: string | undefined,
  allowedOrigins: string[],
  allowedMethods: string[] = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: string[] = ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
): CorsResult {
  const span = createSpan('msf.web.validateCors');
  try {
    logger.debug({ origin, allowedOriginsCount: allowedOrigins.length }, 'Validating CORS');
    const headers: Record<string, string> = {};
    if (!origin) {
      metrics.incCounter('web.cors.missingOrigin');
      return { allowed: false, headers, reason: 'Missing Origin header' };
    }
    const originAllowed = allowedOrigins.includes('*') || allowedOrigins.includes(origin);
    if (!originAllowed) {
      metrics.incCounter('web.cors.rejected');
      return { allowed: false, headers, reason: `Origin not allowed: ${origin}` };
    }
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Access-Control-Allow-Methods'] = allowedMethods.join(', ');
    headers['Access-Control-Allow-Headers'] = allowedHeaders.join(', ');
    headers['Access-Control-Max-Age'] = '86400';
    headers['Access-Control-Allow-Credentials'] = 'true';
    headers['Vary'] = 'Origin';
    metrics.incCounter('web.cors.allowed');
    return { allowed: true, headers };
  } catch (error) {
    logger.error({ error }, 'CORS validation failed');
    metrics.incCounter('web.cors.error');
    throw new SecurityError('CORS validation failed', 'CORS_VALIDATION_ERROR');
  } finally {
    span.end();
  }
}

// --- 19. secureHeaders -------------------------------------------------------

/**
 * @description Generates a set of secure HTTP response headers.
 * @param request - The incoming request object with method, url, and headers.
 * @param config - Configuration options for security headers.
 * @returns Record of secure HTTP headers to include in the response.
 * @example
 * const headers = secureHeaders(request, { hsts: true, xFrameOptions: 'DENY' });
 */
export function secureHeaders(
  request: SecureHeadersRequest,
  config: SecureHeadersConfig = {},
): Record<string, string> {
  const span = createSpan('msf.web.secureHeaders');
  try {
    logger.debug({ method: request.method, url: request.url }, 'Generating secure headers');
    const headers: Record<string, string> = {};
    const {
      hsts = true, hstsMaxAge = 31536000, xFrameOptions = 'DENY',
      xContentTypeOptions = true, xXssProtection = false,
      referrerPolicy = 'strict-origin-when-cross-origin',
      permissionsPolicy = 'camera=(), microphone=(), geolocation=()',
      removeServerHeader = true, removeXPoweredBy = true,
    } = config;
    if (hsts) {
      headers['Strict-Transport-Security'] = `max-age=${hstsMaxAge}; includeSubDomains; preload`;
    }
    headers['X-Frame-Options'] = xFrameOptions;
    if (xContentTypeOptions) {
      headers['X-Content-Type-Options'] = 'nosniff';
    }
    if (xXssProtection) {
      headers['X-XSS-Protection'] = '0';
    }
    headers['Referrer-Policy'] = referrerPolicy;
    headers['Permissions-Policy'] = permissionsPolicy;
    headers['X-DNS-Prefetch-Control'] = 'off';
    headers['X-Download-Options'] = 'noopen';
    headers['X-Permitted-Cross-Domain-Policies'] = 'none';
    headers['Cross-Origin-Opener-Policy'] = 'same-origin';
    headers['Cross-Origin-Resource-Policy'] = 'same-origin';
    headers['Cross-Origin-Embedder-Policy'] = 'require-corp';
    if (removeServerHeader) { headers['Server'] = ''; }
    if (removeXPoweredBy) { headers['X-Powered-By'] = ''; }
    if (request.protocol === 'https') {
      headers['Expect-CT'] = 'max-age=86400, enforce';
    }
    metrics.incCounter('web.secureHeaders');
    return headers;
  } catch (error) {
    logger.error({ error }, 'Secure headers generation failed');
    metrics.incCounter('web.secureHeaders.error');
    throw new SecurityError('Secure headers generation failed', 'SECURE_HEADERS_ERROR');
  } finally {
    span.end();
  }
}

// --- 20. generateCsp ---------------------------------------------------------

/**
 * @description Generates a Content Security Policy (CSP) header string from configuration.
 * @param config - CSP configuration object with directives for various resource types.
 * @returns CSP header string ready to be set on HTTP responses.
 * @example
 * const csp = generateCsp({ defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'"] });
 */
export function generateCsp(config: CspConfig = {}): string {
  const span = createSpan('msf.web.generateCsp');
  try {
    logger.debug({ config }, 'Generating CSP');
    const directives: string[] = [];
    const directiveMap: Record<string, string[] | undefined> = {
      'default-src': config.defaultSrc, 'script-src': config.scriptSrc,
      'style-src': config.styleSrc, 'img-src': config.imgSrc,
      'font-src': config.fontSrc, 'connect-src': config.connectSrc,
      'media-src': config.mediaSrc, 'object-src': config.objectSrc,
      'frame-src': config.frameSrc, 'frame-ancestors': config.frameAncestors,
      'base-uri': config.baseUri, 'form-action': config.formAction,
    };
    for (const [directive, values] of Object.entries(directiveMap)) {
      if (values && values.length > 0) {
        directives.push(`${directive} ${values.join(' ')}`);
      }
    }
    if (config.reportUri) { directives.push(`report-uri ${config.reportUri}`); }
    if (config.upgradeInsecureRequests) { directives.push('upgrade-insecure-requests'); }
    if (config.blockAllMixedContent) { directives.push('block-all-mixed-content'); }
    if (directives.length === 0) { directives.push("default-src 'self'"); }
    const csp = directives.join('; ');
    metrics.incCounter('web.generateCsp');
    return csp;
  } catch (error) {
    logger.error({ error }, 'CSP generation failed');
    metrics.incCounter('web.generateCsp.error');
    throw new SecurityError('CSP generation failed', 'CSP_GENERATION_ERROR');
  } finally {
    span.end();
  }
}

// --- 21. validateCsp ---------------------------------------------------------

/**
 * @description Validates a CSP header string against a policy configuration.
 * @param cspHeader - The CSP header string to validate.
 * @param policy - The expected policy configuration to validate against.
 * @returns Boolean indicating whether the CSP header is valid and compliant.
 * @example
 * const valid = validateCsp("default-src 'self'", { defaultSrc: ["'self'"] });
 */
export function validateCsp(
  cspHeader: string,
  policy: CspConfig,
): boolean {
  const span = createSpan('msf.web.validateCsp');
  try {
    logger.debug({ cspHeader }, 'Validating CSP');
    if (!cspHeader || cspHeader.trim().length === 0) {
      metrics.incCounter('web.validateCsp.empty');
      return false;
    }
    const directives = cspHeader.split(';').map(d => d.trim()).filter(Boolean);
    const parsedDirectives: Record<string, string[]> = {};
    for (const directive of directives) {
      const parts = directive.split(/\s+/);
      if (parts.length >= 2) {
        const name = parts[0];
        const values = parts.slice(1);
        parsedDirectives[name] = values;
      }
    }
    const checks: [string, string[] | undefined][] = [
      ['default-src', policy.defaultSrc], ['script-src', policy.scriptSrc],
      ['style-src', policy.styleSrc], ['img-src', policy.imgSrc],
      ['font-src', policy.fontSrc], ['connect-src', policy.connectSrc],
      ['media-src', policy.mediaSrc], ['object-src', policy.objectSrc],
      ['frame-src', policy.frameSrc], ['frame-ancestors', policy.frameAncestors],
      ['base-uri', policy.baseUri], ['form-action', policy.formAction],
    ];
    for (const [name, expectedValues] of checks) {
      if (expectedValues && expectedValues.length > 0) {
        const actualValues = parsedDirectives[name];
        if (!actualValues) {
          metrics.incCounter('web.validateCsp.missingDirective');
          return false;
        }
        for (const expected of expectedValues) {
          if (!actualValues.includes(expected)) {
            metrics.incCounter('web.validateCsp.missingValue');
            return false;
          }
        }
      }
    }
    if (policy.reportUri) {
      const reportUris = parsedDirectives['report-uri'];
      if (!reportUris || !reportUris.includes(policy.reportUri)) {
        metrics.incCounter('web.validateCsp.missingReportUri');
        return false;
      }
    }
    if (policy.upgradeInsecureRequests) {
      if (!parsedDirectives['upgrade-insecure-requests']) {
        metrics.incCounter('web.validateCsp.missingUpgradeInsecure');
        return false;
      }
    }
    if (policy.blockAllMixedContent) {
      if (!parsedDirectives['block-all-mixed-content']) {
        metrics.incCounter('web.validateCsp.mixedContent');
        return false;
      }
    }
    metrics.incCounter('web.validateCsp.valid');
    return true;
  } catch (error) {
    logger.error({ error }, 'CSP validation failed');
    metrics.incCounter('web.validateCsp.error');
    throw new SecurityError('CSP validation failed', 'CSP_VALIDATION_ERROR');
  } finally {
    span.end();
  }
}

// --- 22. csrfProtect ---------------------------------------------------------

/**
 * @description Validates CSRF protection for a request based on method and tokens.
 * @param request - The request object with method and headers.
 * @param token - The CSRF token from the request (header or body).
 * @param sessionToken - The expected CSRF token from the session.
 * @returns Boolean indicating whether the CSRF validation passed.
 * @example
 * const valid = csrfProtect({ method: 'POST', headers: {} }, 'token123', 'token123');
 */
export function csrfProtect(
  request: CsrfRequest,
  token: string,
  sessionToken: string,
): boolean {
  const span = createSpan('msf.web.csrfProtect');
  try {
    logger.debug({ method: request.method }, 'Validating CSRF protection');
    const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
    if (safeMethods.includes(request.method.toUpperCase())) {
      metrics.incCounter('web.csrf.safeMethod');
      return true;
    }
    if (!token || !sessionToken) {
      logger.warn('Missing CSRF token');
      metrics.incCounter('web.csrf.missingToken');
      return false;
    }
    if (token.length !== sessionToken.length) {
      logger.warn('CSRF token length mismatch');
      metrics.incCounter('web.csrf.invalid');
      return false;
    }
    const tokenBuffer = Buffer.from(token, 'utf8');
    const sessionBuffer = Buffer.from(sessionToken, 'utf8');
    const isValid = timingSafeEqual(tokenBuffer, sessionBuffer);
    if (isValid) { metrics.incCounter('web.csrf.valid'); }
    else { metrics.incCounter('web.csrf.invalid'); }
    return isValid;
  } catch (error) {
    logger.error({ error }, 'CSRF protection failed');
    metrics.incCounter('web.csrf.error');
    throw new SecurityError('CSRF protection failed', 'CSRF_PROTECTION_ERROR');
  } finally {
    span.end();
  }
}

// --- 23. validateCsrf --------------------------------------------------------

/**
 * @description Validates a CSRF token against the session token using timing-safe comparison.
 * @param token - The CSRF token to validate.
 * @param sessionToken - The expected CSRF token from the session.
 * @returns Boolean indicating whether the tokens match.
 * @example
 * const valid = validateCsrf('token123', 'token123');
 */
export function validateCsrf(
  token: string,
  sessionToken: string,
): boolean {
  const span = createSpan('msf.web.validateCsrf');
  try {
    logger.debug('Validating CSRF token');
    if (!token || !sessionToken) {
      logger.warn('Missing CSRF token');
      metrics.incCounter('web.validateCsrf.missingToken');
      return false;
    }
    if (token.length !== sessionToken.length) {
      logger.warn('CSRF token length mismatch');
      metrics.incCounter('web.validateCsrf.invalid');
      return false;
    }
    const tokenBuffer = Buffer.from(token, 'utf8');
    const sessionBuffer = Buffer.from(sessionToken, 'utf8');
    const isValid = timingSafeEqual(tokenBuffer, sessionBuffer);
    if (isValid) { metrics.incCounter('web.validateCsrf.valid'); }
    else { metrics.incCounter('web.validateCsrf.invalid'); }
    return isValid;
  } catch (error) {
    logger.error({ error }, 'CSRF validation failed');
    metrics.incCounter('web.validateCsrf.error');
    throw new SecurityError('CSRF validation failed', 'CSRF_VALIDATION_ERROR');
  } finally {
    span.end();
  }
}

// --- 24. secureCookie --------------------------------------------------------

/**
 * @description Generates a secure Set-Cookie header string with security attributes.
 * @param name - The cookie name.
 * @param value - The cookie value.
 * @param options - Cookie security options (httpOnly, secure, sameSite, maxAge, path, domain, expires).
 * @returns Set-Cookie header string with secure defaults applied.
 * @example
 * const cookie = secureCookie('session', 'abc123', { httpOnly: true, secure: true });
 */
export function secureCookie(
  name: string,
  value: string,
  options: SecureCookieOptions = {},
): string {
  const span = createSpan('msf.web.secureCookie');
  try {
    logger.debug({ name }, 'Generating secure cookie');
    if (!name || name.trim().length === 0) {
      throw new ValidationError('Cookie name cannot be empty', 'name');
    }
    if (name.includes(';') || name.includes(',') || name.includes('=')) {
      throw new ValidationError('Invalid characters in cookie name', 'name');
    }
    const {
      httpOnly = true, secure = true, sameSite = 'strict',
      maxAge, path = '/', domain, expires,
    } = options;
    const parts: string[] = [`${name}=${value}`];
    if (httpOnly) { parts.push('HttpOnly'); }
    if (secure) { parts.push('Secure'); }
    parts.push(`SameSite=${sameSite.charAt(0).toUpperCase() + sameSite.slice(1)}`);
    parts.push(`Path=${path}`);
    if (maxAge !== undefined) { parts.push(`Max-Age=${maxAge}`); }
    if (domain) { parts.push(`Domain=${domain}`); }
    if (expires) { parts.push(`Expires=${expires.toUTCString()}`); }
    const cookieHeader = parts.join('; ');
    metrics.incCounter('web.secureCookie');
    return cookieHeader;
  } catch (error) {
    if (error instanceof ValidationError) throw error;
    logger.error({ error }, 'Secure cookie generation failed');
    metrics.incCounter('web.secureCookie.error');
    throw new SecurityError('Secure cookie generation failed', 'SECURE_COOKIE_ERROR');
  } finally {
    span.end();
  }
}

// --- 25. detectClickjacking --------------------------------------------------

/**
 * @description Detects clickjacking vulnerabilities by checking response headers.
 * @param headers - The response headers to check for clickjacking protection.
 * @param frameOptions - Expected X-Frame-Options value ('DENY', 'SAMEORIGIN', or custom).
 * @returns Boolean indicating whether clickjacking protection is properly configured.
 * @example
 * const protected = detectClickjacking({ 'X-Frame-Options': 'DENY' }, 'DENY');
 */
export function detectClickjacking(
  headers: Record<string, string>,
  frameOptions: string = 'DENY',
): boolean {
  const span = createSpan('msf.web.detectClickjacking');
  try {
    logger.debug({ frameOptions }, 'Detecting clickjacking');
    const headerNames = Object.keys(headers).map(h => h.toLowerCase());
    const hasXFrameOptions = headerNames.includes('x-frame-options');
    const hasCspFrameAncestors = headerNames.includes('content-security-policy');
    if (hasXFrameOptions) {
      const xfoValue = headers['X-Frame-Options'] || headers['x-frame-options'] || '';
      if (
        xfoValue.toUpperCase() === frameOptions.toUpperCase() ||
        (frameOptions.toUpperCase() === 'DENY' && xfoValue.toUpperCase() === 'DENY') ||
        (frameOptions.toUpperCase() === 'SAMEORIGIN' && xfoValue.toUpperCase() === 'SAMEORIGIN')
      ) {
        metrics.incCounter('web.clickjacking.protected');
        return true;
      }
    }
    if (hasCspFrameAncestors) {
      const cspValue = headers['Content-Security-Policy'] || headers['content-security-policy'] || '';
      if (cspValue.includes('frame-ancestors')) {
        const frameAncestorsMatch = cspValue.match(/frame-ancestors\s+([^;]+)/i);
        if (frameAncestorsMatch) {
          const values = frameAncestorsMatch[1].trim().split(/\s+/);
          if (
            (frameOptions === 'DENY' && values.includes("'none'")) ||
            (frameOptions === 'SAMEORIGIN' && values.includes("'self'"))
          ) {
            metrics.incCounter('web.clickjacking.protected');
            return true;
          }
        }
      }
    }
    metrics.incCounter('web.clickjacking.vulnerable');
    return false;
  } catch (error) {
    logger.error({ error }, 'Clickjacking detection failed');
    metrics.incCounter('web.clickjacking.error');
    throw new SecurityError('Clickjacking detection failed', 'CLICKJACKING_DETECTION_ERROR');
  } finally {
    span.end();
  }
}

// --- 26. validateOrigin ------------------------------------------------------

/**
 * @description Validates an origin URL against a list of allowed origins.
 * @param origin - The origin URL to validate (e.g., 'https://example.com').
 * @param allowedOrigins - Array of allowed origin URLs (supports '*' for all).
 * @returns Boolean indicating whether the origin is allowed.
 * @example
 * const allowed = validateOrigin('https://example.com', ['https://example.com', 'https://app.example.com']);
 */
export function validateOrigin(
  origin: string,
  allowedOrigins: string[],
): boolean {
  const span = createSpan('msf.web.validateOrigin');
  try {
    logger.debug({ origin, allowedOriginsCount: allowedOrigins.length }, 'Validating origin');
    if (!origin) {
      metrics.incCounter('web.validateOrigin.missing');
      return false;
    }
    if (allowedOrigins.includes('*')) {
      metrics.incCounter('web.validateOrigin.wildcard');
      return true;
    }
    try {
      const parsedOrigin = new URL(origin);
      const originHost = parsedOrigin.origin.toLowerCase();
      const isAllowed = allowedOrigins.some(allowed => {
        if (allowed === '*') return true;
        try {
          const parsedAllowed = new URL(allowed);
          if (allowed.startsWith('*.')) {
            const suffix = allowed.slice(1);
            return originHost.endsWith(suffix.toLowerCase());
          }
          return originHost === parsedAllowed.origin.toLowerCase();
        } catch {
          return originHost === allowed.toLowerCase();
        }
      });
      if (isAllowed) { metrics.incCounter('web.validateOrigin.allowed'); }
      else { metrics.incCounter('web.validateOrigin.rejected'); }
      return isAllowed;
    } catch {
      const isAllowed = allowedOrigins.includes(origin);
      if (isAllowed) { metrics.incCounter('web.validateOrigin.allowed'); }
      else { metrics.incCounter('web.validateOrigin.rejected'); }
      return isAllowed;
    }
  } catch (error) {
    logger.error({ error }, 'Origin validation failed');
    metrics.incCounter('web.validateOrigin.error');
    throw new SecurityError('Origin validation failed', 'ORIGIN_VALIDATION_ERROR');
  } finally {
    span.end();
  }
}

// --- 27. validateReferer -----------------------------------------------------

/**
 * @description Validates the Referer header against an expected domain.
 * @param referer - The Referer header value from the request.
 * @param expectedDomain - The expected domain that the referer should belong to.
 * @returns Boolean indicating whether the referer is from the expected domain.
 * @example
 * const valid = validateReferer('https://example.com/page', 'example.com');
 */
export function validateReferer(
  referer: string | undefined,
  expectedDomain: string,
): boolean {
  const span = createSpan('msf.web.validateReferer');
  try {
    logger.debug({ referer, expectedDomain }, 'Validating referer');
    if (!referer) {
      metrics.incCounter('web.validateReferer.missing');
      return false;
    }
    try {
      const parsed = new URL(referer);
      const refererHost = parsed.hostname.toLowerCase();
      const expectedHost = expectedDomain.toLowerCase();
      const isValid = refererHost === expectedHost || refererHost.endsWith('.' + expectedHost);
      if (isValid) { metrics.incCounter('web.validateReferer.valid'); }
      else { metrics.incCounter('web.validateReferer.invalid'); }
      return isValid;
    } catch {
      metrics.incCounter('web.validateReferer.invalidUrl');
      return false;
    }
  } catch (error) {
    logger.error({ error }, 'Referer validation failed');
    metrics.incCounter('web.validateReferer.error');
    throw new SecurityError('Referer validation failed', 'REFERER_VALIDATION_ERROR');
  } finally {
    span.end();
  }
}

// --- 28. secureRedirect ------------------------------------------------------

/**
 * @description Validates and returns a safe redirect URL against allowed hosts.
 * @param url - The URL to redirect to.
 * @param allowedHosts - Array of hostnames that are allowed for redirects.
 * @returns The validated URL if safe, or throws SecurityError if not allowed.
 * @example
 * const safeUrl = secureRedirect('https://example.com/dashboard', ['example.com']);
 */
export function secureRedirect(
  url: string,
  allowedHosts: string[],
): string {
  const span = createSpan('msf.web.secureRedirect');
  try {
    logger.debug({ url, allowedHostsCount: allowedHosts.length }, 'Validating redirect URL');
    if (!url || url.trim().length === 0) {
      throw new ValidationError('Redirect URL cannot be empty', 'url');
    }
    try {
      const parsed = new URL(url);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new SecurityError('Invalid redirect protocol', 'INVALID_PROTOCOL');
      }
      const hostname = parsed.hostname.toLowerCase();
      const isAllowed = allowedHosts.some(host => {
        if (host.startsWith('*.')) {
          const suffix = host.slice(1);
          return hostname.endsWith(suffix.toLowerCase());
        }
        return hostname === host.toLowerCase();
      });
      if (!isAllowed) {
        logger.warn({ hostname, allowedHosts }, 'Redirect to disallowed host');
        metrics.incCounter('web.secureRedirect.rejected');
        throw new SecurityError(`Redirect to disallowed host: ${hostname}`, 'DISALLOWED_HOST');
      }
      if (parsed.hostname.includes('@')) {
        throw new SecurityError('URL contains credentials', 'URL_WITH_CREDENTIALS');
      }
      const redirectPatterns = [/\/\/[^/]/, /%2f%2f/i, /%5c/i, /javascript:/i, /data:/i, /vbscript:/i];
      for (const pattern of redirectPatterns) {
        if (pattern.test(url)) {
          throw new SecurityError('Suspicious redirect pattern detected', 'SUSPICIOUS_PATTERN');
        }
      }
      metrics.incCounter('web.secureRedirect.allowed');
      return url;
    } catch (error) {
      if (error instanceof SecurityError) throw error;
      if (error instanceof ValidationError) throw error;
      throw new SecurityError('Invalid redirect URL', 'INVALID_URL');
    }
  } catch (error) {
    if (error instanceof SecurityError) throw error;
    if (error instanceof ValidationError) throw error;
    logger.error({ error }, 'Secure redirect validation failed');
    metrics.incCounter('web.secureRedirect.error');
    throw new SecurityError('Secure redirect validation failed', 'SECURE_REDIRECT_ERROR');
  } finally {
    span.end();
  }
}

// --- 29. webhookSignature ----------------------------------------------------

/**
 * @description Generates an HMAC signature for webhook payload verification.
 * @param payload - The raw webhook payload string to sign.
 * @param secret - The shared secret key for HMAC signing.
 * @param algorithm - The hashing algorithm to use ('sha256', 'sha384', 'sha512', 'sha3-256').
 * @param timestamp - Optional Unix timestamp to include in the signature for replay protection.
 * @returns HMAC signature string in hex format, optionally prefixed with timestamp.
 * @example
 * const sig = webhookSignature('{"event":"push"}', 'secret-key', 'sha256', Date.now());
 */
export function webhookSignature(
  payload: string,
  secret: string,
  algorithm: 'sha256' | 'sha384' | 'sha512' | 'sha3-256' = 'sha256',
  timestamp?: number,
): string {
  const span = createSpan('msf.web.webhookSignature');
  try {
    logger.debug({ algorithm, hasTimestamp: !!timestamp }, 'Generating webhook signature');
    if (!payload) { throw new ValidationError('Payload cannot be empty', 'payload'); }
    if (!secret) { throw new ValidationError('Secret cannot be empty', 'secret'); }
    let signature: string;
    if (algorithm === 'sha3-256') {
      const hash = sha3_256(Buffer.from(payload + (timestamp || ''), 'utf8'));
      signature = Buffer.from(hash).toString('hex');
    } else {
      const hmac = createHmac(algorithm, secret);
      hmac.update(payload);
      if (timestamp) { hmac.update(String(timestamp)); }
      signature = hmac.digest('hex');
    }
    const result = timestamp ? `${timestamp}.${signature}` : signature;
    metrics.incCounter('web.webhookSignature');
    return result;
  } catch (error) {
    if (error instanceof ValidationError) throw error;
    logger.error({ error }, 'Webhook signature generation failed');
    metrics.incCounter('web.webhookSignature.error');
    throw new SecurityError('Webhook signature generation failed', 'WEBHOOK_SIGNATURE_ERROR');
  } finally {
    span.end();
  }
}

// --- 30. webhookReplayProtection ---------------------------------------------

/**
 * @description Validates webhook signature with timestamp-based replay protection.
 * @param signature - The signature to validate (format: 'timestamp.signature' or just 'signature').
 * @param timestamp - The timestamp to validate against (Unix milliseconds).
 * @param payload - The raw webhook payload that was signed.
 * @param secret - The shared secret key used for signing.
 * @param window - Maximum age in milliseconds for the signature to be considered valid.
 * @returns Boolean indicating whether the signature is valid and within the time window.
 * @example
 * const valid = webhookReplayProtection('1234567890.abcdef...', 1234567890, payload, 'secret', 300000);
 */
export function webhookReplayProtection(
  signature: string,
  timestamp: number,
  payload: string,
  secret: string,
  window: number = 300000,
): boolean {
  const span = createSpan('msf.web.webhookReplayProtection');
  try {
    logger.debug({ window }, 'Validating webhook replay protection');
    if (!signature || !payload || !secret) {
      logger.warn('Missing required parameters for replay protection');
      metrics.incCounter('web.webhookReplay.missingParams');
      return false;
    }
    const now = Date.now();
    const timeDiff = Math.abs(now - timestamp);
    if (timeDiff > window) {
      logger.warn({ timeDiff, window }, 'Signature outside time window');
      metrics.incCounter('web.webhookReplay.expired');
      return false;
    }
    const expectedSignature = webhookSignature(payload, secret, 'sha256', timestamp);
    const sigParts = signature.split('.');
    const sigHash = sigParts.length > 1 ? sigParts[1] : sigParts[0];
    const expectedParts = expectedSignature.split('.');
    const expectedHash = expectedParts.length > 1 ? expectedParts[1] : expectedParts[0];
    try {
      const sigBuffer = Buffer.from(sigHash, 'hex');
      const expectedBuffer = Buffer.from(expectedHash, 'hex');
      if (sigBuffer.length !== expectedBuffer.length) {
        metrics.incCounter('web.webhookReplay.invalid');
        return false;
      }
      const isValid = timingSafeEqual(sigBuffer, expectedBuffer);
      if (isValid) { metrics.incCounter('web.webhookReplay.valid'); }
      else { metrics.incCounter('web.webhookReplay.invalid'); }
      return isValid;
    } catch {
      metrics.incCounter('web.webhookReplay.invalid');
      return false;
    }
  } catch (error) {
    logger.error({ error }, 'Webhook replay protection failed');
    metrics.incCounter('web.webhookReplay.error');
    throw new SecurityError('Webhook replay protection failed', 'WEBHOOK_REPLAY_ERROR');
  } finally {
    span.end();
  }
}
