# Master Security Framework (MSF)

> **Comprehensive, multi-language, multi-layer security framework for modern applications.**

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://typescriptlang.org)
[![Tests](https://img.shields.io/badge/Tests-243%20passing-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Installation](#installation)
4. [Python Modules](#python-modules)
   - [Core](#python-core)
   - [Auth](#python-auth)
   - [Crypto](#python-crypto)
   - [Web](#python-web)
   - [API](#python-api)
   - [AI](#python-ai)
   - [Network](#python-network)
   - [Cloud](#python-cloud)
   - [Monitoring](#python-monitoring)
   - [Defensive](#python-defensive)
   - [Honeypot](#python-honeypot)
   - [File](#python-file)
   - [Enterprise](#python-enterprise)
   - [Integrations](#python-integrations)
5. [TypeScript Modules](#typescript-modules)
   - [Core](#ts-core)
   - [Auth](#ts-auth)
   - [Crypto](#ts-crypto)
   - [Web](#ts-web)
   - [API](#ts-api)
   - [AI](#ts-ai)
   - [Network](#ts-network)
   - [Cloud](#ts-cloud)
   - [Monitoring](#ts-monitoring)
   - [Defensive](#ts-defensive)
   - [Honeypot](#ts-honeypot)
   - [File](#ts-file)
   - [Enterprise](#ts-enterprise)
   - [Integrations](#ts-integrations)
6. [Usage Guide](#usage-guide)
7. [Telemetry & Observability](#telemetry--observability)
8. [Contributing](#contributing)

---

## Overview

The **Master Security Framework (MSF)** is a complete security framework designed to protect applications across multiple layers: from authentication and cryptography to web attack detection, network analysis, cloud security, AI protection, and much more.

### Key Features

- **243 tests passing** (77 Python + 166 TypeScript)
- **14 Python modules** with 180+ functions
- **14 TypeScript modules** with 170+ functions
- **OpenTelemetry** integration built-in
- **Structured metrics and logging** with pino/loguru
- **In-memory cache** with automatic invalidation
- **Policy Engine** for configurable security rules
- **Event Bus** for async inter-module communication
- **Post-quantum cryptography** support (Kyber, Dilithium, SPHINCS+, Falcon)
- **Real-time attack detection** (XSS, SQLi, SSRF, RCE, DDoS, etc.)
- **Adaptive honeypots** and honeytokens
- **Enterprise compliance** (LGPD, GDPR, HIPAA, PCI-DSS)
- **Integrations** with FastAPI, Django, Flask, Express, Next.js, NestJS, Cloudflare, and more

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Master Security Framework                    │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │  Core    │ │ Telemetry│ │ Metrics  │ │  Events  │           │
│  │ Config   │ │ OpenTelemetry│ │Registry│ │  Bus     │           │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │  Cache   │ │  Policy  │ │  Logger  │ │Exceptions│           │
│  │ Manager  │ │  Engine  │ │ pino/loguru│ │ Security │           │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │  Auth    │ │  Crypto  │ │   Web    │ │   API    │           │
│  │ JWT/TOTP │ │ AES/ChaCha│ │ XSS/SQLi │ │ Rate Lim │           │
│  │ Passkeys │ │ PQC/HMAC  │ │ SSRF/RCE │ │ GraphQL  │           │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │   AI     │ │ Network  │ │  Cloud   │ │Monitoring│           │
│  │Injection │ │ PortScan │ │ Docker   │ │ Anomaly  │           │
│  │Jailbreak │ │ DDoS/DNS │ │ K8s/S3   │ │ UEBA     │           │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │Defensive │ │ Honeypot │ │   File   │ │Enterprise│           │
│  │Anti-Debug│ │ Fake SSH │ │ Malware  │ │ LGPD/GDPR│           │
│  │Integrity │ │ Honeytok │ │ ZipBomb  │ │ HIPAA/PCI│           │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────┐       │
│  │                  Integrations                         │       │
│  │  FastAPI · Django · Flask · Express · Next.js ·      │       │
│  │  NestJS · Cloudflare · Deno · Bun · WASM             │       │
│  └──────────────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

---

## Installation

### Python

```bash
cd master_security_python
pip install -e .
```

### TypeScript

```bash
cd packages/core
npm install
npm run build
```

---

## Python Modules

### Python: Core

Base module with configuration, logging, telemetry, metrics, cache, policy engine, and event bus.

#### Functions

- `get_config() -> dict`: Gets the global framework configuration with default values and environment variables.
- `set_config(config: dict) -> None`: Sets the global framework configuration.
- `reload_config() -> dict`: Reloads configuration from environment variables.
- `get_logger(name: str, level: str) -> logging.Logger`: Gets a structured logger with context.
- `get_metrics() -> MetricsRegistry`: Gets the global metrics registry.
- `get_policy_engine() -> PolicyEngine`: Gets the security policy engine.
- `get_event_bus() -> EventBus`: Gets the async event bus.
- `get_cache() -> CacheManager`: Gets the in-memory cache manager.
- `get_telemetry() -> TelemetryManager`: Gets the OpenTelemetry manager.
- `create_span(name: str, attributes: dict) -> Span`: Creates an OpenTelemetry tracing span.

---

### Python: Auth (30 functions)

Complete authentication: JWT, TOTP, WebAuthn/Passkeys, credential stuffing detection, brute force, session hijacking, token replay, impossible travel, behavioral analysis, and password breach checking.

#### Functions

- `validate_jwt(token: str, secret: str, algorithms: Optional[list[str]], verify_exp: bool, required_claims: Optional[dict[str, Any]]) -> dict`: Validates and decodes a JWT token. Verifies signature, expiration, required claims, and returns the decoded payload.

- `generate_jwt(subject: str, secret: str, algorithm: str, expiry: int, claims: Optional[dict[str, Any]], issuer: Optional[str]) -> str`: Generates a signed JWT token with subject, custom claims, expiry, and issuer.

- `revoke_jwt(token_id: str, reason: str) -> bool`: Revokes a JWT by its JTI (JWT ID). Adds to the revocation blacklist.

- `rotate_jwt(old_token: str, secret: str, algorithm: str, expiry: int) -> str`: Rotates a JWT by validating the old token and issuing a new one with the same identity.

- `validate_refresh_token(token: str, secret: str, user_id: str) -> dict`: Validates a refresh token for a specific user, checking ownership and expiration.

- `secure_session(user_id: str, ip: str, user_agent: str, device_id: Optional[str]) -> dict`: Creates a secure session for an authenticated user, recording IP, user agent, and device fingerprint.

- `validate_session(session_id: str, user_id: str, ip: str) -> bool`: Validates an existing session by checking session_id ownership and IP match.

- `detect_session_hijack(session_id: str, current_ip: str, current_ua: str, historical_data: dict) -> bool`: Detects potential session hijacking by comparing current IP and user agent against historical data.

- `detect_token_replay(token_id: str, timestamp: float, ip: str) -> bool`: Detects if a token is being replayed by checking if it has been used before.

- `detect_credential_stuffing(ip: str, username: str, attempts: int, window: int) -> bool`: Detects credential stuffing attacks from a single IP based on attempts within a time window.

- `detect_bruteforce(ip: str, attempts: int, window: int, threshold: int) -> bool`: Detects brute force login attempts from a single IP when exceeding the threshold in the window.

- `adaptive_auth(user_id: str, risk_score: float, context: dict) -> dict`: Performs adaptive authentication based on risk score and context (location, device, time).

- `behavioral_auth(user_id: str, behavior_data: dict, baseline: dict) -> float`: Assesses authentication based on behavioral biometrics compared to user baseline.

- `impossible_travel(user_id: str, current_location: dict, last_location: dict, time_delta: float) -> bool`: Detects impossible travel between two login locations based on distance and time.

- `geo_velocity_check(user_id: str, locations: list[dict], max_speed_kmh: float) -> bool`: Checks geographic velocity across multiple login locations against maximum allowed speed.

- `risk_based_auth(user_id: str, context: dict, risk_factors: dict) -> dict`: Performs risk-based authentication calculating score from multiple risk factors.

- `passkey_auth(challenge: str, authenticator_data: bytes, client_data_json: str, signature: bytes) -> bool`: Validates a passkey (FIDO2/WebAuthn) authentication response by verifying signature and authenticator data.

- `webauthn_verify(credential_id: str, challenge: str, origin: str, rp_id: str, public_key: bytes, signature: bytes, auth_data: bytes, client_data: str) -> bool`: Verifies a complete WebAuthn assertion with origin, RP ID, and cryptographic signature validation.

- `generate_totp(secret: str, digits: int, period: int, time_step: Optional[int]) -> str`: Generates a TOTP (Time-based One-Time Password) code with configurable digits and period.

- `validate_totp(secret: str, token: str, digits: int, period: int, drift: int) -> bool`: Validates a TOTP token with clock drift tolerance to compensate for desynchronization.

- `verify_backup_code(code: str, valid_codes: list[str]) -> bool`: Verifies a backup/recovery code and consumes it (removes from valid list).

- `password_entropy(password: str) -> float`: Calculates the Shannon entropy of a password to measure informational complexity.

- `detect_weak_password(password: str, min_entropy: float, common_passwords: Optional[list[str]]) -> bool`: Detects if a password is weak based on low entropy and presence in common password lists.

- `password_breach_check(password_hash: str, breach_db: dict[str, int]) -> bool`: Checks if a password hash appears in a known breach database.

- `secure_password_hash(password: str, algorithm: str, salt: Optional[str], iterations: int) -> str`: Creates a secure password hash with salt and key stretching (iterations) for brute force resistance.

- `verify_password_hash(password: str, hash_value: str) -> bool`: Verifies a password against a stored hash using secure comparison.

- `device_fingerprint(user_agent: str, screen: str, timezone: str, languages: list[str], platform: str) -> str`: Generates a device fingerprint from browser/system attributes.

- `browser_fingerprint(canvas_hash: str, webgl_hash: str, audio_hash: str, fonts: list[str]) -> str`: Generates a browser fingerprint from rendering characteristics (canvas, WebGL, audio, fonts).

- `biometric_validation(biometric_data: dict, stored_template: dict, threshold: float) -> bool`: Validates biometric data against a stored template with similarity threshold.

- `phishing_resistant_auth(auth_method: str, fido_level: str, attestation: Optional[dict]) -> bool`: Verifies if an authentication method is phishing-resistant (FIDO2 level 2+).

---

### Python: Crypto (20 functions)

Authenticated encryption (AES-GCM, ChaCha20-Poly1305), hybrid encryption, post-quantum cryptography (Kyber, Dilithium, SPHINCS+, Falcon), HMAC, secure key generation, and timing attack protection.

#### Functions

- `encrypt_data(plaintext: bytes, key: bytes, algorithm: str, aad: Optional[bytes]) -> dict[str, Any]`: Encrypts data using authenticated encryption (AES-GCM or ChaCha20-Poly1305) with associated data support.

- `decrypt_data(ciphertext: bytes, key: bytes, nonce: bytes, algorithm: str, aad: Optional[bytes]) -> bytes`: Decrypts data using authenticated decryption, verifying integrity and authenticity.

- `encrypt_file(filepath: str, key: bytes, output_path: Optional[str], algorithm: str) -> str`: Encrypts a file on disk using authenticated encryption, returning the output path.

- `decrypt_file(filepath: str, key: bytes, output_path: Optional[str], algorithm: str) -> str`: Decrypts a file on disk verifying integrity before returning content.

- `generate_keypair(algorithm: str, curve: Optional[str]) -> dict[str, Any]`: Generates an asymmetric key pair for signing or key exchange (Ed25519, X25519, etc.).

- `rotate_keys(old_key: bytes, new_key: bytes, algorithm: str) -> dict[str, Any]`: Rotates encryption keys by re-encrypting a test payload with the new key.

- `secure_random(nbytes: int) -> bytes`: Generates cryptographically secure random bytes using `os.urandom()`.

- `hybrid_encrypt(plaintext: bytes, public_key: bytes, algorithm: str) -> dict[str, Any]`: Encrypts using hybrid scheme: asymmetric key exchange + symmetric payload encryption.

- `hybrid_decrypt(encrypted_data: dict[str, Any], private_key: bytes, algorithm: str) -> bytes`: Decrypts data encrypted with hybrid scheme, recovering the original plaintext.

- `pqc_encrypt(plaintext: bytes, public_key: bytes, algorithm: str) -> dict[str, Any]`: Encrypts using post-quantum algorithm (ML-KEM/Kyber) resistant to quantum computers.

- `pqc_decrypt(encrypted_data: dict[str, Any], private_key: bytes, algorithm: str) -> bytes`: Decrypts data encrypted with post-quantum algorithm.

- `kyber_key_exchange(public_key: bytes, private_key: bytes) -> dict[str, Any]`: Performs Kyber-based (ML-KEM) post-quantum key exchange for shared key establishment.

- `dilithium_sign(message: bytes, private_key: bytes) -> dict[str, Any]`: Signs a message using Dilithium (ML-DSA), NIST post-quantum signature scheme.

- `sphincs_sign(message: bytes, private_key: bytes) -> dict[str, Any]`: Signs a message using SPHINCS+, hash-based post-quantum signature scheme.

- `falcon_sign(message: bytes, private_key: bytes) -> dict[str, Any]`: Signs a message using Falcon, lattice-based post-quantum signature scheme.

- `verify_signature(message: bytes, signature: bytes, public_key: bytes, algorithm: str) -> bool`: Verifies a digital signature against a message and public key.

- `generate_hmac(data: bytes, key: bytes, algorithm: str) -> str`: Generates an HMAC (Hash-based Message Authentication Code) for integrity authentication.

- `verify_hmac(data: bytes, signature: str, key: bytes, algorithm: str) -> bool`: Verifies an HMAC by comparing expected signature with calculated one.

- `secure_memory_erase(data: bytearray) -> None`: Securely erases sensitive data from memory by overwriting with zeros.

- `anti_timing_compare(a: bytes, b: bytes) -> bool`: Compares two byte strings in constant time to prevent timing attacks.

---

### Python: Web (30 functions)

Web attack detection and prevention: XSS, SQL Injection, NoSQL Injection, SSRF, RCE, LFI, RFI, SSTI, Command Injection, Deserialization, Path Traversal, Open Redirect, Clickjacking, CSRF, CORS, and HTML/SVG/Markdown/CSS/JS sanitization.

#### Functions

- `detect_xss(input_str: str, patterns: Optional[list[str]], severity_threshold: str) -> dict[str, Any]`: Detects Cross-Site Scripting (XSS) attack patterns including script tags, event handlers, javascript: URIs, and DOM XSS.

- `sanitize_html(html_str: str, allowed_tags: Optional[list[str]], allowed_attrs: Optional[list[str]]) -> str`: Sanitizes HTML by removing disallowed tags and attributes, preventing XSS via HTML injection.

- `sanitize_svg(svg: str, allowed_elements: Optional[list[str]]) -> str`: Sanitizes SVG content by removing dangerous elements and attributes like `<script>`, `onload`, and event handlers.

- `sanitize_markdown(markdown: str, allowed_html: Optional[list[str]]) -> str`: Sanitizes markdown by removing dangerous embedded HTML while preserving markdown formatting.

- `sanitize_css(css: str, allowed_properties: Optional[list[str]]) -> str`: Sanitizes CSS by removing dangerous properties like `expression()`, `url(javascript:)`, and `behavior`.

- `sanitize_js(js_code: str, dangerous_patterns: Optional[list[str]]) -> str`: Sanitizes JavaScript by removing dangerous patterns like `eval()`, `Function()`, `document.write()`, etc.

- `detect_sqli(input_str: str, patterns: Optional[list[str]], context: Optional[str]) -> dict[str, Any]`: Detects SQL Injection patterns including UNION-based, blind, time-based, and error-based injection.

- `detect_nosqli(input_str: str, patterns: Optional[list[str]]) -> dict[str, Any]`: Detects NoSQL Injection in MongoDB/NoSQL queries using operators like `$gt`, `$ne`, `$regex`.

- `detect_ssrf(url: str, allowed_domains: Optional[list[str]], blocked_ips: Optional[list[str]]) -> dict[str, Any]`: Detects Server-Side Request Forgery by verifying URLs against allowed domains and blocked IPs (including localhost, metadata endpoints).

- `detect_rce(input_str: str, patterns: Optional[list[str]]) -> dict[str, Any]`: Detects Remote Code Execution patterns including `eval()`, `exec()`, `system()`, backticks, and pipe operators.

- `detect_lfi(input_str: str, patterns: Optional[list[str]]) -> dict[str, Any]`: Detects Local File Inclusion using path traversal like `../../etc/passwd`, `php://filter`, and `data://` URIs.

- `detect_rfi(input_str: str, patterns: Optional[list[str]]) -> dict[str, Any]`: Detects Remote File Inclusion via external URLs in include/require parameters.

- `detect_template_injection(input_str: str, engine_type: str) -> dict[str, Any]`: Detects Server-Side Template Injection (SSTI) for Jinja2, EJS, Handlebars, Pug, Twig, etc.

- `detect_command_injection(input_str: str, patterns: Optional[list[str]]) -> dict[str, Any]`: Detects OS Command Injection using operators like `;`, `|`, `&&`, `||`, backticks, and `$()`.

- `detect_deserialization_attack(data: Any, allowed_classes: Optional[list[str]]) -> dict[str, Any]`: Detects insecure deserialization by verifying allowed classes and known gadget patterns.

- `detect_path_traversal(input_str: str, base_path: Optional[str]) -> dict[str, Any]`: Detects path traversal using `../`, `..\\`, encoded traversal, and verifies path resolves within base_path.

- `detect_open_redirect(url: str, allowed_hosts: Optional[list[str]]) -> dict[str, Any]`: Detects open redirect by verifying redirect URL points to an allowed host.

- `validate_cors(origin: str, allowed_origins: Optional[list[str]], allowed_methods: Optional[list[str]], allowed_headers: Optional[list[str]]) -> dict[str, Any]`: Validates CORS request by checking Origin, Methods, and Headers against allowed lists.

- `secure_headers(request: Optional[dict[str, Any]], config: Optional[dict[str, Any]]) -> dict[str, str]`: Generates secure HTTP response headers including HSTS, X-Frame-Options, X-Content-Type-Options, CSP, Referrer-Policy, etc.

- `generate_csp(config: Optional[dict[str, Any]]) -> str`: Generates a Content-Security-Policy header value from directive configuration.

- `validate_csp(csp_header: str, policy: Optional[dict[str, Any]]) -> bool`: Validates a CSP header against a defined security policy.

- `csrf_protect(request: Optional[dict[str, Any]], token: Optional[str], session_token: Optional[str]) -> bool`: Protects against CSRF by verifying request token against session token.

- `validate_csrf(token: Optional[str], session_token: Optional[str]) -> bool`: Validates a CSRF token against the session token using secure comparison.

- `secure_cookie(name: str, value: str, domain: Optional[str], path: str, secure: bool, httponly: bool, samesite: str, max_age: Optional[int]) -> str`: Generates a secure Set-Cookie header with Secure, HttpOnly, SameSite flags and domain scoping.

- `detect_clickjacking(headers: Optional[dict[str, str]], frame_options: Optional[str]) -> bool`: Detects clickjacking vulnerability by checking absence of X-Frame-Options or CSP frame-ancestors.

- `validate_origin(origin: str, allowed_origins: Optional[list[str]]) -> bool`: Validates the Origin header against a list of allowed origins.

- `validate_referer(referer: str, expected_domain: str) -> bool`: Validates the Referer header against an expected domain to prevent CSRF and hotlinking.

- `secure_redirect(url: str, allowed_hosts: Optional[list[str]]) -> str`: Validates and returns a safe redirect URL, preventing open redirect.

- `webhook_signature(payload: str, secret: str, algorithm: str, timestamp: Optional[str]) -> str`: Generates an HMAC signature for webhook payload verification.

- `webhook_replay_protection(signature: str, timestamp: str, payload: str, secret: str, window: int) -> bool`: Protects against webhook replay by verifying signature and timestamp within a window.

---

### Python: API (18 functions)

API security: JSON Schema validation, sanitization, adaptive rate limiting, BOLA/IDOR detection, broken authentication, mass assignment, shadow APIs, GraphQL security (depth limit, cost analysis, abuse detection), gRPC security, WebSocket security, and API key management.

#### Functions

- `validate_json_schema(data: Any, schema: dict[str, Any], strict_mode: bool) -> dict[str, Any]`: Validates data against a JSON Schema definition with optional strict mode for extra fields.

- `validate_input(data: Any, rules: dict[str, Any], max_depth: int, max_size: int) -> dict[str, Any]`: Validates API input data against type, size, pattern, enum, and maximum depth rules.

- `sanitize_json(data: Any, allowed_types: Optional[set[str]], max_string_length: int) -> dict[str, Any]`: Sanitizes JSON data by removing disallowed types and truncating long strings.

- `api_rate_limit(client_id: str, endpoint: str, config: Optional[dict[str, Any]]) -> dict[str, Any]`: Enforces API rate limiting using sliding window algorithm with configurable per-client and per-endpoint limits.

- `adaptive_rate_limit(client_id: str, endpoint: str, behavior: dict[str, Any], config: Optional[dict[str, Any]]) -> dict[str, Any]`: Applies adaptive rate limiting based on client behavior patterns (dynamically adjusts limits).

- `detect_api_abuse(requests: list[dict[str, Any]], patterns: Optional[list[str]], window: int) -> dict[str, Any]`: Detects API abuse patterns such as scraping, enumeration, fuzzing, and malicious automation.

- `detect_bola(resource_id: str, user_id: str, ownership_map: dict[str, Any]) -> bool`: Detects Broken Object Level Authorization (BOLA/IDOR) by verifying user access to the requested resource.

- `detect_broken_auth(auth_header: Optional[str], required_scopes: Optional[list[str]], token: Optional[dict[str, Any]]) -> dict[str, Any]`: Detects authentication and authorization issues such as missing, expired, or insufficient-scope tokens.

- `detect_mass_assignment(input_data: dict[str, Any], model_fields: set[str], readonly_fields: Optional[set[str]]) -> dict[str, Any]`: Detects mass assignment by checking if protected or unknown fields are being submitted.

- `detect_shadow_api(endpoint: str, documented_apis: set[str], traffic_patterns: dict[str, Any]) -> dict[str, Any]`: Detects shadow APIs - undocumented endpoints receiving traffic.

- `api_threat_score(request: dict[str, Any], context: Optional[dict[str, Any]], threat_intel: Optional[dict[str, Any]]) -> float`: Calculates composite threat score for an API request based on context and threat intelligence.

- `graphql_depth_limit(query: str, max_depth: int, introspection_enabled: bool) -> dict[str, Any]`: Validates GraphQL query depth against configured limit, preventing malicious recursive queries.

- `graphql_cost_analysis(query: str, complexity_map: Optional[dict[str, int]], max_cost: int) -> dict[str, Any]`: Analyzes computational cost of GraphQL query based on field complexity and nested queries.

- `graphql_abuse_detection(queries: list[dict[str, Any]], window: int, thresholds: Optional[dict[str, Any]]) -> dict[str, Any]`: Detects GraphQL abuse patterns such as query flooding, introspection abuse, and repeated high-cost queries.

- `grpc_security_validation(metadata: dict[str, str], required_headers: Optional[list[str]], tls_info: Optional[dict[str, Any]]) -> dict[str, Any]`: Validates gRPC request security by checking metadata, required headers, and TLS information.

- `secure_websocket(origin: Optional[str], allowed_origins: Optional[list[str]], subprotocols: Optional[list[str]]) -> dict[str, Any]`: Configures and validates secure WebSocket connection with origin validation and allowed subprotocols.

- `api_key_rotation(current_key: str, algorithm: str, expiry_days: int) -> dict[str, Any]`: Generates a new API key with secure rotation parameters (hash, expiry, prefix).

- `api_key_validation(api_key: str, valid_keys: dict[str, Any], scopes: Optional[list[str]], required_scope: Optional[str]) -> dict[str, Any]`: Validates an API key against a registry of known keys, checking scopes and expiration.

---

### Python: AI (20 functions)

AI application protection: prompt injection detection, jailbreak, sensitive data leak, system prompt leak, data exfiltration, impersonation, model abuse, agent abuse, LLM firewall, policy engine, RAG source validation, hallucination risk, output guardrails, tool call validation, multi-agent isolation, memory sanitization, token monitoring, and behavior monitoring.

#### Functions

- `detect_prompt_injection(prompt: str, patterns: Optional[list[str]], threshold: float) -> dict[str, Any]`: Detects prompt injection attempts such as "ignore previous instructions", "forget all rules", "system:", "you are now", etc.

- `detect_jailbreak(prompt: str, patterns: Optional[list[str]], threshold: float) -> dict[str, Any]`: Detects jailbreaks such as DAN mode, "do anything now", "disable safety", "unrestricted mode", unfiltered roleplay.

- `sanitize_prompt(prompt: str, max_length: int, blocked_patterns: Optional[list[str]]) -> str`: Sanitizes user prompt by removing blocked patterns and enforcing length limits.

- `sanitize_llm_output(output: str, max_length: int, blocked_patterns: Optional[list[str]]) -> str`: Sanitizes LLM output by removing scripts, event handlers, and sensitive data.

- `detect_sensitive_leak(text: str, patterns: Optional[list[str]]) -> dict[str, Any]`: Detects sensitive data leaks such as SSN, CPF, credit cards, emails, API keys, passwords.

- `detect_prompt_leak(prompt: str, system_prompt: str, threshold: float) -> dict[str, Any]`: Detects attempts to extract or leak the system prompt using content similarity.

- `detect_data_exfiltration(output: str, sensitive_patterns: Optional[list[str]]) -> dict[str, Any]`: Detects potential data exfiltration in LLM output using sensitive data pattern matching.

- `detect_ai_impersonation(content: str, claimed_identity: str, markers: Optional[list[str]]) -> dict[str, Any]`: Detects AI impersonation attempts by verifying identity markers and inconsistencies.

- `detect_model_abuse(request_patterns: list[str], rate: float, complexity: float) -> dict[str, Any]`: Detects model abuse via excessive repetition, high request rate, and abnormal complexity.

- `detect_agent_abuse(agent_behavior: dict[str, Any], policy: dict[str, Any], thresholds: Optional[dict[str, float]]) -> dict[str, Any]`: Detects agent behavior that violates usage policies and configured thresholds.

- `llm_firewall(input_data: dict[str, Any], rules: list[dict[str, Any]], action_on_violation: str) -> dict[str, Any]`: Evaluates input against LLM firewall rules with configurable actions (block, warn, log).

- `ai_policy_engine(prompt: str, output: str, policies: list[dict[str, Any]]) -> dict[str, Any]`: Evaluates prompt and output against a set of AI security policies.

- `rag_source_validation(sources: list[dict[str, Any]], trusted_domains: Optional[list[str]], validation_rules: Optional[dict[str, Any]]) -> dict[str, Any]`: Validates RAG (Retrieval-Augmented Generation) source credibility against trusted domains.

- `hallucination_risk(output: str, confidence_scores: Optional[list[float]], factual_checks: Optional[list[dict[str, Any]]]) -> dict[str, Any]`: Assesses hallucination risk in LLM output based on confidence scores and factual checks.

- `ai_output_guard(output: str, guardrails: Optional[list[dict[str, Any]]], redaction_rules: Optional[list[dict[str, Any]]]) -> str`: Applies guardrails and redaction rules to LLM output.

- `tool_call_validation(tool_name: str, arguments: dict[str, Any], allowed_tools: list[str], argument_schemas: Optional[dict[str, dict[str, Any]]]) -> dict[str, Any]`: Validates tool call against allowed tools and argument schemas.

- `multi_agent_isolation(agents: list[dict[str, Any]], communication_rules: Optional[dict[str, Any]]) -> dict[str, Any]`: Validates multi-agent isolation and communication policies.

- `ai_memory_sanitizer(memory_entries: list[dict[str, Any]], retention_policy: Optional[dict[str, Any]]) -> list[dict[str, Any]]`: Sanitizes AI memory entries based on retention policy and expiration.

- `ai_token_monitor(usage: dict[str, int], limits: Optional[dict[str, int]], window: int) -> dict[str, Any]`: Monitors AI token usage against defined limits (per request, minute, day, cost).

- `ai_behavior_monitor(behavior_log: list[dict[str, Any]], baseline: Optional[dict[str, Any]], deviation_threshold: float) -> dict[str, Any]`: Monitors AI behavior for deviations from established baseline.

---

### Python: Network (21 functions)

Network security: port scan detection, DNS tunneling, traffic anomalies, proxy/VPN/Tor detection, DDoS, IP/domain validation, IP spoofing, ARP poisoning, TLS fingerprinting (JA3), beaconing detection (C2), lateral movement, C2 communication detection, network entropy analysis, traffic behavior analysis, and protocol anomaly detection.

#### Functions

- `detect_port_scan(source_ip: str, connections: list[dict[str, Any]], window: float, threshold: int) -> dict[str, Any]`: Detects port scanning activity by analyzing unique ports, connection rate, SYN/RST patterns.

- `detect_dns_tunneling(dns_queries: list[dict[str, Any]], domain: str, threshold: float) -> dict[str, Any]`: Detects DNS tunneling by analyzing query entropy, subdomain size, and frequency.

- `detect_traffic_anomaly(traffic_data: list[dict[str, Any]], baseline: dict[str, float], deviation_threshold: float) -> dict[str, Any]`: Detects traffic anomalies by comparing current metrics against baseline using z-score.

- `detect_proxy(ip: str, headers: dict[str, str], detection_methods: Optional[list[str]]) -> dict[str, Any]`: Detects if a connection comes through a proxy by checking headers like X-Forwarded-For, Via, etc.

- `detect_vpn(ip: str, headers: dict[str, str], vpn_db: Optional[dict[str, Any]]) -> dict[str, Any]`: Detects if an IP originates from a VPN service using a known IP database.

- `detect_tor(ip: str, tor_nodes: Optional[list[str]], exit_nodes: Optional[list[str]]) -> dict[str, Any]`: Detects if an IP belongs to the Tor network by checking against node and exit node lists.

- `detect_ddos(traffic_data: list[dict[str, Any]], baseline: dict[str, float], threshold: float, window: float) -> dict[str, Any]`: Detects DDoS attacks by analyzing bytes/packets per second against baseline and threshold.

- `validate_ip(ip: str, allowed_ranges: Optional[list[str]], blocked_ranges: Optional[list[str]]) -> dict[str, Any]`: Validates IP address against allowed and blocked ranges using CIDR matching.

- `validate_domain(domain: str, allowed_tlds: Optional[list[str]], blocked_domains: Optional[list[str]]) -> dict[str, Any]`: Validates domain by checking TLD against allowed list and domain against blocked list.

- `detect_spoofing(packet_data: dict[str, Any], expected_source: str, network_topology: dict[str, Any]) -> dict[str, Any]`: Detects IP spoofing by analyzing packet data against expected sources and network topology.

- `detect_arp_poisoning(arp_table: list[dict[str, Any]], expected_mappings: dict[str, str]) -> dict[str, Any]`: Detects ARP poisoning by comparing current ARP table against expected IP-to-MAC mappings.

- `tls_fingerprint(tls_handshake: dict[str, Any], ja3_database: Optional[dict[str, Any]]) -> dict[str, Any]`: Generates and matches TLS fingerprint from handshake data against known fingerprint database.

- `ja3_fingerprint(tls_client_hello: dict[str, Any]) -> str`: Generates a JA3 fingerprint hash from a TLS ClientHello for TLS client identification.

- `suspicious_dns_detection(dns_queries: list[dict[str, Any]], threat_intel: Optional[dict[str, Any]], patterns: Optional[list[str]]) -> dict[str, Any]`: Detects suspicious DNS activity using threat intelligence and malicious domain pattern matching.

- `beaconing_detection(connections: list[dict[str, Any]], interval_threshold: float, jitter_threshold: float) -> dict[str, Any]`: Detects beaconing behavior indicative of command-and-control (C2) communication.

- `lateral_movement_detection(events: list[dict[str, Any]], network_topology: dict[str, Any], user_behavior: Optional[dict[str, Any]]) -> dict[str, Any]`: Detects lateral movement within a network by analyzing access patterns between hosts.

- `command_and_control_detection(traffic_patterns: list[dict[str, Any]], known_c2: Optional[dict[str, Any]], behavioral_analysis: Optional[dict[str, Any]]) -> dict[str, Any]`: Detects C2 communication patterns using threat intelligence and behavioral analysis.

- `network_entropy_analysis(packets: list[dict[str, Any]], block_size: int, threshold: float) -> dict[str, Any]`: Analyzes network packet entropy to detect encrypted or encoded traffic.

- `traffic_behavior_analysis(traffic_data: list[dict[str, Any]], baseline: dict[str, Any], time_window: float) -> dict[str, Any]`: Analyzes network traffic behavior against established baselines within a time window.

- `protocol_anomaly_detection(protocol_data: list[dict[str, Any]], protocol_spec: dict[str, Any], deviation_threshold: float) -> dict[str, Any]`: Detects protocol anomalies by comparing data against protocol specification.

- `shannon_entropy(data: str|bytes) -> float`: Calculates Shannon entropy of data to measure randomness/informational complexity.

---

### Python: Cloud (21 functions)

Cloud security: Dockerfile validation, container escape detection, Kubernetes RBAC, S3 public bucket detection, IAM policies, misconfig detection, secrets manager, Terraform validation, Kubernetes manifests, runtime container protection, supply chain validation, SBOM generation, dependency audit, typosquatting detection, container image scanning, K8s runtime anomaly, cloud security score, workload identity, confidential computing validation.

#### Functions

- `validate_dockerfile(dockerfile_content: str, rules: Optional[dict[str, Any]], severity_threshold: str) -> dict[str, Any]`: Validates Dockerfile against best practices: no `latest`, no `root`, with healthcheck, no hardcoded secrets.

- `detect_container_escape(container_config: dict[str, Any], capabilities: Optional[list[str]], namespaces: Optional[list[str]]) -> dict[str, Any]`: Detects potential container escape vectors such as privileged mode, hostPath mounts, dangerous capabilities.

- `validate_k8s_rbac(rbac_config: dict[str, Any], least_privilege_rules: Optional[dict[str, Any]]) -> dict[str, Any]`: Validates Kubernetes RBAC configuration against least privilege principles.

- `detect_public_bucket(bucket_config: dict[str, Any], policies: Optional[list[dict[str, Any]]], acl: Optional[str]) -> dict[str, Any]`: Detects if a cloud storage bucket is publicly accessible via policy, ACL, or configuration.

- `validate_s3_permissions(bucket_policy: dict[str, Any], expected_permissions: dict[str, Any]) -> dict[str, Any]`: Validates S3 bucket permissions against expected security requirements.

- `validate_iam_policy(iam_policy: dict[str, Any], allowed_actions: Optional[list[str]], denied_actions: Optional[list[str]]) -> dict[str, Any]`: Validates IAM policy against allowed and denied action lists, detecting over-permission.

- `detect_cloud_misconfig(config: dict[str, Any], security_baseline: Optional[dict[str, Any]], cloud_provider: str) -> dict[str, Any]`: Detects cloud infrastructure misconfigurations against security baselines per provider (AWS, GCP, Azure).

- `validate_secrets_manager(secrets_config: dict[str, Any], rotation_policy: Optional[dict[str, Any]], encryption: Optional[dict[str, Any]]) -> dict[str, Any]`: Validates secrets manager configuration checking automatic rotation, encryption at rest, and access controls.

- `validate_terraform(terraform_plan: dict[str, Any], policies: Optional[list[dict[str, Any]]], severity_threshold: str) -> dict[str, Any]`: Validates Terraform plan against security policies detecting insecure resources.

- `validate_kubernetes_manifest(manifest: dict[str, Any], pod_security_policy: Optional[dict[str, Any]], network_policy: Optional[dict[str, Any]]) -> dict[str, Any]`: Validates Kubernetes manifest against pod security policies and network policies.

- `runtime_container_protection(container_events: list[dict[str, Any]], threat_rules: Optional[list[dict[str, Any]]], actions: Optional[dict[str, str]]) -> dict[str, Any]`: Analyzes runtime container events against threat rules and executes actions (block, alert, isolate).

- `supply_chain_validation(dependencies: list[dict[str, Any]], trusted_sources: Optional[list[str]], vulnerability_db: Optional[dict[str, Any]]) -> dict[str, Any]`: Validates software dependencies against trusted sources and vulnerability database.

- `sbom_generator(components: list[dict[str, Any]], format: str, metadata: Optional[dict[str, Any]]) -> dict[str, Any]`: Generates Software Bill of Materials (SBOM) in SPDX, CycloneDX, or custom format.

- `dependency_audit(dependencies: list[dict[str, Any]], audit_db: Optional[dict[str, Any]], severity_threshold: str) -> dict[str, Any]`: Audits dependencies against vulnerability database with severity filtering.

- `detect_typosquatting(package_name: str, known_packages: Optional[list[str]], similarity_threshold: float) -> dict[str, Any]`: Detects typosquatting by comparing package name against known packages using string similarity.

- `container_image_scan(image_layers: list[dict[str, Any]], signatures: Optional[list[dict[str, Any]]], vulnerability_db: Optional[dict[str, Any]]) -> dict[str, Any]`: Scans container image layers for vulnerabilities and verifies signatures.

- `runtime_k8s_anomaly(k8s_events: list[dict[str, Any]], baseline: Optional[dict[str, Any]], anomaly_threshold: float) -> dict[str, Any]`: Detects anomalous behavior in Kubernetes runtime events.

- `cloud_security_score(config: dict[str, Any], benchmarks: Optional[dict[str, Any]], weights: Optional[dict[str, float]]) -> dict[str, Any]`: Calculates overall cloud security score based on CIS benchmarks and configurable weights.

- `workload_identity_validation(workload_config: dict[str, Any], identity_provider: Optional[str], trust_policy: Optional[dict[str, Any]]) -> dict[str, Any]`: Validates workload identity configuration (IRSA, GKE Workload Identity, etc.).

- `confidential_computing_validation(attestation: dict[str, Any], tee_type: str, expected_measurements: Optional[dict[str, str]]) -> dict[str, Any]`: Validates confidential computing attestation for TEEs (SGX, TDX, SEV-SNP, Nitro Enclaves).

---

### Python: Monitoring (20 functions)

Security monitoring: tamperproof logging, anomaly scoring, threat scoring, risk scoring, event correlation, real-time alerting, adaptive alerting, attack path analysis, threat graph, behavioral analysis, UEBA, account takeover detection, fraud detection, autonomous response, security event bus, forensic snapshot, incident timeline, MITRE ATT&CK mapping, autonomous triage.

#### Functions

- `secure_log(event: str, level: str, data: Optional[dict[str, Any]], tamperproof: bool) -> dict[str, Any]`: Creates a tamper-resistant security log entry with cryptographic integrity (hash chain).

- `tamperproof_logs(log_entries: list[dict[str, Any]], chain_verification: bool) -> bool`: Verifies integrity of tamperproof log chain by validating chained hashes.

- `anomaly_score(metrics: dict[str, float], baseline: dict[str, dict[str, float]], weights: Optional[dict[str, float]]) -> float`: Calculates anomaly score using z-score statistical deviation from baseline with per-metric weights.

- `threat_score(events: list[dict[str, Any]], threat_intel: Optional[dict[str, Any]], context: Optional[dict[str, Any]]) -> float`: Calculates composite threat score from events and threat intelligence.

- `risk_score(user_id: str, events: list[dict[str, Any]], context: Optional[dict[str, Any]], historical: Optional[dict[str, Any]]) -> float`: Calculates risk score for a user based on events, context, and history.

- `correlate_events(events: list[dict[str, Any]], time_window: int, correlation_rules: Optional[list[dict[str, Any]]]) -> list[dict[str, Any]]`: Correlates security events within a time window using rule-based matching.

- `realtime_alert(event: dict[str, Any], alert_rules: Optional[list[dict[str, Any]]], notification_channels: Optional[list[str]]) -> dict[str, Any]`: Evaluates event against alert rules and generates real-time alerts with notifications.

- `adaptive_alerting(events: list[dict[str, Any]], baseline: Optional[dict[str, Any]], alert_fatigue_threshold: float) -> dict[str, Any]`: Adaptively generates alerts based on baseline deviation and alert fatigue management.

- `attack_path_analysis(events: list[dict[str, Any]], network_topology: Optional[dict[str, Any]], attack_graph: Optional[dict[str, list[str]]]) -> dict[str, Any]`: Analyzes potential attack paths through the network based on events and topology.

- `threat_graph(events: list[dict[str, Any]], entities: Optional[list[dict[str, Any]]], relationships: Optional[list[dict[str, Any]]]) -> dict[str, Any]`: Builds a threat knowledge graph from events, entities, and relationships.

- `behavioral_analysis(user_events: list[dict[str, Any]], baseline: Optional[dict[str, Any]], deviation_threshold: float) -> dict[str, Any]`: Analyzes user behavior against established baselines to detect deviations.

- `ueba_analysis(user_events: list[dict[str, Any]], peer_group: Optional[dict[str, Any]], anomaly_threshold: float) -> dict[str, Any]`: Performs User and Entity Behavior Analytics (UEBA) comparing against peer groups.

- `detect_account_takeover(user_events: list[dict[str, Any]], baseline: Optional[dict[str, Any]], risk_factors: Optional[dict[str, Any]]) -> dict[str, Any]`: Detects potential account takeover attempts based on behavioral anomalies.

- `detect_fraud(transactions: list[dict[str, Any]], patterns: Optional[list[dict[str, Any]]], risk_threshold: float) -> dict[str, Any]`: Detects potential fraud in transaction patterns using rule-based analysis.

- `autonomous_response(threat: dict[str, Any], response_rules: Optional[list[dict[str, Any]]], actions: Optional[list[dict[str, Any]]]) -> dict[str, Any]`: Executes autonomous incident response based on threat severity and rules.

- `security_event_bus(event: dict[str, Any], handlers: Optional[list[dict[str, Any]]], routing: Optional[dict[str, list[str]]]) -> dict[str, Any]`: Routes security events through an event bus to registered handlers.

- `forensic_snapshot(system_state: dict[str, Any], evidence: Optional[list[dict[str, Any]]], chain_of_custody: Optional[dict[str, Any]]) -> dict[str, Any]`: Creates a forensic snapshot of system state with evidence chain of custody.

- `incident_timeline(events: list[dict[str, Any]], incident_id: str, classification: Optional[str]) -> dict[str, Any]`: Builds a chronological incident timeline from security events.

- `attack_chain_mapping(events: list[dict[str, Any]], mitre_framework: Optional[dict[str, Any]], kill_chain: Optional[list[str]]) -> dict[str, Any]`: Maps security events to MITRE ATT&CK framework and Cyber Kill Chain stages.

- `autonomous_triage(alert: dict[str, Any], triage_rules: Optional[list[dict[str, Any]]], enrichment_sources: Optional[list[dict[str, Any]]]) -> dict[str, Any]`: Autonomously triages security alerts using rules and enrichment data.

---

### Python: Defensive (20 functions)

Active defense: runtime self-protection, anti-debugging, anti-tampering, memory integrity, process integrity, code signing validation, binary integrity, secure boot validation, secure update validation, anti-hook, anti-injection, anti-rootkit, anti-VM, anti-emulation, moving target defense, dynamic attack surface, runtime policy engine, self-healing security, adaptive threat response, autonomous containment.

#### Functions

- `runtime_self_protection(config: Optional[dict[str, Any]], integrity_checks: Optional[list[str]], monitoring: bool) -> dict[str, Any]`: Enables runtime self-protection mechanisms: integrity checks, anti-debug, monitoring.

- `anti_debugging_detection(process_info: Optional[dict[str, Any]], ptrace_status: Optional[str], debugger_signals: Optional[list[str]]) -> dict[str, Any]`: Detects active debugging attempts via ptrace, debugger signals, and process anomalies.

- `anti_tampering(binary_hash: Optional[str], expected_hash: Optional[str], integrity_checks: Optional[list[str]]) -> dict[str, Any]`: Verifies binary integrity by comparing expected hashes against current hashes.

- `memory_integrity_check(memory_regions: Optional[list[dict[str, Any]]], expected_state: Optional[dict[str, Any]], signatures: Optional[list[str]]) -> dict[str, Any]`: Verifies memory region integrity against expected state and known signatures.

- `process_integrity_check(process_id: Optional[int], expected_modules: Optional[list[str]], allowed_parents: Optional[list[str]]) -> dict[str, Any]`: Verifies process integrity including loaded modules and parent process chain.

- `code_signing_validation(binary_path: Optional[str], certificate_store: Optional[dict[str, Any]], revocation_check: bool) -> dict[str, Any]`: Validates binary code signing certificate against trusted store and revocation list.

- `binary_integrity_validation(binary_path: Optional[str], expected_hashes: Optional[dict[str, str]], sections: Optional[list[str]]) -> dict[str, Any]`: Validates binary integrity by section-level hash verification (.text, .data, .rsrc, etc.).

- `secure_boot_validation(boot_chain: Optional[list[dict[str, Any]]], measurements: Optional[dict[str, str]], pcr_values: Optional[dict[int, str]]) -> dict[str, Any]`: Validates secure boot chain and TPM PCR measurements.

- `secure_update_validation(update_package: Optional[dict[str, Any]], signature: Optional[str], version: Optional[str], channel: str) -> dict[str, Any]`: Validates update package authenticity, integrity, version, and channel.

- `anti_hook_detection(functions: Optional[list[dict[str, Any]]], memory_regions: Optional[list[dict[str, Any]]], known_hooks: Optional[list[str]]) -> dict[str, Any]`: Detects function hooks and inline modifications in memory (IAT hooking, inline hooking).

- `anti_injection_detection(process_modules: Optional[list[str]], loaded_libraries: Optional[list[str]], injection_signatures: Optional[list[str]]) -> dict[str, Any]`: Detects code injection in process memory space (DLL injection, process hollowing).

- `anti_rootkit_detection(system_calls: Optional[list[dict[str, Any]]], kernel_modules: Optional[list[str]], hidden_processes: Optional[list[int]]) -> dict[str, Any]`: Detects rootkit indicators in syscalls, kernel modules, and hidden processes.

- `anti_vm_detection(hardware_info: Optional[dict[str, Any]], timing_checks: Optional[list[dict[str, Any]]], vm_artifacts: Optional[list[str]]) -> dict[str, Any]`: Detects virtual machine/sandbox execution via hardware info, timing checks, and VM artifacts.

- `anti_emulation_detection(environment_checks: Optional[list[dict[str, Any]]], timing: Optional[dict[str, Any]], api_availability: Optional[list[str]]) -> dict[str, Any]`: Detects emulation/sandbox analysis environments via environment checks and timing.

- `moving_target_runtime(services: Optional[list[dict[str, Any]]], rotation_config: Optional[dict[str, Any]], randomization: Optional[dict[str, Any]]) -> dict[str, Any]`: Implements moving target defense via service rotation and layout randomization.

- `dynamic_attack_surface(endpoints: Optional[list[dict[str, Any]]], exposure_config: Optional[dict[str, Any]], threat_level: str) -> dict[str, Any]`: Dynamically adjusts attack surface based on current threat level.

- `runtime_policy_engine(policies: Optional[list[dict[str, Any]]], context: Optional[dict[str, Any]], enforcement_mode: str) -> dict[str, Any]`: Evaluates and enforces security policies at runtime with configurable enforcement mode.

- `self_healing_security(state: Optional[dict[str, Any]], healing_rules: Optional[list[dict[str, Any]]], recovery_actions: Optional[list[str]]) -> dict[str, Any]`: Automatically detects and recovers from security incidents using healing rules.

- `adaptive_threat_response(threat: Optional[dict[str, Any]], response_playbook: Optional[dict[str, Any]], context: Optional[dict[str, Any]]) -> dict[str, Any]`: Executes adaptive threat response based on threat characteristics and playbook.

- `autonomous_containment(threat: Optional[dict[str, Any]], containment_rules: Optional[list[dict[str, Any]]], network_topology: Optional[dict[str, Any]]) -> dict[str, Any]`: Autonomously contains active threats using containment rules and network topology.

---

### Python: Honeypot (20 functions)

Honeypots and deception: adaptive honeypot, fake admin panel, fake database, fake API, fake filesystem, fake SSH, fake RDP, fake Kubernetes, fake S3, fake secrets, deceptive routes, attacker behavior tracking, adaptive deception, moving target defense, honeytoken generation, honeycredential detection, decoy endpoints, deceptive responses, fake login page, fake debug panel.

#### Functions

- `adaptive_honeypot(config: dict[str, Any], traffic_analysis: dict[str, Any], threat_level: str) -> dict[str, Any]`: Dynamically adjusts honeypot configuration based on observed traffic and threat level.

- `fake_admin_panel(template: str, routes: list[str] | None, responses: dict[str, Any] | None) -> dict[str, Any]`: Deploys a realistic fake admin panel to attract and track unauthorized access attempts.

- `fake_database(schema: dict[str, Any] | None, records: dict[str, list[dict[str, Any]]] | None, connection_string: str) -> dict[str, Any]`: Creates a convincing fake database with realistic schema and sample records.

- `fake_api(endpoints: list[str] | None, responses: dict[str, Any] | None, rate_limit: int) -> dict[str, Any]`: Deploys a fake REST API with realistic endpoints and response payloads.

- `fake_filesystem(structure: dict[str, Any] | None, files: dict[str, str] | None, permissions: dict[str, str] | None) -> dict[str, Any]`: Creates a realistic fake filesystem with plausible directory structures and files.

- `fake_ssh_service(banner: str, host_key: str | None, port: int) -> dict[str, Any]`: Deploys a fake SSH service that accepts connections and logs all interaction attempts.

- `fake_rdp_service(banner: str, port: int, authentication: str) -> dict[str, Any]`: Deploys a fake RDP service to detect and track remote desktop attacks.

- `fake_kubernetes_cluster(api_server: str, nodes: list[dict[str, Any]] | None, namespaces: list[str] | None) -> dict[str, Any]`: Deploys a fake Kubernetes cluster API to attract container-focused attackers.

- `fake_s3_bucket(bucket_name: str, objects: list[dict[str, Any]] | None, permissions: dict[str, str] | None) -> dict[str, Any]`: Creates a fake S3 bucket with realistic objects and access policies.

- `fake_secrets(secrets_list: list[dict[str, Any]] | None, rotation_policy: dict[str, Any] | None) -> dict[str, Any]`: Generates and manages fake secrets to detect credential harvesting attempts.

- `deceptive_routes(route_patterns: list[str] | None, handlers: dict[str, Any] | None, detection_callback: str | None) -> dict[str, Any]`: Registers deceptive routes that appear legitimate but trigger alerts when accessed.

- `attacker_behavior_tracking(session_id: str, actions: list[dict[str, Any]], timeline: list[dict[str, Any]] | None) -> dict[str, Any]`: Tracks and analyzes attacker behavior patterns within a honeypot session.

- `adaptive_deception(current_deception: dict[str, Any], attacker_profile: dict[str, Any], effectiveness: dict[str, float]) -> dict[str, Any]`: Dynamically adjusts deception tactics based on attacker profile and effectiveness metrics.

- `moving_target_defense(services: list[dict[str, Any]], rotation_interval: int, randomization: dict[str, Any] | None) -> dict[str, Any]`: Implements moving target defense by rotating service configurations.

- `honeytoken_generation(token_type: str, metadata: dict[str, Any] | None, tracking: dict[str, Any] | None) -> dict[str, Any]`: Generates trackable honeytokens that alert when used outside authorized contexts.

- `honeycredential_detection(credentials: list[dict[str, Any]], honeytoken_db: dict[str, Any]) -> dict[str, Any]`: Checks submitted credentials against known honeytoken database.

- `decoy_endpoints(base_path: str, count: int, patterns: list[str] | None) -> list[dict[str, Any]]`: Generates a list of decoy API endpoints that mimic real service endpoints.

- `deceptive_responses(request: dict[str, Any], deception_config: dict[str, Any] | None, attacker_profile: dict[str, Any] | None) -> dict[str, Any]`: Generates contextually appropriate deceptive responses based on request and attacker profile.

- `fake_login_page(template: str, branding: dict[str, Any] | None, tracking_script: str | None) -> dict[str, Any]`: Deploys a convincing fake login page to capture credential submission attempts.

- `fake_debug_panel(config: dict[str, Any] | None, endpoints: list[str] | None, data: dict[str, Any] | None) -> dict[str, Any]`: Deploys a fake debug/development panel that appears to expose internal system information.

---

### Python: File (21 functions)

File security: secure upload, extension/MIME validation, polyglot file detection, zip bomb, office macros, PDF JavaScript, malware scan, YARA rules, heuristic scan, quarantine, filename sanitization, executable payloads, entropy analysis, sandbox execution, embedded scripts, steganography, obfuscation detection, secure temp files, immutable storage.

#### Functions

- `secure_upload(file_data: bytes, filename: str, allowed_extensions: Optional[list[str]], max_size: int) -> dict[str, Any]`: Securely validates and processes an uploaded file by checking extension, MIME, size, and content.

- `validate_extension(filename: str, allowed_extensions: list[str]) -> bool`: Validates that a filename has an allowed extension from the allowlist.

- `validate_mime(file_data: bytes, expected_mime: Optional[str], magic_bytes: Optional[dict[str, bytes]]) -> dict[str, Any]`: Validates MIME type using magic byte detection, preventing extension spoofing.

- `detect_polyglot_file(file_data: bytes, signatures: Optional[list[dict[str, Any]]]) -> dict[str, Any]`: Detects if a file contains multiple file format signatures (polyglot file attack).

- `detect_zip_bomb(file_data: bytes, max_ratio: float, max_uncompressed: int) -> dict[str, Any]`: Detects potential zip bomb by analyzing compression ratios and uncompressed size.

- `detect_office_macro(file_data: bytes, file_type: Optional[str]) -> dict[str, Any]`: Detects VBA macros in Office documents (Word, Excel, PowerPoint) that can execute malicious code.

- `detect_pdf_javascript(file_data: bytes) -> dict[str, Any]`: Detects JavaScript embedded in PDF files that can execute malicious actions.

- `malware_scan(file_data: bytes, signatures: Optional[list[dict[str, Any]]], yara_rules: Optional[list[dict[str, Any]]]) -> dict[str, Any]`: Scans file data for malware using signature matching and YARA rules.

- `yara_scan(file_data: bytes, rules: Optional[list[dict[str, Any]]], namespace: Optional[str]) -> dict[str, Any]`: Scans file data using YARA-like pattern matching rules with optional namespace.

- `heuristic_scan(file_data: bytes, heuristics: Optional[list[dict[str, Any]]], threshold: float) -> dict[str, Any]`: Performs heuristic analysis to detect suspicious behavior in files.

- `quarantine_file(filepath: str, quarantine_dir: Optional[str], reason: str) -> str`: Moves a file to a quarantine directory with metadata tracking.

- `sanitize_filename(filename: str, max_length: int, allowed_chars: Optional[str]) -> str`: Sanitizes a filename by removing dangerous characters and path traversal sequences.

- `detect_executable_payload(file_data: bytes, file_type: Optional[str]) -> dict[str, Any]`: Detects executable payloads embedded within non-executable files.

- `entropy_analysis(file_data: bytes, block_size: int, threshold: float) -> dict[str, Any]`: Calculates Shannon entropy of file data to detect encryption or compression.

- `sandbox_execute(file_path: str, sandbox_config: Optional[dict[str, Any]], timeout: int) -> dict[str, Any]`: Executes a file in a sandboxed environment for behavioral analysis.

- `detect_embedded_script(file_data: bytes, file_type: Optional[str], script_types: Optional[list[str]]) -> dict[str, Any]`: Detects embedded scripts within files (JavaScript in PDF, macros in Office, etc.).

- `detect_steganography(file_data: bytes, analysis_methods: Optional[list[str]]) -> dict[str, Any]`: Detects potential steganography in image files using LSB, appended data, entropy, histogram analysis.

- `detect_obfuscation(file_data: bytes, detection_methods: Optional[list[str]]) -> dict[str, Any]`: Detects obfuscated content in files (base64, hex, string concatenation, control flow).

- `secure_tempfile(prefix: str, suffix: str, directory: Optional[str], delete_on_close: bool) -> str`: Creates a secure temporary file with restricted permissions and optional auto-deletion.

- `immutable_storage_check(filepath: str, expected_hash: Optional[str], storage_type: str) -> bool`: Verifies file integrity against expected hash for immutable storage.

---

### Python: Enterprise (10 functions)

Enterprise compliance: LGPD (Brazil), GDPR (EU), HIPAA (healthcare), PCI-DSS (payments), compliance reports, audit trails, policy as code, real-time security dashboard, tenant isolation, multi-region security.

#### Functions

- `lgpd_check(system_config: dict[str, Any], data_flows: list[dict[str, Any]], controls: dict[str, Any]) -> dict[str, Any]`: Checks compliance with Brazilian LGPD (Lei Geral de Protecao de Dados): consent, DPO, data subject rights, etc.

- `gdpr_check(system_config: dict[str, Any], data_processing: list[dict[str, Any]], controls: dict[str, Any]) -> dict[str, Any]`: Checks compliance with EU GDPR: lawful basis, DPO, data minimization, right to be forgotten, etc.

- `hipaa_check(system_config: dict[str, Any], phi_handling: list[dict[str, Any]], controls: dict[str, Any]) -> dict[str, Any]`: Checks compliance with HIPAA (healthcare): PHI encryption, access controls, audit controls, etc.

- `pci_check(system_config: dict[str, Any], card_data_handling: list[dict[str, Any]], controls: dict[str, Any]) -> dict[str, Any]`: Checks compliance with PCI-DSS (payments): card data encryption, network segmentation, access control, etc.

- `compliance_report(checks: list[dict[str, Any]], framework: str, scope: dict[str, Any]) -> dict[str, Any]`: Generates a comprehensive compliance report from multiple check results.

- `audit_trail(events: list[dict[str, Any]], user_actions: list[dict[str, Any]], data_changes: list[dict[str, Any]]) -> dict[str, Any]`: Generates an immutable audit trail from security events, user actions, and data changes.

- `policy_as_code(policies: list[dict[str, Any]], context: dict[str, Any], enforcement: dict[str, Any]) -> dict[str, Any]`: Evaluates and enforces security policies defined as code (IaC for security policies).

- `realtime_security_dashboard(metrics: dict[str, Any], alerts: list[dict[str, Any]], trends: dict[str, Any]) -> dict[str, Any]`: Generates a real-time security dashboard from metrics, alerts, and trends.

- `tenant_isolation(tenant_config: dict[str, Any], network_policies: list[dict[str, Any]], data_segregation: dict[str, Any]) -> dict[str, Any]`: Verifies and enforces tenant isolation in a multi-tenant environment.

- `multi_region_security(regions: list[dict[str, Any]], data_residency_rules: dict[str, Any], encryption: dict[str, Any]) -> dict[str, Any]`: Evaluates multi-region security posture and data residency compliance.

---

### Python: Integrations (10 functions)

Framework integrations: FastAPI, Django, Flask, Celery, SQLAlchemy, async threat pipeline, YARA real-time engine, AI threat classifier, secure CLI runtime, Python runtime guard.

#### Functions

- `fastapi_security_dependency(config: dict[str, Any], security_schemes: dict[str, Any], middleware_config: dict[str, Any]) -> dict[str, Any]`: Creates FastAPI security dependency with OAuth2, JWT validation, and rate limiting.

- `django_security_middleware(config: dict[str, Any], settings: dict[str, Any], middleware_config: dict[str, Any]) -> dict[str, Any]`: Creates Django security middleware with CSP, CSRF, and security headers.

- `flask_security_extension(app: Any, config: dict[str, Any], security_config: dict[str, Any]) -> dict[str, Any]`: Creates Flask security extension with security wrappers and request protection.

- `celery_security_monitor(app: Any, config: dict[str, Any], task_security: dict[str, Any]) -> dict[str, Any]`: Creates Celery task security monitoring with validation and audit logging.

- `sqlalchemy_query_protection(query: Any, user_permissions: dict[str, Any], row_level_security: dict[str, Any]) -> dict[str, Any]`: Applies SQLAlchemy query protection with row-level security and permission filtering.

- `async_threat_pipeline(config: dict[str, Any], processors: list[dict[str, Any]], output_channels: list[dict[str, Any]]) -> dict[str, Any]`: Creates async threat detection pipeline with configurable processors and output channels.

- `yara_realtime_engine(rules: list[dict[str, Any]], watch_dirs: list[str], scan_interval: int) -> dict[str, Any]`: Creates YARA real-time scanning engine with file watch and rule matching.

- `ai_threat_classifier(model_path: str, classification_rules: dict[str, Any], confidence_threshold: float) -> dict[str, Any]`: Creates AI-powered threat classifier with model loading and confidence-based decisions.

- `secure_cli_runtime(config: dict[str, Any], input_sanitization: dict[str, Any], timeout_config: dict[str, Any]) -> dict[str, Any]`: Creates secure CLI runtime with input sanitization and execution timeouts.

- `python_runtime_guard(config: dict[str, Any], import_whitelist: list[str], sandbox_config: dict[str, Any]) -> dict[str, Any]`: Creates Python runtime guard with import whitelisting and sandboxing.

---

## TypeScript Modules

### TS: Core (11 functions)

Base infrastructure: configuration, structured logging with pino, metrics, LRU cache, policy engine, event bus, OpenTelemetry, security exceptions, and tracing spans.

#### Functions

- `getConfig(): MSFConfig`: Gets the global framework configuration. Creates default instance if none exists.

- `setConfig(config: MSFConfig): void`: Sets the global framework configuration.

- `reloadConfig(): MSFConfig`: Reloads configuration from environment variables.

- `getLogger(component: string, options?: MSFLoggerOptions): MSFLogger`: Gets structured pino logger for a component.

- `getMetrics(): MetricsRegistry`: Gets the global metrics registry with counters, gauges, histograms.

- `getPolicyEngine(): PolicyEngine`: Gets the security policy engine singleton.

- `getEventBus(maxHistory?: number, maxDeadLetter?: number): EventBus`: Gets the event bus with history and dead letter queue.

- `getCache(options?: Partial<CacheOptions>): CacheManager`: Gets LRU cache manager with TTL and invalidation.

- `getTelemetry(serviceName?: string, serviceVersion?: string, enabled?: boolean): TelemetryManager`: Gets the OpenTelemetry manager.

- `createSpan(name: string, attributes: Record<string, string | number | boolean>): otel.Span`: Creates an OpenTelemetry tracing span with attributes.

- `redactPII(value: string): string`: Redacts PII (Personally Identifiable Information) from a string.

---

### TS: Auth (7 functions)

Authentication: TOTP, backup codes, password entropy, device/browser fingerprinting, phishing-resistant auth.

#### Functions

- `generateTotp(secret: string, digits: number = 6, period: number = 30, timeStep?: number): string`: Generates TOTP code with configurable digits and period.

- `validateTotp(secret: string, token: string, digits: number = 6, period: number = 30, drift: number = 1): boolean`: Validates TOTP token with drift tolerance.

- `verifyBackupCode(code: string, validCodes: string[]): boolean`: Verifies and consumes a backup code.

- `passwordEntropy(password: string): number`: Calculates Shannon entropy of a password.

- `deviceFingerprint(userAgent: string, screen: string, timezone: string, languages: string[], platform: string): string`: Generates device fingerprint.

- `browserFingerprint(canvasHash: string, webglHash: string, audioHash: string, fonts: string[]): string`: Generates browser fingerprint.

- `phishingResistantAuth(authMethod: string, fidoLevel: number, attestation: string): boolean`: Verifies if auth method is phishing-resistant.

---

### TS: Crypto (5 functions)

Cryptography: secure random, HMAC, memory-safe erase, timing-safe compare.

#### Functions

- `secureRandom(nbytes: number): Uint8Array`: Generates cryptographically secure random bytes using `crypto.getRandomValues()`.

- `generateHmac(data: Uint8Array | string, key: Uint8Array | string, algorithm: HmacAlgorithm = 'hmac-sha256'): string`: Generates HMAC for integrity authentication.

- `verifyHmac(data: Uint8Array | string, signature: string, key: Uint8Array | string, algorithm: HmacAlgorithm = 'hmac-sha256'): boolean`: Verifies HMAC by comparing signature.

- `secureMemoryErase(data: Uint8Array): void`: Securely erases data from memory by overwriting.

- `antiTimingCompare(a: Uint8Array, b: Uint8Array): boolean`: Compares in constant time to prevent timing attacks.

---

### TS: Web (35 functions)

Web attack detection and sanitization: XSS, SQLi, NoSQLi, SSRF, RCE, LFI, RFI, SSTI, Command Injection, Deserialization, Path Traversal, Open Redirect, CORS, CSP, CSRF, secure cookies, clickjacking, webhooks.

#### Functions

- `detectXss(input: string, patterns?: RegExp[], severityThreshold: number = 0.3): DetectionResult`: Detects XSS patterns including script tags, event handlers, javascript: URIs.

- `sanitizeHtml(html: string, allowedTags: string[], allowedAttrs: string[]): string`: Sanitizes HTML by removing disallowed tags and attributes.

- `sanitizeSvg(svg: string, allowedElements: string[]): string`: Sanitizes SVG by removing dangerous elements.

- `sanitizeMarkdown(markdown: string, allowedHtml: string[]): string`: Sanitizes markdown by removing dangerous embedded HTML.

- `sanitizeCss(css: string, allowedProperties: string[]): string`: Sanitizes CSS by removing dangerous properties.

- `sanitizeJs(jsCode: string, dangerousPatterns: RegExp[]): string`: Sanitizes JavaScript by removing `eval()`, `Function()`, `document.write()`, etc.

- `detectSqli(input: string, patterns?: RegExp[], context?: string): DetectionResult`: Detects SQL injection (UNION, blind, time-based, error-based).

- `detectNosqli(input: string, patterns?: RegExp[]): DetectionResult`: Detects NoSQL injection in MongoDB/NoSQL queries.

- `detectSsrf(url: string, allowedDomains: string[], blockedIps: string[]): DetectionResult`: Detects SSRF by verifying URLs against allowlist and blocklist.

- `detectRce(input: string, patterns?: RegExp[]): DetectionResult`: Detects Remote Code Execution patterns.

- `detectLfi(input: string, patterns?: RegExp[]): DetectionResult`: Detects Local File Inclusion via path traversal.

- `detectRfi(input: string, patterns?: RegExp[]): DetectionResult`: Detects Remote File Inclusion via external URLs.

- `detectTemplateInjection(input: string, engineType: 'jinja2' | 'ejs' | 'handlebars' | 'mustache' | 'pug' | 'twig' | 'generic'): DetectionResult`: Detects Server-Side Template Injection for multiple engines.

- `detectCommandInjection(input: string, patterns?: RegExp[]): DetectionResult`: Detects OS Command Injection.

- `detectDeserializationAttack(data: string, allowedClasses: string[]): DetectionResult`: Detects insecure deserialization.

- `detectPathTraversal(input: string, basePath: string): DetectionResult`: Detects path traversal by verifying resolution within basePath.

- `detectOpenRedirect(url: string, allowedHosts: string[]): DetectionResult`: Detects open redirect by verifying allowed hosts.

- `validateCors(origin: string | undefined, allowedOrigins: string[], allowedMethods: string[], allowedHeaders: string[]): CorsResult`: Validates CORS request.

- `secureHeaders(request: SecureHeadersRequest, config: SecureHeadersConfig): Record<string, string>`: Generates secure HTTP response headers.

- `generateCsp(config: CspConfig): string`: Generates Content-Security-Policy header.

- `validateCsp(cspHeader: string, policy: CspConfig): boolean`: Validates CSP header against policy.

- `csrfProtect(request: CsrfRequest, token: string, sessionToken: string): boolean`: Protects against CSRF.

- `validateCsrf(token: string, sessionToken: string): boolean`: Validates CSRF token.

- `secureCookie(name: string, value: string, options: SecureCookieOptions): string`: Generates secure Set-Cookie header.

- `detectClickjacking(headers: Record<string, string>, frameOptions: string): boolean`: Detects clickjacking vulnerability.

- `validateOrigin(origin: string, allowedOrigins: string[]): boolean`: Validates Origin header.

- `validateReferer(referer: string | undefined, expectedDomain: string): boolean`: Validates Referer header.

- `secureRedirect(url: string, allowedHosts: string[]): string`: Validates safe redirect URL.

- `webhookSignature(payload: string, secret: string, algorithm: 'sha256' | 'sha384' | 'sha512' | 'sha3-256', timestamp?: number): string`: Generates webhook signature.

- `webhookReplayProtection(signature: string, timestamp: number, payload: string, secret: string, window: number): boolean`: Protects against webhook replay.

---

### TS: API (16 functions)

API security: JSON Schema validation, input validation, sanitization, API abuse detection, BOLA, broken auth, mass assignment, shadow API, threat scoring, GraphQL (depth, cost, abuse), gRPC, WebSocket, API key rotation/validation.

#### Functions

- `validateJsonSchema(data: unknown, schema: Record<string, unknown>, strictMode = false): ValidationResult`: Validates data against JSON Schema.

- `validateInput(data: unknown, rules: Record<string, {...}>, maxDepth = 5, maxSize = 1048576): ValidationResult`: Validates API input against rules.

- `sanitizeJson(data: unknown, allowedTypes: string[], maxStringLength = 10000): SanitizedData`: Sanitizes JSON data.

- `detectApiAbuse(requests: Array<{...}>, patterns: RequestPattern[], window: number): AbuseDetectionResult`: Detects API abuse.

- `detectBola(resourceId: string, userId: string, ownershipMap: Record<string, string>): boolean`: Detects BOLA/IDOR.

- `detectBrokenAuth(authHeader: string, requiredScopes: string[], token?: Record<string, unknown>): AuthValidationResult`: Detects broken authentication.

- `detectMassAssignment(inputData: Record<string, unknown>, modelFields: string[], readonlyFields: string[]): MassAssignmentResult`: Detects mass assignment.

- `detectShadowApi(endpoint: string, documentedApis: string[], trafficPatterns: TrafficPattern[]): ShadowApiResult`: Detects shadow APIs.

- `apiThreatScore(request: {...}, context: ApiThreatContext, threatIntel: ThreatIntelEntry[]): number`: Calculates API request threat score.

- `graphqlDepthLimit(query: string, maxDepth = 10, introspectionEnabled = false): GraphqlValidationResult`: Validates GraphQL query depth.

- `graphqlCostAnalysis(query: string, complexityMap: Record<string, number>, maxCost = 1000): GraphqlCostResult`: Analyzes GraphQL query cost.

- `graphqlAbuseDetection(queries: Array<{...}>, window: number, thresholds: {...}): GraphqlAbuseResult`: Detects GraphQL abuse.

- `grpcSecurityValidation(metadata: Record<string, string | string[]>, requiredHeaders: string[], tlsInfo: {...}): GrpcValidationResult`: Validates gRPC security.

- `secureWebsocket(origin: string, allowedOrigins: string[], subprotocols?: string[]): WsSecurityResult`: Configures secure WebSocket.

- `apiKeyRotation(currentKey: string, algorithm = 'sha3-256', expiryDays = 90): KeyRotationResult`: Rotates API key.

- `apiKeyValidation(apiKey: string, validKeys: Record<string, {...}>, scopes: string[], requiredScope?: string): KeyValidationResult`: Validates API key.

---

### TS: AI (14 functions)

AI protection: prompt leak detection, impersonation, model abuse, agent abuse, LLM firewall, policy engine, RAG validation, hallucination risk, output guard, tool call validation, multi-agent isolation, memory sanitization, token monitoring, behavior monitoring.

#### Functions

- `detectPromptLeak(prompt: string, systemPrompt: string, threshold: number = 0.4): DetectionResult`: Detects system prompt leak attempts.

- `detectAiImpersonation(content: string, claimedIdentity: string, markers?: string[]): DetectionResult`: Detects AI impersonation.

- `detectModelAbuse(requestPatterns: string[], rate: number, complexity: number): DetectionResult`: Detects model abuse.

- `detectAgentAbuse(agentBehavior: AgentBehaviorAnalysis, policy: Record<string, unknown>, thresholds: Record<string, number>): DetectionResult`: Detects agent abuse.

- `llmFirewall(inputData: string | Record<string, unknown>, rules: FirewallRule[], actionOnViolation: FirewallResult['action'] = 'block'): FirewallResult`: LLM firewall with configurable rules.

- `aiPolicyEngine(prompt: string, output: string = '', policies: AiPolicy[]): PolicyResult`: AI security policy engine.

- `ragSourceValidation(sources: RagSource[], trustedDomains: string[], validationRules: ValidationRule[]): ValidationResult`: Validates RAG sources.

- `hallucinationRisk(output: string, confidenceScores: number[] = [], factualChecks: {...}[] = []): RiskResult`: Assesses hallucination risk.

- `aiOutputGuard(output: string, guardrails: Guardrail[], redactionRules: RedactionRule[]): string`: Applies guardrails to output.

- `toolCallValidation(toolName: string, arguments_: Record<string, unknown>, allowedTools: AllowedTool[], argumentSchemas: Record<string, {...}>): ValidationResult`: Validates tool call.

- `multiAgentIsolation(agents: AgentDefinition[], communicationRules: CommunicationRules): IsolationResult`: Validates multi-agent isolation.

- `aiMemorySanitizer(memoryEntries: MemoryEntry[], retentionPolicy: RetentionPolicy): MemoryEntry[]`: Sanitizes AI memory.

- `aiTokenMonitor(usage: TokenUsage, limits: TokenLimits, window: number = 60): MonitorResult`: Monitors token usage.

- `aiBehaviorMonitor(behaviorLog: AgentBehaviorEntry[], baseline: BehaviorBaseline, deviationThreshold: number = 0.3): MonitorResult`: Monitors AI behavior.

---

### TS: Network (16 functions)

Network security: port scan, DNS tunneling, traffic anomaly, proxy detection, DDoS, IP/domain validation, spoofing, ARP poisoning, TLS fingerprinting, beaconing, lateral movement, network entropy, traffic behavior, protocol anomaly.

#### Functions

- `detectPortScan(sourceIp: string, connections: ConnectionRecord[], window: number = 60, threshold: number = 20): DetectionResult`: Detects port scanning.

- `detectDnsTunneling(dnsQueries: DnsQuery[], domain: string, threshold: number = 50): DetectionResult`: Detects DNS tunneling.

- `detectTrafficAnomaly(trafficData: TrafficData, baseline: Record<string, number>, deviationThreshold: number = 2.0): DetectionResult`: Detects traffic anomalies.

- `detectProxy(ip: string, headers: Record<string, string>, detectionMethods: string[] = ['header', 'behavior', 'database']): DetectionResult`: Detects proxy.

- `detectDdos(trafficData: TrafficData, baseline: Record<string, number>, threshold: number = 5.0, window: number = 60): DetectionResult`: Detects DDoS attacks.

- `validateIp(ip: string, allowedRanges: string[] = [], blockedRanges: string[] = []): IpValidationResult`: Validates IP address.

- `validateDomain(domain: string, allowedTlds: string[] = [], blockedDomains: string[] = []): DomainValidationResult`: Validates domain.

- `detectSpoofing(packetData: PacketData, expectedSource: string, networkTopology: NetworkTopology): DetectionResult`: Detects IP spoofing.

- `detectArpPoisoning(arpTable: ArpEntry[], expectedMappings: Record<string, string> = {}): DetectionResult`: Detects ARP poisoning.

- `tlsFingerprint(tlsHandshake: TlsHandshake, ja3Database: Record<string, string> = {}): FingerprintResult`: Generates/compares TLS fingerprint.

- `ja3Fingerprint(tlsClientHello: TlsClientHello): string`: Generates JA3 fingerprint.

- `beaconingDetection(connections: ConnectionRecord[], intervalThreshold: number = 0.8, jitterThreshold: number = 0.15): DetectionResult`: Detects beaconing (C2).

- `lateralMovementDetection(events: SecurityEventRecord[], networkTopology: NetworkTopology, userBehavior: UserBehavior): DetectionResult`: Detects lateral movement.

- `networkEntropyAnalysis(packets: PacketData[], blockSize: number = 256, threshold: number = 7.5): EntropyResult`: Analyzes network entropy.

- `trafficBehaviorAnalysis(trafficData: TrafficData, baseline: Record<string, number>, timeWindow: number = 3600): BehaviorResult`: Analyzes traffic behavior.

- `protocolAnomalyDetection(protocolData: Record<string, unknown>, protocolSpec: Record<string, unknown>, deviationThreshold: number = 0.3): DetectionResult`: Detects protocol anomalies.

---

### TS: Cloud (20 functions)

Cloud security: Dockerfile validation, container escape, K8s RBAC, S3 public bucket, IAM policies, cloud misconfig, secrets manager, Terraform, K8s manifests, runtime container protection, supply chain, SBOM, dependency audit, typosquatting, container image scan, K8s anomaly, security score, workload identity, confidential computing.

#### Functions

- `validateDockerfile(dockerfileContent: string, rules: Rule[], severityThreshold: SeverityLevel = 'medium'): ValidationResult`: Validates Dockerfile against security rules.

- `detectContainerEscape(containerConfig: ContainerConfig, capabilities: string[] = [], namespaces: string[] = []): DetectionResult`: Detects container escape vectors.

- `validateK8sRbac(rbacConfig: Record<string, unknown>, leastPrivilegeRules: Rule[]): ValidationResult`: Validates Kubernetes RBAC.

- `detectPublicBucket(bucketConfig: BucketConfig, policies: Record<string, unknown>[], acl: Record<string, unknown>): DetectionResult`: Detects public bucket.

- `validateS3Permissions(bucketPolicy: Record<string, unknown>, expectedPermissions: Record<string, string[]>): ValidationResult`: Validates S3 permissions.

- `validateIamPolicy(iamPolicy: IamPolicy, allowedActions: string[], deniedActions: string[]): ValidationResult`: Validates IAM policy.

- `detectCloudMisconfig(config: Record<string, unknown>, securityBaseline: Record<string, unknown>, cloudProvider: string): DetectionResult`: Detects cloud misconfigurations.

- `validateSecretsManager(secretsConfig: SecretConfig, rotationPolicy: {...}, encryption: {...}): ValidationResult`: Validates secrets manager.

- `validateTerraform(terraformPlan: TerraformPlan, policies: Rule[], severityThreshold: SeverityLevel = 'medium'): ValidationResult`: Validates Terraform plan.

- `validateKubernetesManifest(manifest: K8sManifest, podSecurityPolicy: Record<string, unknown>, networkPolicy: Record<string, unknown>): ValidationResult`: Validates K8s manifest.

- `runtimeContainerProtection(containerEvents: Record<string, unknown>[], threatRules: Rule[], actions: Record<string, 'block' | 'alert' | 'isolate' | 'terminate' | 'log'>): ProtectionResult`: Protects containers at runtime.

- `supplyChainValidation(dependencies: DependencyEntry[], trustedSources: string[], vulnerabilityDb: VulnerabilityEntry[]): ValidationResult`: Validates supply chain.

- `sbomGenerator(components: Array<{...}>, format: 'spdx' | 'cyclonedx' | 'custom' = 'spdx', metadata: Record<string, unknown> = {}): SbomResult`: Generates SBOM.

- `dependencyAudit(dependencies: DependencyEntry[], auditDb: VulnerabilityEntry[], severityThreshold: SeverityLevel = 'medium'): AuditResult`: Audits dependencies.

- `detectTyposquatting(packageName: string, knownPackages: string[], similarityThreshold: number = 0.85): DetectionResult`: Detects typosquatting.

- `containerImageScan(imageLayers: Array<{...}>, signatures: Array<{...}>, vulnerabilityDb: VulnerabilityEntry[]): ScanResult`: Scans container image.

- `runtimeK8sAnomaly(k8sEvents: Record<string, unknown>[], baseline: Record<string, number>, anomalyThreshold: number = 2.0): AnomalyResult`: Detects K8s runtime anomaly.

- `cloudSecurityScore(config: Record<string, unknown>, benchmarks: Record<string, Record<string, unknown>>, weights: Record<string, number>): ScoreResult`: Calculates cloud security score.

- `workloadIdentityValidation(workloadConfig: WorkloadConfig, identityProvider: string, trustPolicy: Record<string, unknown>): ValidationResult`: Validates workload identity.

- `confidentialComputingValidation(attestation: Attestation, teeType: 'sgx' | 'tdx' | 'sev' | 'snp' | 'nitro' | 'cvm', expectedMeasurements: Record<string, string>): ValidationResult`: Validates confidential computing.

---

### TS: Monitoring (12 functions)

Monitoring: anomaly score, threat score, risk score, event correlation, adaptive alerting, attack path analysis, threat graph, behavioral analysis, UEBA, account takeover detection, incident timeline, MITRE ATT&CK mapping.

#### Functions

- `anomalyScore(metrics: MetricsData, baseline: BaselineData, weights: Record<string, number> = {}): number`: Calculates anomaly score via z-score.

- `threatScore(events: SecurityEvent[], threatIntel: ThreatIntel, context: Record<string, unknown> = {}): number`: Calculates threat score.

- `riskScore(userId: string, events: SecurityEvent[], context: Record<string, unknown> = {}, historical: {...}): number`: Calculates user risk score.

- `correlateEvents(events: SecurityEvent[], timeWindow: number = 300000, correlationRules: CorrelationRule[] = []): CorrelatedEvent[]`: Correlates security events.

- `adaptiveAlerting(events: SecurityEvent[], baseline: {...}, alertFatigueThreshold: number = 10): AlertResult`: Adaptive alerting with fatigue prevention.

- `attackPathAnalysis(events: SecurityEvent[], networkTopology: {...}, attackGraph: {...}): PathResult`: Analyzes attack paths.

- `threatGraph(events: SecurityEvent[], entities: {...}[], relationships: {...}[]): GraphResult`: Constructs threat graph.

- `behavioralAnalysis(userEvents: SecurityEvent[], baseline: {...}, deviationThreshold: number = 2.0): AnalysisResult`: Analyzes user behavior.

- `uebaAnalysis(userEvents: SecurityEvent[], peerGroup: {...}, anomalyThreshold: number = 2.5): UebaResult`: UEBA against peer groups.

- `detectAccountTakeover(userEvents: SecurityEvent[], baseline: {...}, riskFactors: {...}): DetectionResult`: Detects account takeover.

- `incidentTimeline(events: SecurityEvent[], incidentId: string, classification: string = 'unclassified'): TimelineResult`: Constructs incident timeline.

- `attackChainMapping(events: SecurityEvent[], mitreFramework: {...}, killChain: {...}): ChainResult`: Maps to MITRE ATT&CK and Kill Chain.

---

### TS: Defensive (20 functions)

Active defense: runtime self-protection, anti-debugging, anti-tampering, memory integrity, process integrity, code signing, binary integrity, secure boot, secure update, anti-hook, anti-injection, anti-rootkit, anti-VM, anti-emulation, moving target, dynamic attack surface, runtime policy engine, self-healing, adaptive threat response, autonomous containment.

#### Functions

- `runtimeSelfProtection(config: ProtectionConfig, integrityChecks: IntegrityCheckConfig[], monitoring: MonitoringConfig): ProtectionResult`: Runtime self-protection with integrity checks.

- `antiDebuggingDetection(processInfo: ProcessInfo, ptraceStatus: PtraceStatus, debuggerSignals: DebuggerSignal[]): DetectionResult`: Detects active debugging.

- `antiTampering(binaryHash: BinaryHash[], expectedHash: Record<string, string>, integrityChecks: IntegrityCheckConfig[]): DetectionResult`: Detects binary tampering.

- `memoryIntegrityCheck(memoryRegions: MemoryRegion[], expectedState: MemoryExpectedState[], signatures: MemorySignature[]): IntegrityResult`: Verifies memory integrity.

- `processIntegrityCheck(processId: number, expectedModules: string[], allowedParents: number[]): IntegrityResult`: Verifies process integrity.

- `codeSigningValidation(binaryPath: string, certificateStore: CertificateStore, revocationCheck: boolean): ValidationResult`: Validates code signing.

- `binaryIntegrityValidation(binaryPath: string, expectedHashes: Record<string, string>, sections: string[]): ValidationResult`: Validates binary integrity by section.

- `secureBootValidation(bootChain: BootMeasurement[], measurements: BootMeasurement[], pcrValues: PcrValue[]): ValidationResult`: Validates secure boot chain.

- `secureUpdateValidation(updatePackage: UpdatePackage, signature: UpdateSignature, version: string, channel: string): ValidationResult`: Validates update package.

- `antiHookDetection(functions: HookInfo[], memoryRegions: MemoryRegion[], knownHooks: string[]): DetectionResult`: Detects function hooks.

- `antiInjectionDetection(processModules: ProcessModule[], loadedLibraries: string[], injectionSignatures: InjectionSignature[]): DetectionResult`: Detects code injection.

- `antiRootkitDetection(systemCalls: SystemCallInfo[], kernelModules: KernelModule[], hiddenProcesses: ProcessEntry[]): DetectionResult`: Detects rootkit activity.

- `antiVmDetection(hardwareInfo: HardwareInfo, timingChecks: TimingCheck, vmArtifacts: VmArtifact[]): DetectionResult`: Detects VM environment.

- `antiEmulationDetection(environmentChecks: EnvironmentCheck[], timing: TimingCheck, apiAvailability: ApiAvailability[]): DetectionResult`: Detects emulation/sandbox.

- `movingTargetRuntime(services: ServiceConfig[], rotationConfig: RotationConfig, randomization: RandomizationConfig): MTDResult`: Moving target defense.

- `dynamicAttackSurface(endpoints: EndpointConfig[], exposureConfig: ExposureConfig, threatLevel: number): SurfaceResult`: Adjusts attack surface.

- `runtimePolicyEngine(policies: SecurityPolicy[], context: PolicyContext, enforcementMode: EnforcementConfig): PolicyResult`: Runtime policy engine.

- `selfHealingSecurity(state: SystemState, healingRules: HealingRule[], recoveryActions: RecoveryAction[]): HealingResult`: Self-healing security.

- `adaptiveThreatResponse(threat: ThreatInfo, responsePlaybook: ResponsePlaybook, context: ResponseContext): ResponseResult`: Adaptive threat response.

- `autonomousContainment(threat: ThreatInfo, containmentRules: ContainmentRule[], networkTopology: NetworkNode[]): ContainmentResult`: Autonomous threat containment.

---

### TS: Honeypot

*(Module under development - functions will be added in the next version)*

---

### TS: File (18 functions)

File security: extension validation, MIME validation, polyglot detection, zip bomb, office macros, PDF JavaScript, malware scan, YARA scan, heuristic scan, quarantine, filename sanitization, executable payload, entropy analysis, embedded script, steganography, obfuscation, secure tempfile, immutable storage.

#### Functions

- `validateExtension(filename: string, allowedExtensions: string[]): boolean`: Validates file extension.

- `validateMime(fileData: Buffer, expectedMime: string, magicBytes?: string): MimeResult`: Validates MIME type via magic bytes.

- `detectPolyglotFile(fileData: Buffer, signatures: FileSignature[]): DetectionResult`: Detects polyglot files.

- `detectZipBomb(fileData: Buffer, maxRatio: number = 100, maxUncompressed: number = 1073741824): DetectionResult`: Detects zip bombs.

- `detectOfficeMacro(fileData: Buffer, fileType: string): DetectionResult`: Detects Office macros.

- `detectPdfJavascript(fileData: Buffer): DetectionResult`: Detects JS in PDF.

- `malwareScan(fileData: Buffer, signatures: Array<{...}>, yaraRules?: YaraRule[]): ScanResult`: Scans for malware.

- `yaraScan(fileData: Buffer, rules: YaraRule[], namespace?: string): ScanResult`: Scans with YARA rules.

- `heuristicScan(fileData: Buffer, heuristics: HeuristicRule[], threshold: number = 0.5): ScanResult`: Heuristic scan.

- `quarantineFile(filePath: string, quarantineDir: string, reason: string): string`: File quarantine.

- `sanitizeFilename(filename: string, maxLength: number = 255, allowedChars: RegExp = /^[a-zA-Z0-9._-]+$/): string`: Sanitizes filename.

- `detectExecutablePayload(fileData: Buffer, fileType: string): DetectionResult`: Detects executable payload.

- `entropyAnalysis(fileData: Buffer, blockSize: number = 1024, threshold: number = 7.5): EntropyResult`: Entropy analysis.

- `detectEmbeddedScript(fileData: Buffer, fileType: string, scriptTypes: string[] = ['javascript', 'vbscript', 'powershell', 'python', 'batch']): DetectionResult`: Detects embedded scripts.

- `detectSteganography(fileData: Buffer, analysisMethods: string[] = ['lsb', 'appended', 'entropy', 'histogram']): DetectionResult`: Detects steganography.

- `detectObfuscation(fileData: Buffer, detectionMethods: string[] = ['base64', 'hex', 'string_concat', 'entropy', 'control_flow']): DetectionResult`: Detects obfuscation.

- `secureTempfile(prefix: string = 'msf', suffix: string = '.tmp', directory?: string, deleteOnClose: boolean = true): string`: Creates secure tempfile.

- `immutableStorageCheck(filePath: string, expectedHash: string, storageType: string): boolean`: Verifies immutable storage.

---

### TS: Enterprise (10 functions)

Enterprise compliance: LGPD, GDPR, HIPAA, PCI-DSS, compliance reports, audit trails, policy as code, security dashboard, tenant isolation, multi-region security.

#### Functions

- `lgpdCheck(systemConfig: SystemConfig, dataFlows: DataFlow[], controls: Control[]): ComplianceResult`: Checks LGPD compliance.

- `gdprCheck(systemConfig: SystemConfig, dataProcessing: DataProcessing, controls: Control[]): ComplianceResult`: Checks GDPR compliance.

- `hipaaCheck(systemConfig: SystemConfig, phiHandling: PHIHandling, controls: Control[]): ComplianceResult`: Checks HIPAA compliance.

- `pciCheck(systemConfig: SystemConfig, cardDataHandling: CardDataHandling, controls: Control[]): ComplianceResult`: Checks PCI-DSS compliance.

- `complianceReport(checks: ComplianceResult[], framework: string, scope: string): ReportResult`: Generates compliance report.

- `auditTrail(events: AuditEvent[], userActions: UserAction[], dataChanges: DataChange[]): AuditResult`: Generates audit trail.

- `policyAsCode(policies: Policy[], context: PolicyContext, enforcement: PolicyEnforcement): PolicyResult`: Policy as code.

- `realtimeSecurityDashboard(metrics: SecurityMetric[], alerts: SecurityAlert[], trends: SecurityTrend[]): DashboardResult`: Security dashboard.

- `tenantIsolation(tenantConfig: TenantConfig, networkPolicies: NetworkPolicy[], dataSegregation: DataSegregation): IsolationResult`: Tenant isolation.

- `multiRegionSecurity(regions: RegionConfig[], dataResidencyRules: DataResidencyRule[], encryption: RegionEncryption): RegionResult`: Multi-region security.

---

### TS: Integrations (9 functions)

Integrations: Express, Fastify, NestJS, Next.js, Cloudflare, Deno, Bun, Browser Runtime, Service Worker, WASM.

#### Functions

- `expressSecurityMiddleware(app: unknown, config: ExpressConfig = {}, middlewareConfig: ExpressMiddlewareConfig = {}): MiddlewareResult`: Express security middleware.

- `fastifySecurityMiddleware(app: unknown, config: FastifyConfig = {}, securityConfig: FastifySecurityConfig = {}): MiddlewareResult`: Fastify security middleware.

- `nestjsSecurityModule(config: NestjsConfig = {}, guards: string[] = [], interceptors: string[] = []): ModuleResult`: NestJS security module.

- `nextjsSecurityHeaders(config: NextjsConfig = {}, headers: Record<string, string> = {}): HeadersResult`: Next.js security headers.

- `cloudflareEdgeProtection(config: CloudflareConfig = {}, rules: EdgeRule[] = [], workers: string[] = []): EdgeResult`: Cloudflare edge protection.

- `denoSecurityPlugin(config: DenoConfig = {}, permissions: string[] = [], sandbox: Record<string, unknown> = {}): PluginResult`: Deno security plugin.

- `bunSecurityPlugin(config: BunConfig = {}, optimizations: Record<string, unknown> = {}, security: Record<string, unknown> = {}): PluginResult`: Bun security plugin.

- `browserRuntimeProtection(config: BrowserConfig = {}, csp: string = '', sandbox: Record<string, unknown> = {}): ProtectionResult`: Browser runtime protection.

- `serviceWorkerSecurity(config: ServiceWorkerConfig = {}, scope: string = '/', permissions: string[] = []): SecurityResult`: Service Worker security.

- `wasmSecurityRuntime(config: WasmConfig = {}, memoryLimits: MemoryLimit = { initial: 1024, maximum: 4096, shared: false }, syscalls: string[] = []): RuntimeResult`: WASM security runtime.

---

## Usage Guide

### Python - Basic Example

```python
from master_security.auth import validate_jwt, generate_jwt
from master_security.web import detect_xss, sanitize_html
from master_security.api import validate_input, api_rate_limit
from master_security.network import validate_ip, detect_port_scan
from master_security.crypto import encrypt_data, decrypt_data, secure_random

# Generate and validate JWT
token = generate_jwt(
    subject="user-123",
    secret="my-secret-key",
    algorithm="HS256",
    expiry=3600,
    claims={"role": "admin"}
)
payload = validate_jwt(token, "my-secret-key", ["HS256"], True, None)

# Detect XSS
result = detect_xss("<script>alert('xss')</script>")
if result['detected']:
    print(f"Threat detected: {result['severity']}")

# Encrypt data
key = secure_random(32)
encrypted = encrypt_data(b"secret data", key, "aes-256-gcm")
decrypted = decrypt_data(encrypted['ciphertext'], key, encrypted['nonce'], "aes-256-gcm")
```

### TypeScript - Basic Example

```typescript
import { detectXss, sanitizeHtml, validateCors } from './src/web/index.js';
import { validateIp, detectPortScan } from './src/network/index.js';
import { generateHmac, verifyHmac, secureRandom } from './src/crypto/index.js';
import { getConfig, getMetrics, getEventBus } from './src/core/index.js';

// Detect XSS
const xssResult = detectXss("<script>alert('xss')</script>");
if (xssResult.detected) {
  console.log(`Threat: ${xssResult.severity}`);
}

// Generate and verify HMAC
const key = secureRandom(32);
const data = new TextEncoder().encode("payload");
const hmac = generateHmac(data, key);
const isValid = verifyHmac(data, hmac, key);

// Use metrics
const metrics = getMetrics();
metrics.incCounter('security_checks', { module: 'web' });
metrics.observeHistogram('detection_time_ms', 42.5);
```

---

## Telemetry & Observability

MSF integrates **OpenTelemetry** for distributed tracing, **metrics** (counters, gauges, histograms), **structured logging** (pino in TS, loguru in Python), and **event bus** for async communication.

### Available Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `jwt_validations` | Counter | Total JWT validations |
| `xss_detections` | Counter | XSS detections |
| `sqli_detections` | Counter | SQL Injection detections |
| `port_scan_detections` | Counter | Port scan detections |
| `ddos_detections` | Counter | DDoS detections |
| `malware_scans` | Counter | Malware scans executed |
| `anomaly_scores` | Histogram | Anomaly score distribution |
| `threat_scores` | Histogram | Threat score distribution |
| `detection_latency_ms` | Histogram | Detection latency |
| `active_sessions` | Gauge | Active sessions |
| `cache_hit_ratio` | Gauge | Cache hit ratio |

---

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Running Tests

```bash
# Python
cd master_security_python
python test_full.py

# TypeScript
cd packages/core
npx vitest run
```

---

## License

MIT License - see the LICENSE file for details.
