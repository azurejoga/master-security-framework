# Master Security Framework (MSF)

> **Framework de segurança abrangente, multi-linguagem e multi-camada para aplicações modernas.**

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://typescriptlang.org)
[![Tests](https://img.shields.io/badge/Tests-243%20passing-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

---

## Índice

1. [Visão Geral](#visão-geral)
2. [Arquitetura](#arquitetura)
3. [Instalação](#instalação)
4. [Módulos Python](#módulos-python)
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
5. [Módulos TypeScript](#módulos-typescript)
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
6. [Guia de Uso](#guia-de-uso)
7. [Telemetria e Observabilidade](#telemetria-e-observabilidade)
8. [Contribuição](#contribuição)

---

## Visão Geral

O **Master Security Framework (MSF)** é um framework de segurança completo, projetado para proteger aplicações em múltiplas camadas: desde autenticação e criptografia até detecção de ataques web, análise de rede, segurança cloud, proteção de IA e muito mais.

### Características Principais

- **243 testes passando** (77 Python + 166 TypeScript)
- **14 módulos Python** com 180+ funções
- **14 módulos TypeScript** com 170+ funções
- **Telemetria OpenTelemetry** integrada
- **Métricas e logging** estruturado com pino/loguru
- **Cache in-memory** com invalidação automática
- **Policy Engine** para regras de segurança configuráveis
- **Event Bus** para comunicação assíncrona entre módulos
- **Suporte a criptografia pós-quântica** (Kyber, Dilithium, SPHINCS+, Falcon)
- **Detecção de ataques** em tempo real (XSS, SQLi, SSRF, RCE, DDoS, etc.)
- **Honeypots adaptativos** e tokens de mel (honeytokens)
- **Conformidade enterprise** (LGPD, GDPR, HIPAA, PCI-DSS)
- **Integrações** com FastAPI, Django, Flask, Express, Next.js, NestJS, Cloudflare, e mais

---

## Arquitetura

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

## Instalação

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

## Módulos Python

### Python: Core

Módulo base com configuração, logging, telemetria, métricas, cache, policy engine e event bus.

#### Funções

- `get_config() -> dict`: Obtém a configuração global do framework com valores default e variáveis de ambiente.
- `set_config(config: dict) -> None`: Define a configuração global do framework.
- `reload_config() -> dict`: Recarrega a configuração a partir de variáveis de ambiente.
- `get_logger(name: str, level: str) -> logging.Logger`: Obtém um logger estruturado com contexto.
- `get_metrics() -> MetricsRegistry`: Obtém o registrador de métricas global.
- `get_policy_engine() -> PolicyEngine`: Obtém o motor de políticas de segurança.
- `get_event_bus() -> EventBus`: Obtém o barramento de eventos assíncrono.
- `get_cache() -> CacheManager`: Obtém o gerenciador de cache in-memory.
- `get_telemetry() -> TelemetryManager`: Obtém o gerenciador de telemetria OpenTelemetry.
- `create_span(name: str, attributes: dict) -> Span`: Cria um span de tracing OpenTelemetry.

---

### Python: Auth (30 funções)

Autenticação completa: JWT, TOTP, WebAuthn/Passkeys, detecção de ataques de credential stuffing, brute force, session hijacking, token replay, impossible travel, análise comportamental e verificação de breach de senhas.

#### Funções

- `validate_jwt(token: str, secret: str, algorithms: Optional[list[str]], verify_exp: bool, required_claims: Optional[dict[str, Any]]) -> dict`: Valida e decodifica um token JWT. Verifica assinatura, expiração, claims obrigatórios e retorna o payload decodificado.

- `generate_jwt(subject: str, secret: str, algorithm: str, expiry: int, claims: Optional[dict[str, Any]], issuer: Optional[str]) -> str`: Gera um token JWT assinado com subject, claims personalizadas, expiração e issuer configuráveis.

- `revoke_jwt(token_id: str, reason: str) -> bool`: Revoga um token JWT pelo seu JTI (JWT ID). Adiciona à blacklist de tokens revogados.

- `rotate_jwt(old_token: str, secret: str, algorithm: str, expiry: int) -> str`: Rotaciona um JWT validando o token antigo e emitindo um novo com mesma identidade.

- `validate_refresh_token(token: str, secret: str, user_id: str) -> dict`: Valida um refresh token para um usuário específico, verificando pertencimento e expiração.

- `secure_session(user_id: str, ip: str, user_agent: str, device_id: Optional[str]) -> dict`: Cria uma sessão segura para um usuário autenticado, registrando IP, user agent e device fingerprint.

- `validate_session(session_id: str, user_id: str, ip: str) -> bool`: Valida uma sessão existente verificando se o session_id pertence ao usuário e se o IP corresponde.

- `detect_session_hijack(session_id: str, current_ip: str, current_ua: str, historical_data: dict) -> bool`: Detecta possível sequestro de sessão comparando IP e user agent atuais com dados históricos.

- `detect_token_replay(token_id: str, timestamp: float, ip: str) -> bool`: Detecta se um token está sendo reutilizado (replay) verificando se já foi usado antes.

- `detect_credential_stuffing(ip: str, username: str, attempts: int, window: int) -> bool`: Detecta ataques de credential stuffing de um único IP baseado em tentativas em uma janela de tempo.

- `detect_bruteforce(ip: str, attempts: int, window: int, threshold: int) -> bool`: Detecta tentativas de brute force login de um único IP quando excede o threshold na janela.

- `adaptive_auth(user_id: str, risk_score: float, context: dict) -> dict`: Realiza autenticação adaptativa baseada em score de risco e contexto (localização, dispositivo, horário).

- `behavioral_auth(user_id: str, behavior_data: dict, baseline: dict) -> float`: Avalia autenticação baseada em biometria comportamental comparando com baseline do usuário.

- `impossible_travel(user_id: str, current_location: dict, last_location: dict, time_delta: float) -> bool`: Detecta viagem impossível entre duas localizações de login baseado em distância e tempo.

- `geo_velocity_check(user_id: str, locations: list[dict], max_speed_kmh: float) -> bool`: Verifica velocidade geográfica através de múltiplas localizações de login contra velocidade máxima permitida.

- `risk_based_auth(user_id: str, context: dict, risk_factors: dict) -> dict`: Realiza autenticação baseada em risco calculando score a partir de múltiplos fatores de risco.

- `passkey_auth(challenge: str, authenticator_data: bytes, client_data_json: str, signature: bytes) -> bool`: Valida uma autenticação passkey (FIDO2/WebAuthn) verificando assinatura e dados do autenticador.

- `webauthn_verify(credential_id: str, challenge: str, origin: str, rp_id: str, public_key: bytes, signature: bytes, auth_data: bytes, client_data: str) -> bool`: Verifica uma asserção WebAuthn completa com validação de origin, RP ID e assinatura criptográfica.

- `generate_totp(secret: str, digits: int, period: int, time_step: Optional[int]) -> str`: Gera um código TOTP (Time-based One-Time Password) com dígitos e período configuráveis.

- `validate_totp(secret: str, token: str, digits: int, period: int, drift: int) -> bool`: Valida um token TOTP com tolerância de drift de relógio para compensar dessincronização.

- `verify_backup_code(code: str, valid_codes: list[str]) -> bool`: Verifica um código de backup/recovery e o consome (remove da lista de válidos).

- `password_entropy(password: str) -> float`: Calcula a entropia Shannon de uma senha para medir sua complexidade informacional.

- `detect_weak_password(password: str, min_entropy: float, common_passwords: Optional[list[str]]) -> bool`: Detecta se uma senha é fraca baseada em entropia baixa e presença em listas de senhas comuns.

- `password_breach_check(password_hash: str, breach_db: dict[str, int]) -> bool`: Verifica se um hash de senha aparece em um banco de dados de breaches conhecidas.

- `secure_password_hash(password: str, algorithm: str, salt: Optional[str], iterations: int) -> str`: Cria um hash seguro de senha com salt e key stretching (iterações) para resistência a brute force.

- `verify_password_hash(password: str, hash_value: str) -> bool`: Verifica uma senha contra um hash armazenado usando comparação segura.

- `device_fingerprint(user_agent: str, screen: str, timezone: str, languages: list[str], platform: str) -> str`: Gera um fingerprint de dispositivo a partir de atributos do browser/sistema.

- `browser_fingerprint(canvas_hash: str, webgl_hash: str, audio_hash: str, fonts: list[str]) -> str`: Gera um fingerprint de browser baseado em características de rendering (canvas, WebGL, áudio, fontes).

- `biometric_validation(biometric_data: dict, stored_template: dict, threshold: float) -> bool`: Valida dados biométricos contra um template armazenado com threshold de similaridade.

- `phishing_resistant_auth(auth_method: str, fido_level: str, attestation: Optional[dict]) -> bool`: Verifica se um método de autenticação é resistente a phishing (FIDO2 level 2+).

---

### Python: Crypto (20 funções)

Criptografia autenticada (AES-GCM, ChaCha20-Poly1305), criptografia híbrida, criptografia pós-quântica (Kyber, Dilithium, SPHINCS+, Falcon), HMAC, geração segura de chaves e proteção contra timing attacks.

#### Funções

- `encrypt_data(plaintext: bytes, key: bytes, algorithm: str, aad: Optional[bytes]) -> dict[str, Any]`: Criptografa dados usando authenticated encryption (AES-GCM ou ChaCha20-Poly1305) com suporte a associated data.

- `decrypt_data(ciphertext: bytes, key: bytes, nonce: bytes, algorithm: str, aad: Optional[bytes]) -> bytes`: Descriptografa dados usando authenticated decryption, verificando integridade e autenticidade.

- `encrypt_file(filepath: str, key: bytes, output_path: Optional[str], algorithm: str) -> str`: Criptografa um arquivo em disco usando authenticated encryption, retornando o path do output.

- `decrypt_file(filepath: str, key: bytes, output_path: Optional[str], algorithm: str) -> str`: Descriptografa um arquivo em disco verificando integridade antes de retornar o conteúdo.

- `generate_keypair(algorithm: str, curve: Optional[str]) -> dict[str, Any]`: Gera um par de chaves assimétricas para assinatura ou troca de chaves (Ed25519, X25519, etc.).

- `rotate_keys(old_key: bytes, new_key: bytes, algorithm: str) -> dict[str, Any]`: Rotaciona chaves de criptografia re-criptografando um payload de teste com a nova chave.

- `secure_random(nbytes: int) -> bytes`: Gera bytes criptograficamente seguros usando `os.urandom()`.

- `hybrid_encrypt(plaintext: bytes, public_key: bytes, algorithm: str) -> dict[str, Any]`: Criptografa usando esquema híbrido: key exchange assimétrico + criptografia simétrica do payload.

- `hybrid_decrypt(encrypted_data: dict[str, Any], private_key: bytes, algorithm: str) -> bytes`: Descriptografa dados criptografados com esquema híbrido, recuperando o plaintext original.

- `pqc_encrypt(plaintext: bytes, public_key: bytes, algorithm: str) -> dict[str, Any]`: Criptografa usando algoritmo pós-quântico (ML-KEM/Kyber) resistente a computadores quânticos.

- `pqc_decrypt(encrypted_data: dict[str, Any], private_key: bytes, algorithm: str) -> bytes`: Descriptografa dados criptografados com algoritmo pós-quântico.

- `kyber_key_exchange(public_key: bytes, private_key: bytes) -> dict[str, Any]`: Realiza troca de chaves baseada em Kyber (ML-KEM) para estabelecimento de chave compartilhada pós-quântica.

- `dilithium_sign(message: bytes, private_key: bytes) -> dict[str, Any]`: Assina uma mensagem usando Dilithium (ML-DSA), esquema de assinatura pós-quântico do NIST.

- `sphincs_sign(message: bytes, private_key: bytes) -> dict[str, Any]`: Assina uma mensagem usando SPHINCS+, esquema de assinatura hash-based pós-quântico.

- `falcon_sign(message: bytes, private_key: bytes) -> dict[str, Any]`: Assina uma mensagem usando Falcon, esquema de assinatura lattice-based pós-quântico.

- `verify_signature(message: bytes, signature: bytes, public_key: bytes, algorithm: str) -> bool`: Verifica uma assinatura digital contra uma mensagem e chave pública.

- `generate_hmac(data: bytes, key: bytes, algorithm: str) -> str`: Gera um HMAC (Hash-based Message Authentication Code) para autenticação de integridade.

- `verify_hmac(data: bytes, signature: str, key: bytes, algorithm: str) -> bool`: Verifica um HMAC comparando a assinatura esperada com a calculada.

- `secure_memory_erase(data: bytearray) -> None`: Apaga seguramente dados sensíveis da memória sobrescrevendo com zeros.

- `anti_timing_compare(a: bytes, b: bytes) -> bool`: Compara duas sequências de bytes em tempo constante para prevenir timing attacks.

---

### Python: Web (30 funções)

Detecção e prevenção de ataques web: XSS, SQL Injection, NoSQL Injection, SSRF, RCE, LFI, RFI, SSTI, Command Injection, Deserialization, Path Traversal, Open Redirect, Clickjacking, CSRF, CORS, e sanitização de HTML/SVG/Markdown/CSS/JS.

#### Funções

- `detect_xss(input_str: str, patterns: Optional[list[str]], severity_threshold: str) -> dict[str, Any]`: Detecta padrões de ataque Cross-Site Scripting (XSS) incluindo script tags, event handlers, javascript: URIs e DOM XSS.

- `sanitize_html(html_str: str, allowed_tags: Optional[list[str]], allowed_attrs: Optional[list[str]]) -> str`: Sanitiza HTML removendo tags e atributos não permitidos, prevenindo XSS via HTML injection.

- `sanitize_svg(svg: str, allowed_elements: Optional[list[str]]) -> str`: Sanitiza SVG removendo elementos e atributos perigosos como `<script>`, `onload`, e event handlers.

- `sanitize_markdown(markdown: str, allowed_html: Optional[list[str]]) -> str`: Sanitiza markdown removendo HTML perigoso embutido enquanto preserva a formatação markdown.

- `sanitize_css(css: str, allowed_properties: Optional[list[str]]) -> str`: Sanitiza CSS removendo propriedades perigosas como `expression()`, `url(javascript:)`, e `behavior`.

- `sanitize_js(js_code: str, dangerous_patterns: Optional[list[str]]) -> str`: Sanitiza JavaScript removendo padrões perigosos como `eval()`, `Function()`, `document.write()`, etc.

- `detect_sqli(input_str: str, patterns: Optional[list[str]], context: Optional[str]) -> dict[str, Any]`: Detecta padrões de SQL Injection incluindo UNION-based, blind, time-based, e error-based injection.

- `detect_nosqli(input_str: str, patterns: Optional[list[str]]) -> dict[str, Any]`: Detecta padrões de NoSQL Injection em queries MongoDB/NoSQL usando operadores como `$gt`, `$ne`, `$regex`.

- `detect_ssrf(url: str, allowed_domains: Optional[list[str]], blocked_ips: Optional[list[str]]) -> dict[str, Any]`: Detecta Server-Side Request Forgery verificando URLs contra domínios permitidos e IPs bloqueados (incluindo localhost, metadata endpoints).

- `detect_rce(input_str: str, patterns: Optional[list[str]]) -> dict[str, Any]`: Detecta padrões de Remote Code Execution incluindo chamadas a `eval()`, `exec()`, `system()`, backticks, e pipe operators.

- `detect_lfi(input_str: str, patterns: Optional[list[str]]) -> dict[str, Any]`: Detecta Local File Inclusion usando path traversal como `../../etc/passwd`, `php://filter`, e `data://` URIs.

- `detect_rfi(input_str: str, patterns: Optional[list[str]]) -> dict[str, Any]`: Detecta Remote File Inclusion via URLs externas em parâmetros de include/require.

- `detect_template_injection(input_str: str, engine_type: str) -> dict[str, Any]`: Detecta Server-Side Template Injection (SSTI) para engines Jinja2, EJS, Handlebars, Pug, Twig, etc.

- `detect_command_injection(input_str: str, patterns: Optional[list[str]]) -> dict[str, Any]`: Detecta OS Command Injection usando operadores como `;`, `|`, `&&`, `||`, backticks, e `$()`.

- `detect_deserialization_attack(data: Any, allowed_classes: Optional[list[str]]) -> dict[str, Any]`: Detecta insecure deserialization verificando classes permitidas e padrões de gadgets conhecidos.

- `detect_path_traversal(input_str: str, base_path: Optional[str]) -> dict[str, Any]`: Detecta path traversal usando `../`, `..\\`, encoded traversal, e verifica se o path resolve dentro do base_path.

- `detect_open_redirect(url: str, allowed_hosts: Optional[list[str]]) -> dict[str, Any]`: Detecta open redirect verificando se a URL de redirecionamento aponta para um host permitido.

- `validate_cors(origin: str, allowed_origins: Optional[list[str]], allowed_methods: Optional[list[str]], allowed_headers: Optional[list[str]]) -> dict[str, Any]`: Valida requisição CORS verificando Origin, Methods e Headers contra listas de permitidos.

- `secure_headers(request: Optional[dict[str, Any]], config: Optional[dict[str, Any]]) -> dict[str, str]`: Gera headers HTTP seguros incluindo HSTS, X-Frame-Options, X-Content-Type-Options, CSP, Referrer-Policy, etc.

- `generate_csp(config: Optional[dict[str, Any]]) -> str`: Gera um header Content-Security-Policy a partir de uma configuração de diretivas.

- `validate_csp(csp_header: str, policy: Optional[dict[str, Any]]) -> bool`: Valida um header CSP contra uma política de segurança definida.

- `csrf_protect(request: Optional[dict[str, Any]], token: Optional[str], session_token: Optional[str]) -> bool`: Protege contra CSRF verificando o token da requisição contra o token da sessão.

- `validate_csrf(token: Optional[str], session_token: Optional[str]) -> bool`: Valida um token CSRF contra o token da sessão usando comparação segura.

- `secure_cookie(name: str, value: str, domain: Optional[str], path: str, secure: bool, httponly: bool, samesite: str, max_age: Optional[int]) -> str`: Gera um header Set-Cookie seguro com flags Secure, HttpOnly, SameSite e domínio escopo.

- `detect_clickjacking(headers: Optional[dict[str, str]], frame_options: Optional[str]) -> bool`: Detecta vulnerabilidade de clickjacking verificando ausência de X-Frame-Options ou CSP frame-ancestors.

- `validate_origin(origin: str, allowed_origins: Optional[list[str]]) -> bool`: Valida o header Origin contra uma lista de origens permitidas.

- `validate_referer(referer: str, expected_domain: str) -> bool`: Valida o header Referer contra um domínio esperado para prevenir CSRF e hotlinking.

- `secure_redirect(url: str, allowed_hosts: Optional[list[str]]) -> str`: Valida e retorna uma URL de redirecionamento segura, prevenindo open redirect.

- `webhook_signature(payload: str, secret: str, algorithm: str, timestamp: Optional[str]) -> str`: Gera uma assinatura HMAC para verificação de payload de webhook.

- `webhook_replay_protection(signature: str, timestamp: str, payload: str, secret: str, window: int) -> bool`: Protege contra replay de webhooks verificando assinatura e timestamp dentro de uma janela.

---

### Python: API (18 funções)

Segurança de APIs: validação JSON Schema, sanitização, rate limiting adaptativo, detecção de BOLA/IDOR, broken authentication, mass assignment, shadow APIs, GraphQL security (depth limit, cost analysis, abuse detection), gRPC security, WebSocket security, e API key management.

#### Funções

- `validate_json_schema(data: Any, schema: dict[str, Any], strict_mode: bool) -> dict[str, Any]`: Valida dados contra uma definição JSON Schema com modo estrito opcional para campos extras.

- `validate_input(data: Any, rules: dict[str, Any], max_depth: int, max_size: int) -> dict[str, Any]`: Valida dados de entrada de API contra regras de tipo, tamanho, padrão, enum, e profundidade máxima.

- `sanitize_json(data: Any, allowed_types: Optional[set[str]], max_string_length: int) -> dict[str, Any]`: Sanitiza dados JSON removendo tipos não permitidos e truncando strings longas.

- `api_rate_limit(client_id: str, endpoint: str, config: Optional[dict[str, Any]]) -> dict[str, Any]`: Aplica rate limiting usando sliding window algorithm com limites configuráveis por cliente e endpoint.

- `adaptive_rate_limit(client_id: str, endpoint: str, behavior: dict[str, Any], config: Optional[dict[str, Any]]) -> dict[str, Any]`: Aplica rate limiting adaptativo baseado em padrões de comportamento do cliente (ajusta limites dinamicamente).

- `detect_api_abuse(requests: list[dict[str, Any]], patterns: Optional[list[str]], window: int) -> dict[str, Any]`: Detecta padrões de abuso de API como scraping, enumeration, fuzzing, e automação maliciosa.

- `detect_bola(resource_id: str, user_id: str, ownership_map: dict[str, Any]) -> bool`: Detecta Broken Object Level Authorization (BOLA/IDOR) verificando se o usuário tem acesso ao recurso solicitado.

- `detect_broken_auth(auth_header: Optional[str], required_scopes: Optional[list[str]], token: Optional[dict[str, Any]]) -> dict[str, Any]`: Detecta problemas de autenticação e autorização como tokens ausentes, expirados, ou com scopes insuficientes.

- `detect_mass_assignment(input_data: dict[str, Any], model_fields: set[str], readonly_fields: Optional[set[str]]) -> dict[str, Any]`: Detecta mass assignment verificando se campos protegidos ou desconhecidos estão sendo enviados.

- `detect_shadow_api(endpoint: str, documented_apis: set[str], traffic_patterns: dict[str, Any]) -> dict[str, Any]`: Detecta shadow APIs - endpoints não documentados que estão recebendo tráfego.

- `api_threat_score(request: dict[str, Any], context: Optional[dict[str, Any]], threat_intel: Optional[dict[str, Any]]) -> float`: Calcula score de ameaça composto para uma requisição API baseado em contexto e threat intelligence.

- `graphql_depth_limit(query: str, max_depth: int, introspection_enabled: bool) -> dict[str, Any]`: Valida profundidade de query GraphQL contra limite configurado, prevenindo queries recursivas maliciosas.

- `graphql_cost_analysis(query: str, complexity_map: Optional[dict[str, int]], max_cost: int) -> dict[str, Any]`: Analisa custo computacional de query GraphQL baseado em complexidade de campos e nested queries.

- `graphql_abuse_detection(queries: list[dict[str, Any]], window: int, thresholds: Optional[dict[str, Any]]) -> dict[str, Any]`: Detecta padrões de abuso GraphQL como query flooding, introspection abuse, e queries de alto custo repetidas.

- `grpc_security_validation(metadata: dict[str, str], required_headers: Optional[list[str]], tls_info: Optional[dict[str, Any]]) -> dict[str, Any]`: Valida segurança de requisições gRPC verificando metadata, headers obrigatórios e informações TLS.

- `secure_websocket(origin: Optional[str], allowed_origins: Optional[list[str]], subprotocols: Optional[list[str]]) -> dict[str, Any]`: Configura e valida conexão WebSocket segura com origin validation e subprotocolos permitidos.

- `api_key_rotation(current_key: str, algorithm: str, expiry_days: int) -> dict[str, Any]`: Gera nova API key com parâmetros seguros de rotação (hash, expiração, prefixo).

- `api_key_validation(api_key: str, valid_keys: dict[str, Any], scopes: Optional[list[str]], required_scope: Optional[str]) -> dict[str, Any]`: Valida uma API key contra registry de keys conhecidas verificando scopes e expiração.

---

### Python: AI (20 funções)

Proteção de aplicações IA: detecção de prompt injection, jailbreak, vazamento de dados sensíveis, system prompt leak, data exfiltration, impersonation, model abuse, agent abuse, LLM firewall, policy engine, RAG source validation, hallucination risk, output guardrails, tool call validation, multi-agent isolation, memory sanitization, token monitoring, e behavior monitoring.

#### Funções

- `detect_prompt_injection(prompt: str, patterns: Optional[list[str]], threshold: float) -> dict[str, Any]`: Detecta tentativas de prompt injection como "ignore previous instructions", "forget all rules", "system:", "you are now", etc.

- `detect_jailbreak(prompt: str, patterns: Optional[list[str]], threshold: float) -> dict[str, Any]`: Detecta jailbreaks como DAN mode, "do anything now", "disable safety", "unrestricted mode", roleplay sem filtros.

- `sanitize_prompt(prompt: str, max_length: int, blocked_patterns: Optional[list[str]]) -> str`: Sanitiza prompt do usuário removendo padrões bloqueados e aplicando limite de tamanho.

- `sanitize_llm_output(output: str, max_length: int, blocked_patterns: Optional[list[str]]) -> str`: Sanitiza output do LLM removendo scripts, event handlers, e dados sensíveis.

- `detect_sensitive_leak(text: str, patterns: Optional[list[str]]) -> dict[str, Any]`: Detecta vazamento de dados sensíveis como SSN, CPF, cartões de crédito, emails, chaves API, senhas.

- `detect_prompt_leak(prompt: str, system_prompt: str, threshold: float) -> dict[str, Any]`: Detecta tentativas de extrair ou vazar o system prompt usando similaridade de conteúdo.

- `detect_data_exfiltration(output: str, sensitive_patterns: Optional[list[str]]) -> dict[str, Any]`: Detecta potencial exfiltração de dados no output do LLM usando pattern matching de dados sensíveis.

- `detect_ai_impersonation(content: str, claimed_identity: str, markers: Optional[list[str]]) -> dict[str, Any]`: Detecta tentativas de impersonação de IA verificando markers de identidade e inconsistências.

- `detect_model_abuse(request_patterns: list[str], rate: float, complexity: float) -> dict[str, Any]`: Detecta abuso de modelo via repetição excessiva, alta taxa de requisições, e complexidade anormal.

- `detect_agent_abuse(agent_behavior: dict[str, Any], policy: dict[str, Any], thresholds: Optional[dict[str, float]]) -> dict[str, Any]`: Detecta comportamento de agente que viola políticas de uso e thresholds configurados.

- `llm_firewall(input_data: dict[str, Any], rules: list[dict[str, Any]], action_on_violation: str) -> dict[str, Any]`: Avalia input contra regras de firewall LLM com ações configuráveis (block, warn, log).

- `ai_policy_engine(prompt: str, output: str, policies: list[dict[str, Any]]) -> dict[str, Any]`: Avalia prompt e output contra um conjunto de políticas de segurança IA.

- `rag_source_validation(sources: list[dict[str, Any]], trusted_domains: Optional[list[str]], validation_rules: Optional[dict[str, Any]]) -> dict[str, Any]`: Valida credibilidade de fontes RAG (Retrieval-Augmented Generation) contra domínios confiáveis.

- `hallucination_risk(output: str, confidence_scores: Optional[list[float]], factual_checks: Optional[list[dict[str, Any]]]) -> dict[str, Any]`: Avalia risco de alucinação no output do LLM baseado em scores de confiança e verificações factuais.

- `ai_output_guard(output: str, guardrails: Optional[list[dict[str, Any]]], redaction_rules: Optional[list[dict[str, Any]]]) -> str`: Aplica guardrails e regras de redação ao output do LLM.

- `tool_call_validation(tool_name: str, arguments: dict[str, Any], allowed_tools: list[str], argument_schemas: Optional[dict[str, dict[str, Any]]]) -> dict[str, Any]`: Valida chamada de ferramenta contra ferramentas permitidas e schemas de argumentos.

- `multi_agent_isolation(agents: list[dict[str, Any]], communication_rules: Optional[dict[str, Any]]) -> dict[str, Any]`: Valida isolamento e políticas de comunicação entre múltiplos agentes IA.

- `ai_memory_sanitizer(memory_entries: list[dict[str, Any]], retention_policy: Optional[dict[str, Any]]) -> list[dict[str, Any]`: Sanitiza entradas de memória IA baseado em política de retenção e expiração.

- `ai_token_monitor(usage: dict[str, int], limits: Optional[dict[str, int]], window: int) -> dict[str, Any]`: Monitora uso de tokens IA contra limites definidos (por request, minuto, dia, custo).

- `ai_behavior_monitor(behavior_log: list[dict[str, Any]], baseline: Optional[dict[str, Any]], deviation_threshold: float) -> dict[str, Any]`: Monitora comportamento IA para desvios de baseline estabelecida.

---

### Python: Network (21 funções)

Segurança de rede: detecção de port scan, DNS tunneling, anomalias de tráfego, proxy/VPN/Tor detection, DDoS, validação de IP/domínio, IP spoofing, ARP poisoning, TLS fingerprinting (JA3), beaconing detection (C2), lateral movement, C2 communication detection, network entropy analysis, traffic behavior analysis, e protocol anomaly detection.

#### Funções

- `detect_port_scan(source_ip: str, connections: list[dict[str, Any]], window: float, threshold: int) -> dict[str, Any]`: Detecta port scanning activity analisando portas únicas, taxa de conexão, padrões SYN/RST.

- `detect_dns_tunneling(dns_queries: list[dict[str, Any]], domain: str, threshold: float) -> dict[str, Any]`: Detecta DNS tunneling analisando entropia de queries, tamanho de subdomínios, e frequência.

- `detect_traffic_anomaly(traffic_data: list[dict[str, Any]], baseline: dict[str, float], deviation_threshold: float) -> dict[str, Any]`: Detecta anomalias de tráfego comparando métricas atuais contra baseline usando z-score.

- `detect_proxy(ip: str, headers: dict[str, str], detection_methods: Optional[list[str]]) -> dict[str, Any]`: Detecta se uma conexão vem através de proxy verificando headers como X-Forwarded-For, Via, etc.

- `detect_vpn(ip: str, headers: dict[str, str], vpn_db: Optional[dict[str, Any]]) -> dict[str, Any]`: Detecta se um IP origina de serviço VPN usando database de IPs conhecidos.

- `detect_tor(ip: str, tor_nodes: Optional[list[str]], exit_nodes: Optional[list[str]]) -> dict[str, Any]`: Detecta se um IP pertence à rede Tor verificando contra lista de nós e exit nodes.

- `detect_ddos(traffic_data: list[dict[str, Any]], baseline: dict[str, float], threshold: float, window: float) -> dict[str, Any]`: Detecta ataques DDoS analisando bytes/packets por segundo contra baseline e threshold.

- `validate_ip(ip: str, allowed_ranges: Optional[list[str]], blocked_ranges: Optional[list[str]]) -> dict[str, Any]`: Valida endereço IP contra ranges permitidos e bloqueados usando CIDR matching.

- `validate_domain(domain: str, allowed_tlds: Optional[list[str]], blocked_domains: Optional[list[str]]) -> dict[str, Any]`: Valida domínio verificando TLD contra lista permitida e domínio contra lista bloqueada.

- `detect_spoofing(packet_data: dict[str, Any], expected_source: str, network_topology: dict[str, Any]) -> dict[str, Any]`: Detecta IP spoofing analisando dados do pacote contra fontes esperadas e topologia de rede.

- `detect_arp_poisoning(arp_table: list[dict[str, Any]], expected_mappings: dict[str, str]) -> dict[str, Any]`: Detecta ARP poisoning comparando tabela ARP atual contra mapeamentos esperados IP→MAC.

- `tls_fingerprint(tls_handshake: dict[str, Any], ja3_database: Optional[dict[str, Any]]) -> dict[str, Any]`: Gera e compara fingerprint TLS do handshake contra database de fingerprints conhecidos.

- `ja3_fingerprint(tls_client_hello: dict[str, Any]) -> str`: Gera fingerprint JA3 hash de um TLS ClientHello para identificação de client TLS.

- `suspicious_dns_detection(dns_queries: list[dict[str, Any]], threat_intel: Optional[dict[str, Any]], patterns: Optional[list[str]]) -> dict[str, Any]`: Detecta atividade DNS suspeita usando threat intelligence e pattern matching de domínios maliciosos.

- `beaconing_detection(connections: list[dict[str, Any]], interval_threshold: float, jitter_threshold: float) -> dict[str, Any]`: Detecta comportamento de beaconing indicativo de comunicação command-and-control (C2).

- `lateral_movement_detection(events: list[dict[str, Any]], network_topology: dict[str, Any], user_behavior: Optional[dict[str, Any]]) -> dict[str, Any]`: Detecta movimento lateral na rede analisando padrões de acesso entre hosts.

- `command_and_control_detection(traffic_patterns: list[dict[str, Any]], known_c2: Optional[dict[str, Any]], behavioral_analysis: Optional[dict[str, Any]]) -> dict[str, Any]`: Detecta padrões de comunicação C2 usando threat intelligence e análise comportamental.

- `network_entropy_analysis(packets: list[dict[str, Any]], block_size: int, threshold: float) -> dict[str, Any]`: Analisa entropia de pacotes de rede para detectar tráfego criptografado ou codificado.

- `traffic_behavior_analysis(traffic_data: list[dict[str, Any]], baseline: dict[str, Any], time_window: float) -> dict[str, Any]`: Analisa comportamento de tráfego contra baselines estabelecidas em janela de tempo.

- `protocol_anomaly_detection(protocol_data: list[dict[str, Any]], protocol_spec: dict[str, Any], deviation_threshold: float) -> dict[str, Any]`: Detecta anomalias em protocolo comparando dados contra especificação do protocolo.

- `shannon_entropy(data: str|bytes) -> float`: Calcula entropia Shannon de dados para medir aleatoriedade/complexidade informacional.

---

### Python: Cloud (21 funções)

Segurança cloud: validação de Dockerfile, detecção de container escape, Kubernetes RBAC, S3 bucket público, IAM policies, detecção de misconfig, secrets manager, Terraform validation, Kubernetes manifests, runtime container protection, supply chain validation, SBOM generation, dependency audit, typosquatting detection, container image scanning, K8s runtime anomaly, cloud security score, workload identity, confidential computing validation.

#### Funções

- `validate_dockerfile(dockerfile_content: str, rules: Optional[dict[str, Any]], severity_threshold: str) -> dict[str, Any]`: Valida Dockerfile contra best practices: sem `latest`, sem `root`, com healthcheck, sem secrets hardcoded.

- `detect_container_escape(container_config: dict[str, Any], capabilities: Optional[list[str]], namespaces: Optional[list[str]]) -> dict[str, Any]`: Detecta vetores potenciais de container escape como privileged mode, hostPath mounts, capabilities perigosas.

- `validate_k8s_rbac(rbac_config: dict[str, Any], least_privilege_rules: Optional[dict[str, Any]]) -> dict[str, Any]`: Valida configuração RBAC do Kubernetes contra princípios de menor privilégio.

- `detect_public_bucket(bucket_config: dict[str, Any], policies: Optional[list[dict[str, Any]]], acl: Optional[str]) -> dict[str, Any]`: Detecta se bucket de cloud storage está publicamente acessível via policy, ACL, ou config.

- `validate_s3_permissions(bucket_policy: dict[str, Any], expected_permissions: dict[str, Any]) -> dict[str, Any]`: Valida permissões de bucket S3 contra requisitos de segurança esperados.

- `validate_iam_policy(iam_policy: dict[str, Any], allowed_actions: Optional[list[str]], denied_actions: Optional[list[str]]) -> dict[str, Any]`: Valida política IAM contra listas de ações permitidas e negadas, detectando over-permission.

- `detect_cloud_misconfig(config: dict[str, Any], security_baseline: Optional[dict[str, Any]], cloud_provider: str) -> dict[str, Any]`: Detecta misconfigurações de infraestrutura cloud contra baseline de segurança por provider (AWS, GCP, Azure).

- `validate_secrets_manager(secrets_config: dict[str, Any], rotation_policy: Optional[dict[str, Any]], encryption: Optional[dict[str, Any]]) -> dict[str, Any]`: Valida configuração de secrets manager verificando rotação automática, encryption at rest, e acesso.

- `validate_terraform(terraform_plan: dict[str, Any], policies: Optional[list[dict[str, Any]]], severity_threshold: str) -> dict[str, Any]`: Valida plano Terraform contra políticas de segurança detectando recursos inseguros.

- `validate_kubernetes_manifest(manifest: dict[str, Any], pod_security_policy: Optional[dict[str, Any]], network_policy: Optional[dict[str, Any]]) -> dict[str, Any]`: Valida manifest Kubernetes contra pod security policies e network policies.

- `runtime_container_protection(container_events: list[dict[str, Any]], threat_rules: Optional[list[dict[str, Any]]], actions: Optional[dict[str, str]]) -> dict[str, Any]`: Analisa eventos de container em runtime contra regras de ameaça e executa ações (block, alert, isolate).

- `supply_chain_validation(dependencies: list[dict[str, Any]], trusted_sources: Optional[list[str]], vulnerability_db: Optional[dict[str, Any]]) -> dict[str, Any]`: Valida dependências de software contra fontes confiáveis e database de vulnerabilidades.

- `sbom_generator(components: list[dict[str, Any]], format: str, metadata: Optional[dict[str, Any]]) -> dict[str, Any]`: Gera Software Bill of Materials (SBOM) nos formatos SPDX, CycloneDX ou custom.

- `dependency_audit(dependencies: list[dict[str, Any]], audit_db: Optional[dict[str, Any]], severity_threshold: str) -> dict[str, Any]`: Audita dependências contra database de vulnerabilidades com filtro de severidade.

- `detect_typosquatting(package_name: str, known_packages: Optional[list[str]], similarity_threshold: float) -> dict[str, Any]`: Detecta typosquatting comparando nome do package contra packages conhecidos usando similaridade de string.

- `container_image_scan(image_layers: list[dict[str, Any]], signatures: Optional[list[dict[str, Any]]], vulnerability_db: Optional[dict[str, Any]]) -> dict[str, Any]`: Escaneia layers de imagem de container por vulnerabilidades e verifica assinaturas.

- `runtime_k8s_anomaly(k8s_events: list[dict[str, Any]], baseline: Optional[dict[str, Any]], anomaly_threshold: float) -> dict[str, Any]`: Detecta comportamento anômalo em eventos runtime do Kubernetes.

- `cloud_security_score(config: dict[str, Any], benchmarks: Optional[dict[str, Any]], weights: Optional[dict[str, float]]) -> dict[str, Any]`: Calcula score geral de segurança cloud baseado em benchmarks CIS e pesos configuráveis.

- `workload_identity_validation(workload_config: dict[str, Any], identity_provider: Optional[str], trust_policy: Optional[dict[str, Any]]) -> dict[str, Any]`: Valida configuração de workload identity (IRSA, GKE Workload Identity, etc.).

- `confidential_computing_validation(attestation: dict[str, Any], tee_type: str, expected_measurements: Optional[dict[str, str]]) -> dict[str, Any]`: Valida attestation de confidential computing para TEEs (SGX, TDX, SEV-SNP, Nitro Enclaves).

---

### Python: Monitoring (20 funções)

Monitoramento de segurança: tamperproof logging, anomaly scoring, threat scoring, risk scoring, event correlation, real-time alerting, adaptive alerting, attack path analysis, threat graph, behavioral analysis, UEBA, account takeover detection, fraud detection, autonomous response, security event bus, forensic snapshot, incident timeline, MITRE ATT&CK mapping, autonomous triage.

#### Funções

- `secure_log(event: str, level: str, data: Optional[dict[str, Any]], tamperproof: bool) -> dict[str, Any]`: Cria entrada de log de segurança tamper-resistant com integridade criptográfica (hash chain).

- `tamperproof_logs(log_entries: list[dict[str, Any]], chain_verification: bool) -> bool`: Verifica integridade de cadeia de logs tamperproof validando hashes encadeados.

- `anomaly_score(metrics: dict[str, float], baseline: dict[str, dict[str, float]], weights: Optional[dict[str, float]]) -> float`: Calcula score de anomalia usando z-score estatístico contra baseline com pesos por métrica.

- `threat_score(events: list[dict[str, Any]], threat_intel: Optional[dict[str, Any]], context: Optional[dict[str, Any]]) -> float`: Calcula score de ameaça composto a partir de eventos e threat intelligence.

- `risk_score(user_id: str, events: list[dict[str, Any]], context: Optional[dict[str, Any]], historical: Optional[dict[str, Any]]) -> float`: Calcula score de risco para usuário baseado em eventos, contexto e histórico.

- `correlate_events(events: list[dict[str, Any]], time_window: int, correlation_rules: Optional[list[dict[str, Any]]]) -> list[dict[str, Any]]`: Correlaciona eventos de segurança em janela de tempo usando rule-based matching.

- `realtime_alert(event: dict[str, Any], alert_rules: Optional[list[dict[str, Any]]], notification_channels: Optional[list[str]]) -> dict[str, Any]`: Avalia evento contra regras de alerta e gera alertas em tempo real com notificações.

- `adaptive_alerting(events: list[dict[str, Any]], baseline: Optional[dict[str, Any]], alert_fatigue_threshold: float) -> dict[str, Any]`: Gera alertas adaptativamente baseado em baseline e gerenciamento de fadiga de alerta.

- `attack_path_analysis(events: list[dict[str, Any]], network_topology: Optional[dict[str, Any]], attack_graph: Optional[dict[str, list[str]]]) -> dict[str, Any]`: Analisa caminhos de ataque potenciais através da rede baseado em eventos e topologia.

- `threat_graph(events: list[dict[str, Any]], entities: Optional[list[dict[str, Any]]], relationships: Optional[list[dict[str, Any]]]) -> dict[str, Any]`: Constrói grafo de conhecimento de ameaça a partir de eventos, entidades e relacionamentos.

- `behavioral_analysis(user_events: list[dict[str, Any]], baseline: Optional[dict[str, Any]], deviation_threshold: float) -> dict[str, Any]`: Analisa comportamento de usuário contra baselines estabelecidas para detectar desvios.

- `ueba_analysis(user_events: list[dict[str, Any]], peer_group: Optional[dict[str, Any]], anomaly_threshold: float) -> dict[str, Any]`: Realiza User and Entity Behavior Analytics (UEBA) comparando contra peer groups.

- `detect_account_takeover(user_events: list[dict[str, Any]], baseline: Optional[dict[str, Any]], risk_factors: Optional[dict[str, Any]]) -> dict[str, Any]`: Detecta tentativas de account takeover baseado em anomalias comportamentais.

- `detect_fraud(transactions: list[dict[str, Any]], patterns: Optional[list[dict[str, Any]]], risk_threshold: float) -> dict[str, Any]`: Detecta fraude potencial em transações usando análise de padrões rule-based.

- `autonomous_response(threat: dict[str, Any], response_rules: Optional[list[dict[str, Any]]], actions: Optional[list[dict[str, Any]]]) -> dict[str, Any]`: Executa resposta autônoma a incidente baseado em severidade da ameaça e regras.

- `security_event_bus(event: dict[str, Any], handlers: Optional[list[dict[str, Any]]], routing: Optional[dict[str, list[str]]]) -> dict[str, Any]`: Roteia eventos de segurança através de event bus para handlers registrados.

- `forensic_snapshot(system_state: dict[str, Any], evidence: Optional[list[dict[str, Any]]], chain_of_custody: Optional[dict[str, Any]]) -> dict[str, Any]`: Cria snapshot forense do estado do sistema com cadeia de custódia de evidências.

- `incident_timeline(events: list[dict[str, Any]], incident_id: str, classification: Optional[str]) -> dict[str, Any]`: Constrói timeline cronológica de incidente a partir de eventos de segurança.

- `attack_chain_mapping(events: list[dict[str, Any]], mitre_framework: Optional[dict[str, Any]], kill_chain: Optional[list[str]]) -> dict[str, Any]`: Mapeia eventos de segurança para framework MITRE ATT&CK e Cyber Kill Chain.

- `autonomous_triage(alert: dict[str, Any], triage_rules: Optional[list[dict[str, Any]]], enrichment_sources: Optional[list[dict[str, Any]]]) -> dict[str, Any]`: Realiza triagem autônoma de alertas usando regras e dados de enriquecimento.

---

### Python: Defensive (20 funções)

Defesa ativa: runtime self-protection, anti-debugging, anti-tampering, memory integrity, process integrity, code signing validation, binary integrity, secure boot validation, secure update validation, anti-hook, anti-injection, anti-rootkit, anti-VM, anti-emulation, moving target defense, dynamic attack surface, runtime policy engine, self-healing security, adaptive threat response, autonomous containment.

#### Funções

- `runtime_self_protection(config: Optional[dict[str, Any]], integrity_checks: Optional[list[str]], monitoring: bool) -> dict[str, Any]`: Habilita mecanismos de auto-proteção em runtime: integrity checks, anti-debug, monitoring.

- `anti_debugging_detection(process_info: Optional[dict[str, Any]], ptrace_status: Optional[str], debugger_signals: Optional[list[str]]) -> dict[str, Any]`: Detecta tentativas de debugging ativo via ptrace, sinais de debugger, e anomalias de processo.

- `anti_tampering(binary_hash: Optional[str], expected_hash: Optional[str], integrity_checks: Optional[list[str]]) -> dict[str, Any]`: Verifica integridade de binário comparando hashes esperados contra hashes atuais.

- `memory_integrity_check(memory_regions: Optional[list[dict[str, Any]]], expected_state: Optional[dict[str, Any]], signatures: Optional[list[str]]) -> dict[str, Any]`: Verifica integridade de regiões de memória contra estado esperado e assinaturas conhecidas.

- `process_integrity_check(process_id: Optional[int], expected_modules: Optional[list[str]], allowed_parents: Optional[list[str]]) -> dict[str, Any]`: Verifica integridade de processo incluindo módulos carregados e cadeia de processos pais.

- `code_signing_validation(binary_path: Optional[str], certificate_store: Optional[dict[str, Any]], revocation_check: bool) -> dict[str, Any]`: Valida certificado de code signing de binário contra store confiável e lista de revogação.

- `binary_integrity_validation(binary_path: Optional[str], expected_hashes: Optional[dict[str, str]], sections: Optional[list[str]]) -> dict[str, Any]`: Valida integridade de binário por verificação de hash por seção (.text, .data, .rsrc, etc.).

- `secure_boot_validation(boot_chain: Optional[list[dict[str, Any]]], measurements: Optional[dict[str, str]], pcr_values: Optional[dict[int, str]]) -> dict[str, Any]`: Valida cadeia de secure boot e medições PCR do TPM.

- `secure_update_validation(update_package: Optional[dict[str, Any]], signature: Optional[str], version: Optional[str], channel: str) -> dict[str, Any]`: Valida pacote de update verificando autenticidade, integridade, versão e canal.

- `anti_hook_detection(functions: Optional[list[dict[str, Any]]], memory_regions: Optional[list[dict[str, Any]]], known_hooks: Optional[list[str]]) -> dict[str, Any]`: Detecta hooks de função e modificações inline em memória (IAT hooking, inline hooking).

- `anti_injection_detection(process_modules: Optional[list[str]], loaded_libraries: Optional[list[str]], injection_signatures: Optional[list[str]]) -> dict[str, Any]`: Detecta injeção de código em espaço de memória de processo (DLL injection, process hollowing).

- `anti_rootkit_detection(system_calls: Optional[list[dict[str, Any]]], kernel_modules: Optional[list[str]], hidden_processes: Optional[list[int]]) -> dict[str, Any]`: Detecta indicadores de rootkit em syscalls, módulos kernel, e processos ocultos.

- `anti_vm_detection(hardware_info: Optional[dict[str, Any]], timing_checks: Optional[list[dict[str, Any]]], vm_artifacts: Optional[list[str]]) -> dict[str, Any]`: Detecta execução em ambiente virtual/sandbox via hardware info, timing checks, e artefatos VM.

- `anti_emulation_detection(environment_checks: Optional[list[dict[str, Any]]], timing: Optional[dict[str, Any]], api_availability: Optional[list[str]]) -> dict[str, Any]`: Detecta ambientes de emulação/sandbox analysis via environment checks e timing.

- `moving_target_runtime(services: Optional[list[dict[str, Any]]], rotation_config: Optional[dict[str, Any]], randomization: Optional[dict[str, Any]]) -> dict[str, Any]`: Implementa moving target defense via rotação de serviços e randomização de layout.

- `dynamic_attack_surface(endpoints: Optional[list[dict[str, Any]]], exposure_config: Optional[dict[str, Any]], threat_level: str) -> dict[str, Any]`: Ajusta dinamicamente superfície de ataque baseado no nível de ameaça atual.

- `runtime_policy_engine(policies: Optional[list[dict[str, Any]]], context: Optional[dict[str, Any]], enforcement_mode: str) -> dict[str, Any]`: Avalia e aplica políticas de segurança em runtime com modo de enforcement configurável.

- `self_healing_security(state: Optional[dict[str, Any]], healing_rules: Optional[list[dict[str, Any]]], recovery_actions: Optional[list[str]]) -> dict[str, Any]`: Detecta e recupera automaticamente de incidentes de segurança usando regras de healing.

- `adaptive_threat_response(threat: Optional[dict[str, Any]], response_playbook: Optional[dict[str, Any]], context: Optional[dict[str, Any]]) -> dict[str, Any]`: Executa resposta adaptativa a ameaças baseado em características da ameaça e playbook.

- `autonomous_containment(threat: Optional[dict[str, Any]], containment_rules: Optional[list[dict[str, Any]]], network_topology: Optional[dict[str, Any]]) -> dict[str, Any]`: Contém ameaças ativas autonomamente usando regras de contenção e topologia de rede.

---

### Python: Honeypot (20 funções)

Honeypots e deception: adaptive honeypot, fake admin panel, fake database, fake API, fake filesystem, fake SSH, fake RDP, fake Kubernetes, fake S3, fake secrets, deceptive routes, attacker behavior tracking, adaptive deception, moving target defense, honeytoken generation, honeycredential detection, decoy endpoints, deceptive responses, fake login page, fake debug panel.

#### Funções

- `adaptive_honeypot(config: dict[str, Any], traffic_analysis: dict[str, Any], threat_level: str) -> dict[str, Any]`: Ajusta dinamicamente configuração do honeypot baseado em tráfego observado e nível de ameaça.

- `fake_admin_panel(template: str, routes: list[str] | None, responses: dict[str, Any] | None) -> dict[str, Any]`: Deploy de fake admin panel realista para atrair e rastrear tentativas de acesso não autorizado.

- `fake_database(schema: dict[str, Any] | None, records: dict[str, list[dict[str, Any]]] | None, connection_string: str) -> dict[str, Any]`: Cria fake database convincente com schema realista e registros de exemplo.

- `fake_api(endpoints: list[str] | None, responses: dict[str, Any] | None, rate_limit: int) -> dict[str, Any]`: Deploy de fake REST API com endpoints realistas e payloads de resposta.

- `fake_filesystem(structure: dict[str, Any] | None, files: dict[str, str] | None, permissions: dict[str, str] | None) -> dict[str, Any]`: Cria fake filesystem realista com estrutura de diretórios e arquivos plausíveis.

- `fake_ssh_service(banner: str, host_key: str | None, port: int) -> dict[str, Any]`: Deploy de fake SSH service que aceita conexões e loga todas as tentativas de interação.

- `fake_rdp_service(banner: str, port: int, authentication: str) -> dict[str, Any]`: Deploy de fake RDP service para detectar e rastrear ataques de remote desktop.

- `fake_kubernetes_cluster(api_server: str, nodes: list[dict[str, Any]] | None, namespaces: list[str] | None) -> dict[str, Any]`: Deploy de fake Kubernetes cluster API para atrair atacantes focados em containers.

- `fake_s3_bucket(bucket_name: str, objects: list[dict[str, Any]] | None, permissions: dict[str, str] | None) -> dict[str, Any]`: Cria fake S3 bucket com objetos realistas e políticas de acesso.

- `fake_secrets(secrets_list: list[dict[str, Any]] | None, rotation_policy: dict[str, Any] | None) -> dict[str, Any]`: Gere e gerencia fake secrets para detectar tentativas de credential harvesting.

- `deceptive_routes(route_patterns: list[str] | None, handlers: dict[str, Any] | None, detection_callback: str | None) -> dict[str, Any]`: Registra rotas enganosas que parecem legítimas mas disparam alertas quando acessadas.

- `attacker_behavior_tracking(session_id: str, actions: list[dict[str, Any]], timeline: list[dict[str, Any]] | None) -> dict[str, Any]`: Rastreia e analisa padrões de comportamento de atacante dentro de sessão honeypot.

- `adaptive_deception(current_deception: dict[str, Any], attacker_profile: dict[str, Any], effectiveness: dict[str, float]) -> dict[str, Any]`: Ajusta dinamicamente táticas de deception baseado em perfil do atacante e efetividade.

- `moving_target_defense(services: list[dict[str, Any]], rotation_interval: int, randomization: dict[str, Any] | None) -> dict[str, Any]`: Implementa moving target defense rotacionando configurações de serviço.

- `honeytoken_generation(token_type: str, metadata: dict[str, Any] | None, tracking: dict[str, Any] | None) -> dict[str, Any]`: Gera honeytokens rastreáveis que alertam quando usados fora de contextos autorizados.

- `honeycredential_detection(credentials: list[dict[str, Any]], honeytoken_db: dict[str, Any]) -> dict[str, Any]`: Verifica credenciais submetidas contra database de honeytokens conhecidos.

- `decoy_endpoints(base_path: str, count: int, patterns: list[str] | None) -> list[dict[str, Any]]`: Gera lista de endpoints API enganosos que imitam endpoints de serviço reais.

- `deceptive_responses(request: dict[str, Any], deception_config: dict[str, Any] | None, attacker_profile: dict[str, Any] | None) -> dict[str, Any]`: Gera respostas enganosas contextualmente baseadas em request e perfil do atacante.

- `fake_login_page(template: str, branding: dict[str, Any] | None, tracking_script: str | None) -> dict[str, Any]`: Deploy de fake login page convincente para capturar tentativas de credential submission.

- `fake_debug_panel(config: dict[str, Any] | None, endpoints: list[str] | None, data: dict[str, Any] | None) -> dict[str, Any]`: Deploy de fake debug/development panel que parece expor informações internas do sistema.

---

### Python: File (21 funções)

Segurança de arquivos: upload seguro, validação de extensão/MIME, detecção de polyglot files, zip bomb, office macros, PDF JavaScript, malware scan, YARA rules, heuristic scan, quarantine, filename sanitization, executable payloads, entropy analysis, sandbox execution, embedded scripts, steganography, obfuscation detection, secure temp files, immutable storage.

#### Funções

- `secure_upload(file_data: bytes, filename: str, allowed_extensions: Optional[list[str]], max_size: int) -> dict[str, Any]`: Valida e processa upload de arquivo de forma segura verificando extensão, MIME, tamanho e conteúdo.

- `validate_extension(filename: str, allowed_extensions: list[str]) -> bool`: Valida se um arquivo tem extensão permitida na lista de allowlist.

- `validate_mime(file_data: bytes, expected_mime: Optional[str], magic_bytes: Optional[dict[str, bytes]]) -> dict[str, Any]`: Valida MIME type usando detecção de magic bytes, prevenindo spoofing de extensão.

- `detect_polyglot_file(file_data: bytes, signatures: Optional[list[dict[str, Any]]]) -> dict[str, Any]`: Detecta se arquivo contém múltiplas assinaturas de formato (polyglot file attack).

- `detect_zip_bomb(file_data: bytes, max_ratio: float, max_uncompressed: int) -> dict[str, Any]`: Detecta potencial zip bomb analisando ratios de compressão e tamanho descomprimido.

- `detect_office_macro(file_data: bytes, file_type: Optional[str]) -> dict[str, Any]`: Detecta macros VBA em documentos Office (Word, Excel, PowerPoint) que podem executar código malicioso.

- `detect_pdf_javascript(file_data: bytes) -> dict[str, Any]`: Detecta JavaScript embutido em arquivos PDF que pode executar ações maliciosas.

- `malware_scan(file_data: bytes, signatures: Optional[list[dict[str, Any]]], yara_rules: Optional[list[dict[str, Any]]]) -> dict[str, Any]`: Escaneia arquivo por malware usando signature matching e regras YARA.

- `yara_scan(file_data: bytes, rules: Optional[list[dict[str, Any]]], namespace: Optional[str]) -> dict[str, Any]`: Escaneia arquivo usando regras YARA-like pattern matching com namespace opcional.

- `heuristic_scan(file_data: bytes, heuristics: Optional[list[dict[str, Any]]], threshold: float) -> dict[str, Any]`: Realiza análise heurística para detectar comportamento suspeito em arquivos.

- `quarantine_file(filepath: str, quarantine_dir: Optional[str], reason: str) -> str`: Move arquivo para diretório de quarentena com metadata tracking.

- `sanitize_filename(filename: str, max_length: int, allowed_chars: Optional[str]) -> str`: Sanitiza nome de arquivo removendo caracteres perigosos e path traversal.

- `detect_executable_payload(file_data: bytes, file_type: Optional[str]) -> dict[str, Any]`: Detecta payloads executáveis embutidos em arquivos não-executáveis.

- `entropy_analysis(file_data: bytes, block_size: int, threshold: float) -> dict[str, Any]`: Calcula entropia Shannon de dados do arquivo para detectar criptografia ou compressão.

- `sandbox_execute(file_path: str, sandbox_config: Optional[dict[str, Any]], timeout: int) -> dict[str, Any]`: Executa arquivo em ambiente sandboxed para análise comportamental.

- `detect_embedded_script(file_data: bytes, file_type: Optional[str], script_types: Optional[list[str]]) -> dict[str, Any]`: Detecta scripts embutidos em arquivos (JavaScript em PDF, macros em Office, etc.).

- `detect_steganography(file_data: bytes, analysis_methods: Optional[list[str]]) -> dict[str, Any]`: Detecta esteganografia potencial em arquivos de imagem usando LSB, appended data, entropy, histogram.

- `detect_obfuscation(file_data: bytes, detection_methods: Optional[list[str]]) -> dict[str, Any]`: Detecta conteúdo ofuscado em arquivos (base64, hex, string concatenation, control flow).

- `secure_tempfile(prefix: str, suffix: str, directory: Optional[str], delete_on_close: bool) -> str`: Cria arquivo temporário seguro com permissões restritas e auto-deleção opcional.

- `immutable_storage_check(filepath: str, expected_hash: Optional[str], storage_type: str) -> bool`: Verifica integridade de arquivo contra hash esperado para storage imutável.

---

### Python: Enterprise (10 funções)

Conformidade enterprise: LGPD (Brasil), GDPR (EU), HIPAA (saúde), PCI-DSS (pagamentos), compliance reports, audit trails, policy as code, real-time security dashboard, tenant isolation, multi-region security.

#### Funções

- `lgpd_check(system_config: dict[str, Any], data_flows: list[dict[str, Any]], controls: dict[str, Any]) -> dict[str, Any]`: Verifica conformidade com LGPD (Lei Geral de Proteção de Dados - Brasil): consentimento, DPO, data subject rights, etc.

- `gdpr_check(system_config: dict[str, Any], data_processing: list[dict[str, Any]], controls: dict[str, Any]) -> dict[str, Any]`: Verifica conformidade com GDPR (EU): lawful basis, DPO, data minimization, right to be forgotten, etc.

- `hipaa_check(system_config: dict[str, Any], phi_handling: list[dict[str, Any]], controls: dict[str, Any]) -> dict[str, Any]`: Verifica conformidade com HIPAA (saúde): PHI encryption, access controls, audit controls, etc.

- `pci_check(system_config: dict[str, Any], card_data_handling: list[dict[str, Any]], controls: dict[str, Any]) -> dict[str, Any]`: Verifica conformidade com PCI-DSS (pagamentos): card data encryption, network segmentation, access control, etc.

- `compliance_report(checks: list[dict[str, Any]], framework: str, scope: dict[str, Any]) -> dict[str, Any]`: Gera relatório de compliance abrangente a partir de múltiplos resultados de check.

- `audit_trail(events: list[dict[str, Any]], user_actions: list[dict[str, Any]], data_changes: list[dict[str, Any]]) -> dict[str, Any]`: Gera audit trail imutável a partir de eventos de segurança, ações de usuários e mudanças de dados.

- `policy_as_code(policies: list[dict[str, Any]], context: dict[str, Any], enforcement: dict[str, Any]) -> dict[str, Any]`: Avalia e aplica políticas de segurança definidas como código (IaC para security policies).

- `realtime_security_dashboard(metrics: dict[str, Any], alerts: list[dict[str, Any]], trends: dict[str, Any]) -> dict[str, Any]`: Gera dashboard de segurança em tempo real a partir de métricas, alertas e tendências.

- `tenant_isolation(tenant_config: dict[str, Any], network_policies: list[dict[str, Any]], data_segregation: dict[str, Any]) -> dict[str, Any]`: Verifica e aplica isolamento de tenant em ambiente multi-tenant.

- `multi_region_security(regions: list[dict[str, Any]], data_residency_rules: dict[str, Any], encryption: dict[str, Any]) -> dict[str, Any]`: Avalia postura de segurança multi-region e conformidade de data residency.

---

### Python: Integrations (10 funções)

Integrações com frameworks: FastAPI, Django, Flask, Celery, SQLAlchemy, async threat pipeline, YARA real-time engine, AI threat classifier, secure CLI runtime, Python runtime guard.

#### Funções

- `fastapi_security_dependency(config: dict[str, Any], security_schemes: dict[str, Any], middleware_config: dict[str, Any]) -> dict[str, Any]`: Cria dependência de segurança FastAPI com OAuth2, validação JWT, e rate limiting.

- `django_security_middleware(config: dict[str, Any], settings: dict[str, Any], middleware_config: dict[str, Any]) -> dict[str, Any]`: Cria middleware de segurança Django com CSP, CSRF, e security headers.

- `flask_security_extension(app: Any, config: dict[str, Any], security_config: dict[str, Any]) -> dict[str, Any]`: Cria extensão de segurança Flask com security wrappers e proteção de requisições.

- `celery_security_monitor(app: Any, config: dict[str, Any], task_security: dict[str, Any]) -> dict[str, Any]`: Cria monitor de segurança para tarefas Celery com validação e audit logging.

- `sqlalchemy_query_protection(query: Any, user_permissions: dict[str, Any], row_level_security: dict[str, Any]) -> dict[str, Any]`: Aplica proteção a queries SQLAlchemy com row-level security e permission filtering.

- `async_threat_pipeline(config: dict[str, Any], processors: list[dict[str, Any]], output_channels: list[dict[str, Any]]) -> dict[str, Any]`: Cria pipeline assíncrono de detecção de ameaças com processadores configuráveis.

- `yara_realtime_engine(rules: list[dict[str, Any]], watch_dirs: list[str], scan_interval: int) -> dict[str, Any]`: Cria engine de escaneamento YARA em tempo real com file watch e rule matching.

- `ai_threat_classifier(model_path: str, classification_rules: dict[str, Any], confidence_threshold: float) -> dict[str, Any]`: Cria classificador de ameaças com IA usando modelo treinado e threshold de confiança.

- `secure_cli_runtime(config: dict[str, Any], input_sanitization: dict[str, Any], timeout_config: dict[str, Any]) -> dict[str, Any]`: Cria runtime CLI seguro com sanitização de input e timeouts de execução.

- `python_runtime_guard(config: dict[str, Any], import_whitelist: list[str], sandbox_config: dict[str, Any]) -> dict[str, Any]`: Cria guard de runtime Python com import whitelisting e sandboxing.

---

## Módulos TypeScript

### TS: Core (11 funções)

Infraestrutura base: configuração, logging estruturado com pino, métricas, cache LRU, policy engine, event bus, telemetria OpenTelemetry, exceções de segurança, e spans de tracing.

#### Funções

- `getConfig(): MSFConfig`: Obtém a configuração global do framework. Cria instância default se não existir.

- `setConfig(config: MSFConfig): void`: Define a configuração global do framework.

- `reloadConfig(): MSFConfig`: Recarrega a configuração a partir de variáveis de ambiente.

- `getLogger(component: string, options?: MSFLoggerOptions): MSFLogger`: Obtém logger estruturado com pino para um componente.

- `getMetrics(): MetricsRegistry`: Obtém o registrador de métricas global com counters, gauges, histograms.

- `getPolicyEngine(): PolicyEngine`: Obtém o singleton do motor de políticas de segurança.

- `getEventBus(maxHistory?: number, maxDeadLetter?: number): EventBus`: Obtém o barramento de eventos com histórico e dead letter queue.

- `getCache(options?: Partial<CacheOptions>): CacheManager`: Obtém gerenciador de cache LRU com TTL e invalidação.

- `getTelemetry(serviceName?: string, serviceVersion?: string, enabled?: boolean): TelemetryManager`: Obtém gerenciador de telemetria OpenTelemetry.

- `createSpan(name: string, attributes: Record<string, string | number | boolean>): otel.Span`: Cria span de tracing OpenTelemetry com atributos.

- `redactPII(value: string): string`: Reduz dados PII (Personally Identifiable Information) de uma string.

---

### TS: Auth (7 funções)

Autenticação: TOTP, backup codes, password entropy, device/browser fingerprinting, phishing-resistant auth.

#### Funções

- `generateTotp(secret: string, digits: number = 6, period: number = 30, timeStep?: number): string`: Gera código TOTP com dígitos e período configuráveis.

- `validateTotp(secret: string, token: string, digits: number = 6, period: number = 30, drift: number = 1): boolean`: Valida token TOTP com tolerância de drift.

- `verifyBackupCode(code: string, validCodes: string[]): boolean`: Verifica e consome um backup code.

- `passwordEntropy(password: string): number`: Calcula entropia Shannon de senha.

- `deviceFingerprint(userAgent: string, screen: string, timezone: string, languages: string[], platform: string): string`: Gera fingerprint de dispositivo.

- `browserFingerprint(canvasHash: string, webglHash: string, audioHash: string, fonts: string[]): string`: Gera fingerprint de browser.

- `phishingResistantAuth(authMethod: string, fidoLevel: number, attestation: string): boolean`: Verifica se método de auth é phishing-resistant.

---

### TS: Crypto (5 funções)

Criptografia: random seguro, HMAC, memory-safe erase, timing-safe compare.

#### Funções

- `secureRandom(nbytes: number): Uint8Array`: Gera bytes criptograficamente seguros usando `crypto.getRandomValues()`.

- `generateHmac(data: Uint8Array | string, key: Uint8Array | string, algorithm: HmacAlgorithm = 'hmac-sha256'): string`: Gera HMAC para autenticação de integridade.

- `verifyHmac(data: Uint8Array | string, signature: string, key: Uint8Array | string, algorithm: HmacAlgorithm = 'hmac-sha256'): boolean`: Verifica HMAC comparando assinatura.

- `secureMemoryErase(data: Uint8Array): void`: Apaga seguramente dados da memória sobrescrevendo.

- `antiTimingCompare(a: Uint8Array, b: Uint8Array): boolean`: Compara em tempo constante para prevenir timing attacks.

---

### TS: Web (35 funções)

Detecção de ataques web e sanitização: XSS, SQLi, NoSQLi, SSRF, RCE, LFI, RFI, SSTI, Command Injection, Deserialization, Path Traversal, Open Redirect, CORS, CSP, CSRF, secure cookies, clickjacking, webhooks.

#### Funções

- `detectXss(input: string, patterns?: RegExp[], severityThreshold: number = 0.3): DetectionResult`: Detecta padrões XSS incluindo script tags, event handlers, javascript: URIs.

- `sanitizeHtml(html: string, allowedTags: string[], allowedAttrs: string[]): string`: Sanitiza HTML removendo tags e atributos não permitidos.

- `sanitizeSvg(svg: string, allowedElements: string[]): string`: Sanitiza SVG removendo elementos perigosos.

- `sanitizeMarkdown(markdown: string, allowedHtml: string[]): string`: Sanitiza markdown removendo HTML perigoso embutido.

- `sanitizeCss(css: string, allowedProperties: string[]): string`: Sanitiza CSS removendo propriedades perigosas.

- `sanitizeJs(jsCode: string, dangerousPatterns: RegExp[]): string`: Sanitiza JavaScript removendo `eval()`, `Function()`, `document.write()`, etc.

- `detectSqli(input: string, patterns?: RegExp[], context?: string): DetectionResult`: Detecta SQL injection (UNION, blind, time-based, error-based).

- `detectNosqli(input: string, patterns?: RegExp[]): DetectionResult`: Detecta NoSQL injection em queries MongoDB/NoSQL.

- `detectSsrf(url: string, allowedDomains: string[], blockedIps: string[]): DetectionResult`: Detecta SSRF verificando URLs contra allowlist e blocklist.

- `detectRce(input: string, patterns?: RegExp[]): DetectionResult`: Detecta Remote Code Execution patterns.

- `detectLfi(input: string, patterns?: RegExp[]): DetectionResult`: Detecta Local File Inclusion via path traversal.

- `detectRfi(input: string, patterns?: RegExp[]): DetectionResult`: Detecta Remote File Inclusion via URLs externas.

- `detectTemplateInjection(input: string, engineType: 'jinja2' | 'ejs' | 'handlebars' | 'mustache' | 'pug' | 'twig' | 'generic'): DetectionResult`: Detecta Server-Side Template Injection para múltiplos engines.

- `detectCommandInjection(input: string, patterns?: RegExp[]): DetectionResult`: Detecta OS Command Injection.

- `detectDeserializationAttack(data: string, allowedClasses: string[]): DetectionResult`: Detecta insecure deserialization.

- `detectPathTraversal(input: string, basePath: string): DetectionResult`: Detecta path traversal verificando resolução dentro do basePath.

- `detectOpenRedirect(url: string, allowedHosts: string[]): DetectionResult`: Detecta open redirect verificando hosts permitidos.

- `validateCors(origin: string | undefined, allowedOrigins: string[], allowedMethods: string[], allowedHeaders: string[]): CorsResult`: Valida requisição CORS.

- `secureHeaders(request: SecureHeadersRequest, config: SecureHeadersConfig): Record<string, string>`: Gera headers HTTP seguros.

- `generateCsp(config: CspConfig): string`: Gera header Content-Security-Policy.

- `validateCsp(cspHeader: string, policy: CspConfig): boolean`: Valida header CSP contra política.

- `csrfProtect(request: CsrfRequest, token: string, sessionToken: string): boolean`: Protege contra CSRF.

- `validateCsrf(token: string, sessionToken: string): boolean`: Valida token CSRF.

- `secureCookie(name: string, value: string, options: SecureCookieOptions): string`: Gera header Set-Cookie seguro.

- `detectClickjacking(headers: Record<string, string>, frameOptions: string): boolean`: Detecta vulnerabilidade de clickjacking.

- `validateOrigin(origin: string, allowedOrigins: string[]): boolean`: Valida header Origin.

- `validateReferer(referer: string | undefined, expectedDomain: string): boolean`: Valida header Referer.

- `secureRedirect(url: string, allowedHosts: string[]): string`: Valida URL de redirect segura.

- `webhookSignature(payload: string, secret: string, algorithm: 'sha256' | 'sha384' | 'sha512' | 'sha3-256', timestamp?: number): string`: Gera assinatura de webhook.

- `webhookReplayProtection(signature: string, timestamp: number, payload: string, secret: string, window: number): boolean`: Protege contra replay de webhooks.

---

### TS: API (16 funções)

Segurança de APIs: JSON Schema validation, input validation, sanitization, API abuse detection, BOLA, broken auth, mass assignment, shadow API, threat scoring, GraphQL (depth, cost, abuse), gRPC, WebSocket, API key rotation/validation.

#### Funções

- `validateJsonSchema(data: unknown, schema: Record<string, unknown>, strictMode = false): ValidationResult`: Valida dados contra JSON Schema.

- `validateInput(data: unknown, rules: Record<string, {...}>, maxDepth = 5, maxSize = 1048576): ValidationResult`: Valida input de API contra regras.

- `sanitizeJson(data: unknown, allowedTypes: string[], maxStringLength = 10000): SanitizedData`: Sanitiza dados JSON.

- `detectApiAbuse(requests: Array<{...}>, patterns: RequestPattern[], window: number): AbuseDetectionResult`: Detecta abuso de API.

- `detectBola(resourceId: string, userId: string, ownershipMap: Record<string, string>): boolean`: Detecta BOLA/IDOR.

- `detectBrokenAuth(authHeader: string, requiredScopes: string[], token?: Record<string, unknown>): AuthValidationResult`: Detecta broken authentication.

- `detectMassAssignment(inputData: Record<string, unknown>, modelFields: string[], readonlyFields: string[]): MassAssignmentResult`: Detecta mass assignment.

- `detectShadowApi(endpoint: string, documentedApis: string[], trafficPatterns: TrafficPattern[]): ShadowApiResult`: Detecta shadow APIs.

- `apiThreatScore(request: {...}, context: ApiThreatContext, threatIntel: ThreatIntelEntry[]): number`: Calcula threat score de request API.

- `graphqlDepthLimit(query: string, maxDepth = 10, introspectionEnabled = false): GraphqlValidationResult`: Valida profundidade de query GraphQL.

- `graphqlCostAnalysis(query: string, complexityMap: Record<string, number>, maxCost = 1000): GraphqlCostResult`: Analisa custo de query GraphQL.

- `graphqlAbuseDetection(queries: Array<{...}>, window: number, thresholds: {...}): GraphqlAbuseResult`: Detecta abuso GraphQL.

- `grpcSecurityValidation(metadata: Record<string, string | string[]>, requiredHeaders: string[], tlsInfo: {...}): GrpcValidationResult`: Valida segurança gRPC.

- `secureWebsocket(origin: string, allowedOrigins: string[], subprotocols?: string[]): WsSecurityResult`: Configura WebSocket seguro.

- `apiKeyRotation(currentKey: string, algorithm = 'sha3-256', expiryDays = 90): KeyRotationResult`: Rotaciona API key.

- `apiKeyValidation(apiKey: string, validKeys: Record<string, {...}>, scopes: string[], requiredScope?: string): KeyValidationResult`: Valida API key.

---

### TS: AI (14 funções)

Proteção de IA: prompt leak detection, impersonation, model abuse, agent abuse, LLM firewall, policy engine, RAG validation, hallucination risk, output guard, tool call validation, multi-agent isolation, memory sanitization, token monitoring, behavior monitoring.

#### Funções

- `detectPromptLeak(prompt: string, systemPrompt: string, threshold: number = 0.4): DetectionResult`: Detecta tentativas de vazar system prompt.

- `detectAiImpersonation(content: string, claimedIdentity: string, markers?: string[]): DetectionResult`: Detecta impersonação de IA.

- `detectModelAbuse(requestPatterns: string[], rate: number, complexity: number): DetectionResult`: Detecta abuso de modelo.

- `detectAgentAbuse(agentBehavior: AgentBehaviorAnalysis, policy: Record<string, unknown>, thresholds: Record<string, number>): DetectionResult`: Detecta abuso de agente.

- `llmFirewall(inputData: string | Record<string, unknown>, rules: FirewallRule[], actionOnViolation: FirewallResult['action'] = 'block'): FirewallResult`: Firewall LLM com regras configuráveis.

- `aiPolicyEngine(prompt: string, output: string = '', policies: AiPolicy[]): PolicyResult`: Engine de políticas de segurança IA.

- `ragSourceValidation(sources: RagSource[], trustedDomains: string[], validationRules: ValidationRule[]): ValidationResult`: Valida fontes RAG.

- `hallucinationRisk(output: string, confidenceScores: number[] = [], factualChecks: {...}[] = []): RiskResult`: Avalia risco de alucinação.

- `aiOutputGuard(output: string, guardrails: Guardrail[], redactionRules: RedactionRule[]): string`: Aplica guardrails ao output.

- `toolCallValidation(toolName: string, arguments_: Record<string, unknown>, allowedTools: AllowedTool[], argumentSchemas: Record<string, {...}>): ValidationResult`: Valida chamada de ferramenta.

- `multiAgentIsolation(agents: AgentDefinition[], communicationRules: CommunicationRules): IsolationResult`: Valida isolamento multi-agente.

- `aiMemorySanitizer(memoryEntries: MemoryEntry[], retentionPolicy: RetentionPolicy): MemoryEntry[]`: Sanitiza memória IA.

- `aiTokenMonitor(usage: TokenUsage, limits: TokenLimits, window: number = 60): MonitorResult`: Monitora uso de tokens.

- `aiBehaviorMonitor(behaviorLog: AgentBehaviorEntry[], baseline: BehaviorBaseline, deviationThreshold: number = 0.3): MonitorResult`: Monitora comportamento IA.

---

### TS: Network (15 funções)

Segurança de rede: port scan, DNS tunneling, traffic anomaly, proxy detection, DDoS, IP/domain validation, spoofing, ARP poisoning, TLS fingerprinting, beaconing, lateral movement, network entropy, traffic behavior, protocol anomaly.

#### Funções

- `detectPortScan(sourceIp: string, connections: ConnectionRecord[], window: number = 60, threshold: number = 20): DetectionResult`: Detecta port scanning.

- `detectDnsTunneling(dnsQueries: DnsQuery[], domain: string, threshold: number = 50): DetectionResult`: Detecta DNS tunneling.

- `detectTrafficAnomaly(trafficData: TrafficData, baseline: Record<string, number>, deviationThreshold: number = 2.0): DetectionResult`: Detecta anomalias de tráfego.

- `detectProxy(ip: string, headers: Record<string, string>, detectionMethods: string[] = ['header', 'behavior', 'database']): DetectionResult`: Detecta proxy.

- `detectDdos(trafficData: TrafficData, baseline: Record<string, number>, threshold: number = 5.0, window: number = 60): DetectionResult`: Detecta ataques DDoS.

- `validateIp(ip: string, allowedRanges: string[] = [], blockedRanges: string[] = []): IpValidationResult`: Valida endereço IP.

- `validateDomain(domain: string, allowedTlds: string[] = [], blockedDomains: string[] = []): DomainValidationResult`: Valida domínio.

- `detectSpoofing(packetData: PacketData, expectedSource: string, networkTopology: NetworkTopology): DetectionResult`: Detecta IP spoofing.

- `detectArpPoisoning(arpTable: ArpEntry[], expectedMappings: Record<string, string> = {}): DetectionResult`: Detecta ARP poisoning.

- `tlsFingerprint(tlsHandshake: TlsHandshake, ja3Database: Record<string, string> = {}): FingerprintResult`: Gera/compara TLS fingerprint.

- `ja3Fingerprint(tlsClientHello: TlsClientHello): string`: Gera fingerprint JA3.

- `beaconingDetection(connections: ConnectionRecord[], intervalThreshold: number = 0.8, jitterThreshold: number = 0.15): DetectionResult`: Detecta beaconing (C2).

- `lateralMovementDetection(events: SecurityEventRecord[], networkTopology: NetworkTopology, userBehavior: UserBehavior): DetectionResult`: Detecta movimento lateral.

- `networkEntropyAnalysis(packets: PacketData[], blockSize: number = 256, threshold: number = 7.5): EntropyResult`: Analisa entropia de rede.

- `trafficBehaviorAnalysis(trafficData: TrafficData, baseline: Record<string, number>, timeWindow: number = 3600): BehaviorResult`: Analisa comportamento de tráfego.

- `protocolAnomalyDetection(protocolData: Record<string, unknown>, protocolSpec: Record<string, unknown>, deviationThreshold: number = 0.3): DetectionResult`: Detecta anomalias de protocolo.

---

### TS: Cloud (20 funções)

Segurança cloud: Dockerfile validation, container escape, K8s RBAC, S3 public bucket, IAM policies, cloud misconfig, secrets manager, Terraform, K8s manifests, runtime container protection, supply chain, SBOM, dependency audit, typosquatting, container image scan, K8s anomaly, security score, workload identity, confidential computing.

#### Funções

- `validateDockerfile(dockerfileContent: string, rules: Rule[], severityThreshold: SeverityLevel = 'medium'): ValidationResult`: Valida Dockerfile contra regras de segurança.

- `detectContainerEscape(containerConfig: ContainerConfig, capabilities: string[] = [], namespaces: string[] = []): DetectionResult`: Detecta vetores de container escape.

- `validateK8sRbac(rbacConfig: Record<string, unknown>, leastPrivilegeRules: Rule[]): ValidationResult`: Valida RBAC do Kubernetes.

- `detectPublicBucket(bucketConfig: BucketConfig, policies: Record<string, unknown>[], acl: Record<string, unknown>): DetectionResult`: Detecta bucket público.

- `validateS3Permissions(bucketPolicy: Record<string, unknown>, expectedPermissions: Record<string, string[]>): ValidationResult`: Valida permissões S3.

- `validateIamPolicy(iamPolicy: IamPolicy, allowedActions: string[], deniedActions: string[]): ValidationResult`: Valida política IAM.

- `detectCloudMisconfig(config: Record<string, unknown>, securityBaseline: Record<string, unknown>, cloudProvider: string): DetectionResult`: Detecta misconfig cloud.

- `validateSecretsManager(secretsConfig: SecretConfig, rotationPolicy: {...}, encryption: {...}): ValidationResult`: Valida secrets manager.

- `validateTerraform(terraformPlan: TerraformPlan, policies: Rule[], severityThreshold: SeverityLevel = 'medium'): ValidationResult`: Valida plano Terraform.

- `validateKubernetesManifest(manifest: K8sManifest, podSecurityPolicy: Record<string, unknown>, networkPolicy: Record<string, unknown>): ValidationResult`: Valida manifest K8s.

- `runtimeContainerProtection(containerEvents: Record<string, unknown>[], threatRules: Rule[], actions: Record<string, 'block' | 'alert' | 'isolate' | 'terminate' | 'log'>): ProtectionResult`: Protege containers em runtime.

- `supplyChainValidation(dependencies: DependencyEntry[], trustedSources: string[], vulnerabilityDb: VulnerabilityEntry[]): ValidationResult`: Valida supply chain.

- `sbomGenerator(components: Array<{...}>, format: 'spdx' | 'cyclonedx' | 'custom' = 'spdx', metadata: Record<string, unknown> = {}): SbomResult`: Gera SBOM.

- `dependencyAudit(dependencies: DependencyEntry[], auditDb: VulnerabilityEntry[], severityThreshold: SeverityLevel = 'medium'): AuditResult`: Audita dependências.

- `detectTyposquatting(packageName: string, knownPackages: string[], similarityThreshold: number = 0.85): DetectionResult`: Detecta typosquatting.

- `containerImageScan(imageLayers: Array<{...}>, signatures: Array<{...}>, vulnerabilityDb: VulnerabilityEntry[]): ScanResult`: Escaneia imagem de container.

- `runtimeK8sAnomaly(k8sEvents: Record<string, unknown>[], baseline: Record<string, number>, anomalyThreshold: number = 2.0): AnomalyResult`: Detecta anomalia K8s runtime.

- `cloudSecurityScore(config: Record<string, unknown>, benchmarks: Record<string, Record<string, unknown>>, weights: Record<string, number>): ScoreResult`: Calcula security score cloud.

- `workloadIdentityValidation(workloadConfig: WorkloadConfig, identityProvider: string, trustPolicy: Record<string, unknown>): ValidationResult`: Valida workload identity.

- `confidentialComputingValidation(attestation: Attestation, teeType: 'sgx' | 'tdx' | 'sev' | 'snp' | 'nitro' | 'cvm', expectedMeasurements: Record<string, string>): ValidationResult`: Valida confidential computing.

---

### TS: Monitoring (12 funções)

Monitoramento: anomaly score, threat score, risk score, event correlation, adaptive alerting, attack path analysis, threat graph, behavioral analysis, UEBA, account takeover detection, incident timeline, MITRE ATT&CK mapping.

#### Funções

- `anomalyScore(metrics: MetricsData, baseline: BaselineData, weights: Record<string, number> = {}): number`: Calcula anomaly score via z-score.

- `threatScore(events: SecurityEvent[], threatIntel: ThreatIntel, context: Record<string, unknown> = {}): number`: Calcula threat score.

- `riskScore(userId: string, events: SecurityEvent[], context: Record<string, unknown> = {}, historical: {...}): number`: Calcula risk score de usuário.

- `correlateEvents(events: SecurityEvent[], timeWindow: number = 300000, correlationRules: CorrelationRule[] = []): CorrelatedEvent[]`: Correlaciona eventos.

- `adaptiveAlerting(events: SecurityEvent[], baseline: {...}, alertFatigueThreshold: number = 10): AlertResult`: Alerting adaptativo com fatigue prevention.

- `attackPathAnalysis(events: SecurityEvent[], networkTopology: {...}, attackGraph: {...}): PathResult`: Analisa caminhos de ataque.

- `threatGraph(events: SecurityEvent[], entities: {...}[], relationships: {...}[]): GraphResult`: Constrói grafo de ameaça.

- `behavioralAnalysis(userEvents: SecurityEvent[], baseline: {...}, deviationThreshold: number = 2.0): AnalysisResult`: Analisa comportamento de usuário.

- `uebaAnalysis(userEvents: SecurityEvent[], peerGroup: {...}, anomalyThreshold: number = 2.5): UebaResult`: UEBA contra peer groups.

- `detectAccountTakeover(userEvents: SecurityEvent[], baseline: {...}, riskFactors: {...}): DetectionResult`: Detecta account takeover.

- `incidentTimeline(events: SecurityEvent[], incidentId: string, classification: string = 'unclassified'): TimelineResult`: Constrói timeline de incidente.

- `attackChainMapping(events: SecurityEvent[], mitreFramework: {...}, killChain: {...}): ChainResult`: Mapeia para MITRE ATT&CK e Kill Chain.

---

### TS: Defensive (20 funções)

Defesa ativa: runtime self-protection, anti-debugging, anti-tampering, memory integrity, process integrity, code signing, binary integrity, secure boot, secure update, anti-hook, anti-injection, anti-rootkit, anti-VM, anti-emulation, moving target, dynamic attack surface, runtime policy engine, self-healing, adaptive threat response, autonomous containment.

#### Funções

- `runtimeSelfProtection(config: ProtectionConfig, integrityChecks: IntegrityCheckConfig[], monitoring: MonitoringConfig): ProtectionResult`: Auto-proteção runtime com integrity checks.

- `antiDebuggingDetection(processInfo: ProcessInfo, ptraceStatus: PtraceStatus, debuggerSignals: DebuggerSignal[]): DetectionResult`: Detecta debugging ativo.

- `antiTampering(binaryHash: BinaryHash[], expectedHash: Record<string, string>, integrityChecks: IntegrityCheckConfig[]): DetectionResult`: Detecta tampering de binário.

- `memoryIntegrityCheck(memoryRegions: MemoryRegion[], expectedState: MemoryExpectedState[], signatures: MemorySignature[]): IntegrityResult`: Verifica integridade de memória.

- `processIntegrityCheck(processId: number, expectedModules: string[], allowedParents: number[]): IntegrityResult`: Verifica integridade de processo.

- `codeSigningValidation(binaryPath: string, certificateStore: CertificateStore, revocationCheck: boolean): ValidationResult`: Valida code signing.

- `binaryIntegrityValidation(binaryPath: string, expectedHashes: Record<string, string>, sections: string[]): ValidationResult`: Valida integridade de binário por seção.

- `secureBootValidation(bootChain: BootMeasurement[], measurements: BootMeasurement[], pcrValues: PcrValue[]): ValidationResult`: Valida secure boot chain.

- `secureUpdateValidation(updatePackage: UpdatePackage, signature: UpdateSignature, version: string, channel: string): ValidationResult`: Valida update package.

- `antiHookDetection(functions: HookInfo[], memoryRegions: MemoryRegion[], knownHooks: string[]): DetectionResult`: Detecta function hooks.

- `antiInjectionDetection(processModules: ProcessModule[], loadedLibraries: string[], injectionSignatures: InjectionSignature[]): DetectionResult`: Detecta code injection.

- `antiRootkitDetection(systemCalls: SystemCallInfo[], kernelModules: KernelModule[], hiddenProcesses: ProcessEntry[]): DetectionResult`: Detecta rootkit activity.

- `antiVmDetection(hardwareInfo: HardwareInfo, timingChecks: TimingCheck, vmArtifacts: VmArtifact[]): DetectionResult`: Detecta ambiente VM.

- `antiEmulationDetection(environmentChecks: EnvironmentCheck[], timing: TimingCheck, apiAvailability: ApiAvailability[]): DetectionResult`: Detecta emulação/sandbox.

- `movingTargetRuntime(services: ServiceConfig[], rotationConfig: RotationConfig, randomization: RandomizationConfig): MTDResult`: Moving target defense.

- `dynamicAttackSurface(endpoints: EndpointConfig[], exposureConfig: ExposureConfig, threatLevel: number): SurfaceResult`: Ajusta superfície de ataque.

- `runtimePolicyEngine(policies: SecurityPolicy[], context: PolicyContext, enforcementMode: EnforcementConfig): PolicyResult`: Engine de políticas runtime.

- `selfHealingSecurity(state: SystemState, healingRules: HealingRule[], recoveryActions: RecoveryAction[]): HealingResult`: Auto-recuperação de segurança.

- `adaptiveThreatResponse(threat: ThreatInfo, responsePlaybook: ResponsePlaybook, context: ResponseContext): ResponseResult`: Resposta adaptativa a ameaças.

- `autonomousContainment(threat: ThreatInfo, containmentRules: ContainmentRule[], networkTopology: NetworkNode[]): ContainmentResult`: Contenção autônoma de ameaças.

---

### TS: Honeypot

*(Módulo em desenvolvimento - funções serão adicionadas na próxima versão)*

---

### TS: File (20 funções)

Segurança de arquivos: extension validation, MIME validation, polyglot detection, zip bomb, office macros, PDF JavaScript, malware scan, YARA scan, heuristic scan, quarantine, filename sanitization, executable payload, entropy analysis, embedded script, steganography, obfuscation, secure tempfile, immutable storage.

#### Funções

- `validateExtension(filename: string, allowedExtensions: string[]): boolean`: Valida extensão de arquivo.

- `validateMime(fileData: Buffer, expectedMime: string, magicBytes?: string): MimeResult`: Valida MIME type via magic bytes.

- `detectPolyglotFile(fileData: Buffer, signatures: FileSignature[]): DetectionResult`: Detecta polyglot files.

- `detectZipBomb(fileData: Buffer, maxRatio: number = 100, maxUncompressed: number = 1073741824): DetectionResult`: Detecta zip bombs.

- `detectOfficeMacro(fileData: Buffer, fileType: string): DetectionResult`: Detecta macros Office.

- `detectPdfJavascript(fileData: Buffer): DetectionResult`: Detecta JS em PDF.

- `malwareScan(fileData: Buffer, signatures: Array<{...}>, yaraRules?: YaraRule[]): ScanResult`: Escaneia por malware.

- `yaraScan(fileData: Buffer, rules: YaraRule[], namespace?: string): ScanResult`: Scan com regras YARA.

- `heuristicScan(fileData: Buffer, heuristics: HeuristicRule[], threshold: number = 0.5): ScanResult`: Scan heurístico.

- `quarantineFile(filePath: string, quarantineDir: string, reason: string): string`: Quarentena de arquivo.

- `sanitizeFilename(filename: string, maxLength: number = 255, allowedChars: RegExp = /^[a-zA-Z0-9._-]+$/): string`: Sanitiza nome de arquivo.

- `detectExecutablePayload(fileData: Buffer, fileType: string): DetectionResult`: Detecta payload executável.

- `entropyAnalysis(fileData: Buffer, blockSize: number = 1024, threshold: number = 7.5): EntropyResult`: Análise de entropia.

- `detectEmbeddedScript(fileData: Buffer, fileType: string, scriptTypes: string[] = ['javascript', 'vbscript', 'powershell', 'python', 'batch']): DetectionResult`: Detecta scripts embutidos.

- `detectSteganography(fileData: Buffer, analysisMethods: string[] = ['lsb', 'appended', 'entropy', 'histogram']): DetectionResult`: Detecta esteganografia.

- `detectObfuscation(fileData: Buffer, detectionMethods: string[] = ['base64', 'hex', 'string_concat', 'entropy', 'control_flow']): DetectionResult`: Detecta ofuscação.

- `secureTempfile(prefix: string = 'msf', suffix: string = '.tmp', directory?: string, deleteOnClose: boolean = true): string`: Cria tempfile seguro.

- `immutableStorageCheck(filePath: string, expectedHash: string, storageType: string): boolean`: Verifica storage imutável.

---

### TS: Enterprise (10 funções)

Conformidade enterprise: LGPD, GDPR, HIPAA, PCI-DSS, compliance reports, audit trails, policy as code, security dashboard, tenant isolation, multi-region security.

#### Funções

- `lgpdCheck(systemConfig: SystemConfig, dataFlows: DataFlow[], controls: Control[]): ComplianceResult`: Verifica conformidade LGPD.

- `gdprCheck(systemConfig: SystemConfig, dataProcessing: DataProcessing, controls: Control[]): ComplianceResult`: Verifica conformidade GDPR.

- `hipaaCheck(systemConfig: SystemConfig, phiHandling: PHIHandling, controls: Control[]): ComplianceResult`: Verifica conformidade HIPAA.

- `pciCheck(systemConfig: SystemConfig, cardDataHandling: CardDataHandling, controls: Control[]): ComplianceResult`: Verifica conformidade PCI-DSS.

- `complianceReport(checks: ComplianceResult[], framework: string, scope: string): ReportResult`: Gera relatório de compliance.

- `auditTrail(events: AuditEvent[], userActions: UserAction[], dataChanges: DataChange[]): AuditResult`: Gera audit trail.

- `policyAsCode(policies: Policy[], context: PolicyContext, enforcement: PolicyEnforcement): PolicyResult`: Policy as code.

- `realtimeSecurityDashboard(metrics: SecurityMetric[], alerts: SecurityAlert[], trends: SecurityTrend[]): DashboardResult`: Dashboard de segurança.

- `tenantIsolation(tenantConfig: TenantConfig, networkPolicies: NetworkPolicy[], dataSegregation: DataSegregation): IsolationResult`: Isolamento de tenant.

- `multiRegionSecurity(regions: RegionConfig[], dataResidencyRules: DataResidencyRule[], encryption: RegionEncryption): RegionResult`: Segurança multi-region.

---

### TS: Integrations (9 funções)

Integrações: Express, Fastify, NestJS, Next.js, Cloudflare, Deno, Bun, Browser Runtime, Service Worker, WASM.

#### Funções

- `expressSecurityMiddleware(app: unknown, config: ExpressConfig = {}, middlewareConfig: ExpressMiddlewareConfig = {}): MiddlewareResult`: Middleware de segurança Express.

- `fastifySecurityMiddleware(app: unknown, config: FastifyConfig = {}, securityConfig: FastifySecurityConfig = {}): MiddlewareResult`: Middleware de segurança Fastify.

- `nestjsSecurityModule(config: NestjsConfig = {}, guards: string[] = [], interceptors: string[] = []): ModuleResult`: Módulo de segurança NestJS.

- `nextjsSecurityHeaders(config: NextjsConfig = {}, headers: Record<string, string> = {}): HeadersResult`: Security headers Next.js.

- `cloudflareEdgeProtection(config: CloudflareConfig = {}, rules: EdgeRule[] = [], workers: string[] = []): EdgeResult`: Proteção edge Cloudflare.

- `denoSecurityPlugin(config: DenoConfig = {}, permissions: string[] = [], sandbox: Record<string, unknown> = {}): PluginResult`: Plugin de segurança Deno.

- `bunSecurityPlugin(config: BunConfig = {}, optimizations: Record<string, unknown> = {}, security: Record<string, unknown> = {}): PluginResult`: Plugin de segurança Bun.

- `browserRuntimeProtection(config: BrowserConfig = {}, csp: string = '', sandbox: Record<string, unknown> = {}): ProtectionResult`: Proteção runtime browser.

- `serviceWorkerSecurity(config: ServiceWorkerConfig = {}, scope: string = '/', permissions: string[] = []): SecurityResult`: Segurança Service Worker.

- `wasmSecurityRuntime(config: WasmConfig = {}, memoryLimits: MemoryLimit = { initial: 1024, maximum: 4096, shared: false }, syscalls: string[] = []): RuntimeResult`: Runtime de segurança WASM.

---

## Guia de Uso

### Python - Exemplo Básico

```python
from master_security.auth import validate_jwt, generate_jwt
from master_security.web import detect_xss, sanitize_html
from master_security.api import validate_input, api_rate_limit
from master_security.network import validate_ip, detect_port_scan
from master_security.crypto import encrypt_data, decrypt_data, secure_random

# Gerar e validar JWT
token = generate_jwt(
    subject="user-123",
    secret="my-secret-key",
    algorithm="HS256",
    expiry=3600,
    claims={"role": "admin"}
)
payload = validate_jwt(token, "my-secret-key", ["HS256"], True, None)

# Detectar XSS
result = detect_xss("<script>alert('xss')</script>")
if result['detected']:
    print(f"Ameaça detectada: {result['severity']}")

# Criptografar dados
key = secure_random(32)
encrypted = encrypt_data(b"dados secretos", key, "aes-256-gcm")
decrypted = decrypt_data(encrypted['ciphertext'], key, encrypted['nonce'], "aes-256-gcm")
```

### TypeScript - Exemplo Básico

```typescript
import { detectXss, sanitizeHtml, validateCors } from './src/web/index.js';
import { validateIp, detectPortScan } from './src/network/index.js';
import { generateHmac, verifyHmac, secureRandom } from './src/crypto/index.js';
import { getConfig, getMetrics, getEventBus } from './src/core/index.js';

// Detectar XSS
const xssResult = detectXss("<script>alert('xss')</script>");
if (xssResult.detected) {
  console.log(`Ameaça: ${xssResult.severity}`);
}

// Gerar e verificar HMAC
const key = secureRandom(32);
const data = new TextEncoder().encode("payload");
const hmac = generateHmac(data, key);
const isValid = verifyHmac(data, hmac, key);

// Usar métricas
const metrics = getMetrics();
metrics.incCounter('security_checks', { module: 'web' });
metrics.observeHistogram('detection_time_ms', 42.5);
```

---

## Telemetria e Observabilidade

O MSF integra **OpenTelemetry** para tracing distribuído, **métricas** (counters, gauges, histograms), **logging estruturado** (pino no TS, loguru no Python), e **event bus** para comunicação assíncrona.

### Métricas Disponíveis

| Métrica | Tipo | Descrição |
|---------|------|-----------|
| `jwt_validations` | Counter | Total de validações JWT |
| `xss_detections` | Counter | Detecções de XSS |
| `sqli_detections` | Counter | Detecções de SQL Injection |
| `port_scan_detections` | Counter | Detecções de port scan |
| `ddos_detections` | Counter | Detecções de DDoS |
| `malware_scans` | Counter | Scans de malware executados |
| `anomaly_scores` | Histogram | Distribuição de scores de anomalia |
| `threat_scores` | Histogram | Distribuição de scores de ameaça |
| `detection_latency_ms` | Histogram | Latência de detecção |
| `active_sessions` | Gauge | Sessões ativas |
| `cache_hit_ratio` | Gauge | Taxa de hit do cache |

---

## Contribuição

1. Fork o repositório
2. Crie uma branch para sua feature (`git checkout -b feature/nova-feature`)
3. Commit suas mudanças (`git commit -am 'Adiciona nova feature'`)
4. Push para a branch (`git push origin feature/nova-feature`)
5. Abra um Pull Request

### Rodando os Testes

```bash
# Python
cd master_security_python
python test_full.py

# TypeScript
cd packages/core
npx vitest run
```

---

## Licença

MIT License - veja o arquivo LICENSE para detalhes.
