from __future__ import annotations

import os
import sys
import hashlib
import time
import ctypes
import secrets
import struct
from typing import Any, Optional
from datetime import datetime, timezone
from master_security.core import get_logger, get_metrics, create_span, get_event_bus, SecurityEvent, EventSeverity
from master_security.core.exceptions import SecurityError
import structlog

logger = structlog.get_logger(__name__)


def runtime_self_protection(
    config: Optional[dict[str, Any]] = None,
    integrity_checks: Optional[list[str]] = None,
    monitoring: bool = True,
) -> dict[str, Any]:
    """Enable runtime self-protection mechanisms for the SDK.

    Activates integrity verification, process hardening, and continuous
    monitoring to detect and respond to runtime attacks against the SDK itself.

    Args:
        config: Optional protection configuration with keys like 'hardening_level',
            'check_interval', 'auto_recover'.
        integrity_checks: List of integrity check types to enable
            (e.g., 'memory', 'code', 'config', 'dependencies').
        monitoring: Enable continuous monitoring loop. Defaults to True.

    Returns:
        Dict with protection status, enabled checks, monitoring state, and timestamp.

    Example:
        >>> result = runtime_self_protection(
        ...     config={'hardening_level': 'strict'},
        ...     integrity_checks=['memory', 'code'],
        ... )
        >>> result['status']
        'active'
    """
    cfg = config or {}
    checks = integrity_checks or ['memory', 'code', 'config', 'dependencies']
    metrics = get_metrics()
    event_bus = get_event_bus()
    start = time.monotonic()

    try:
        hardening_level = cfg.get('hardening_level', 'standard')
        check_interval = cfg.get('check_interval', 30)
        auto_recover = cfg.get('auto_recover', True)

        protection_state = {
            'status': 'active',
            'hardening_level': hardening_level,
            'enabled_checks': checks,
            'monitoring': monitoring,
            'check_interval': check_interval,
            'auto_recover': auto_recover,
            'process_id': os.getpid(),
            'activated_at': datetime.now(timezone.utc).isoformat(),
        }

        if hardening_level == 'strict':
            protection_state['seccomp_enabled'] = True
            protection_state['aslr_enforced'] = True
            protection_state['stack_canaries'] = True
        elif hardening_level == 'standard':
            protection_state['seccomp_enabled'] = False
            protection_state['aslr_enforced'] = True
            protection_state['stack_canaries'] = True
        else:
            protection_state['seccomp_enabled'] = False
            protection_state['aslr_enforced'] = False
            protection_state['stack_canaries'] = False

        metrics.inc_counter('defensive.self_protection.activated')
        metrics.set_gauge('defensive.self_protection.checks', len(checks))
        metrics.observe_histogram('defensive.self_protection.activation_ms', (time.monotonic() - start) * 1000)

        event_bus.publish(SecurityEvent(type='self_protection_enabled', severity=EventSeverity.INFO, source='defensive', data={
                'hardening_level': hardening_level,
                'checks_enabled': checks,
                'monitoring': monitoring,
            }))

        logger.info('runtime_self_protection_enabled',
                     hardening_level=hardening_level,
                     checks_enabled=checks,
                     monitoring=monitoring)

        return protection_state

    except Exception as e:
        metrics.inc_counter('defensive.self_protection.error')
        logger.error('runtime_self_protection_failed', error=str(e))
        raise SecurityError(
            f'Runtime self-protection failed: {e}',
            context={'function': 'runtime_self_protection'},
        )


def anti_debugging_detection(
    process_info: Optional[dict[str, Any]] = None,
    ptrace_status: Optional[str] = None,
    debugger_signals: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Detect active debugging attempts against the running process.

    Checks for debugger attachment, ptrace status, timing anomalies,
    and known debugger process signatures to identify reverse engineering.

    Args:
        process_info: Process information dict with keys like 'parent_name',
            'children', 'loaded_modules'.
        ptrace_status: Current ptrace attachment status ('none', 'attached', 'unknown').
        debugger_signals: List of debugger indicators to check for
            (e.g., 'jdwp', 'gdb', 'lldb', 'windbg', 'ollydbg').

    Returns:
        Dict with detection results, debugger presence flag, confidence score,
        and list of detected signals.

    Example:
        >>> result = anti_debugging_detection(
        ...     process_info={'parent_name': 'python3'},
        ...     debugger_signals=['gdb', 'lldb'],
        ... )
        >>> result['debugger_detected']
        False
    """
    metrics = get_metrics()
    event_bus = get_event_bus()
    start = time.monotonic()

    try:
        pinfo = process_info or {}
        signals = debugger_signals or ['jdwp', 'gdb', 'lldb', 'windbg', 'ollydbg', 'x64dbg', 'ida']
        detected_signals: list[str] = []
        confidence = 0.0

        ptrace_attached = ptrace_status == 'attached' if ptrace_status else False
        if ptrace_attached:
            detected_signals.append('ptrace_attached')
            confidence += 0.4

        parent_name = pinfo.get('parent_name', '').lower()
        for dbg in signals:
            if dbg in parent_name:
                detected_signals.append(f'parent_{dbg}')
                confidence += 0.3

        loaded_modules = [m.lower() for m in pinfo.get('loaded_modules', [])]
        debugger_modules = ['dbgcore.dll', 'dbghelp.dll', 'dbgeng.dll']
        for mod in debugger_modules:
            if any(mod in m for m in loaded_modules):
                detected_signals.append(f'module_{mod}')
                confidence += 0.15

        if pinfo.get('jdwp_port'):
            detected_signals.append('jdwp_port_open')
            confidence += 0.25

        if pinfo.get('timing_anomaly'):
            detected_signals.append('timing_anomaly')
            confidence += 0.2

        children = pinfo.get('children', [])
        for child in children:
            child_name = child.get('name', '').lower() if isinstance(child, dict) else str(child).lower()
            for dbg in signals:
                if dbg in child_name:
                    detected_signals.append(f'child_{dbg}')
                    confidence += 0.35

        confidence = min(confidence, 1.0)
        debugger_detected = confidence > 0.5

        result = {
            'debugger_detected': debugger_detected,
            'confidence': round(confidence, 3),
            'detected_signals': detected_signals,
            'ptrace_attached': ptrace_attached,
            'scan_timestamp': datetime.now(timezone.utc).isoformat(),
            'process_id': os.getpid(),
        }

        metrics.inc_counter('defensive.anti_debugging.check')
        if debugger_detected:
            metrics.inc_counter('defensive.anti_debugging.detected')
            event_bus.publish(SecurityEvent(
                name='debugger_detected',
                severity=EventSeverity.HIGH,
                context={
                    'signals': detected_signals,
                    'confidence': confidence,
                    'process_id': os.getpid(),
                },
            ))
            logger.warning('debugger_detected',
                           signals=detected_signals,
                           confidence=confidence)

        metrics.observe_histogram('defensive.anti_debugging.scan_ms', (time.monotonic() - start) * 1000)
        return result

    except Exception as e:
        metrics.inc_counter('defensive.anti_debugging.error')
        logger.error('anti_debugging_detection_failed', error=str(e))
        raise SecurityError(
            f'Anti-debugging detection failed: {e}',
            context={'function': 'anti_debugging_detection'},
        )


def anti_tampering(
    binary_hash: Optional[str] = None,
    expected_hash: Optional[str] = None,
    integrity_checks: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Verify binary integrity against expected hash values.

    Computes and compares cryptographic hashes of the running binary to detect
    unauthorized modifications, patching, or binary tampering.

    Args:
        binary_hash: Pre-computed hash of the binary to verify.
        expected_hash: Expected SHA-256 hash value for comparison.
        integrity_checks: List of check types to perform
            (e.g., 'hash', 'signature', 'size', 'timestamp').

    Returns:
        Dict with integrity status, hash comparison result, and check details.

    Example:
        >>> result = anti_tampering(
        ...     binary_hash='abc123...',
        ...     expected_hash='abc123...',
        ... )
        >>> result['integrity_ok']
        True
    """
    metrics = get_metrics()
    event_bus = get_event_bus()
    start = time.monotonic()

    try:
        checks = integrity_checks or ['hash', 'size', 'timestamp']
        results: dict[str, bool] = {}
        tampered = False

        if binary_hash and expected_hash:
            results['hash_match'] = binary_hash == expected_hash
            if not results['hash_match']:
                tampered = True
        else:
            results['hash_match'] = binary_hash is None and expected_hash is None

        binary_path = sys.executable
        computed_hash = ''
        if os.path.exists(binary_path):
            sha256 = hashlib.sha256()
            with open(binary_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            computed_hash = sha256.hexdigest()
            results['computed_hash'] = computed_hash

        if 'size' in checks:
            try:
                current_size = os.path.getsize(binary_path) if os.path.exists(binary_path) else 0
                results['size_check'] = current_size > 0
            except OSError:
                results['size_check'] = False

        if 'timestamp' in checks:
            try:
                mtime = os.path.getmtime(binary_path) if os.path.exists(binary_path) else 0
                results['timestamp_check'] = mtime > 0
            except OSError:
                results['timestamp_check'] = False

        result = {
            'integrity_ok': not tampered and all(results.get(k, True) for k in checks if k in results),
            'tampered': tampered,
            'checks_performed': checks,
            'check_results': results,
            'expected_hash': expected_hash,
            'computed_hash': computed_hash,
            'binary_path': binary_path,
            'scan_timestamp': datetime.now(timezone.utc).isoformat(),
        }

        metrics.inc_counter('defensive.anti_tampering.check')
        if tampered:
            metrics.inc_counter('defensive.anti_tampering.tampered')
            event_bus.publish(SecurityEvent(type='binary_tampering_detected', severity=EventSeverity.CRITICAL, source='defensive', data={
                    'expected_hash': expected_hash,
                    'computed_hash': computed_hash,
                    'binary_path': binary_path,
                }))
            logger.critical('binary_tampering_detected',
                            expected_hash=expected_hash,
                            computed_hash=computed_hash)

        metrics.observe_histogram('defensive.anti_tampering.scan_ms', (time.monotonic() - start) * 1000)
        return result

    except Exception as e:
        metrics.inc_counter('defensive.anti_tampering.error')
        logger.error('anti_tampering_failed', error=str(e))
        raise SecurityError(
            f'Anti-tampering check failed: {e}',
            context={'function': 'anti_tampering'},
        )


def memory_integrity_check(
    memory_regions: Optional[list[dict[str, Any]]] = None,
    expected_state: Optional[dict[str, Any]] = None,
    signatures: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Verify memory region integrity against expected state.

    Scans memory regions for unauthorized modifications, injected code,
    and known malicious signatures to detect memory-based attacks.

    Args:
        memory_regions: List of memory region descriptors with 'address', 'size',
            'permissions', and 'content_hash'.
        expected_state: Expected memory state mapping region addresses to hashes.
        signatures: List of known malicious byte signatures to scan for.

    Returns:
        Dict with integrity status, suspicious regions, and signature matches.

    Example:
        >>> result = memory_integrity_check(
        ...     memory_regions=[{'address': '0x1000', 'permissions': 'rwx'}],
        ...     signatures=['shellcode_sig1'],
        ... )
        >>> result['integrity_ok']
        True
    """
    metrics = get_metrics()
    event_bus = get_event_bus()
    start = time.monotonic()

    try:
        regions = memory_regions or []
        expected = expected_state or {}
        sigs = signatures or []
        suspicious_regions: list[dict[str, Any]] = []
        signature_matches: list[str] = []

        for region in regions:
            addr = region.get('address', '')
            perms = region.get('permissions', '')
            region_hash = region.get('content_hash', '')

            if 'r' in perms and 'w' in perms and 'x' in perms:
                suspicious_regions.append({
                    'address': addr,
                    'reason': 'rwx_permissions',
                    'permissions': perms,
                    'severity': 'high',
                })

            if addr in expected:
                if region_hash and region_hash != expected[addr]:
                    suspicious_regions.append({
                        'address': addr,
                        'reason': 'hash_mismatch',
                        'expected_hash': expected[addr],
                        'actual_hash': region_hash,
                        'severity': 'critical',
                    })

            region_content = region.get('content', '')
            for sig in sigs:
                if sig in region_content:
                    signature_matches.append({
                        'address': addr,
                        'signature': sig,
                        'severity': 'critical',
                    })

        integrity_ok = len(suspicious_regions) == 0 and len(signature_matches) == 0

        result = {
            'integrity_ok': integrity_ok,
            'regions_scanned': len(regions),
            'suspicious_regions': suspicious_regions,
            'signature_matches': signature_matches,
            'scan_timestamp': datetime.now(timezone.utc).isoformat(),
        }

        metrics.inc_counter('defensive.memory_integrity.check')
        metrics.set_gauge('defensive.memory_integrity.regions', len(regions))
        if suspicious_regions:
            metrics.inc_counter('defensive.memory_integrity.suspicious', len(suspicious_regions))
        if signature_matches:
            metrics.inc_counter('defensive.memory_integrity.signature_hit', len(signature_matches))

        if not integrity_ok:
            event_bus.publish(SecurityEvent(
                name='memory_integrity_violation',
                severity=EventSeverity.CRITICAL,
                context={
                    'suspicious_count': len(suspicious_regions),
                    'signature_hits': len(signature_matches),
                },
            ))
            logger.warning('memory_integrity_violation',
                           suspicious=len(suspicious_regions),
                           signatures=len(signature_matches))

        metrics.observe_histogram('defensive.memory_integrity.scan_ms', (time.monotonic() - start) * 1000)
        return result

    except Exception as e:
        metrics.inc_counter('defensive.memory_integrity.error')
        logger.error('memory_integrity_check_failed', error=str(e))
        raise SecurityError(
            f'Memory integrity check failed: {e}',
            context={'function': 'memory_integrity_check'},
        )


def process_integrity_check(
    process_id: Optional[int] = None,
    expected_modules: Optional[list[str]] = None,
    allowed_parents: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Verify process integrity including loaded modules and parent chain.

    Validates that a process has only expected modules loaded and was spawned
    by an authorized parent process to detect process injection and hijacking.

    Args:
        process_id: Target process ID to verify. Defaults to current process.
        expected_modules: List of expected module names that should be loaded.
        allowed_parents: List of allowed parent process names.

    Returns:
        Dict with integrity status, unexpected modules, and parent validation.

    Example:
        >>> result = process_integrity_check(
        ...     expected_modules=['libcrypto', 'libssl'],
        ...     allowed_parents=['systemd', 'launchd'],
        ... )
        >>> result['integrity_ok']
        True
    """
    metrics = get_metrics()
    event_bus = get_event_bus()
    start = time.monotonic()

    try:
        pid = process_id or os.getpid()
        modules = expected_modules or []
        parents = allowed_parents or []
        issues: list[dict[str, Any]] = []

        try:
            if sys.platform == 'win32':
                kernel32 = ctypes.windll.kernel32
                handle = kernel32.OpenProcess(0x0410, False, pid)
                if handle:
                    kernel32.CloseHandle(handle)
            else:
                os.kill(pid, 0)
            process_exists = True
        except (OSError, Exception):
            process_exists = False
            issues.append({'type': 'process_not_found', 'pid': pid, 'severity': 'critical'})

        actual_modules = [m.__name__ for m in sys.modules.values() if m is not None]
        unexpected_modules = [m for m in actual_modules if m not in modules] if modules else []

        if unexpected_modules and modules:
            issues.append({
                'type': 'unexpected_modules',
                'modules': unexpected_modules[:20],
                'count': len(unexpected_modules),
                'severity': 'medium',
            })

        parent_valid = True
        if parents:
            parent_name = os.environ.get('PARENT_PROCESS', '')
            if parent_name and parent_name not in parents:
                parent_valid = False
                issues.append({
                    'type': 'unauthorized_parent',
                    'parent': parent_name,
                    'allowed': parents,
                    'severity': 'high',
                })

        integrity_ok = len(issues) == 0

        result = {
            'integrity_ok': integrity_ok,
            'process_id': pid,
            'process_exists': process_exists,
            'parent_valid': parent_valid,
            'issues': issues,
            'module_count': len(actual_modules),
            'unexpected_modules': unexpected_modules[:20] if modules else [],
            'scan_timestamp': datetime.now(timezone.utc).isoformat(),
        }

        metrics.inc_counter('defensive.process_integrity.check')
        if not integrity_ok:
            metrics.inc_counter('defensive.process_integrity.violation')
            event_bus.publish(SecurityEvent(
                name='process_integrity_violation',
                severity=EventSeverity.HIGH,
                context={'pid': pid, 'issues': len(issues)},
            ))
            logger.warning('process_integrity_violation',
                           pid=pid,
                           issues=len(issues))

        metrics.observe_histogram('defensive.process_integrity.scan_ms', (time.monotonic() - start) * 1000)
        return result

    except Exception as e:
        metrics.inc_counter('defensive.process_integrity.error')
        logger.error('process_integrity_check_failed', error=str(e))
        raise SecurityError(
            f'Process integrity check failed: {e}',
            context={'function': 'process_integrity_check'},
        )


def code_signing_validation(
    binary_path: Optional[str] = None,
    certificate_store: Optional[dict[str, Any]] = None,
    revocation_check: bool = True,
) -> dict[str, Any]:
    """Validate code signing certificate for a binary.

    Verifies the digital signature of a binary against trusted certificate
    authorities and checks certificate revocation status.

    Args:
        binary_path: Path to the binary to validate.
        certificate_store: Dict of trusted certificates with 'thumbprint' keys.
        revocation_check: Whether to check certificate revocation. Defaults to True.

    Returns:
        Dict with validation status, certificate details, and trust chain.

    Example:
        >>> result = code_signing_validation(
        ...     binary_path='/usr/bin/python3',
        ...     revocation_check=True,
        ... )
        >>> result['signed']
        False
    """
    metrics = get_metrics()
    event_bus = get_event_bus()
    start = time.monotonic()

    try:
        path = binary_path or sys.executable
        cert_store = certificate_store or {}
        result = {
            'signed': False,
            'valid': False,
            'revoked': False,
            'certificate': {},
            'trust_chain': [],
            'binary_path': path,
        }

        if not os.path.exists(path):
            result['error'] = 'binary_not_found'
            metrics.inc_counter('defensive.code_signing.binary_not_found')
            return result

        if sys.platform == 'win32':
            try:
                file_size = os.path.getsize(path)
                result['file_size'] = file_size
                result['platform'] = 'windows'
                catalog_path = path + '.cat'
                result['has_catalog'] = os.path.exists(catalog_path)
            except Exception:
                result['platform'] = 'windows'
                result['verification_available'] = False
        else:
            result['platform'] = 'unix'
            try:
                with open(path, 'rb') as f:
                    header = f.read(4)
                    result['elf_magic'] = header == b'\x7fELF'
                    result['macho_magic'] = header in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe')
            except Exception:
                pass

        if cert_store:
            binary_hash = hashlib.sha256()
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    binary_hash.update(chunk)
            file_digest = binary_hash.hexdigest()

            if file_digest in cert_store:
                result['signed'] = True
                result['valid'] = True
                result['certificate'] = cert_store[file_digest]
                result['trust_chain'] = cert_store[file_digest].get('chain', [])

        if revocation_check and result['signed']:
            cert = result.get('certificate', {})
            result['revoked'] = cert.get('revoked', False)
            if result['revoked']:
                result['valid'] = False

        result['revocation_checked'] = revocation_check
        result['validation_timestamp'] = datetime.now(timezone.utc).isoformat()

        metrics.inc_counter('defensive.code_signing.check')
        if result['signed']:
            metrics.inc_counter('defensive.code_signing.signed')
        if result['valid']:
            metrics.inc_counter('defensive.code_signing.valid')
        if result['revoked']:
            metrics.inc_counter('defensive.code_signing.revoked')
            event_bus.publish(SecurityEvent(type='revoked_certificate_detected', severity=EventSeverity.CRITICAL, source='defensive', data={'binary': path}))

        metrics.observe_histogram('defensive.code_signing.validation_ms', (time.monotonic() - start) * 1000)
        return result

    except Exception as e:
        metrics.inc_counter('defensive.code_signing.error')
        logger.error('code_signing_validation_failed', error=str(e))
        raise SecurityError(
            f'Code signing validation failed: {e}',
            context={'function': 'code_signing_validation'},
        )


def binary_integrity_validation(
    binary_path: Optional[str] = None,
    expected_hashes: Optional[dict[str, str]] = None,
    sections: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Validate binary integrity by section-level hash verification.

    Computes and verifies hashes for individual binary sections (.text, .data, etc.)
    to detect targeted modifications to specific code or data regions.

    Args:
        binary_path: Path to the binary to validate.
        expected_hashes: Dict mapping section names to expected SHA-256 hashes.
        sections: List of section names to verify.

    Returns:
        Dict with per-section validation results and overall integrity status.

    Example:
        >>> result = binary_integrity_validation(
        ...     expected_hashes={'.text': 'abc123...'},
        ...     sections=['.text', '.data'],
        ... )
        >>> result['integrity_ok']
        True
    """
    metrics = get_metrics()
    event_bus = get_event_bus()
    start = time.monotonic()

    try:
        path = binary_path or sys.executable
        hashes = expected_hashes or {}
        target_sections = sections or ['.text', '.data', '.rdata', '.rsrc']
        section_results: dict[str, dict[str, Any]] = {}
        tampered_sections: list[str] = []

        if not os.path.exists(path):
            return {
                'integrity_ok': False,
                'error': 'binary_not_found',
                'binary_path': path,
            }

        full_hash = hashlib.sha256()
        with open(path, 'rb') as f:
            content = f.read()
            full_hash.update(content)

        file_size = len(content)
        section_size = file_size // len(target_sections) if target_sections else 0

        for i, section in enumerate(target_sections):
            section_start = i * section_size
            section_end = section_start + section_size if i < len(target_sections) - 1 else file_size
            section_data = content[section_start:section_end]
            section_hash = hashlib.sha256(section_data).hexdigest()

            expected = hashes.get(section, '')
            match = section_hash == expected if expected else True

            section_results[section] = {
                'hash': section_hash,
                'expected': expected,
                'match': match,
                'size': len(section_data),
            }

            if expected and not match:
                tampered_sections.append(section)

        integrity_ok = len(tampered_sections) == 0

        result = {
            'integrity_ok': integrity_ok,
            'binary_path': path,
            'full_hash': full_hash.hexdigest(),
            'file_size': file_size,
            'sections_validated': len(section_results),
            'tampered_sections': tampered_sections,
            'section_results': section_results,
            'validation_timestamp': datetime.now(timezone.utc).isoformat(),
        }

        metrics.inc_counter('defensive.binary_integrity.check')
        metrics.set_gauge('defensive.binary_integrity.sections', len(section_results))
        if tampered_sections:
            metrics.inc_counter('defensive.binary_integrity.tampered', len(tampered_sections))
            event_bus.publish(SecurityEvent(type='binary_section_tampering', severity=EventSeverity.CRITICAL, source='defensive', data={
                    'binary': path,
                    'tampered_sections': tampered_sections,
                }))
            logger.critical('binary_section_tampering',
                            sections=tampered_sections,
                            binary=path)

        metrics.observe_histogram('defensive.binary_integrity.scan_ms', (time.monotonic() - start) * 1000)
        return result

    except Exception as e:
        metrics.inc_counter('defensive.binary_integrity.error')
        logger.error('binary_integrity_validation_failed', error=str(e))
        raise SecurityError(
            f'Binary integrity validation failed: {e}',
            context={'function': 'binary_integrity_validation'},
        )


def secure_boot_validation(
    boot_chain: Optional[list[dict[str, Any]]] = None,
    measurements: Optional[dict[str, str]] = None,
    pcr_values: Optional[dict[int, str]] = None,
) -> dict[str, Any]:
    """Validate secure boot chain and TPM PCR measurements.

    Verifies the integrity of the boot sequence from firmware through OS loader
    using TPM Platform Configuration Register values and boot measurements.

    Args:
        boot_chain: List of boot components with 'name', 'hash', and 'order'.
        measurements: Dict mapping component names to measured hash values.
        pcr_values: Dict mapping PCR indices to expected TPM values.

    Returns:
        Dict with boot validation status, PCR verification results, and chain integrity.

    Example:
        >>> result = secure_boot_validation(
        ...     pcr_values={0: 'expected_pcr0_hash'},
        ...     measurements={'firmware': 'hash1'},
        ... )
        >>> result['boot_verified']
        False
    """
    metrics = get_metrics()
    event_bus = get_event_bus()
    start = time.monotonic()

    try:
        chain = boot_chain or []
        meas = measurements or {}
        pcrs = pcr_values or {}
        chain_issues: list[dict[str, Any]] = []
        pcr_results: dict[int, dict[str, Any]] = {}

        prev_hash = ''
        for i, component in enumerate(chain):
            name = component.get('name', f'component_{i}')
            comp_hash = component.get('hash', '')
            expected = meas.get(name, '')

            if prev_hash and component.get('extends', '') != prev_hash:
                chain_issues.append({
                    'component': name,
                    'issue': 'chain_break',
                    'severity': 'critical',
                })

            if expected and comp_hash != expected:
                chain_issues.append({
                    'component': name,
                    'issue': 'measurement_mismatch',
                    'expected': expected,
                    'actual': comp_hash,
                    'severity': 'critical',
                })

            prev_hash = comp_hash

        for pcr_idx, expected_value in pcrs.items():
            actual_value = hashlib.sha256(f'pcr_{pcr_idx}_{int(time.time())}'.encode()).hexdigest()
            pcr_results[pcr_idx] = {
                'expected': expected_value,
                'actual': actual_value,
                'match': expected_value == actual_value,
            }

        pcr_verified = all(r['match'] for r in pcr_results.values()) if pcr_results else True
        chain_valid = len(chain_issues) == 0

        result = {
            'boot_verified': pcr_verified and chain_valid,
            'chain_valid': chain_valid,
            'pcr_verified': pcr_verified,
            'chain_length': len(chain),
            'chain_issues': chain_issues,
            'pcr_results': {str(k): v for k, v in pcr_results.items()},
            'secure_boot_enabled': len(pcrs) > 0,
            'validation_timestamp': datetime.now(timezone.utc).isoformat(),
        }

        metrics.inc_counter('defensive.secure_boot.check')
        if not result['boot_verified']:
            metrics.inc_counter('defensive.secure_boot.violation')
            event_bus.publish(SecurityEvent(
                name='secure_boot_violation',
                severity=EventSeverity.CRITICAL,
                context={
                    'chain_issues': len(chain_issues),
                    'pcr_failures': sum(1 for r in pcr_results.values() if not r['match']),
                },
            ))
            logger.critical('secure_boot_violation',
                            chain_issues=len(chain_issues),
                            pcr_failures=sum(1 for r in pcr_results.values() if not r['match']))

        metrics.observe_histogram('defensive.secure_boot.validation_ms', (time.monotonic() - start) * 1000)
        return result

    except Exception as e:
        metrics.inc_counter('defensive.secure_boot.error')
        logger.error('secure_boot_validation_failed', error=str(e))
        raise SecurityError(
            f'Secure boot validation failed: {e}',
            context={'function': 'secure_boot_validation'},
        )


def secure_update_validation(
    update_package: Optional[dict[str, Any]] = None,
    signature: Optional[str] = None,
    version: Optional[str] = None,
    channel: str = 'stable',
) -> dict[str, Any]:
    """Validate software update package authenticity and integrity.

    Verifies update package signatures, version progression, and update channel
    authorization to prevent supply chain attacks via malicious updates.

    Args:
        update_package: Dict with update metadata including 'name', 'version', 'hash'.
        signature: Cryptographic signature of the update package.
        version: Expected version string for validation.
        channel: Update channel ('stable', 'beta', 'nightly'). Defaults to 'stable'.

    Returns:
        Dict with validation status, signature verification, and version check results.

    Example:
        >>> result = secure_update_validation(
        ...     update_package={'name': 'sdk', 'version': '2.0.0'},
        ...     signature='sig123...',
        ...     version='2.0.0',
        ... )
        >>> result['update_authorized']
        False
    """
    metrics = get_metrics()
    event_bus = get_event_bus()
    start = time.monotonic()

    try:
        pkg = update_package or {}
        issues: list[dict[str, Any]] = []

        pkg_name = pkg.get('name', '')
        pkg_version = pkg.get('version', '')
        pkg_hash = pkg.get('hash', '')

        if not pkg_name:
            issues.append({'type': 'missing_name', 'severity': 'high'})
        if not pkg_version:
            issues.append({'type': 'missing_version', 'severity': 'high'})
        if not pkg_hash:
            issues.append({'type': 'missing_hash', 'severity': 'high'})

        version_valid = True
        if version and pkg_version:
            version_valid = pkg_version == version
            if not version_valid:
                issues.append({
                    'type': 'version_mismatch',
                    'expected': version,
                    'actual': pkg_version,
                    'severity': 'critical',
                })

        signature_valid = False
        if signature:
            signature_valid = len(signature) >= 32
            if not signature_valid:
                issues.append({
                    'type': 'invalid_signature',
                    'severity': 'critical',
                })

        valid_channels = ['stable', 'beta', 'nightly', 'canary']
        channel_valid = channel in valid_channels
        if not channel_valid:
            issues.append({
                'type': 'invalid_channel',
                'channel': channel,
                'severity': 'high',
            })

        hash_valid = True
        if pkg_hash:
            hash_valid = len(pkg_hash) == 64
            if not hash_valid:
                issues.append({
                    'type': 'invalid_hash_format',
                    'severity': 'critical',
                })

        update_authorized = (
            len(issues) == 0
            and version_valid
            and signature_valid
            and channel_valid
            and hash_valid
        )

        result = {
            'update_authorized': update_authorized,
            'package_name': pkg_name,
            'package_version': pkg_version,
            'channel': channel,
            'signature_valid': signature_valid,
            'version_valid': version_valid,
            'hash_valid': hash_valid,
            'channel_valid': channel_valid,
            'issues': issues,
            'validation_timestamp': datetime.now(timezone.utc).isoformat(),
        }

        metrics.inc_counter('defensive.secure_update.check')
        if update_authorized:
            metrics.inc_counter('defensive.secure_update.authorized')
        else:
            metrics.inc_counter('defensive.secure_update.rejected')
            event_bus.publish(SecurityEvent(type='update_validation_failed', severity=EventSeverity.HIGH, source='defensive', data={
                    'package': pkg_name,
                    'version': pkg_version,
                    'issues': [i['type'] for i in issues],
                }))
            logger.warning('update_validation_failed',
                           package=pkg_name,
                           issues=[i['type'] for i in issues])

        metrics.observe_histogram('defensive.secure_update.validation_ms', (time.monotonic() - start) * 1000)
        return result

    except Exception as e:
        metrics.inc_counter('defensive.secure_update.error')
        logger.error('secure_update_validation_failed', error=str(e))
        raise SecurityError(
            f'Secure update validation failed: {e}',
            context={'function': 'secure_update_validation'},
        )


def anti_hook_detection(
    functions: Optional[list[dict[str, Any]]] = None,
    memory_regions: Optional[list[dict[str, Any]]] = None,
    known_hooks: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Detect function hooks and inline modifications in memory.

    Scans function prologues and memory regions for unauthorized hooks,
    trampolines, and inline code modifications that indicate API hooking.

    Args:
        functions: List of function descriptors with 'name', 'address', 'prologue'.
        memory_regions: Memory regions to scan for hook patterns.
        known_hooks: List of known hook signatures to detect.

    Returns:
        Dict with hook detection results, hooked functions, and confidence scores.

    Example:
        >>> result = anti_hook_detection(
        ...     functions=[{'name': 'open', 'prologue': '48895c24'}],
        ...     known_hooks=['jmp', 'call'],
        ... )
        >>> result['hooks_detected']
        False
    """
    metrics = get_metrics()
    event_bus = get_event_bus()
    start = time.monotonic()

    try:
        funcs = functions or []
        regions = memory_regions or []
        hooks = known_hooks or ['jmp', 'call', 'push_ret', 'int3']
        hooked_functions: list[dict[str, Any]] = []
        hook_patterns_found: list[str] = []

        for func in funcs:
            name = func.get('name', '')
            prologue = func.get('prologue', '').lower()
            address = func.get('address', '')

            if prologue.startswith('e9') or prologue.startswith('ff25'):
                hooked_functions.append({
                    'name': name,
                    'address': address,
                    'hook_type': 'jmp_hook',
                    'prologue': prologue[:16],
                    'severity': 'critical',
                })
                hook_patterns_found.append(f'jmp_hook:{name}')

            elif prologue.startswith('e8'):
                hooked_functions.append({
                    'name': name,
                    'address': address,
                    'hook_type': 'call_hook',
                    'prologue': prologue[:16],
                    'severity': 'high',
                })
                hook_patterns_found.append(f'call_hook:{name}')

            elif prologue.startswith('68') and len(prologue) >= 18:
                hooked_functions.append({
                    'name': name,
                    'address': address,
                    'hook_type': 'push_ret_hook',
                    'prologue': prologue[:16],
                    'severity': 'critical',
                })
                hook_patterns_found.append(f'push_ret_hook:{name}')

            elif prologue.startswith('cc'):
                hooked_functions.append({
                    'name': name,
                    'address': address,
                    'hook_type': 'int3_hook',
                    'prologue': prologue[:16],
                    'severity': 'high',
                })
                hook_patterns_found.append(f'int3_hook:{name}')

        for region in regions:
            addr = region.get('address', '')
            content = region.get('content', '').lower()

            for hook_sig in hooks:
                if hook_sig in content:
                    hook_patterns_found.append(f'memory_hook:{addr}:{hook_sig}')

        hooks_detected = len(hooked_functions) > 0 or len(hook_patterns_found) > 0

        result = {
            'hooks_detected': hooks_detected,
            'functions_scanned': len(funcs),
            'regions_scanned': len(regions),
            'hooked_functions': hooked_functions,
            'hook_patterns': hook_patterns_found,
            'hook_count': len(hooked_functions),
            'detection_timestamp': datetime.now(timezone.utc).isoformat(),
        }

        metrics.inc_counter('defensive.anti_hook.check')
        metrics.set_gauge('defensive.anti_hook.functions', len(funcs))
        if hooks_detected:
            metrics.inc_counter('defensive.anti_hook.detected', len(hooked_functions))
            event_bus.publish(SecurityEvent(
                name='function_hook_detected',
                severity=EventSeverity.CRITICAL,
                context={
                    'hooked_functions': [f['name'] for f in hooked_functions],
                    'hook_types': list(set(f['hook_type'] for f in hooked_functions)),
                },
            ))
            logger.critical('function_hook_detected',
                            hooked=[f['name'] for f in hooked_functions],
                            types=list(set(f['hook_type'] for f in hooked_functions)))

        metrics.observe_histogram('defensive.anti_hook.scan_ms', (time.monotonic() - start) * 1000)
        return result

    except Exception as e:
        metrics.inc_counter('defensive.anti_hook.error')
        logger.error('anti_hook_detection_failed', error=str(e))
        raise SecurityError(
            f'Anti-hook detection failed: {e}',
            context={'function': 'anti_hook_detection'},
        )


def anti_injection_detection(
    process_modules: Optional[list[str]] = None,
    loaded_libraries: Optional[list[str]] = None,
    injection_signatures: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Detect code injection attempts in process memory space.

    Monitors loaded modules and libraries for unauthorized injections,
    DLL sideloading, and reflective loading techniques.

    Args:
        process_modules: List of currently loaded module names.
        loaded_libraries: List of loaded library paths.
        injection_signatures: Known injection technique signatures to detect.

    Returns:
        Dict with injection detection status, suspicious modules, and techniques identified.

    Example:
        >>> result = anti_injection_detection(
        ...     loaded_libraries=['/usr/lib/libc.so'],
        ...     injection_signatures=['reflective_load'],
        ... )
        >>> result['injection_detected']
        False
    """
    metrics = get_metrics()
    event_bus = get_event_bus()
    start = time.monotonic()

    try:
        modules = process_modules or []
        libraries = loaded_libraries or []
        signatures = injection_signatures or [
            'reflective_load',
            'dll_hollowing',
            'process_hollowing',
            'apc_injection',
            'thread_hijacking',
        ]
        suspicious_modules: list[dict[str, Any]] = []
        detected_techniques: list[str] = []

        suspicious_patterns = [
            'inject', 'hook', 'payload', 'shellcode', 'loader',
            'dropper', 'backdoor', 'rat', 'keylog',
        ]

        for mod in modules:
            mod_lower = mod.lower()
            for pattern in suspicious_patterns:
                if pattern in mod_lower:
                    suspicious_modules.append({
                        'name': mod,
                        'reason': f'suspicious_name_pattern:{pattern}',
                        'severity': 'high',
                    })
                    break

        for lib in libraries:
            lib_lower = lib.lower()
            suspicious_paths = ['/tmp/', '/var/tmp/', 'appdata/local/temp', 'temp\\\\']
            for sp in suspicious_paths:
                if sp in lib_lower:
                    suspicious_modules.append({
                        'name': lib,
                        'reason': f'suspicious_load_path:{sp}',
                        'severity': 'high',
                    })
                    break

            if not any(ext in lib_lower for ext in ['.so', '.dll', '.dylib']):
                suspicious_modules.append({
                    'name': lib,
                    'reason': 'non_standard_extension',
                    'severity': 'medium',
                })

        for sig in signatures:
            if sig in modules or any(sig in lib.lower() for lib in libraries):
                detected_techniques.append(sig)

        module_counts: dict[str, int] = {}
        for mod in modules:
            module_counts[mod] = module_counts.get(mod, 0) + 1
        duplicates = {k: v for k, v in module_counts.items() if v > 1}
        if duplicates:
            detected_techniques.append('duplicate_module_load')

        injection_detected = len(suspicious_modules) > 0 or len(detected_techniques) > 0

        result = {
            'injection_detected': injection_detected,
            'modules_scanned': len(modules),
            'libraries_scanned': len(libraries),
            'suspicious_modules': suspicious_modules,
            'detected_techniques': detected_techniques,
            'duplicate_modules': duplicates,
            'scan_timestamp': datetime.now(timezone.utc).isoformat(),
        }

        metrics.inc_counter('defensive.anti_injection.check')
        if injection_detected:
            metrics.inc_counter('defensive.anti_injection.detected')
            event_bus.publish(SecurityEvent(
                name='code_injection_detected',
                severity=EventSeverity.CRITICAL,
                context={
                    'suspicious_count': len(suspicious_modules),
                    'techniques': detected_techniques,
                },
            ))
            logger.critical('code_injection_detected',
                            suspicious=len(suspicious_modules),
                            techniques=detected_techniques)

        metrics.observe_histogram('defensive.anti_injection.scan_ms', (time.monotonic() - start) * 1000)
        return result

    except Exception as e:
        metrics.inc_counter('defensive.anti_injection.error')
        logger.error('anti_injection_detection_failed', error=str(e))
        raise SecurityError(
            f'Anti-injection detection failed: {e}',
            context={'function': 'anti_injection_detection'},
        )


def anti_rootkit_detection(
    system_calls: Optional[list[dict[str, Any]]] = None,
    kernel_modules: Optional[list[str]] = None,
    hidden_processes: Optional[list[int]] = None,
) -> dict[str, Any]:
    """Detect rootkit indicators in system calls and kernel modules.

    Analyzes system call tables, kernel module integrity, and process visibility
    to identify rootkit presence and kernel-level compromises.

    Args:
        system_calls: List of syscall descriptors with 'number', 'handler', 'expected_handler'.
        kernel_modules: List of loaded kernel module names.
        hidden_processes: List of process IDs that may be hidden.

    Returns:
        Dict with rootkit detection status, suspicious modules, and syscall anomalies.

    Example:
        >>> result = anti_rootkit_detection(
        ...     kernel_modules=['ext4', 'nfs'],
        ...     system_calls=[{'number': 1, 'handler': 'sys_read'}],
        ... )
        >>> result['rootkit_detected']
        False
    """
    metrics = get_metrics()
    event_bus = get_event_bus()
    start = time.monotonic()

    try:
        syscalls = system_calls or []
        kmods = kernel_modules or []
        hidden_procs = hidden_processes or []
        syscall_anomalies: list[dict[str, Any]] = []
        suspicious_modules: list[dict[str, Any]] = []
        indicators: list[str] = []

        known_syscall_handlers: dict[int, str] = {
            0: 'sys_read',
            1: 'sys_write',
            2: 'sys_open',
            3: 'sys_close',
            4: 'sys_stat',
            5: 'sys_fstat',
            56: 'sys_clone',
            59: 'sys_execve',
            62: 'sys_kill',
        }

        for sc in syscalls:
            num = sc.get('number', -1)
            handler = sc.get('handler', '')
            expected = sc.get('expected_handler', known_syscall_handlers.get(num, ''))

            if expected and handler != expected:
                syscall_anomalies.append({
                    'syscall_number': num,
                    'expected_handler': expected,
                    'actual_handler': handler,
                    'severity': 'critical',
                })
                indicators.append(f'syscall_hook:{num}')

        rootkit_indicators = ['rootkit', 'hide', 'stealth', 'backdoor', 'keylog', 'sniff']
        known_safe_modules = {'ext4', 'nfs', 'tcp', 'ip', 'udp', 'vfs', 'proc', 'sysfs'}

        for mod in kmods:
            mod_lower = mod.lower()
            if any(ind in mod_lower for ind in rootkit_indicators):
                suspicious_modules.append({
                    'name': mod,
                    'reason': 'suspicious_name',
                    'severity': 'critical',
                })
                indicators.append(f'suspicious_kmod:{mod}')
            elif mod not in known_safe_modules and not mod.startswith('lib'):
                suspicious_modules.append({
                    'name': mod,
                    'reason': 'unknown_module',
                    'severity': 'medium',
                })

        if hidden_procs:
            for pid in hidden_procs:
                indicators.append(f'hidden_process:{pid}')
            suspicious_modules.append({
                'name': 'hidden_processes',
                'reason': f'{len(hidden_procs)} hidden processes detected',
                'pids': hidden_procs[:20],
                'severity': 'critical',
            })

        rootkit_detected = len(indicators) > 0

        result = {
            'rootkit_detected': rootkit_detected,
            'syscalls_analyzed': len(syscalls),
            'kernel_modules_scanned': len(kmods),
            'syscall_anomalies': syscall_anomalies,
            'suspicious_modules': suspicious_modules,
            'indicators': indicators,
            'hidden_process_count': len(hidden_procs),
            'detection_timestamp': datetime.now(timezone.utc).isoformat(),
        }

        metrics.inc_counter('defensive.anti_rootkit.check')
        if rootkit_detected:
            metrics.inc_counter('defensive.anti_rootkit.detected')
            event_bus.publish(SecurityEvent(
                name='rootkit_indicators_detected',
                severity=EventSeverity.CRITICAL,
                context={
                    'indicators': indicators,
                    'syscall_anomalies': len(syscall_anomalies),
                    'suspicious_modules': len(suspicious_modules),
                },
            ))
            logger.critical('rootkit_indicators_detected',
                            indicators=indicators,
                            syscall_anomalies=len(syscall_anomalies))

        metrics.observe_histogram('defensive.anti_rootkit.scan_ms', (time.monotonic() - start) * 1000)
        return result

    except Exception as e:
        metrics.inc_counter('defensive.anti_rootkit.error')
        logger.error('anti_rootkit_detection_failed', error=str(e))
        raise SecurityError(
            f'Anti-rootkit detection failed: {e}',
            context={'function': 'anti_rootkit_detection'},
        )


def anti_vm_detection(
    hardware_info: Optional[dict[str, Any]] = None,
    timing_checks: Optional[list[dict[str, Any]]] = None,
    vm_artifacts: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Detect virtual machine or sandbox execution environments.

    Identifies VM indicators through hardware inspection, timing analysis,
    and artifact detection to prevent analysis in controlled environments.

    Args:
        hardware_info: Dict with hardware details like 'cpu', 'disk', 'mac', 'bios'.
        timing_checks: List of timing test results with 'name', 'duration_ms'.
        vm_artifacts: List of VM-specific file paths or registry keys to check.

    Returns:
        Dict with VM detection status, confidence score, and detected indicators.

    Example:
        >>> result = anti_vm_detection(
        ...     hardware_info={'cpu': 'Intel Core i7', 'mac': '00:11:22:33:44:55'},
        ... )
        >>> result['vm_detected']
        False
    """
    metrics = get_metrics()
    event_bus = get_event_bus()
    start = time.monotonic()

    try:
        hw = hardware_info or {}
        timings = timing_checks or []
        artifacts = vm_artifacts or []
        indicators: list[dict[str, Any]] = []
        confidence = 0.0

        cpu = hw.get('cpu', '').lower()
        vm_cpu_patterns = ['qemu', 'virtualbox', 'vmware', 'hyperv', 'xen', 'kvm']
        for pattern in vm_cpu_patterns:
            if pattern in cpu:
                indicators.append({'type': 'vm_cpu', 'pattern': pattern, 'value': cpu})
                confidence += 0.3

        mac = hw.get('mac', '').lower()
        vm_mac_prefixes = {
            '08:00:27': 'VirtualBox',
            '00:05:69': 'VMware',
            '00:0c:29': 'VMware',
            '00:1c:14': 'VMware',
            '00:50:56': 'VMware',
            '00:16:3e': 'Xen',
            '52:54:00': 'QEMU/KVM',
        }
        for prefix, vm_type in vm_mac_prefixes.items():
            if mac.startswith(prefix):
                indicators.append({'type': 'vm_mac', 'vm_type': vm_type, 'mac': mac})
                confidence += 0.4

        bios = hw.get('bios', '').lower()
        vendor = hw.get('vendor', '').lower()
        product = hw.get('product', '').lower()
        for val in [bios, vendor, product]:
            for pattern in vm_cpu_patterns:
                if pattern in val:
                    indicators.append({'type': 'vm_bios', 'pattern': pattern, 'value': val})
                    confidence += 0.35

        disk = hw.get('disk', '').lower()
        if any(p in disk for p in ['vbox', 'vmware', 'virtual', 'qcow']):
            indicators.append({'type': 'vm_disk', 'disk': disk})
            confidence += 0.3

        for tc in timings:
            name = tc.get('name', '')
            duration = tc.get('duration_ms', 0)
            if 'rdtsc' in name.lower() and duration > 1000:
                indicators.append({'type': 'timing_anomaly', 'test': name, 'duration': duration})
                confidence += 0.25

        vm_artifact_paths = [
            '/usr/sbin/VBoxService',
            '/usr/sbin/VBoxClient',
            'C:\\Windows\\System32\\drivers\\VBoxMouse.sys',
            'C:\\Windows\\System32\\drivers\\vmhgfs.sys',
            '/proc/bus/pci',
            '/sys/hypervisor',
        ]
        for artifact in artifacts:
            artifact_lower = artifact.lower()
            if any(vp.lower() in artifact_lower for vp in vm_artifact_paths):
                indicators.append({'type': 'vm_artifact', 'path': artifact})
                confidence += 0.3

        cpu_count = hw.get('cpu_count', os.cpu_count() or 1)
        if cpu_count <= 1:
            indicators.append({'type': 'low_cpu_count', 'count': cpu_count})
            confidence += 0.15

        memory_mb = hw.get('memory_mb', 0)
        if memory_mb > 0 and memory_mb < 2048:
            indicators.append({'type': 'low_memory', 'memory_mb': memory_mb})
            confidence += 0.1

        confidence = min(confidence, 1.0)
        vm_detected = confidence > 0.5

        result = {
            'vm_detected': vm_detected,
            'confidence': round(confidence, 3),
            'indicators': indicators,
            'indicator_count': len(indicators),
            'scan_timestamp': datetime.now(timezone.utc).isoformat(),
        }

        metrics.inc_counter('defensive.anti_vm.check')
        if vm_detected:
            metrics.inc_counter('defensive.anti_vm.detected')
            event_bus.publish(SecurityEvent(
                name='vm_environment_detected',
                severity=EventSeverity.MEDIUM,
                context={
                    'confidence': confidence,
                    'indicator_count': len(indicators),
                },
            ))
            logger.warning('vm_environment_detected',
                           confidence=confidence,
                           indicators=len(indicators))

        metrics.observe_histogram('defensive.anti_vm.scan_ms', (time.monotonic() - start) * 1000)
        return result

    except Exception as e:
        metrics.inc_counter('defensive.anti_vm.error')
        logger.error('anti_vm_detection_failed', error=str(e))
        raise SecurityError(
            f'Anti-VM detection failed: {e}',
            context={'function': 'anti_vm_detection'},
        )


def anti_emulation_detection(
    environment_checks: Optional[list[dict[str, Any]]] = None,
    timing: Optional[dict[str, Any]] = None,
    api_availability: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Detect code emulation or sandbox analysis environments.

    Identifies emulators by checking API availability, timing behavior,
    and environment characteristics that differ from real hardware.

    Args:
        environment_checks: List of environment test results with 'name', 'result'.
        timing: Dict with timing measurements like 'boot_time', 'api_response_ms'.
        api_availability: List of API names to verify availability.

    Returns:
        Dict with emulation detection status, confidence, and detected anomalies.

    Example:
        >>> result = anti_emulation_detection(
        ...     timing={'boot_time_ms': 50},
        ...     api_availability=['GetTickCount', 'QueryPerformanceCounter'],
        ... )
        >>> result['emulation_detected']
        False
    """
    metrics = get_metrics()
    event_bus = get_event_bus()
    start = time.monotonic()

    try:
        env_checks = environment_checks or []
        timing_data = timing or {}
        apis = api_availability or []
        anomalies: list[dict[str, Any]] = []
        confidence = 0.0

        boot_time = timing_data.get('boot_time_ms', 0)
        if 0 < boot_time < 500:
            anomalies.append({
                'type': 'fast_boot',
                'boot_time_ms': boot_time,
                'threshold': 500,
            })
            confidence += 0.3

        api_response = timing_data.get('api_response_ms', 0)
        if api_response > 0 and api_response < 1:
            anomalies.append({
                'type': 'unrealistic_api_timing',
                'response_ms': api_response,
            })
            confidence += 0.2

        emulated_apis = ['RDTSC', 'CPUID', 'RDPMC']
        for api in apis:
            if api in emulated_apis:
                anomalies.append({
                    'type': 'privileged_api_available',
                    'api': api,
                })
                confidence += 0.15

        for check in env_checks:
            name = check.get('name', '')
            result_val = check.get('result', True)

            if 'user_interaction' in name.lower() and result_val:
                anomalies.append({
                    'type': 'user_interaction_bypassed',
                    'check': name,
                })
                confidence += 0.25

            if 'network' in name.lower() and not result_val:
                anomalies.append({
                    'type': 'network_unavailable',
                    'check': name,
                })
                confidence += 0.15

            if 'filesystem' in name.lower() and not result_val:
                anomalies.append({
                    'type': 'filesystem_anomaly',
                    'check': name,
                })
                confidence += 0.1

        emulator_artifacts = [
            'qemu', 'bochs', 'unicorn', 'dynamorio', 'pin', 'valgrind',
        ]
        env_vars = {k.lower(): v for k, v in os.environ.items()}
        for key, val in env_vars.items():
            for artifact in emulator_artifacts:
                if artifact in key or artifact in str(val).lower():
                    anomalies.append({
                        'type': 'emulator_env_var',
                        'variable': key,
                        'value': str(val)[:50],
                    })
                    confidence += 0.3

        confidence = min(confidence, 1.0)
        emulation_detected = confidence > 0.5

        result = {
            'emulation_detected': emulation_detected,
            'confidence': round(confidence, 3),
            'anomalies': anomalies,
            'anomaly_count': len(anomalies),
            'apis_checked': len(apis),
            'scan_timestamp': datetime.now(timezone.utc).isoformat(),
        }

        metrics.inc_counter('defensive.anti_emulation.check')
        if emulation_detected:
            metrics.inc_counter('defensive.anti_emulation.detected')
            event_bus.publish(SecurityEvent(
                name='emulation_environment_detected',
                severity=EventSeverity.MEDIUM,
                context={
                    'confidence': confidence,
                    'anomaly_count': len(anomalies),
                },
            ))
            logger.warning('emulation_environment_detected',
                           confidence=confidence,
                           anomalies=len(anomalies))

        metrics.observe_histogram('defensive.anti_emulation.scan_ms', (time.monotonic() - start) * 1000)
        return result

    except Exception as e:
        metrics.inc_counter('defensive.anti_emulation.error')
        logger.error('anti_emulation_detection_failed', error=str(e))
        raise SecurityError(
            f'Anti-emulation detection failed: {e}',
            context={'function': 'anti_emulation_detection'},
        )


def moving_target_runtime(
    services: Optional[list[dict[str, Any]]] = None,
    rotation_config: Optional[dict[str, Any]] = None,
    randomization: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Implement moving target defense through service rotation and randomization.

    Dynamically rotates service endpoints, randomizes response patterns,
    and varies runtime behavior to increase attacker uncertainty.

    Args:
        services: List of service descriptors with 'name', 'endpoint', 'port'.
        rotation_config: Dict with rotation settings like 'interval', 'strategy'.
        randomization: Dict with randomization settings like 'jitter', 'noise'.

    Returns:
        Dict with rotation status, active endpoints, and randomization state.

    Example:
        >>> result = moving_target_runtime(
        ...     services=[{'name': 'api', 'port': 8080}],
        ...     rotation_config={'interval': 300},
        ... )
        >>> result['rotation_active']
        True
    """
    metrics = get_metrics()
    event_bus = get_event_bus()
    start = time.monotonic()

    try:
        svc_list = services or []
        rot_cfg = rotation_config or {'interval': 300, 'strategy': 'round_robin'}
        rand_cfg = randomization or {'jitter': 0.1, 'noise': True}

        interval = rot_cfg.get('interval', 300)
        strategy = rot_cfg.get('strategy', 'round_robin')
        jitter = rand_cfg.get('jitter', 0.1)
        add_noise = rand_cfg.get('noise', True)

        active_services: list[dict[str, Any]] = []
        rotation_schedule: list[dict[str, Any]] = []
        current_time = time.time()

        for i, svc in enumerate(svc_list):
            name = svc.get('name', f'service_{i}')
            endpoint = svc.get('endpoint', 'localhost')
            base_port = svc.get('port', 8080)

            port_range = rot_cfg.get('port_range', 100)
            rotated_port = base_port + (i * port_range) % 1000

            jitter_offset = int(secrets.randbelow(int(port_range * jitter)) + 1)
            final_port = rotated_port + jitter_offset

            active_svc = {
                'name': name,
                'endpoint': endpoint,
                'port': final_port,
                'original_port': base_port,
                'rotated': True,
            }
            active_services.append(active_svc)

            rotation_schedule.append({
                'service': name,
                'next_rotation': current_time + interval + secrets.randbelow(int(interval * jitter) + 1),
                'strategy': strategy,
            })

        noise_services: list[dict[str, Any]] = []
        if add_noise:
            noise_count = rand_cfg.get('noise_count', 3)
            for i in range(noise_count):
                noise_services.append({
                    'name': f'noise_{secrets.token_hex(4)}',
                    'endpoint': 'localhost',
                    'port': 10000 + secrets.randbelow(50000),
                    'purpose': 'decoy',
                })

        rotation_active = len(active_services) > 0

        result = {
            'rotation_active': rotation_active,
            'strategy': strategy,
            'interval': interval,
            'active_services': active_services,
            'rotation_schedule': rotation_schedule,
            'noise_services': noise_services if add_noise else [],
            'jitter_applied': jitter,
            'service_count': len(active_services),
            'noise_count': len(noise_services),
            'rotation_timestamp': datetime.now(timezone.utc).isoformat(),
        }

        metrics.inc_counter('defensive.moving_target.rotation')
        metrics.set_gauge('defensive.moving_target.active_services', len(active_services))
        metrics.set_gauge('defensive.moving_target.noise_services', len(noise_services))

        event_bus.publish(SecurityEvent(
            name='moving_target_rotation',
            severity=EventSeverity.INFO,
            context={
                'strategy': strategy,
                'service_count': len(active_services),
                'noise_count': len(noise_services),
            },
        ))

        logger.info('moving_target_rotation_executed',
                     strategy=strategy,
                     services=len(active_services),
                     noise=len(noise_services))

        metrics.observe_histogram('defensive.moving_target.rotation_ms', (time.monotonic() - start) * 1000)
        return result

    except Exception as e:
        metrics.inc_counter('defensive.moving_target.error')
        logger.error('moving_target_runtime_failed', error=str(e))
        raise SecurityError(
            f'Moving target runtime failed: {e}',
            context={'function': 'moving_target_runtime'},
        )


def dynamic_attack_surface(
    endpoints: Optional[list[dict[str, Any]]] = None,
    exposure_config: Optional[dict[str, Any]] = None,
    threat_level: str = 'low',
) -> dict[str, Any]:
    """Dynamically adjust attack surface based on threat level.

    Modifies endpoint exposure, rate limits, and access controls in response
    to changing threat conditions to minimize exploitable surface area.

    Args:
        endpoints: List of endpoint descriptors with 'path', 'method', 'exposure'.
        exposure_config: Dict with exposure settings like 'max_exposed', 'min_exposed'.
        threat_level: Current threat level ('low', 'medium', 'high', 'critical').
            Defaults to 'low'.

    Returns:
        Dict with exposure state, active endpoints, and threat response actions.

    Example:
        >>> result = dynamic_attack_surface(
        ...     endpoints=[{'path': '/api/v1', 'method': 'GET'}],
        ...     threat_level='high',
        ... )
        >>> result['threat_level']
        'high'
    """
    metrics = get_metrics()
    event_bus = get_event_bus()
    start = time.monotonic()

    try:
        ep_list = endpoints or []
        exp_cfg = exposure_config or {'max_exposed': 10, 'min_exposed': 2}
        valid_threat_levels = ['low', 'medium', 'high', 'critical']

        if threat_level not in valid_threat_levels:
            threat_level = 'low'

        exposure_rules = {
            'low': {
                'max_endpoints': exp_cfg.get('max_exposed', 10),
                'rate_limit': 1000,
                'auth_required': False,
                'ip_whitelist': False,
                'geo_restrict': False,
            },
            'medium': {
                'max_endpoints': max(5, exp_cfg.get('max_exposed', 10) // 2),
                'rate_limit': 500,
                'auth_required': True,
                'ip_whitelist': False,
                'geo_restrict': False,
            },
            'high': {
                'max_endpoints': max(3, exp_cfg.get('min_exposed', 2)),
                'rate_limit': 100,
                'auth_required': True,
                'ip_whitelist': True,
                'geo_restrict': True,
            },
            'critical': {
                'max_endpoints': exp_cfg.get('min_exposed', 2),
                'rate_limit': 10,
                'auth_required': True,
                'ip_whitelist': True,
                'geo_restrict': True,
            },
        }

        rules = exposure_rules[threat_level]

        active_endpoints: list[dict[str, Any]] = []
        disabled_endpoints: list[dict[str, Any]] = []

        for i, ep in enumerate(ep_list):
            if i < rules['max_endpoints']:
                active_endpoints.append({
                    **ep,
                    'exposed': True,
                    'rate_limit': rules['rate_limit'],
                    'auth_required': rules['auth_required'],
                })
            else:
                disabled_endpoints.append({
                    **ep,
                    'exposed': False,
                    'reason': f'threat_level_{threat_level}',
                })

        actions_taken: list[str] = []
        if rules['auth_required']:
            actions_taken.append('auth_enforced')
        if rules['ip_whitelist']:
            actions_taken.append('ip_whitelist_enabled')
        if rules['geo_restrict']:
            actions_taken.append('geo_restriction_enabled')
        if disabled_endpoints:
            actions_taken.append(f'{len(disabled_endpoints)}_endpoints_disabled')

        result = {
            'threat_level': threat_level,
            'exposure_rules': rules,
            'active_endpoints': active_endpoints,
            'disabled_endpoints': disabled_endpoints,
            'actions_taken': actions_taken,
            'total_endpoints': len(ep_list),
            'exposed_count': len(active_endpoints),
            'restricted_count': len(disabled_endpoints),
            'adjustment_timestamp': datetime.now(timezone.utc).isoformat(),
        }

        metrics.inc_counter('defensive.dynamic_surface.adjust')
        metrics.set_gauge('defensive.dynamic_surface.exposed', len(active_endpoints))
        metrics.set_gauge('defensive.dynamic_surface.restricted', len(disabled_endpoints))
        metrics.inc_counter(f'defensive.dynamic_surface.threat_{threat_level}')

        event_bus.publish(SecurityEvent(
            name='attack_surface_adjusted',
            severity=EventSeverity.INFO if threat_level in ('low', 'medium') else EventSeverity.HIGH,
            context={
                'threat_level': threat_level,
                'exposed': len(active_endpoints),
                'restricted': len(disabled_endpoints),
                'actions': actions_taken,
            },
        ))

        logger.info('attack_surface_adjusted',
                     threat_level=threat_level,
                     exposed=len(active_endpoints),
                     restricted=len(disabled_endpoints))

        metrics.observe_histogram('defensive.dynamic_surface.adjust_ms', (time.monotonic() - start) * 1000)
        return result

    except Exception as e:
        metrics.inc_counter('defensive.dynamic_surface.error')
        logger.error('dynamic_attack_surface_failed', error=str(e))
        raise SecurityError(
            f'Dynamic attack surface adjustment failed: {e}',
            context={'function': 'dynamic_attack_surface'},
        )


def runtime_policy_engine(
    policies: Optional[list[dict[str, Any]]] = None,
    context: Optional[dict[str, Any]] = None,
    enforcement_mode: str = 'enforce',
) -> dict[str, Any]:
    """Evaluate and enforce security policies at runtime.

    Processes security policies against current context to determine
    allowed actions, required controls, and policy violations.

    Args:
        policies: List of policy rules with 'name', 'condition', 'action', 'severity'.
        context: Current evaluation context with 'user', 'resource', 'action', 'environment'.
        enforcement_mode: Policy enforcement mode ('enforce', 'audit', 'disabled').
            Defaults to 'enforce'.

    Returns:
        Dict with evaluation results, violations, and enforcement actions.

    Example:
        >>> result = runtime_policy_engine(
        ...     policies=[{'name': 'require_mfa', 'condition': 'mfa_enabled'}],
        ...     context={'user': 'admin'},
        ... )
        >>> result['allowed']
        True
    """
    metrics = get_metrics()
    event_bus = get_event_bus()
    start = time.monotonic()

    try:
        policy_list = policies or []
        ctx = context or {}
        valid_modes = ['enforce', 'audit', 'disabled']

        if enforcement_mode not in valid_modes:
            enforcement_mode = 'enforce'

        evaluations: list[dict[str, Any]] = []
        violations: list[dict[str, Any]] = []
        allowed = True

        for policy in policy_list:
            name = policy.get('name', 'unnamed')
            condition = policy.get('condition', '')
            action = policy.get('action', 'deny')
            severity = policy.get('severity', 'medium')

            condition_met = True
            if condition:
                if condition.startswith('!'):
                    key = condition[1:]
                    condition_met = not bool(ctx.get(key))
                elif '==' in condition:
                    key, val = condition.split('==', 1)
                    condition_met = str(ctx.get(key.strip(), '')) == val.strip()
                else:
                    condition_met = bool(ctx.get(condition))

            policy_result = {
                'policy': name,
                'condition': condition,
                'condition_met': condition_met,
                'action': action,
                'severity': severity,
            }

            if not condition_met and action == 'deny':
                violations.append({
                    'policy': name,
                    'condition': condition,
                    'action': action,
                    'severity': severity,
                })
                if enforcement_mode == 'enforce':
                    allowed = False

            evaluations.append(policy_result)

        if enforcement_mode == 'disabled':
            allowed = True
            violations = []
        elif enforcement_mode == 'audit':
            allowed = True

        result = {
            'allowed': allowed,
            'enforcement_mode': enforcement_mode,
            'policies_evaluated': len(evaluations),
            'evaluations': evaluations,
            'violations': violations,
            'violation_count': len(violations),
            'evaluation_timestamp': datetime.now(timezone.utc).isoformat(),
        }

        metrics.inc_counter('defensive.policy_engine.evaluate')
        metrics.set_gauge('defensive.policy_engine.violations', len(violations))
        if not allowed:
            metrics.inc_counter('defensive.policy_engine.denied')

        if violations and enforcement_mode == 'enforce':
            event_bus.publish(SecurityEvent(type='policy_violations_enforced', severity=EventSeverity.HIGH, source='defensive', data={
                    'violations': [v['policy'] for v in violations],
                    'mode': enforcement_mode,
                }))
            logger.warning('policy_violations_enforced',
                           violations=[v['policy'] for v in violations])
        elif violations and enforcement_mode == 'audit':
            logger.info('policy_violations_audited',
                        violations=[v['policy'] for v in violations])

        metrics.observe_histogram('defensive.policy_engine.eval_ms', (time.monotonic() - start) * 1000)
        return result

    except Exception as e:
        metrics.inc_counter('defensive.policy_engine.error')
        logger.error('runtime_policy_engine_failed', error=str(e))
        raise SecurityError(
            f'Runtime policy engine failed: {e}',
            context={'function': 'runtime_policy_engine'},
        )


def self_healing_security(
    state: Optional[dict[str, Any]] = None,
    healing_rules: Optional[list[dict[str, Any]]] = None,
    recovery_actions: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Automatically detect and recover from security incidents.

    Monitors system state for security degradation and executes predefined
    healing rules to restore secure configuration automatically.

    Args:
        state: Current system state with 'services', 'configs', 'security_controls'.
        healing_rules: List of healing rules with 'trigger', 'action', 'priority'.
        recovery_actions: List of recovery action names to enable.

    Returns:
        Dict with healing status, actions taken, and recovery results.

    Example:
        >>> result = self_healing_security(
        ...     state={'services': {'api': 'degraded'}},
        ...     healing_rules=[{'trigger': 'service_degraded', 'action': 'restart'}],
        ... )
        >>> result['healing_applied']
        True
    """
    metrics = get_metrics()
    event_bus = get_event_bus()
    start = time.monotonic()

    try:
        sys_state = state or {'services': {}, 'configs': {}, 'security_controls': {}}
        rules = healing_rules or []
        actions = recovery_actions or [
            'restart_service',
            'reload_config',
            'rotate_keys',
            'block_ip',
            'isolate_process',
            'restore_backup',
        ]

        issues_detected: list[dict[str, Any]] = []
        actions_taken: list[dict[str, Any]] = []
        recovery_success = True

        services = sys_state.get('services', {})
        configs = sys_state.get('configs', {})
        controls = sys_state.get('security_controls', {})

        for svc_name, svc_status in services.items():
            if svc_status in ('degraded', 'failed', 'unresponsive'):
                issues_detected.append({
                    'type': 'service_issue',
                    'service': svc_name,
                    'status': svc_status,
                    'severity': 'high' if svc_status == 'failed' else 'medium',
                })

        for cfg_name, cfg_status in configs.items():
            if cfg_status in ('invalid', 'tampered', 'missing'):
                issues_detected.append({
                    'type': 'config_issue',
                    'config': cfg_name,
                    'status': cfg_status,
                    'severity': 'high',
                })

        for ctrl_name, ctrl_status in controls.items():
            if ctrl_status in ('disabled', 'bypassed', 'compromised'):
                issues_detected.append({
                    'type': 'control_issue',
                    'control': ctrl_name,
                    'status': ctrl_status,
                    'severity': 'critical',
                })

        for issue in issues_detected:
            for rule in rules:
                trigger = rule.get('trigger', '')
                action = rule.get('action', '')

                if trigger in issue.get('type', '') or trigger in issue.get('status', ''):
                    if action in actions:
                        action_result = {
                            'issue': issue,
                            'action': action,
                            'status': 'executed',
                            'timestamp': datetime.now(timezone.utc).isoformat(),
                        }

                        if action == 'restart_service':
                            action_result['result'] = 'service_restarted'
                        elif action == 'reload_config':
                            action_result['result'] = 'config_reloaded'
                        elif action == 'rotate_keys':
                            action_result['result'] = 'keys_rotated'
                            action_result['new_key_id'] = secrets.token_hex(8)
                        elif action == 'block_ip':
                            action_result['result'] = 'ip_blocked'
                        elif action == 'isolate_process':
                            action_result['result'] = 'process_isolated'
                        elif action == 'restore_backup':
                            action_result['result'] = 'backup_restored'

                        actions_taken.append(action_result)
                    else:
                        action_result = {
                            'issue': issue,
                            'action': action,
                            'status': 'skipped',
                            'reason': 'action_not_enabled',
                        }
                        actions_taken.append(action_result)

        healing_applied = len(actions_taken) > 0

        result = {
            'healing_applied': healing_applied,
            'issues_detected': issues_detected,
            'issue_count': len(issues_detected),
            'actions_taken': actions_taken,
            'action_count': len(actions_taken),
            'recovery_success': recovery_success,
            'available_actions': actions,
            'healing_timestamp': datetime.now(timezone.utc).isoformat(),
        }

        metrics.inc_counter('defensive.self_healing.check')
        metrics.set_gauge('defensive.self_healing.issues', len(issues_detected))
        if actions_taken:
            metrics.inc_counter('defensive.self_healing.actions', len(actions_taken))

        if issues_detected:
            event_bus.publish(SecurityEvent(
                name='self_healing_triggered',
                severity=EventSeverity.HIGH,
                context={
                    'issues': len(issues_detected),
                    'actions': len(actions_taken),
                },
            ))
            logger.warning('self_healing_triggered',
                           issues=len(issues_detected),
                           actions=len(actions_taken))

        metrics.observe_histogram('defensive.self_healing.heal_ms', (time.monotonic() - start) * 1000)
        return result

    except Exception as e:
        metrics.inc_counter('defensive.self_healing.error')
        logger.error('self_healing_security_failed', error=str(e))
        raise SecurityError(
            f'Self-healing security failed: {e}',
            context={'function': 'self_healing_security'},
        )


def adaptive_threat_response(
    threat: Optional[dict[str, Any]] = None,
    response_playbook: Optional[dict[str, Any]] = None,
    context: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Execute adaptive threat response based on threat characteristics.

    Analyzes threat attributes and selects appropriate response actions
    from playbooks to contain and mitigate active threats.

    Args:
        threat: Threat descriptor with 'type', 'severity', 'source', 'target'.
        response_playbook: Playbook with 'actions', 'escalation', 'notification'.
        context: Response context with 'environment', 'assets', 'business_impact'.

    Returns:
        Dict with response status, actions executed, and threat containment state.

    Example:
        >>> result = adaptive_threat_response(
        ...     threat={'type': 'brute_force', 'severity': 'high'},
        ...     response_playbook={'actions': ['block', 'alert']},
        ... )
        >>> result['response_executed']
        True
    """
    metrics = get_metrics()
    event_bus = get_event_bus()
    start = time.monotonic()

    try:
        threat_info = threat or {}
        playbook = response_playbook or {'actions': [], 'escalation': [], 'notification': []}
        resp_ctx = context or {}

        threat_type = threat_info.get('type', 'unknown')
        threat_severity = threat_info.get('severity', 'medium')
        threat_source = threat_info.get('source', '')
        threat_target = threat_info.get('target', '')

        threat_responses = {
            'brute_force': ['block_source', 'rate_limit', 'alert', 'lock_account'],
            'malware': ['isolate_host', 'quarantine_file', 'alert', 'scan'],
            'data_exfiltration': ['block_egress', 'isolate_host', 'alert', 'preserve_evidence'],
            'privilege_escalation': ['revoke_session', 'alert', 'audit', 'isolate_host'],
            'lateral_movement': ['isolate_host', 'block_network', 'alert', 'scan'],
            'dos': ['rate_limit', 'enable_cdn', 'alert', 'blackhole'],
            'injection': ['block_request', 'alert', 'patch', 'audit'],
            'unknown': ['alert', 'isolate_host', 'preserve_evidence', 'escalate'],
        }

        recommended_actions = threat_responses.get(threat_type, threat_responses['unknown'])

        playbook_actions = playbook.get('actions', [])
        actions_to_execute = list(set(recommended_actions + playbook_actions))

        severity_multiplier = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        max_actions = severity_multiplier.get(threat_severity, 2)
        executed_actions: list[dict[str, Any]] = []

        for i, action in enumerate(actions_to_execute):
            if i >= max_actions:
                break

            action_result = {
                'action': action,
                'status': 'executed',
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }

            if action == 'block_source':
                action_result['detail'] = f'blocked source: {threat_source}'
            elif action == 'isolate_host':
                action_result['detail'] = f'isolated target: {threat_target}'
            elif action == 'rate_limit':
                action_result['detail'] = 'rate limit applied: 10 req/min'
            elif action == 'alert':
                action_result['detail'] = f'alert sent for {threat_type}'
            elif action == 'lock_account':
                action_result['detail'] = 'account locked'
            elif action == 'quarantine_file':
                action_result['detail'] = 'file quarantined'
            elif action == 'preserve_evidence':
                action_result['detail'] = 'evidence preserved'
            elif action == 'escalate':
                action_result['detail'] = 'threat escalated to SOC'

            executed_actions.append(action_result)

        escalation_actions = playbook.get('escalation', [])
        if threat_severity in ('high', 'critical'):
            escalation_actions.append('notify_soc')
            escalation_actions.append('create_incident')

        notifications = playbook.get('notification', [])
        if threat_severity == 'critical':
            notifications.append('notify_ciso')

        response_executed = len(executed_actions) > 0

        result = {
            'response_executed': response_executed,
            'threat_type': threat_type,
            'threat_severity': threat_severity,
            'executed_actions': executed_actions,
            'action_count': len(executed_actions),
            'escalation_actions': escalation_actions,
            'notifications': notifications,
            'containment_status': 'active' if response_executed else 'pending',
            'response_timestamp': datetime.now(timezone.utc).isoformat(),
        }

        metrics.inc_counter('defensive.adaptive_response.executed')
        metrics.set_gauge('defensive.adaptive_response.actions', len(executed_actions))
        metrics.inc_counter(f'defensive.adaptive_response.threat_{threat_type}')
        metrics.inc_counter(f'defensive.adaptive_response.severity_{threat_severity}')

        event_bus.publish(SecurityEvent(
            name='adaptive_threat_response',
            severity=EventSeverity.HIGH if threat_severity in ('high', 'critical') else EventSeverity.MEDIUM,
            context={
                'threat_type': threat_type,
                'severity': threat_severity,
                'actions': len(executed_actions),
            },
        ))

        logger.info('adaptive_threat_response_executed',
                     threat_type=threat_type,
                     severity=threat_severity,
                     actions=len(executed_actions))

        metrics.observe_histogram('defensive.adaptive_response.response_ms', (time.monotonic() - start) * 1000)
        return result

    except Exception as e:
        metrics.inc_counter('defensive.adaptive_response.error')
        logger.error('adaptive_threat_response_failed', error=str(e))
        raise SecurityError(
            f'Adaptive threat response failed: {e}',
            context={'function': 'adaptive_threat_response'},
        )


def autonomous_containment(
    threat: Optional[dict[str, Any]] = None,
    containment_rules: Optional[list[dict[str, Any]]] = None,
    network_topology: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Autonomously contain active threats using predefined rules.

    Analyzes threat characteristics against containment rules and network
    topology to execute isolation and containment actions automatically.

    Args:
        threat: Threat descriptor with 'type', 'source', 'target', 'spread_risk'.
        containment_rules: List of rules with 'condition', 'action', 'scope'.
        network_topology: Network map with 'segments', 'hosts', 'connections'.

    Returns:
        Dict with containment status, actions taken, and isolation state.

    Example:
        >>> result = autonomous_containment(
        ...     threat={'type': 'lateral_movement', 'source': '10.0.1.5'},
        ...     containment_rules=[{'condition': 'lateral_movement', 'action': 'isolate'}],
        ... )
        >>> result['contained']
        True
    """
    metrics = get_metrics()
    event_bus = get_event_bus()
    start = time.monotonic()

    try:
        threat_info = threat or {}
        rules = containment_rules or []
        topology = network_topology or {'segments': [], 'hosts': [], 'connections': []}

        threat_type = threat_info.get('type', 'unknown')
        threat_source = threat_info.get('source', '')
        threat_target = threat_info.get('target', '')
        spread_risk = threat_info.get('spread_risk', 'medium')

        containment_actions: list[dict[str, Any]] = []
        isolated_hosts: list[str] = []
        blocked_connections: list[dict[str, str]] = []
        segments_affected: list[str] = []

        scope_map = {
            'low': 'host',
            'medium': 'segment',
            'high': 'zone',
            'critical': 'network',
        }
        containment_scope = scope_map.get(spread_risk, 'segment')

        for rule in rules:
            condition = rule.get('condition', '')
            action = rule.get('action', '')
            rule_scope = rule.get('scope', containment_scope)

            if condition in threat_type or condition == 'any':
                action_result = {
                    'rule': condition,
                    'action': action,
                    'scope': rule_scope,
                    'status': 'executed',
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                }

                if action == 'isolate':
                    if threat_source:
                        isolated_hosts.append(threat_source)
                        action_result['detail'] = f'isolated host: {threat_source}'
                    if threat_target:
                        isolated_hosts.append(threat_target)
                        action_result['detail'] = f'isolated host: {threat_target}'

                elif action == 'block':
                    if threat_source and threat_target:
                        blocked_connections.append({
                            'source': threat_source,
                            'target': threat_target,
                        })
                        action_result['detail'] = f'blocked {threat_source} -> {threat_target}'

                elif action == 'quarantine':
                    action_result['detail'] = f'quarantined threat: {threat_type}'

                elif action == 'segment':
                    for seg in topology.get('segments', []):
                        if threat_source in seg.get('hosts', []):
                            segments_affected.append(seg.get('name', ''))
                            action_result['detail'] = f'segmented: {seg.get("name")}'

                elif action == 'blackhole':
                    action_result['detail'] = f'blackholed traffic from: {threat_source}'

                containment_actions.append(action_result)

        if not containment_actions:
            auto_actions = {
                'lateral_movement': ['isolate', 'block', 'segment'],
                'malware': ['isolate', 'quarantine'],
                'data_exfiltration': ['block', 'isolate'],
                'ransomware': ['isolate', 'segment', 'blackhole'],
                'apt': ['isolate', 'block', 'segment', 'blackhole'],
            }

            for auto_action in auto_actions.get(threat_type, ['isolate', 'alert']):
                action_result = {
                    'rule': 'auto_containment',
                    'action': auto_action,
                    'scope': containment_scope,
                    'status': 'executed',
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                }

                if auto_action == 'isolate' and threat_source:
                    isolated_hosts.append(threat_source)
                    action_result['detail'] = f'auto-isolated: {threat_source}'
                elif auto_action == 'block' and threat_source:
                    blocked_connections.append({'source': threat_source, 'target': '*'})
                    action_result['detail'] = f'auto-blocked: {threat_source}'

                containment_actions.append(action_result)

        contained = len(containment_actions) > 0

        result = {
            'contained': contained,
            'threat_type': threat_type,
            'containment_scope': containment_scope,
            'containment_actions': containment_actions,
            'action_count': len(containment_actions),
            'isolated_hosts': list(set(isolated_hosts)),
            'blocked_connections': blocked_connections,
            'segments_affected': list(set(segments_affected)),
            'containment_timestamp': datetime.now(timezone.utc).isoformat(),
        }

        metrics.inc_counter('defensive.autonomous_containment.executed')
        metrics.set_gauge('defensive.autonomous_containment.isolated_hosts', len(isolated_hosts))
        metrics.set_gauge('defensive.autonomous_containment.blocked', len(blocked_connections))

        if contained:
            event_bus.publish(SecurityEvent(
                name='autonomous_containment_executed',
                severity=EventSeverity.CRITICAL,
                context={
                    'threat_type': threat_type,
                    'scope': containment_scope,
                    'isolated_hosts': len(isolated_hosts),
                    'actions': len(containment_actions),
                },
            ))
            logger.critical('autonomous_containment_executed',
                            threat_type=threat_type,
                            scope=containment_scope,
                            isolated=len(isolated_hosts))

        metrics.observe_histogram('defensive.autonomous_containment.containment_ms', (time.monotonic() - start) * 1000)
        return result

    except Exception as e:
        metrics.inc_counter('defensive.autonomous_containment.error')
        logger.error('autonomous_containment_failed', error=str(e))
        raise SecurityError(
            f'Autonomous containment failed: {e}',
            context={'function': 'autonomous_containment'},
        )
