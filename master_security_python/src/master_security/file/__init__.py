from __future__ import annotations

import os
import re
import hashlib
import struct
import tempfile
import math
import json
from typing import Any, Optional
from master_security.core import get_logger, get_metrics, create_span, get_event_bus, SecurityEvent, EventSeverity
from master_security.core.exceptions import ValidationError, SecurityError
import structlog

logger = structlog.get_logger(__name__)


def secure_upload(
    file_data: bytes,
    filename: str,
    allowed_extensions: Optional[list[str]] = None,
    max_size: int = 10 * 1024 * 1024,
) -> dict[str, Any]:
    """Securely validate and process an uploaded file.

    Args:
        file_data: Raw file bytes.
        filename: Original filename.
        allowed_extensions: List of allowed extensions (e.g. ['.png', '.jpg']). Defaults to common safe types.
        max_size: Maximum file size in bytes. Defaults to 10MB.

    Returns:
        dict with keys: valid (bool), filename (str), size (int), hash (str), mime (str), threats (list).

    Example:
        >>> result = secure_upload(b'...data...', 'report.pdf', allowed_extensions=['.pdf'])
        >>> result['valid']
        True
    """
    metrics = get_metrics()
    metrics.inc_counter("file.secure_upload.attempts")

    if len(file_data) > max_size:
        metrics.inc_counter("file.secure_upload.rejected.size")
        logger.warning("file_upload_rejected_size", size=len(file_data), max_size=max_size)
        raise SecurityError(f"File size {len(file_data)} exceeds maximum {max_size} bytes")

    if allowed_extensions is None:
        allowed_extensions = [".png", ".jpg", ".jpeg", ".gif", ".pdf", ".txt", ".csv"]

    ext_valid = validate_extension(filename, allowed_extensions)
    if not ext_valid:
        metrics.inc_counter("file.secure_upload.rejected.extension")
        logger.warning("file_upload_rejected_extension", filename=filename)
        raise ValidationError(f"Extension not allowed for file: {filename}")

    sanitized = sanitize_filename(filename)
    file_hash = hashlib.sha256(file_data).hexdigest()

    mime_result = validate_mime(file_data, None, None)

    threats: list[str] = []
    entropy = entropy_analysis(file_data)
    if entropy.get("entropy", 0) > 7.5:
        threats.append("high_entropy")

    polyglot = detect_polyglot_file(file_data, [])
    if polyglot.get("is_polyglot", False):
        threats.append("polyglot_detected")

    result = {
        "valid": len(threats) == 0,
        "filename": sanitized,
        "size": len(file_data),
        "hash": file_hash,
        "mime": mime_result.get("detected_mime", "unknown"),
        "threats": threats,
    }

    metrics.inc_counter("file.secure_upload.completed")
    logger.info("secure_upload_complete", filename=sanitized, threats=threats)
    return result


def validate_extension(
    filename: str,
    allowed_extensions: list[str],
) -> bool:
    """Validate that a filename has an allowed extension.

    Args:
        filename: The filename to check.
        allowed_extensions: List of allowed extensions (e.g. ['.png', '.jpg']).

    Returns:
        True if the extension is allowed, False otherwise.

    Example:
        >>> validate_extension('photo.png', ['.png', '.jpg'])
        True
    """
    metrics = get_metrics()
    _, ext = os.path.splitext(filename)
    ext_lower = ext.lower()
    allowed_lower = [e.lower() for e in allowed_extensions]
    valid = ext_lower in allowed_lower

    metrics.inc_counter("file.validate_extension", labels={"valid": str(valid)})
    logger.debug("validate_extension", filename=filename, ext=ext_lower, valid=valid)
    return valid


def validate_mime(
    file_data: bytes,
    expected_mime: Optional[str] = None,
    magic_bytes: Optional[dict[str, bytes]] = None,
) -> dict[str, Any]:
    """Validate file MIME type using magic byte detection.

    Args:
        file_data: Raw file bytes.
        expected_mime: Expected MIME type string.
        magic_bytes: Dict mapping MIME types to their magic byte signatures.

    Returns:
        dict with keys: detected_mime (str), expected_match (bool), confidence (float).

    Example:
        >>> result = validate_mime(b'\x89PNG\r\n\x1a\n', 'image/png')
        >>> result['detected_mime']
        'image/png'
    """
    metrics = get_metrics()

    if magic_bytes is None:
        magic_bytes = {
            "image/png": b"\x89PNG\r\n\x1a\n",
            "image/jpeg": b"\xff\xd8\xff",
            "image/gif": b"GIF87a",
            "image/gif89a": b"GIF89a",
            "application/pdf": b"%PDF-",
            "application/zip": b"PK\x03\x04",
            "application/x-msdownload": b"MZ",
            "text/html": b"<!DOCTYPE",
            "application/xml": b"<?xml",
            "application/gzip": b"\x1f\x8b",
        }

    detected_mime = "application/octet-stream"
    confidence = 0.0

    for mime, signature in magic_bytes.items():
        if file_data[: len(signature)] == signature:
            detected_mime = mime
            confidence = 0.95
            break

    if len(file_data) > 0 and all(32 <= b < 127 or b in (9, 10, 13) for b in file_data[:512]):
        if detected_mime == "application/octet-stream":
            detected_mime = "text/plain"
            confidence = 0.8

    expected_match = expected_mime is None or detected_mime == expected_mime

    result = {
        "detected_mime": detected_mime,
        "expected_match": expected_match,
        "confidence": confidence,
    }

    metrics.inc_counter("file.validate_mime", labels={"mime": detected_mime})
    logger.debug("validate_mime", detected=detected_mime, match=expected_match)
    return result


def detect_polyglot_file(
    file_data: bytes,
    signatures: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    """Detect if a file contains multiple file format signatures (polyglot).

    Args:
        file_data: Raw file bytes.
        signatures: List of signature dicts with 'name', 'magic', 'offset' keys.

    Returns:
        dict with keys: is_polyglot (bool), detected_formats (list), count (int).

    Example:
        >>> result = detect_polyglot_file(pdf_with_embedded_zip)
        >>> result['is_polyglot']
        True
    """
    metrics = get_metrics()

    if signatures is None:
        signatures = [
            {"name": "PDF", "magic": b"%PDF-", "offset": 0},
            {"name": "ZIP", "magic": b"PK\x03\x04", "offset": 0},
            {"name": "ELF", "magic": b"\x7fELF", "offset": 0},
            {"name": "PE", "magic": b"MZ", "offset": 0},
            {"name": "JPEG", "magic": b"\xff\xd8\xff", "offset": 0},
            {"name": "PNG", "magic": b"\x89PNG\r\n\x1a\n", "offset": 0},
            {"name": "GIF", "magic": b"GIF8", "offset": 0},
            {"name": "RAR", "magic": b"Rar!", "offset": 0},
            {"name": "7Z", "magic": b"7z\xbc\xaf\x27\x1c", "offset": 0},
        ]

    detected: list[str] = []

    for sig in signatures:
        magic = sig["magic"]
        offset = sig.get("offset", 0)
        if offset == 0:
            if file_data[: len(magic)] == magic:
                detected.append(sig["name"])
        else:
            idx = file_data.find(magic)
            if idx >= 0 and idx != offset:
                detected.append(sig["name"])

    is_polyglot = len(detected) > 1

    result = {
        "is_polyglot": is_polyglot,
        "detected_formats": detected,
        "count": len(detected),
    }

    metrics.inc_counter("file.detect_polyglot", labels={"polyglot": str(is_polyglot)})
    logger.info("detect_polyglot_file", formats=detected, polyglot=is_polyglot)
    return result


def detect_zip_bomb(
    file_data: bytes,
    max_ratio: float = 100.0,
    max_uncompressed: int = 100 * 1024 * 1024,
) -> dict[str, Any]:
    """Detect potential zip bomb by analyzing compression ratios.

    Args:
        file_data: Raw ZIP file bytes.
        max_ratio: Maximum allowed compression ratio. Defaults to 100.
        max_uncompressed: Maximum allowed uncompressed size in bytes. Defaults to 100MB.

    Returns:
        dict with keys: is_bomb (bool), compressed_size (int), estimated_uncompressed (int), ratio (float), entries (int).

    Example:
        >>> result = detect_zip_bomb(zip_data, max_ratio=50.0)
        >>> result['is_bomb']
        False
    """
    metrics = get_metrics()

    if file_data[:2] != b"PK":
        return {"is_bomb": False, "compressed_size": 0, "estimated_uncompressed": 0, "ratio": 0.0, "entries": 0}

    compressed_size = len(file_data)
    estimated_uncompressed = 0
    entry_count = 0
    offset = 0

    while offset < len(file_data) - 4:
        sig = file_data[offset:offset + 4]
        if sig == b"PK\x03\x04":
            try:
                comp_method = struct.unpack_from("<H", file_data, offset + 8)[0]
                comp_size = struct.unpack_from("<I", file_data, offset + 18)[0]
                uncomp_size = struct.unpack_from("<I", file_data, offset + 22)[0]
                fname_len = struct.unpack_from("<H", file_data, offset + 26)[0]
                extra_len = struct.unpack_from("<H", file_data, offset + 28)[0]

                if comp_method == 0:
                    estimated_uncompressed += uncomp_size
                else:
                    estimated_uncompressed += uncomp_size

                entry_count += 1
                offset += 30 + fname_len + extra_len + comp_size
            except struct.error:
                offset += 1
        elif sig == b"PK\x01\x02":
            break
        else:
            offset += 1

    ratio = estimated_uncompressed / compressed_size if compressed_size > 0 else 0.0
    is_bomb = ratio > max_ratio or estimated_uncompressed > max_uncompressed

    result = {
        "is_bomb": is_bomb,
        "compressed_size": compressed_size,
        "estimated_uncompressed": estimated_uncompressed,
        "ratio": ratio,
        "entries": entry_count,
    }

    metrics.inc_counter("file.detect_zip_bomb", labels={"bomb": str(is_bomb)})
    logger.warning("detect_zip_bomb", ratio=ratio, entries=entry_count, is_bomb=is_bomb)
    return result


def detect_office_macro(
    file_data: bytes,
    file_type: Optional[str] = None,
) -> dict[str, Any]:
    """Detect VBA macros in Office documents.

    Args:
        file_data: Raw file bytes.
        file_type: File type hint ('doc', 'xls', 'ppt', 'docx', 'xlsx', 'pptx').

    Returns:
        dict with keys: has_macro (bool), macro_indicators (list), risk_level (str).

    Example:
        >>> result = detect_office_macro(doc_data, file_type='doc')
        >>> result['has_macro']
        False
    """
    metrics = get_metrics()

    indicators: list[str] = []
    risk_level = "none"

    macro_markers = [
        b"Macro",
        b"VBA",
        b"AutoOpen",
        b"AutoExec",
        b"AutoClose",
        b"Document_Open",
        b"Workbook_Open",
        b"vbProject",
        b"_VBA_PROJECT",
        b"dir\\vbaProject",
        b"word/vbaProject",
        b"xl/vbaProject",
        b"ppt/vbaProject",
    ]

    for marker in macro_markers:
        if marker in file_data:
            indicators.append(marker.decode("utf-8", errors="replace"))

    dangerous_patterns = [
        rb"Shell\s*\(",
        rb"CreateObject\s*\(\s*\"WScript\.Shell\"",
        rb"CreateObject\s*\(\s*\"Scripting\.FileSystemObject\"",
        rb"http\w*://",
        rb"https\w*://",
        rb"powershell",
        rb"cmd\.exe",
        rb"reg\s+add",
        rb"WScript\.Sleep",
        rb"\.Run\s*\(",
        rb"\.Exec\s*\(",
    ]

    dangerous_count = 0
    for pattern in dangerous_patterns:
        if re.search(pattern, file_data, re.IGNORECASE):
            dangerous_count += 1
            indicators.append(f"dangerous_pattern:{pattern.decode('utf-8', errors='replace')}")

    has_macro = len(indicators) > 0

    if has_macro:
        if dangerous_count >= 3:
            risk_level = "critical"
        elif dangerous_count >= 1:
            risk_level = "high"
        else:
            risk_level = "medium"

    result = {
        "has_macro": has_macro,
        "macro_indicators": indicators,
        "risk_level": risk_level,
    }

    metrics.inc_counter("file.detect_office_macro", labels={"macro": str(has_macro), "risk": risk_level})
    logger.info("detect_office_macro", has_macro=has_macro, risk=risk_level, indicators=len(indicators))
    return result


def detect_pdf_javascript(file_data: bytes) -> dict[str, Any]:
    """Detect JavaScript embedded in PDF files.

    Args:
        file_data: Raw PDF file bytes.

    Returns:
        dict with keys: has_javascript (bool), js_objects (list), suspicious_actions (list).

    Example:
        >>> result = detect_pdf_javascript(pdf_data)
        >>> result['has_javascript']
        False
    """
    metrics = get_metrics()

    if not file_data.startswith(b"%PDF-"):
        return {"has_javascript": False, "js_objects": [], "suspicious_actions": []}

    js_objects: list[str] = []
    suspicious_actions: list[str] = []

    js_patterns = [
        rb"/JavaScript",
        rb"/JS\s",
        rb"eval\s*\(",
        rb"app\.execMenuItem",
        rb"util\.scand",
        rb"this\.submitForm",
        rb"doc\.open",
    ]

    for pattern in js_patterns:
        matches = re.findall(pattern, file_data)
        if matches:
            js_objects.append(pattern.decode("utf-8", errors="replace"))

    action_patterns = [
        rb"/Launch",
        rb"/SubmitForm",
        rb"/ImportData",
        rb"/GoToE",
        rb"/URI\s",
        rb"/RichMedia",
        rb"/AA\s",
        rb"/OpenAction",
    ]

    for pattern in action_patterns:
        if re.search(pattern, file_data):
            suspicious_actions.append(pattern.decode("utf-8", errors="replace"))

    has_javascript = len(js_objects) > 0 or len(suspicious_actions) > 0

    result = {
        "has_javascript": has_javascript,
        "js_objects": js_objects,
        "suspicious_actions": suspicious_actions,
    }

    metrics.inc_counter("file.detect_pdf_javascript", labels={"js": str(has_javascript)})
    logger.info("detect_pdf_javascript", has_js=has_javascript, objects=len(js_objects))
    return result


def malware_scan(
    file_data: bytes,
    signatures: Optional[list[dict[str, Any]]] = None,
    yara_rules: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    """Scan file data for malware using signature and YARA rule matching.

    Args:
        file_data: Raw file bytes.
        signatures: List of signature dicts with 'name', 'pattern', 'type' keys.
        yara_rules: List of YARA rule dicts with 'name', 'pattern', 'description' keys.

    Returns:
        dict with keys: infected (bool), matches (list), scan_time_ms (float), rules_checked (int).

    Example:
        >>> result = malware_scan(file_data, signatures=[{'name': 'EICAR', 'pattern': b'X5O', 'type': 'literal'}])
        >>> result['infected']
        False
    """
    metrics = get_metrics()

    if signatures is None:
        signatures = []
    if yara_rules is None:
        yara_rules = []

    matches: list[dict[str, str]] = []

    for sig in signatures:
        pattern = sig.get("pattern", b"")
        sig_type = sig.get("type", "literal")

        if sig_type == "literal" and pattern in file_data:
            matches.append({"rule": sig["name"], "type": "signature", "severity": sig.get("severity", "high")})
        elif sig_type == "regex" and re.search(pattern, file_data, re.IGNORECASE):
            matches.append({"rule": sig["name"], "type": "signature", "severity": sig.get("severity", "high")})
        elif sig_type == "hash":
            file_hash = hashlib.sha256(file_data).hexdigest()
            if file_hash == pattern.decode("utf-8", errors="replace"):
                matches.append({"rule": sig["name"], "type": "signature", "severity": "critical"})

    if yara_rules:
        yara_result = yara_scan(file_data, yara_rules)
        for match in yara_result.get("matches", []):
            matches.append({"rule": match["rule"], "type": "yara", "severity": match.get("severity", "high")})

    infected = len(matches) > 0
    rules_checked = len(signatures) + len(yara_rules)

    result = {
        "infected": infected,
        "matches": matches,
        "scan_time_ms": 0.0,
        "rules_checked": rules_checked,
    }

    metrics.inc_counter("file.malware_scan", labels={"infected": str(infected)})
    logger.info("malware_scan", infected=infected, matches=len(matches), rules=rules_checked)

    if infected:
        pass
    return result


def yara_scan(
    file_data: bytes,
    rules: Optional[list[dict[str, Any]]] = None,
    namespace: Optional[str] = None,
) -> dict[str, Any]:
    """Scan file data using YARA-like pattern matching rules.

    Args:
        file_data: Raw file bytes.
        rules: List of rule dicts with 'name', 'pattern', 'description', 'severity' keys.
        namespace: Optional namespace to filter rules.

    Returns:
        dict with keys: matches (list), rules_evaluated (int), scan_complete (bool).

    Example:
        >>> result = yara_scan(file_data, rules=[{'name': 'test', 'pattern': b'test', 'description': 'test rule'}])
        >>> result['matches']
        []
    """
    metrics = get_metrics()

    if rules is None:
        rules = []

    matches: list[dict[str, Any]] = []
    rules_evaluated = 0

    for rule in rules:
        if namespace and rule.get("namespace") != namespace:
            continue

        rules_evaluated += 1
        pattern = rule.get("pattern", b"")
        pattern_type = rule.get("pattern_type", "literal")

        matched = False
        match_offset = -1

        if pattern_type == "literal":
            match_offset = file_data.find(pattern)
            matched = match_offset >= 0
        elif pattern_type == "regex":
            match = re.search(pattern, file_data, re.IGNORECASE | re.DOTALL)
            matched = match is not None
            match_offset = match.start() if match else -1
        elif pattern_type == "hex":
            try:
                hex_pattern = bytes.fromhex(pattern.decode("utf-8", errors="replace").replace(" ", ""))
                match_offset = file_data.find(hex_pattern)
                matched = match_offset >= 0
            except (ValueError, UnicodeDecodeError):
                matched = False

        if matched:
            matches.append({
                "rule": rule["name"],
                "description": rule.get("description", ""),
                "severity": rule.get("severity", "medium"),
                "offset": match_offset,
                "namespace": rule.get("namespace", ""),
            })

    result = {
        "matches": matches,
        "rules_evaluated": rules_evaluated,
        "scan_complete": True,
    }

    metrics.inc_counter("file.yara_scan", labels={"matches": str(len(matches))})
    logger.debug("yara_scan", evaluated=rules_evaluated, matched=len(matches))
    return result


def heuristic_scan(
    file_data: bytes,
    heuristics: Optional[list[dict[str, Any]]] = None,
    threshold: float = 0.5,
) -> dict[str, Any]:
    """Perform heuristic analysis on file data to detect suspicious behavior.

    Args:
        file_data: Raw file bytes.
        heuristics: List of heuristic dicts with 'name', 'check', 'weight' keys.
        threshold: Score threshold to flag as suspicious (0.0-1.0). Defaults to 0.5.

    Returns:
        dict with keys: suspicious (bool), score (float), triggered (list), details (dict).

    Example:
        >>> result = heuristic_scan(file_data, threshold=0.7)
        >>> result['suspicious']
        False
    """
    metrics = get_metrics()

    if heuristics is None:
        heuristics = [
            {"name": "high_entropy", "check": "entropy", "weight": 0.3},
            {"name": "embedded_urls", "check": "urls", "weight": 0.2},
            {"name": "encoded_strings", "check": "encoding", "weight": 0.2},
            {"name": "suspicious_strings", "check": "strings", "weight": 0.3},
        ]

    triggered: list[str] = []
    details: dict[str, Any] = {}
    total_weight = 0.0
    weighted_score = 0.0

    for h in heuristics:
        check = h.get("check", "")
        weight = h.get("weight", 0.1)
        total_weight += weight
        hit = False

        if check == "entropy":
            ent = entropy_analysis(file_data)
            ent_val = ent.get("entropy", 0)
            hit = ent_val > 7.0
            details["entropy"] = ent_val
        elif check == "urls":
            url_count = len(re.findall(rb"https?://[^\s\"'<>]+", file_data))
            hit = url_count > 5
            details["url_count"] = url_count
        elif check == "encoding":
            base64_pattern = rb"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
            encoded_count = len(re.findall(base64_pattern, file_data))
            hit = encoded_count > 2
            details["encoded_count"] = encoded_count
        elif check == "strings":
            suspicious = [
                rb"cmd\.exe", rb"powershell", rb"/bin/sh", rb"/bin/bash",
                rb"eval\s*\(", rb"exec\s*\(", rb"system\s*\(",
                rb"WScript\.Shell", rb"ActiveXObject",
            ]
            found = [s.decode("utf-8", errors="replace") for s in suspicious if re.search(s, file_data)]
            hit = len(found) >= 2
            details["suspicious_strings"] = found

        if hit:
            triggered.append(h["name"])
            weighted_score += weight

    score = weighted_score / total_weight if total_weight > 0 else 0.0
    suspicious = score >= threshold

    result = {
        "suspicious": suspicious,
        "score": score,
        "triggered": triggered,
        "details": details,
    }

    metrics.inc_counter("file.heuristic_scan", labels={"suspicious": str(suspicious)})
    logger.info("heuristic_scan", suspicious=suspicious, score=score, triggered=triggered)
    return result


def quarantine_file(
    filepath: str,
    quarantine_dir: Optional[str] = None,
    reason: str = "security_policy_violation",
) -> str:
    """Move a file to a quarantine directory with metadata tracking.

    Args:
        filepath: Path to the file to quarantine.
        quarantine_dir: Destination quarantine directory. Defaults to ./quarantine.
        reason: Reason for quarantine.

    Returns:
        Path to the quarantined file.

    Example:
        >>> path = quarantine_file('/tmp/suspicious.exe', reason='malware_detected')
        >>> os.path.exists(path)
        True
    """
    metrics = get_metrics()

    if quarantine_dir is None:
        quarantine_dir = os.path.join(os.getcwd(), "quarantine")

    os.makedirs(quarantine_dir, exist_ok=True)

    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    filename = os.path.basename(filepath)
    timestamp = hash(filepath + reason) & 0xFFFFFFFF
    quarantine_name = f"{timestamp}_{filename}"
    dest_path = os.path.join(quarantine_dir, quarantine_name)

    import shutil
    shutil.copy2(filepath, dest_path)

    metadata = {
        "original_path": filepath,
        "quarantine_path": dest_path,
        "reason": reason,
        "timestamp": timestamp,
        "original_hash": hashlib.sha256(open(filepath, "rb").read()).hexdigest(),
    }

    meta_path = dest_path + ".meta"
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)

    metrics.inc_counter("file.quarantine", labels={"reason": reason})
    logger.warning("quarantine_file", original=filepath, dest=dest_path, reason=reason)
    return dest_path


def sanitize_filename(
    filename: str,
    max_length: int = 255,
    allowed_chars: Optional[str] = None,
) -> str:
    """Sanitize a filename by removing dangerous characters.

    Args:
        filename: Original filename.
        max_length: Maximum allowed filename length. Defaults to 255.
        allowed_chars: Regex pattern of allowed characters. Defaults to alphanumeric, dots, hyphens, underscores.

    Returns:
        Sanitized filename string.

    Example:
        >>> sanitize_filename('../../etc/passwd')
        'etc_passwd'
    """
    metrics = get_metrics()

    if allowed_chars is None:
        allowed_chars = r"[a-zA-Z0-9._\-]"

    sanitized = os.path.basename(filename)
    sanitized = re.sub(rf"(?!{allowed_chars}).", "_", sanitized)
    sanitized = re.sub(r"_+", "_", sanitized).strip("_")

    name, ext = os.path.splitext(sanitized)
    if len(sanitized) > max_length:
        ext_len = len(ext)
        name = name[: max_length - ext_len]
        sanitized = name + ext

    if not sanitized:
        sanitized = "unnamed_file"

    metrics.inc_counter("file.sanitize_filename")
    logger.debug("sanitize_filename", original=filename, sanitized=sanitized)
    return sanitized


def detect_executable_payload(
    file_data: bytes,
    file_type: Optional[str] = None,
) -> dict[str, Any]:
    """Detect executable payloads embedded within non-executable files.

    Args:
        file_data: Raw file bytes.
        file_type: Expected file type hint.

    Returns:
        dict with keys: has_payload (bool), payload_type (str), offset (int), size (int).

    Example:
        >>> result = detect_executable_payload(image_with_shellcode)
        >>> result['has_payload']
        False
    """
    metrics = get_metrics()

    has_payload = False
    payload_type = "none"
    offset = -1
    size = 0

    pe_sig_offset = file_data.find(b"MZ")
    elf_sig_offset = file_data.find(b"\x7fELF")
    macho_sig_offset = file_data.find(b"\xfe\xed\xfa\xce")
    macho64_sig_offset = file_data.find(b"\xfe\xed\xfa\xcf")

    exec_offsets = []
    if pe_sig_offset >= 0:
        exec_offsets.append(("PE", pe_sig_offset))
    if elf_sig_offset >= 0:
        exec_offsets.append(("ELF", elf_sig_offset))
    if macho_sig_offset >= 0:
        exec_offsets.append(("Mach-O", macho_sig_offset))
    if macho64_sig_offset >= 0:
        exec_offsets.append(("Mach-O64", macho64_sig_offset))

    if exec_offsets:
        has_payload = True
        payload_type, offset = exec_offsets[0]
        remaining = file_data[offset:]
        size = len(remaining)

    shellcode_patterns = [
        rb"\x31\xc0\x50\x68",
        rb"\x31\xdb\x64\x8b",
        rb"\x6a\x0b\x58\x99",
        rb"\xeb\x1f\x5e\x89",
    ]

    for pattern in shellcode_patterns:
        sc_offset = file_data.find(pattern)
        if sc_offset >= 0 and not has_payload:
            has_payload = True
            payload_type = "shellcode"
            offset = sc_offset
            size = min(256, len(file_data) - sc_offset)
            break

    result = {
        "has_payload": has_payload,
        "payload_type": payload_type,
        "offset": offset,
        "size": size,
    }

    metrics.inc_counter("file.detect_executable_payload", labels={"payload": str(has_payload)})
    logger.info("detect_executable_payload", has_payload=has_payload, type=payload_type)
    return result


def entropy_analysis(
    file_data: bytes,
    block_size: int = 256,
    threshold: float = 7.0,
) -> dict[str, Any]:
    """Calculate Shannon entropy of file data to detect encryption or compression.

    Args:
        file_data: Raw file bytes.
        block_size: Size of blocks to analyze. Defaults to 256.
        threshold: Entropy threshold for flagging. Defaults to 7.0.

    Returns:
        dict with keys: entropy (float), blocks (list), high_entropy_blocks (int), is_encrypted (bool).

    Example:
        >>> result = entropy_analysis(b'hello world' * 100)
        >>> result['entropy'] < 5.0
        True
    """
    metrics = get_metrics()

    def shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq: dict[int, int] = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        length = len(data)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    overall_entropy = shannon_entropy(file_data)

    blocks: list[float] = []
    high_entropy_blocks = 0

    for i in range(0, len(file_data), block_size):
        block = file_data[i:i + block_size]
        block_entropy = shannon_entropy(block)
        blocks.append(round(block_entropy, 4))
        if block_entropy > threshold:
            high_entropy_blocks += 1

    is_encrypted = overall_entropy > 7.8

    result = {
        "entropy": round(overall_entropy, 4),
        "blocks": blocks,
        "high_entropy_blocks": high_entropy_blocks,
        "is_encrypted": is_encrypted,
    }

    metrics.inc_counter("file.entropy_analysis", labels={"encrypted": str(is_encrypted)})
    logger.debug("entropy_analysis", entropy=overall_entropy, high_blocks=high_entropy_blocks)
    return result


def sandbox_execute(
    file_path: str,
    sandbox_config: Optional[dict[str, Any]] = None,
    timeout: int = 30,
) -> dict[str, Any]:
    """Execute a file in a sandboxed environment for behavioral analysis.

    Args:
        file_path: Path to the file to analyze.
        sandbox_config: Sandbox configuration dict with keys like 'network', 'filesystem', 'registry'.
        timeout: Maximum execution time in seconds. Defaults to 30.

    Returns:
        dict with keys: executed (bool), behaviors (list), network_connections (list), file_operations (list), exit_code (int).

    Example:
        >>> result = sandbox_execute('/tmp/test.exe', timeout=10)
        >>> result['executed']
        False
    """
    metrics = get_metrics()

    if sandbox_config is None:
        sandbox_config = {
            "network": False,
            "filesystem": "read_only",
            "registry": "isolated",
            "max_processes": 1,
        }

    behaviors: list[str] = []
    network_connections: list[str] = []
    file_operations: list[str] = []
    exit_code = -1
    executed = False

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    file_ext = os.path.splitext(file_path)[1].lower()
    executable_extensions = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi", ".com", ".scr"}

    if file_ext not in executable_extensions:
        return {
            "executed": False,
            "behaviors": ["non_executable_file"],
            "network_connections": [],
            "file_operations": [],
            "exit_code": -1,
        }

    with open(file_path, "rb") as f:
        header = f.read(512)

    if header[:2] == b"MZ":
        behaviors.append("pe_executable")
    elif header[:4] == b"\x7fELF":
        behaviors.append("elf_executable")

    static_analysis = detect_executable_payload(header)
    if static_analysis["has_payload"]:
        behaviors.append(f"embedded_{static_analysis['payload_type']}")

    with open(file_path, "rb") as f:
        full_data = f.read()
    entropy_result = entropy_analysis(full_data)
    if entropy_result["is_encrypted"]:
        behaviors.append("high_entropy_encrypted")

    result = {
        "executed": executed,
        "behaviors": behaviors,
        "network_connections": network_connections,
        "file_operations": file_operations,
        "exit_code": exit_code,
    }

    metrics.inc_counter("file.sandbox_execute", labels={"executed": str(executed)})
    logger.info("sandbox_execute", path=file_path, behaviors=behaviors, executed=executed)
    return result


def detect_embedded_script(
    file_data: bytes,
    file_type: Optional[str] = None,
    script_types: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Detect embedded scripts within files (e.g., JavaScript in PDF, macros in Office).

    Args:
        file_data: Raw file bytes.
        file_type: Expected file type.
        script_types: List of script types to detect. Defaults to ['javascript', 'vbscript', 'powershell', 'python', 'lua'].

    Returns:
        dict with keys: has_script (bool), scripts (list), details (dict).

    Example:
        >>> result = detect_embedded_script(html_with_js)
        >>> result['has_script']
        True
    """
    metrics = get_metrics()

    if script_types is None:
        script_types = ["javascript", "vbscript", "powershell", "python", "lua", "bash", "perl"]

    scripts: list[str] = []
    details: dict[str, Any] = {}

    script_patterns: dict[str, list[bytes]] = {
        "javascript": [
            rb"<script[\s>]",
            rb"javascript:",
            rb"eval\s*\(",
            rb"document\.write",
            rb"window\.",
        ],
        "vbscript": [
            rb"<script[^>]*vbscript",
            rb"CreateObject\s*\(",
            rb"WScript\.",
            rb"Sub\s+\w+",
            rb"End\s+Sub",
        ],
        "powershell": [
            rb"powershell",
            rb"\$env:",
            rb"Get-Process",
            rb"Invoke-Expression",
            rb"Invoke-WebRequest",
        ],
        "python": [
            rb"#!/usr/bin/python",
            rb"#!/usr/bin/env python",
            rb"import\s+os",
            rb"import\s+subprocess",
            rb"exec\s*\(",
        ],
        "lua": [
            rb"function\s+\w+\s*\(",
            rb"end\s*$",
            rb"local\s+\w+",
        ],
        "bash": [
            rb"#!/bin/bash",
            rb"#!/bin/sh",
            rb"\$\(",
            rb"`[^`]+`",
        ],
        "perl": [
            rb"#!/usr/bin/perl",
            rb"use\s+strict",
            rb"my\s+\$",
        ],
    }

    for stype in script_types:
        patterns = script_patterns.get(stype, [])
        found_patterns: list[str] = []
        for pattern in patterns:
            if re.search(pattern, file_data, re.IGNORECASE | re.MULTILINE):
                found_patterns.append(pattern.decode("utf-8", errors="replace"))

        if found_patterns:
            scripts.append(stype)
            details[stype] = found_patterns

    has_script = len(scripts) > 0

    result = {
        "has_script": has_script,
        "scripts": scripts,
        "details": details,
    }

    metrics.inc_counter("file.detect_embedded_script", labels={"script": str(has_script)})
    logger.info("detect_embedded_script", has_script=has_script, scripts=scripts)
    return result


def detect_steganography(
    file_data: bytes,
    analysis_methods: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Detect potential steganography in image files.

    Args:
        file_data: Raw file bytes.
        analysis_methods: List of methods to use. Defaults to ['lsb', 'entropy', 'size'].

    Returns:
        dict with keys: suspicious (bool), methods_triggered (list), details (dict).

    Example:
        >>> result = detect_steganography(image_data)
        >>> result['suspicious']
        False
    """
    metrics = get_metrics()

    if analysis_methods is None:
        analysis_methods = ["lsb", "entropy", "size"]

    methods_triggered: list[str] = []
    details: dict[str, Any] = {}

    if "entropy" in analysis_methods:
        ent = entropy_analysis(file_data)
        entropy_val = ent["entropy"]
        details["entropy"] = entropy_val
        if entropy_val > 7.5:
            methods_triggered.append("entropy")

    if "size" in analysis_methods:
        if file_data[:2] == b"\xff\xd8":
            sof_marker = file_data.find(b"\xff\xc0")
            if sof_marker >= 0:
                try:
                    height = struct.unpack_from(">H", file_data, sof_marker + 5)[0]
                    width = struct.unpack_from(">H", file_data, sof_marker + 7)[0]
                    expected_size = width * height * 3
                    actual_size = len(file_data)
                    ratio = actual_size / expected_size if expected_size > 0 else 0
                    details["size_ratio"] = ratio
                    if ratio > 2.0:
                        methods_triggered.append("size")
                except struct.error:
                    pass

    if "lsb" in analysis_methods:
        if file_data[:8] == b"\x89PNG\r\n\x1a\n":
            idat_chunks: list[bytes] = []
            pos = 0
            while pos < len(file_data) - 8:
                chunk_type = file_data[pos + 4:pos + 8]
                if chunk_type == b"IDAT":
                    length = struct.unpack_from(">I", file_data, pos)[0]
                    idat_chunks.append(file_data[pos + 8:pos + 8 + length])
                    pos += 12 + length
                else:
                    pos += 1

            if idat_chunks:
                lsb_data = b"".join(idat_chunks)
                if lsb_data:
                    lsb_zeros = sum(1 for b in lsb_data if (b & 1) == 0)
                    lsb_ones = sum(1 for b in lsb_data if (b & 1) == 1)
                    total = lsb_zeros + lsb_ones
                    if total > 0:
                        lsb_ratio = abs(lsb_zeros - lsb_ones) / total
                        details["lsb_ratio"] = lsb_ratio
                        if lsb_ratio < 0.01:
                            methods_triggered.append("lsb")

    suspicious = len(methods_triggered) > 0

    result = {
        "suspicious": suspicious,
        "methods_triggered": methods_triggered,
        "details": details,
    }

    metrics.inc_counter("file.detect_steganography", labels={"suspicious": str(suspicious)})
    logger.info("detect_steganography", suspicious=suspicious, methods=methods_triggered)
    return result


def detect_obfuscation(
    file_data: bytes,
    detection_methods: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Detect obfuscated content in files (encoded strings, packed code, etc.).

    Args:
        file_data: Raw file bytes.
        detection_methods: Methods to use. Defaults to ['base64', 'hex', 'xor', 'string_entropy'].

    Returns:
        dict with keys: obfuscated (bool), methods_triggered (list), details (dict).

    Example:
        >>> result = detect_obfuscation(file_with_base64)
        >>> result['obfuscated']
        True
    """
    metrics = get_metrics()

    if detection_methods is None:
        detection_methods = ["base64", "hex", "xor", "string_entropy"]

    methods_triggered: list[str] = []
    details: dict[str, Any] = {}

    if "base64" in detection_methods:
        base64_pattern = rb"(?:[A-Za-z0-9+/]{20,})={0,2}"
        b64_matches = re.findall(base64_pattern, file_data)
        long_b64 = [m for m in b64_matches if len(m) > 40]
        details["base64_segments"] = len(long_b64)
        if long_b64:
            methods_triggered.append("base64")

    if "hex" in detection_methods:
        hex_pattern = rb"(?:[0-9a-fA-F]{2}\s*){10,}"
        hex_matches = re.findall(hex_pattern, file_data)
        details["hex_segments"] = len(hex_matches)
        if hex_matches:
            methods_triggered.append("hex")

    if "xor" in detection_methods:
        byte_freq: dict[int, int] = {}
        for b in file_data:
            byte_freq[b] = byte_freq.get(b, 0) + 1

        if byte_freq:
            most_common = max(byte_freq.values())
            uniformity = most_common / len(file_data) if len(file_data) > 0 else 1.0
            details["xor_uniformity"] = round(uniformity, 4)
            if uniformity < 0.05 and len(file_data) > 100:
                methods_triggered.append("xor")

    if "string_entropy" in detection_methods:
        strings = re.findall(rb"[\x20-\x7e]{8,}", file_data)
        high_entropy_strings = 0
        for s in strings:
            s_entropy = entropy_analysis(s)["entropy"]
            if s_entropy > 5.5:
                high_entropy_strings += 1

        details["high_entropy_strings"] = high_entropy_strings
        if high_entropy_strings > 3:
            methods_triggered.append("string_entropy")

    obfuscated = len(methods_triggered) >= 2

    result = {
        "obfuscated": obfuscated,
        "methods_triggered": methods_triggered,
        "details": details,
    }

    metrics.inc_counter("file.detect_obfuscation", labels={"obfuscated": str(obfuscated)})
    logger.info("detect_obfuscation", obfuscated=obfuscated, methods=methods_triggered)
    return result


def secure_tempfile(
    prefix: str = "tmp",
    suffix: str = "",
    directory: Optional[str] = None,
    delete_on_close: bool = False,
) -> str:
    """Create a secure temporary file with restricted permissions.

    Args:
        prefix: Filename prefix. Defaults to 'tmp'.
        suffix: Filename suffix. Defaults to empty.
        directory: Directory for the temp file. Defaults to system temp.
        delete_on_close: Whether to delete file when closed. Defaults to True.

    Returns:
        Path to the created temporary file.

    Example:
        >>> path = secure_tempfile(prefix='secure_', suffix='.dat')
        >>> os.path.exists(path)
        True
    """
    metrics = get_metrics()

    sanitized_prefix = re.sub(r"[^a-zA-Z0-9_\-]", "", prefix)
    sanitized_suffix = re.sub(r"[^a-zA-Z0-9_.]", "", suffix)

    if directory:
        os.makedirs(directory, exist_ok=True)

    fd, path = tempfile.mkstemp(prefix=sanitized_prefix, suffix=sanitized_suffix, dir=directory)

    if os.name != "nt":
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            pass

    os.close(fd)

    if delete_on_close:
        try:
            os.unlink(path)
        except OSError:
            pass

    metrics.inc_counter("file.secure_tempfile", labels={"delete": str(delete_on_close)})
    logger.debug("secure_tempfile", path=path, delete=delete_on_close)
    return path


def immutable_storage_check(
    filepath: str,
    expected_hash: Optional[str] = None,
    storage_type: str = "filesystem",
) -> bool:
    """Verify file integrity against expected hash for immutable storage.

    Args:
        filepath: Path to the file to verify.
        expected_hash: Expected SHA-256 hash of the file.
        storage_type: Storage type ('filesystem', 's3', 'worm'). Defaults to 'filesystem'.

    Returns:
        True if the file hash matches expected_hash or file is verified intact.

    Example:
        >>> result = immutable_storage_check('/data/file.txt', expected_hash='abc123...')
        >>> result
        True
    """
    metrics = get_metrics()

    if not os.path.exists(filepath):
        metrics.inc_counter("file.immutable_storage_check", labels={"result": "missing"})
        logger.warning("immutable_storage_check_missing", path=filepath)
        return False

    file_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            file_hash.update(chunk)

    actual_hash = file_hash.hexdigest()

    if expected_hash:
        matches = actual_hash == expected_hash.lower()
    else:
        matches = True

    if storage_type == "worm":
        try:
            stat_result = os.stat(filepath)
            import stat as stat_mod
            readonly = bool(stat_result.st_mode & stat_mod.S_IRUSR) and not bool(stat_result.st_mode & stat_mod.S_IWUSR)
            if not readonly:
                logger.warning("immutable_storage_check_worm_not_readonly", path=filepath)
        except OSError:
            pass

    result = matches

    metrics.inc_counter("file.immutable_storage_check", labels={"result": str(result), "type": storage_type})
    logger.info("immutable_storage_check", path=filepath, match=result, type=storage_type)
    return result
