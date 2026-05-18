from __future__ import annotations
import json
import hashlib
import time
from typing import Any, Optional
from datetime import datetime, timezone
from master_security.core import get_logger, get_metrics, create_span, get_event_bus, SecurityEvent, EventSeverity
from master_security.core.exceptions import SecurityError, ValidationError
import structlog

logger = structlog.get_logger(__name__)


def lgpd_check(
    system_config: dict[str, Any],
    data_flows: list[dict[str, Any]],
    controls: dict[str, Any],
) -> dict[str, Any]:
    """Check compliance with Brazilian LGPD (Lei Geral de Protecao de Dados).

    Validates consent management, DPO appointment, data subject rights,
    data localization, and breach notification procedures.

    Args:
        system_config: System configuration including data categories and retention.
        data_flows: List of data flow definitions with source, destination, and purpose.
        controls: Existing security controls mapped by control ID.

    Returns:
        Dict with compliant (bool), score (float), findings (list), and metadata.

    Example:
        >>> result = lgpd_check(
        ...     system_config={"data_categories": ["personal", "sensitive"]},
        ...     data_flows=[{"source": "web", "destination": "db", "purpose": "auth"}],
        ...     controls={"consent_mgmt": True, "dpo_appointed": True},
        ... )
    """
    start = time.monotonic()
    metrics = get_metrics()
    findings: list[dict[str, Any]] = []
    compliant = True

    with create_span("lgpd_check") as span:
        # Check consent management
        has_consent = controls.get("consent_mgmt", False)
        if not has_consent:
            findings.append({
                "control": "consent_management",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": "No consent management mechanism detected for personal data processing",
            })
            compliant = False
        else:
            findings.append({"control": "consent_management", "status": "PASS", "severity": "INFO", "detail": "Consent management in place"})

        # Check DPO appointment (Art. 41 LGPD)
        has_dpo = controls.get("dpo_appointed", False)
        if not has_dpo:
            findings.append({
                "control": "dpo_appointment",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": "Data Protection Officer (Encarregado) not appointed per Art. 41",
            })
            compliant = False
        else:
            findings.append({"control": "dpo_appointment", "status": "PASS", "severity": "INFO", "detail": "DPO appointed"})

        # Check data subject rights (Art. 18 LGPD)
        rights_controls = controls.get("data_subject_rights", {})
        required_rights = ["access", "rectification", "deletion", "portability", "revocation"]
        missing_rights = [r for r in required_rights if not rights_controls.get(r, False)]
        if missing_rights:
            findings.append({
                "control": "data_subject_rights",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": f"Missing data subject rights: {', '.join(missing_rights)}",
            })
            compliant = False
        else:
            findings.append({"control": "data_subject_rights", "status": "PASS", "severity": "INFO", "detail": "All data subject rights implemented"})

        # Check sensitive data handling (Art. 5, II LGPD)
        sensitive_categories = system_config.get("data_categories", [])
        has_sensitive = any(c in ("sensitive", "health", "biometric", "genetic") for c in sensitive_categories)
        if has_sensitive and not controls.get("sensitive_data_encryption", False):
            findings.append({
                "control": "sensitive_data_protection",
                "status": "FAIL",
                "severity": "CRITICAL",
                "detail": "Sensitive personal data not encrypted at rest",
            })
            compliant = False
        else:
            findings.append({"control": "sensitive_data_protection", "status": "PASS", "severity": "INFO", "detail": "Sensitive data properly protected"})

        # Check data flow transparency
        for flow in data_flows:
            if not flow.get("legal_basis"):
                findings.append({
                    "control": "legal_basis",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "detail": f"Data flow {flow.get('source', 'unknown')} -> {flow.get('destination', 'unknown')} lacks legal basis",
                })
                compliant = False

        # Check breach notification (Art. 48 LGPD - 2 business days)
        if not controls.get("breach_notification_procedure", False):
            findings.append({
                "control": "breach_notification",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": "No breach notification procedure for ANPD (2 business day requirement)",
            })
            compliant = False
        else:
            findings.append({"control": "breach_notification", "status": "PASS", "severity": "INFO", "detail": "Breach notification procedure in place"})

        # Check data retention policy
        if not controls.get("retention_policy", False):
            findings.append({
                "control": "data_retention",
                "status": "FAIL",
                "severity": "MEDIUM",
                "detail": "No data retention and deletion policy defined",
            })
            compliant = False
        else:
            findings.append({"control": "data_retention", "status": "PASS", "severity": "INFO", "detail": "Retention policy defined"})

        score = sum(1 for f in findings if f["status"] == "PASS") / max(len(findings), 1)

        elapsed = time.monotonic() - start
        metrics.inc_counter("compliance.lgpd_check")
        metrics.observe_histogram("compliance.lgpd_check.duration", elapsed)

        span.set_attribute("lgpd.compliant", compliant)
        span.set_attribute("lgpd.score", score)

        result = {
            "framework": "LGPD",
            "compliant": compliant,
            "score": round(score, 2),
            "findings": findings,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "checks_performed": len(findings),
        }

        logger.info(
            "lgpd_check_completed",
            compliant=compliant,
            score=score,
            findings=len(findings),
        )

        return result


def gdpr_check(
    system_config: dict[str, Any],
    data_processing: list[dict[str, Any]],
    controls: dict[str, Any],
) -> dict[str, Any]:
    """Check compliance with EU GDPR (General Data Protection Regulation).

    Validates lawful basis, DPO appointment, DPIA completion, data subject
    rights, breach notification, and cross-border transfer safeguards.

    Args:
        system_config: System configuration including processing purposes and data categories.
        data_processing: List of processing activities with purpose, category, and retention.
        controls: Existing security and privacy controls mapped by control ID.

    Returns:
        Dict with compliant (bool), score (float), findings (list), and metadata.

    Example:
        >>> result = gdpr_check(
        ...     system_config={"processing_purposes": ["service_delivery"]},
        ...     data_processing=[{"purpose": "marketing", "category": "personal"}],
        ...     controls={"lawful_basis": True, "dpo_appointed": True},
        ... )
    """
    start = time.monotonic()
    metrics = get_metrics()
    findings: list[dict[str, Any]] = []
    compliant = True

    with create_span("gdpr_check") as span:
        # Check lawful basis for processing (Art. 6 GDPR)
        lawful_basis = controls.get("lawful_basis", {})
        for activity in data_processing:
            purpose = activity.get("purpose", "unknown")
            if not lawful_basis.get(purpose):
                findings.append({
                    "control": "lawful_basis",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "detail": f"No lawful basis identified for processing purpose: {purpose}",
                })
                compliant = False

        if not findings or findings[-1].get("control") != "lawful_basis":
            findings.append({"control": "lawful_basis", "status": "PASS", "severity": "INFO", "detail": "Lawful basis documented for all processing activities"})

        # Check DPO appointment (Art. 37 GDPR)
        if not controls.get("dpo_appointed", False):
            findings.append({
                "control": "dpo_appointment",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": "Data Protection Officer not appointed per Art. 37",
            })
            compliant = False
        else:
            findings.append({"control": "dpo_appointment", "status": "PASS", "severity": "INFO", "detail": "DPO appointed"})

        # Check DPIA (Art. 35 GDPR)
        if not controls.get("dpia_completed", False):
            findings.append({
                "control": "dpia",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": "Data Protection Impact Assessment not completed per Art. 35",
            })
            compliant = False
        else:
            findings.append({"control": "dpia", "status": "PASS", "severity": "INFO", "detail": "DPIA completed"})

        # Check data subject rights (Art. 15-22 GDPR)
        rights = controls.get("data_subject_rights", {})
        gdpr_rights = ["access", "rectification", "erasure", "portability", "object", "restrict_processing"]
        missing = [r for r in gdpr_rights if not rights.get(r, False)]
        if missing:
            findings.append({
                "control": "data_subject_rights",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": f"Missing GDPR data subject rights: {', '.join(missing)}",
            })
            compliant = False
        else:
            findings.append({"control": "data_subject_rights", "status": "PASS", "severity": "INFO", "detail": "All GDPR data subject rights implemented"})

        # Check breach notification (Art. 33 GDPR - 72 hours)
        if not controls.get("breach_notification_72h", False):
            findings.append({
                "control": "breach_notification",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": "No 72-hour breach notification procedure per Art. 33",
            })
            compliant = False
        else:
            findings.append({"control": "breach_notification", "status": "PASS", "severity": "INFO", "detail": "72-hour breach notification procedure in place"})

        # Check data minimization (Art. 5(1)(c))
        if not controls.get("data_minimization", False):
            findings.append({
                "control": "data_minimization",
                "status": "FAIL",
                "severity": "MEDIUM",
                "detail": "Data minimization principle not enforced",
            })
            compliant = False
        else:
            findings.append({"control": "data_minimization", "status": "PASS", "severity": "INFO", "detail": "Data minimization enforced"})

        # Check cross-border transfers (Art. 44-49 GDPR)
        transfers = controls.get("cross_border_transfers", {})
        if transfers.get("enabled", False):
            if not transfers.get("safeguards") or not transfers.get("adequacy_decision") and not transfers.get("sccs"):
                findings.append({
                    "control": "cross_border_transfers",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "detail": "Cross-border data transfers lack adequate safeguards (SCCs, adequacy decision, or BCRs)",
                })
                compliant = False
            else:
                findings.append({"control": "cross_border_transfers", "status": "PASS", "severity": "INFO", "detail": "Cross-border transfer safeguards in place"})

        # Check encryption (Art. 32 GDPR)
        if not controls.get("encryption_at_rest", False) or not controls.get("encryption_in_transit", False):
            findings.append({
                "control": "encryption",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": "Personal data not fully encrypted (at rest and/or in transit) per Art. 32",
            })
            compliant = False
        else:
            findings.append({"control": "encryption", "status": "PASS", "severity": "INFO", "detail": "Data encrypted at rest and in transit"})

        # Check records of processing (Art. 30 GDPR)
        if not controls.get("processing_records", False):
            findings.append({
                "control": "processing_records",
                "status": "FAIL",
                "severity": "MEDIUM",
                "detail": "Records of processing activities not maintained per Art. 30",
            })
            compliant = False
        else:
            findings.append({"control": "processing_records", "status": "PASS", "severity": "INFO", "detail": "Processing records maintained"})

        score = sum(1 for f in findings if f["status"] == "PASS") / max(len(findings), 1)

        elapsed = time.monotonic() - start
        metrics.inc_counter("compliance.gdpr_check")
        metrics.observe_histogram("compliance.gdpr_check.duration", elapsed)

        span.set_attribute("gdpr.compliant", compliant)
        span.set_attribute("gdpr.score", score)

        result = {
            "framework": "GDPR",
            "compliant": compliant,
            "score": round(score, 2),
            "findings": findings,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "checks_performed": len(findings),
        }

        logger.info(
            "gdpr_check_completed",
            compliant=compliant,
            score=score,
            findings=len(findings),
        )

        return result


def hipaa_check(
    system_config: dict[str, Any],
    phi_handling: list[dict[str, Any]],
    controls: dict[str, Any],
) -> dict[str, Any]:
    """Check compliance with HIPAA (Health Insurance Portability and Accountability Act).

    Validates PHI encryption, access controls, audit logging, business associate
    agreements, and minimum necessary access principles.

    Args:
        system_config: System configuration including entity type and covered functions.
        phi_handling: List of PHI handling procedures with access, storage, and transmission details.
        controls: Security controls mapped by control ID.

    Returns:
        Dict with compliant (bool), score (float), findings (list), and metadata.

    Example:
        >>> result = hipaa_check(
        ...     system_config={"entity_type": "covered_entity"},
        ...     phi_handling=[{"type": "storage", "encryption": "AES-256"}],
        ...     controls={"phi_encryption": True, "access_controls": True},
        ... )
    """
    start = time.monotonic()
    metrics = get_metrics()
    findings: list[dict[str, Any]] = []
    compliant = True

    with create_span("hipaa_check") as span:
        # Check PHI encryption at rest (Security Rule 164.312(a)(2)(iv))
        if not controls.get("phi_encryption_at_rest", False):
            findings.append({
                "control": "phi_encryption_at_rest",
                "status": "FAIL",
                "severity": "CRITICAL",
                "detail": "PHI not encrypted at rest per Security Rule 164.312(a)(2)(iv)",
            })
            compliant = False
        else:
            findings.append({"control": "phi_encryption_at_rest", "status": "PASS", "severity": "INFO", "detail": "PHI encrypted at rest"})

        # Check PHI encryption in transit (Security Rule 164.312(e)(1))
        if not controls.get("phi_encryption_in_transit", False):
            findings.append({
                "control": "phi_encryption_in_transit",
                "status": "FAIL",
                "severity": "CRITICAL",
                "detail": "PHI not encrypted in transit per Security Rule 164.312(e)(1)",
            })
            compliant = False
        else:
            findings.append({"control": "phi_encryption_in_transit", "status": "PASS", "severity": "INFO", "detail": "PHI encrypted in transit"})

        # Check access controls (Security Rule 164.312(a)(1))
        access_controls = controls.get("access_controls", {})
        if not access_controls.get("unique_user_id", False):
            findings.append({
                "control": "unique_user_identification",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": "Unique user identification not enforced per 164.312(a)(2)(i)",
            })
            compliant = False
        else:
            findings.append({"control": "unique_user_identification", "status": "PASS", "severity": "INFO", "detail": "Unique user IDs enforced"})

        if not access_controls.get("emergency_access", False):
            findings.append({
                "control": "emergency_access_procedure",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": "Emergency access procedure not defined per 164.312(a)(2)(ii)",
            })
            compliant = False
        else:
            findings.append({"control": "emergency_access_procedure", "status": "PASS", "severity": "INFO", "detail": "Emergency access procedure defined"})

        # Check audit controls (Security Rule 164.312(b))
        if not controls.get("audit_controls", False):
            findings.append({
                "control": "audit_controls",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": "Audit controls not implemented per Security Rule 164.312(b)",
            })
            compliant = False
        else:
            findings.append({"control": "audit_controls", "status": "PASS", "severity": "INFO", "detail": "Audit controls implemented"})

        # Check integrity controls (Security Rule 164.312(c)(1))
        if not controls.get("integrity_controls", False):
            findings.append({
                "control": "integrity_controls",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": "PHI integrity controls not in place per 164.312(c)(1)",
            })
            compliant = False
        else:
            findings.append({"control": "integrity_controls", "status": "PASS", "severity": "INFO", "detail": "PHI integrity controls in place"})

        # Check minimum necessary access (Privacy Rule 164.502(b))
        if not controls.get("minimum_necessary", False):
            findings.append({
                "control": "minimum_necessary_access",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": "Minimum necessary access principle not enforced per Privacy Rule 164.502(b)",
            })
            compliant = False
        else:
            findings.append({"control": "minimum_necessary_access", "status": "PASS", "severity": "INFO", "detail": "Minimum necessary access enforced"})

        # Check business associate agreements (164.308(b)(1))
        if not controls.get("baa_executed", False):
            findings.append({
                "control": "business_associate_agreements",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": "Business Associate Agreements not executed per 164.308(b)(1)",
            })
            compliant = False
        else:
            findings.append({"control": "business_associate_agreements", "status": "PASS", "severity": "INFO", "detail": "BAAs executed with all business associates"})

        # Check PHI handling procedures
        for handling in phi_handling:
            if handling.get("type") == "disposal" and not handling.get("secure_disposal", False):
                findings.append({
                    "control": "secure_disposal",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "detail": "PHI not securely disposed of per 164.310(d)(2)",
                })
                compliant = False

        # Check workforce training (164.308(a)(5))
        if not controls.get("workforce_training", False):
            findings.append({
                "control": "workforce_security_training",
                "status": "FAIL",
                "severity": "MEDIUM",
                "detail": "HIPAA security awareness training not conducted per 164.308(a)(5)",
            })
            compliant = False
        else:
            findings.append({"control": "workforce_security_training", "status": "PASS", "severity": "INFO", "detail": "Workforce training conducted"})

        # Check risk assessment (164.308(a)(1)(ii)(A))
        if not controls.get("risk_assessment", False):
            findings.append({
                "control": "risk_assessment",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": "Risk assessment not performed per 164.308(a)(1)(ii)(A)",
            })
            compliant = False
        else:
            findings.append({"control": "risk_assessment", "status": "PASS", "severity": "INFO", "detail": "Risk assessment completed"})

        score = sum(1 for f in findings if f["status"] == "PASS") / max(len(findings), 1)

        elapsed = time.monotonic() - start
        metrics.inc_counter("compliance.hipaa_check")
        metrics.observe_histogram("compliance.hipaa_check.duration", elapsed)

        span.set_attribute("hipaa.compliant", compliant)
        span.set_attribute("hipaa.score", score)

        result = {
            "framework": "HIPAA",
            "compliant": compliant,
            "score": round(score, 2),
            "findings": findings,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "checks_performed": len(findings),
        }

        logger.info(
            "hipaa_check_completed",
            compliant=compliant,
            score=score,
            findings=len(findings),
        )

        return result


def pci_check(
    system_config: dict[str, Any],
    card_data_handling: list[dict[str, Any]],
    controls: dict[str, Any],
) -> dict[str, Any]:
    """Check compliance with PCI-DSS (Payment Card Industry Data Security Standard).

    Validates cardholder data encryption, network segmentation, access controls,
    vulnerability management, and secure development practices.

    Args:
        system_config: System configuration including merchant level and SAQ type.
        card_data_handling: List of cardholder data handling procedures.
        controls: Security controls mapped by control ID.

    Returns:
        Dict with compliant (bool), score (float), findings (list), and metadata.

    Example:
        >>> result = pci_check(
        ...     system_config={"merchant_level": "level_1"},
        ...     card_data_handling=[{"type": "storage", "masked": True}],
        ...     controls={"network_segmentation": True, "encryption": True},
        ... )
    """
    start = time.monotonic()
    metrics = get_metrics()
    findings: list[dict[str, Any]] = []
    compliant = True

    with create_span("pci_check") as span:
        # Check network segmentation (Req 1)
        if not controls.get("network_segmentation", False):
            findings.append({
                "control": "network_segmentation",
                "status": "FAIL",
                "severity": "CRITICAL",
                "detail": "Cardholder data environment not properly segmented (PCI-DSS Req 1)",
            })
            compliant = False
        else:
            findings.append({"control": "network_segmentation", "status": "PASS", "severity": "INFO", "detail": "CDE properly segmented"})

        # Check firewall configuration (Req 1)
        if not controls.get("firewall_config", False):
            findings.append({
                "control": "firewall_configuration",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": "Firewall configuration not reviewed per PCI-DSS Req 1",
            })
            compliant = False
        else:
            findings.append({"control": "firewall_configuration", "status": "PASS", "severity": "INFO", "detail": "Firewalls properly configured"})

        # Check cardholder data encryption at rest (Req 3)
        if not controls.get("chd_encryption_at_rest", False):
            findings.append({
                "control": "chd_encryption_at_rest",
                "status": "FAIL",
                "severity": "CRITICAL",
                "detail": "Cardholder data not encrypted at rest per PCI-DSS Req 3",
            })
            compliant = False
        else:
            findings.append({"control": "chd_encryption_at_rest", "status": "PASS", "severity": "INFO", "detail": "CHD encrypted at rest"})

        # Check cardholder data encryption in transit (Req 4)
        if not controls.get("chd_encryption_in_transit", False):
            findings.append({
                "control": "chd_encryption_in_transit",
                "status": "FAIL",
                "severity": "CRITICAL",
                "detail": "Cardholder data not encrypted in transit per PCI-DSS Req 4",
            })
            compliant = False
        else:
            findings.append({"control": "chd_encryption_in_transit", "status": "PASS", "severity": "INFO", "detail": "CHD encrypted in transit"})

        # Check PAN masking (Req 3.3)
        for handling in card_data_handling:
            if handling.get("type") == "display" and not handling.get("pan_masked", False):
                findings.append({
                    "control": "pan_masking",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "detail": "Primary Account Number not masked on display per Req 3.3",
                })
                compliant = False

        if not any(f["control"] == "pan_masking" for f in findings):
            findings.append({"control": "pan_masking", "status": "PASS", "severity": "INFO", "detail": "PAN properly masked"})

        # Check access controls (Req 7, 8)
        access_controls = controls.get("access_controls", {})
        if not access_controls.get("role_based", False):
            findings.append({
                "control": "access_control_rbac",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": "Role-based access control not implemented per PCI-DSS Req 7",
            })
            compliant = False
        else:
            findings.append({"control": "access_control_rbac", "status": "PASS", "severity": "INFO", "detail": "RBAC implemented"})

        if not access_controls.get("mfa", False):
            findings.append({
                "control": "multi_factor_authentication",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": "Multi-factor authentication not required for CDE access per Req 8",
            })
            compliant = False
        else:
            findings.append({"control": "multi_factor_authentication", "status": "PASS", "severity": "INFO", "detail": "MFA enforced for CDE access"})

        # Check unique IDs (Req 8)
        if not access_controls.get("unique_ids", False):
            findings.append({
                "control": "unique_user_ids",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": "Unique user IDs not assigned per PCI-DSS Req 8",
            })
            compliant = False
        else:
            findings.append({"control": "unique_user_ids", "status": "PASS", "severity": "INFO", "detail": "Unique user IDs assigned"})

        # Check vulnerability management (Req 6, 11)
        if not controls.get("vulnerability_scanning", False):
            findings.append({
                "control": "vulnerability_scanning",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": "Regular vulnerability scanning not performed per Req 11",
            })
            compliant = False
        else:
            findings.append({"control": "vulnerability_scanning", "status": "PASS", "severity": "INFO", "detail": "Vulnerability scanning active"})

        if not controls.get("secure_development", False):
            findings.append({
                "control": "secure_development",
                "status": "FAIL",
                "severity": "MEDIUM",
                "detail": "Secure development lifecycle not followed per Req 6",
            })
            compliant = False
        else:
            findings.append({"control": "secure_development", "status": "PASS", "severity": "INFO", "detail": "Secure SDLC followed"})

        # Check audit logging (Req 10)
        if not controls.get("audit_logging", False):
            findings.append({
                "control": "audit_logging",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": "Audit logging not enabled for all CDE access per Req 10",
            })
            compliant = False
        else:
            findings.append({"control": "audit_logging", "status": "PASS", "severity": "INFO", "detail": "Audit logging enabled"})

        # Check log monitoring (Req 10.6)
        if not controls.get("log_monitoring", False):
            findings.append({
                "control": "log_monitoring",
                "status": "FAIL",
                "severity": "MEDIUM",
                "detail": "Logs not reviewed daily per PCI-DSS Req 10.6",
            })
            compliant = False
        else:
            findings.append({"control": "log_monitoring", "status": "PASS", "severity": "INFO", "detail": "Daily log review active"})

        # Check security policy (Req 12)
        if not controls.get("security_policy", False):
            findings.append({
                "control": "information_security_policy",
                "status": "FAIL",
                "severity": "MEDIUM",
                "detail": "Information security policy not maintained per Req 12",
            })
            compliant = False
        else:
            findings.append({"control": "information_security_policy", "status": "PASS", "severity": "INFO", "detail": "Security policy maintained"})

        score = sum(1 for f in findings if f["status"] == "PASS") / max(len(findings), 1)

        elapsed = time.monotonic() - start
        metrics.inc_counter("compliance.pci_check")
        metrics.observe_histogram("compliance.pci_check.duration", elapsed)

        span.set_attribute("pci.compliant", compliant)
        span.set_attribute("pci.score", score)

        result = {
            "framework": "PCI-DSS",
            "compliant": compliant,
            "score": round(score, 2),
            "findings": findings,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "checks_performed": len(findings),
        }

        logger.info(
            "pci_check_completed",
            compliant=compliant,
            score=score,
            findings=len(findings),
        )

        return result


def compliance_report(
    checks: list[dict[str, Any]],
    framework: str,
    scope: dict[str, Any],
) -> dict[str, Any]:
    """Generate a comprehensive compliance report from multiple check results.

    Aggregates individual compliance checks into a unified report with
    executive summary, detailed findings, and remediation recommendations.

    Args:
        checks: List of compliance check results from lgpd_check, gdpr_check, etc.
        framework: The compliance framework name (e.g., "SOC2", "ISO27001", "multi").
        scope: Scope definition including systems, regions, and data types.

    Returns:
        Dict with report_id, framework, overall_status, summary, findings, and metadata.

    Example:
        >>> report = compliance_report(
        ...     checks=[lgpd_result, gdpr_result],
        ...     framework="multi",
        ...     scope={"systems": ["api", "web"], "regions": ["us", "eu"]},
        ... )
    """
    start = time.monotonic()
    metrics = get_metrics()

    with create_span("compliance_report") as span:
        report_id = hashlib.sha256(
            f"{framework}-{scope}-{datetime.now(timezone.utc).isoformat()}".encode()
        ).hexdigest()[:16]

        total_checks = len(checks)
        compliant_checks = sum(1 for c in checks if c.get("compliant", False))
        overall_score = sum(c.get("score", 0) for c in checks) / max(total_checks, 1)

        all_findings: list[dict[str, Any]] = []
        critical_findings: list[dict[str, Any]] = []
        high_findings: list[dict[str, Any]] = []

        for check in checks:
            fw = check.get("framework", "unknown")
            for finding in check.get("findings", []):
                enriched = {**finding, "framework": fw}
                all_findings.append(enriched)
                if finding.get("severity") == "CRITICAL":
                    critical_findings.append(enriched)
                elif finding.get("severity") == "HIGH":
                    high_findings.append(enriched)

        overall_status = "COMPLIANT" if compliant_checks == total_checks else "NON_COMPLIANT"
        if critical_findings:
            overall_status = "CRITICAL_NON_COMPLIANT"
        elif overall_score >= 0.8:
            overall_status = "PARTIALLY_COMPLIANT"

        # Generate remediation recommendations
        remediation: list[dict[str, Any]] = []
        for finding in critical_findings + high_findings:
            remediation.append({
                "control": finding["control"],
                "framework": finding["framework"],
                "priority": "P1" if finding["severity"] == "CRITICAL" else "P2",
                "action": f"Implement {finding['control']} control to address: {finding['detail']}",
                "severity": finding["severity"],
            })

        elapsed = time.monotonic() - start
        metrics.inc_counter("compliance.report_generated")
        metrics.observe_histogram("compliance.report.duration", elapsed)

        span.set_attribute("report.framework", framework)
        span.set_attribute("report.status", overall_status)

        report = {
            "report_id": report_id,
            "framework": framework,
            "scope": scope,
            "overall_status": overall_status,
            "summary": {
                "total_checks": total_checks,
                "compliant_checks": compliant_checks,
                "overall_score": round(overall_score, 2),
                "critical_findings": len(critical_findings),
                "high_findings": len(high_findings),
                "total_findings": len(all_findings),
            },
            "findings": all_findings,
            "remediation": remediation,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "valid_until": None,
        }

        logger.info(
            "compliance_report_generated",
            report_id=report_id,
            framework=framework,
            status=overall_status,
            score=overall_score,
        )

        return report


def audit_trail(
    events: list[dict[str, Any]],
    user_actions: list[dict[str, Any]],
    data_changes: list[dict[str, Any]],
) -> dict[str, Any]:
    """Generate an immutable audit trail from security events, user actions, and data changes.

    Creates a cryptographically verifiable audit trail with chain-of-custody
    hashing for tamper detection.

    Args:
        events: List of security events with timestamps and severity.
        user_actions: List of user actions with user ID, action type, and target.
        data_changes: List of data modifications with before/after state hashes.

    Returns:
        Dict with trail_id, entries (list), chain_hash, and metadata.

    Example:
        >>> trail = audit_trail(
        ...     events=[{"type": "login", "severity": "info"}],
        ...     user_actions=[{"user": "admin", "action": "update_role"}],
        ...     data_changes=[{"table": "users", "operation": "update"}],
        ... )
    """
    start = time.monotonic()
    metrics = get_metrics()

    with create_span("audit_trail") as span:
        entries: list[dict[str, Any]] = []
        prev_hash = "0" * 64

        # Process security events
        for event in events:
            entry_hash = hashlib.sha256(
                f"{prev_hash}-{json.dumps(event, sort_keys=True)}".encode()
            ).hexdigest()
            entries.append({
                "type": "security_event",
                "timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "event_type": event.get("type", "unknown"),
                "severity": event.get("severity", "info"),
                "details": event,
                "entry_hash": entry_hash,
                "prev_hash": prev_hash,
            })
            prev_hash = entry_hash

        # Process user actions
        for action in user_actions:
            entry_hash = hashlib.sha256(
                f"{prev_hash}-{json.dumps(action, sort_keys=True)}".encode()
            ).hexdigest()
            entries.append({
                "type": "user_action",
                "timestamp": action.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "user_id": action.get("user_id", "unknown"),
                "action": action.get("action", "unknown"),
                "target": action.get("target"),
                "details": action,
                "entry_hash": entry_hash,
                "prev_hash": prev_hash,
            })
            prev_hash = entry_hash

        # Process data changes
        for change in data_changes:
            entry_hash = hashlib.sha256(
                f"{prev_hash}-{json.dumps(change, sort_keys=True)}".encode()
            ).hexdigest()
            entries.append({
                "type": "data_change",
                "timestamp": change.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "resource": change.get("resource", "unknown"),
                "operation": change.get("operation", "unknown"),
                "before_hash": change.get("before_hash"),
                "after_hash": change.get("after_hash"),
                "details": change,
                "entry_hash": entry_hash,
                "prev_hash": prev_hash,
            })
            prev_hash = entry_hash

        chain_hash = prev_hash
        trail_id = hashlib.sha256(
            f"audit-{chain_hash}-{datetime.now(timezone.utc).isoformat()}".encode()
        ).hexdigest()[:16]

        elapsed = time.monotonic() - start
        metrics.inc_counter("compliance.audit_trail_created")
        metrics.observe_histogram("compliance.audit_trail.duration", elapsed)
        metrics.set_gauge("compliance.audit_trail.entries", len(entries))

        span.set_attribute("audit.entries", len(entries))
        span.set_attribute("audit.trail_id", trail_id)

        result = {
            "trail_id": trail_id,
            "entries": entries,
            "entry_count": len(entries),
            "chain_hash": chain_hash,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "tamper_evident": True,
        }

        logger.info(
            "audit_trail_created",
            trail_id=trail_id,
            entries=len(entries),
            chain_hash=chain_hash[:16],
        )

        return result


def policy_as_code(
    policies: list[dict[str, Any]],
    context: dict[str, Any],
    enforcement: dict[str, Any],
) -> dict[str, Any]:
    """Evaluate and enforce security policies defined as code.

    Parses policy definitions, evaluates them against the provided context,
    and applies enforcement actions for policy violations.

    Args:
        policies: List of policy definitions with conditions and actions.
        context: Current system state and resource attributes for evaluation.
        enforcement: Enforcement configuration including mode and notification settings.

    Returns:
        Dict with evaluation_id, results per policy, violations, and actions taken.

    Example:
        >>> result = policy_as_code(
        ...     policies=[{"id": "POL-001", "condition": "encryption == 'AES-256'"}],
        ...     context={"encryption": "AES-256", "region": "us-east-1"},
        ...     enforcement={"mode": "enforce", "notify": True},
        ... )
    """
    start = time.monotonic()
    metrics = get_metrics()

    with create_span("policy_as_code") as span:
        evaluation_id = hashlib.sha256(
            f"policy-{datetime.now(timezone.utc).isoformat()}".encode()
        ).hexdigest()[:16]

        results: list[dict[str, Any]] = []
        violations: list[dict[str, Any]] = []
        actions_taken: list[dict[str, Any]] = []
        mode = enforcement.get("mode", "audit")

        for policy in policies:
            policy_id = policy.get("id", "unknown")
            condition = policy.get("condition", {})
            severity = policy.get("severity", "medium")

            # Evaluate policy condition against context
            passed = _evaluate_condition(condition, context)

            result_entry = {
                "policy_id": policy_id,
                "passed": passed,
                "severity": severity,
                "evaluated_at": datetime.now(timezone.utc).isoformat(),
            }
            results.append(result_entry)

            if not passed:
                violation = {
                    "policy_id": policy_id,
                    "severity": severity,
                    "condition": condition,
                    "context_snapshot": {k: context.get(k) for k in condition.keys()},
                    "message": policy.get("message", f"Policy {policy_id} violated"),
                }
                violations.append(violation)

                # Apply enforcement actions
                if mode == "enforce":
                    action = policy.get("on_violation", {})
                    action_type = action.get("type", "block")
                    actions_taken.append({
                        "policy_id": policy_id,
                        "action": action_type,
                        "applied_at": datetime.now(timezone.utc).isoformat(),
                        "status": "applied",
                    })

                    if action_type == "block":
                        logger.warning(
                            "policy_violation_blocked",
                            policy_id=policy_id,
                            severity=severity,
                        )
                    elif action_type == "quarantine":
                        logger.warning(
                            "policy_violation_quarantine",
                            policy_id=policy_id,
                            severity=severity,
                        )
                elif mode == "audit":
                    actions_taken.append({
                        "policy_id": policy_id,
                        "action": "log",
                        "applied_at": datetime.now(timezone.utc).isoformat(),
                        "status": "logged",
                    })

                # Send notifications if configured
                if enforcement.get("notify", False):
                    actions_taken.append({
                        "policy_id": policy_id,
                        "action": "notify",
                        "channels": enforcement.get("channels", ["log"]),
                        "applied_at": datetime.now(timezone.utc).isoformat(),
                        "status": "sent",
                    })

        total_policies = len(policies)
        passed_policies = sum(1 for r in results if r["passed"])
        compliance_rate = passed_policies / max(total_policies, 1)

        elapsed = time.monotonic() - start
        metrics.inc_counter("compliance.policy_evaluation")
        metrics.observe_histogram("compliance.policy.duration", elapsed)
        metrics.set_gauge("compliance.policy.violations", len(violations))

        span.set_attribute("policy.evaluation_id", evaluation_id)
        span.set_attribute("policy.violations", len(violations))
        span.set_attribute("policy.mode", mode)

        result = {
            "evaluation_id": evaluation_id,
            "mode": mode,
            "total_policies": total_policies,
            "passed": passed_policies,
            "failed": len(violations),
            "compliance_rate": round(compliance_rate, 2),
            "results": results,
            "violations": violations,
            "actions_taken": actions_taken,
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "policy_evaluation_completed",
            evaluation_id=evaluation_id,
            violations=len(violations),
            mode=mode,
        )

        return result


def _evaluate_condition(condition: dict[str, Any], context: dict[str, Any]) -> bool:
    """Evaluate a policy condition against the current context.

    Args:
        condition: Policy condition as key-value pairs or operator expressions.
        context: Current system state to evaluate against.

    Returns:
        True if the condition is satisfied, False otherwise.
    """
    for key, expected in condition.items():
        actual = context.get(key)

        if isinstance(expected, dict):
            # Handle operator-based conditions
            if "equals" in expected and actual != expected["equals"]:
                return False
            if "not_equals" in expected and actual == expected["not_equals"]:
                return False
            if "in" in expected and actual not in expected["in"]:
                return False
            if "not_in" in expected and actual in expected["not_in"]:
                return False
            if "min" in expected and (actual is None or actual < expected["min"]):
                return False
            if "max" in expected and (actual is None or actual > expected["max"]):
                return False
            if "contains" in expected and expected["contains"] not in str(actual):
                return False
            if "regex" in expected:
                import re
                if not re.search(expected["regex"], str(actual)):
                    return False
        else:
            # Simple equality check
            if actual != expected:
                return False

    return True


def realtime_security_dashboard(
    metrics: dict[str, Any],
    alerts: list[dict[str, Any]],
    trends: dict[str, Any],
) -> dict[str, Any]:
    """Generate a real-time security dashboard from metrics, alerts, and trends.

    Aggregates live security data into a comprehensive dashboard view with
    threat levels, active incidents, and trend analysis.

    Args:
        metrics: Current security metrics including threat counts, response times, and coverage.
        alerts: Active security alerts with severity, type, and status.
        trends: Historical trend data for threat patterns and system health.

    Returns:
        Dict with dashboard_id, threat_level, summary, active_incidents, and widgets.

    Example:
        >>> dashboard = realtime_security_dashboard(
        ...     metrics={"threats_blocked": 150, "response_time_ms": 45},
        ...     alerts=[{"severity": "high", "type": "intrusion"}],
        ...     trends={"threat_volume": [10, 15, 12, 20]},
        ... )
    """
    start = time.monotonic()
    metrics_tracker = get_metrics()

    with create_span("realtime_security_dashboard") as span:
        dashboard_id = hashlib.sha256(
            f"dashboard-{datetime.now(timezone.utc).isoformat()}".encode()
        ).hexdigest()[:16]

        # Determine overall threat level
        active_alerts = [a for a in alerts if a.get("status") in ("active", "new", "investigating")]
        critical_alerts = [a for a in active_alerts if a.get("severity") == "critical"]
        high_alerts = [a for a in active_alerts if a.get("severity") == "high"]

        if critical_alerts:
            threat_level = "CRITICAL"
        elif high_alerts:
            threat_level = "HIGH"
        elif active_alerts:
            threat_level = "ELEVATED"
        else:
            threat_level = "LOW"

        # Build summary
        summary = {
            "total_metrics": len(metrics),
            "active_alerts": len(active_alerts),
            "critical_alerts": len(critical_alerts),
            "high_alerts": len(high_alerts),
            "threat_level": threat_level,
            "metrics": metrics,
        }

        # Active incidents
        active_incidents: list[dict[str, Any]] = []
        for alert in active_alerts:
            incident = {
                "id": alert.get("id", hashlib.sha256(json.dumps(alert, sort_keys=True).encode()).hexdigest()[:8]),
                "severity": alert.get("severity", "unknown"),
                "type": alert.get("type", "unknown"),
                "title": alert.get("title", "Unknown alert"),
                "detected_at": alert.get("detected_at", datetime.now(timezone.utc).isoformat()),
                "status": alert.get("status", "active"),
                "source": alert.get("source"),
                "target": alert.get("target"),
            }
            active_incidents.append(incident)

        # Trend analysis
        trend_analysis: dict[str, Any] = {}
        for key, values in trends.items():
            if isinstance(values, list) and len(values) >= 2:
                recent = values[-1]
                previous = values[-2]
                if previous > 0:
                    change_pct = ((recent - previous) / previous) * 100
                else:
                    change_pct = 100.0 if recent > 0 else 0.0
                trend_analysis[key] = {
                    "current": recent,
                    "previous": previous,
                    "change_pct": round(change_pct, 2),
                    "direction": "increasing" if change_pct > 0 else "decreasing" if change_pct < 0 else "stable",
                }

        # Widget data
        widgets = [
            {
                "type": "threat_level",
                "title": "Current Threat Level",
                "value": threat_level,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            },
            {
                "type": "alert_summary",
                "title": "Active Alerts",
                "value": len(active_alerts),
                "breakdown": {
                    "critical": len(critical_alerts),
                    "high": len(high_alerts),
                    "medium": sum(1 for a in active_alerts if a.get("severity") == "medium"),
                    "low": sum(1 for a in active_alerts if a.get("severity") == "low"),
                },
            },
            {
                "type": "metrics_overview",
                "title": "Security Metrics",
                "data": metrics,
            },
            {
                "type": "trend_analysis",
                "title": "Trend Analysis",
                "data": trend_analysis,
            },
        ]

        elapsed = time.monotonic() - start
        metrics_tracker.increment("compliance.dashboard_generated")
        metrics_tracker.histogram("compliance.dashboard.duration", elapsed)

        span.set_attribute("dashboard.threat_level", threat_level)
        span.set_attribute("dashboard.alerts", len(active_alerts))

        result = {
            "dashboard_id": dashboard_id,
            "threat_level": threat_level,
            "summary": summary,
            "active_incidents": active_incidents,
            "trend_analysis": trend_analysis,
            "widgets": widgets,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "refresh_interval_seconds": 30,
        }

        logger.info(
            "security_dashboard_generated",
            dashboard_id=dashboard_id,
            threat_level=threat_level,
            active_alerts=len(active_alerts),
        )

        return result


def tenant_isolation(
    tenant_config: dict[str, Any],
    network_policies: list[dict[str, Any]],
    data_segregation: dict[str, Any],
) -> dict[str, Any]:
    """Verify and enforce tenant isolation in a multi-tenant environment.

    Validates network segmentation, data segregation, access controls,
    and resource isolation between tenants.

    Args:
        tenant_config: Tenant configuration including ID, tier, and isolation requirements.
        network_policies: Network policies defining tenant traffic rules.
        data_segregation: Data segregation configuration including storage and encryption.

    Returns:
        Dict with tenant_id, isolation_status, checks, and recommendations.

    Example:
        >>> result = tenant_isolation(
        ...     tenant_config={"tenant_id": "tenant-001", "tier": "enterprise"},
        ...     network_policies=[{"tenant": "tenant-001", "allow": ["internal"]}],
        ...     data_segregation={"storage": "dedicated", "encryption": True},
        ... )
    """
    start = time.monotonic()
    metrics = get_metrics()

    with create_span("tenant_isolation") as span:
        tenant_id = tenant_config.get("tenant_id", "unknown")
        checks: list[dict[str, Any]] = []
        isolated = True

        # Check network isolation
        tenant_policies = [p for p in network_policies if p.get("tenant") == tenant_id]
        if not tenant_policies:
            checks.append({
                "check": "network_policies",
                "status": "FAIL",
                "severity": "CRITICAL",
                "detail": f"No network policies defined for tenant {tenant_id}",
            })
            isolated = False
        else:
            # Check for cross-tenant access
            for policy in tenant_policies:
                allowed = policy.get("allow", [])
                if any("other-tenant" in str(a) or "*" in str(a) for a in allowed):
                    checks.append({
                        "check": "cross_tenant_access",
                        "status": "FAIL",
                        "severity": "HIGH",
                        "detail": f"Policy allows cross-tenant access for {tenant_id}",
                    })
                    isolated = False

            if all(c["check"] != "cross_tenant_access" or c["status"] == "PASS" for c in checks):
                checks.append({
                    "check": "network_policies",
                    "status": "PASS",
                    "severity": "INFO",
                    "detail": f"Network policies properly configured for {tenant_id}",
                })

        # Check data segregation
        storage_mode = data_segregation.get("storage", "shared")
        if storage_mode == "dedicated":
            checks.append({
                "check": "data_storage_segregation",
                "status": "PASS",
                "severity": "INFO",
                "detail": "Dedicated storage for tenant isolation",
            })
        elif storage_mode == "shared":
            if data_segregation.get("row_level_security", False):
                checks.append({
                    "check": "data_storage_segregation",
                    "status": "PASS",
                    "severity": "INFO",
                    "detail": "Row-level security implemented for shared storage",
                })
            elif data_segregation.get("schema_separation", False):
                checks.append({
                    "check": "data_storage_segregation",
                    "status": "PASS",
                    "severity": "INFO",
                    "detail": "Schema separation implemented for shared storage",
                })
            else:
                checks.append({
                    "check": "data_storage_segregation",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "detail": "Shared storage without row-level security or schema separation",
                })
                isolated = False

        # Check tenant-specific encryption
        if data_segregation.get("tenant_specific_encryption", False):
            checks.append({
                "check": "tenant_encryption",
                "status": "PASS",
                "severity": "INFO",
                "detail": "Tenant-specific encryption keys in use",
            })
        elif data_segregation.get("encryption", False):
            checks.append({
                "check": "tenant_encryption",
                "status": "PASS",
                "severity": "INFO",
                "detail": "Encryption enabled (shared keys)",
            })
        else:
            checks.append({
                "check": "tenant_encryption",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": "No encryption configured for tenant data",
            })
            isolated = False

        # Check access control isolation
        access_controls = tenant_config.get("access_controls", {})
        if access_controls.get("tenant_scoped_roles", False):
            checks.append({
                "check": "access_control_isolation",
                "status": "PASS",
                "severity": "INFO",
                "detail": "Tenant-scoped roles prevent cross-tenant access",
            })
        else:
            checks.append({
                "check": "access_control_isolation",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": "Tenant-scoped roles not configured",
            })
            isolated = False

        # Check resource isolation
        resource_limits = tenant_config.get("resource_limits", {})
        if resource_limits.get("compute_isolation", False) or resource_limits.get("namespace_isolation", False):
            checks.append({
                "check": "resource_isolation",
                "status": "PASS",
                "severity": "INFO",
                "detail": "Compute or namespace isolation configured",
            })
        else:
            checks.append({
                "check": "resource_isolation",
                "status": "WARN",
                "severity": "MEDIUM",
                "detail": "No explicit compute or namespace isolation",
            })

        # Check audit isolation
        if data_segregation.get("tenant_audit_logs", False):
            checks.append({
                "check": "audit_log_isolation",
                "status": "PASS",
                "severity": "INFO",
                "detail": "Tenant-specific audit logs maintained",
            })
        else:
            checks.append({
                "check": "audit_log_isolation",
                "status": "WARN",
                "severity": "MEDIUM",
                "detail": "Audit logs not segregated by tenant",
            })

        score = sum(1 for c in checks if c["status"] == "PASS") / max(len(checks), 1)

        # Generate recommendations
        recommendations: list[str] = []
        failed_checks = [c for c in checks if c["status"] == "FAIL"]
        for fc in failed_checks:
            if fc["check"] == "network_policies":
                recommendations.append("Define explicit network policies restricting tenant traffic")
            elif fc["check"] == "cross_tenant_access":
                recommendations.append("Remove wildcard and cross-tenant rules from network policies")
            elif fc["check"] == "data_storage_segregation":
                recommendations.append("Implement row-level security or migrate to dedicated storage")
            elif fc["check"] == "tenant_encryption":
                recommendations.append("Enable tenant-specific encryption keys (BYOK recommended)")
            elif fc["check"] == "access_control_isolation":
                recommendations.append("Configure tenant-scoped RBAC roles")

        elapsed = time.monotonic() - start
        metrics.inc_counter("compliance.tenant_isolation_check")
        metrics.observe_histogram("compliance.tenant_isolation.duration", elapsed)

        span.set_attribute("tenant.id", tenant_id)
        span.set_attribute("tenant.isolated", isolated)

        result = {
            "tenant_id": tenant_id,
            "isolation_status": "ISOLATED" if isolated else "NOT_ISOLATED",
            "isolated": isolated,
            "score": round(score, 2),
            "checks": checks,
            "recommendations": recommendations,
            "tier": tenant_config.get("tier", "standard"),
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "tenant_isolation_check_completed",
            tenant_id=tenant_id,
            isolated=isolated,
            score=score,
        )

        return result


def multi_region_security(
    regions: list[dict[str, Any]],
    data_residency_rules: dict[str, Any],
    encryption: dict[str, Any],
) -> dict[str, Any]:
    """Evaluate multi-region security posture and data residency compliance.

    Checks encryption standards per region, data residency requirements,
    cross-region transfer controls, and regional compliance frameworks.

    Args:
        regions: List of region configurations with name, compliance frameworks, and settings.
        data_residency_rules: Rules mapping data types to allowed regions and restrictions.
        encryption: Encryption configuration per region including algorithms and key management.

    Returns:
        Dict with assessment_id, regions_status, residency_compliance, and recommendations.

    Example:
        >>> result = multi_region_security(
        ...     regions=[{"name": "us-east-1", "frameworks": ["SOC2"]}],
        ...     data_residency_rules={"pii": {"allowed_regions": ["us-east-1", "eu-west-1"]}},
        ...     encryption={"us-east-1": {"algorithm": "AES-256"}},
        ... )
    """
    start = time.monotonic()
    metrics = get_metrics()

    with create_span("multi_region_security") as span:
        assessment_id = hashlib.sha256(
            f"multi-region-{datetime.now(timezone.utc).isoformat()}".encode()
        ).hexdigest()[:16]

        regions_status: list[dict[str, Any]] = []
        residency_violations: list[dict[str, Any]] = []
        all_recommendations: list[str] = []

        for region in regions:
            region_name = region.get("name", "unknown")
            region_checks: list[dict[str, Any]] = []
            region_compliant = True

            # Check encryption standards
            region_encryption = encryption.get(region_name, {})
            algorithm = region_encryption.get("algorithm", "")
            if algorithm not in ("AES-256", "AES-128", "ChaCha20", "RSA-4096"):
                region_checks.append({
                    "check": "encryption_standard",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "detail": f"Weak or missing encryption algorithm in {region_name}: {algorithm}",
                })
                region_compliant = False
                all_recommendations.append(f"Upgrade encryption in {region_name} to AES-256 or stronger")
            else:
                region_checks.append({
                    "check": "encryption_standard",
                    "status": "PASS",
                    "severity": "INFO",
                    "detail": f"Strong encryption ({algorithm}) in {region_name}",
                })

            # Check key management
            if not region_encryption.get("key_management", ""):
                region_checks.append({
                    "check": "key_management",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "detail": f"No key management configured for {region_name}",
                })
                region_compliant = False
                all_recommendations.append(f"Configure KMS/HSM for {region_name}")
            else:
                region_checks.append({
                    "check": "key_management",
                    "status": "PASS",
                    "severity": "INFO",
                    "detail": f"Key management configured in {region_name}",
                })

            # Check regional compliance frameworks
            frameworks = region.get("frameworks", [])
            if not frameworks:
                region_checks.append({
                    "check": "compliance_frameworks",
                    "status": "WARN",
                    "severity": "MEDIUM",
                    "detail": f"No compliance frameworks mapped for {region_name}",
                })
                all_recommendations.append(f"Map compliance frameworks for {region_name}")
            else:
                region_checks.append({
                    "check": "compliance_frameworks",
                    "status": "PASS",
                    "severity": "INFO",
                    "detail": f"Frameworks active in {region_name}: {', '.join(frameworks)}",
                })

            # Check data residency rules
            restricted_regions = []
            for data_type, rules in data_residency_rules.items():
                restricted = rules.get("restricted_regions", [])
                restricted_regions.extend(restricted)

            if region_name in restricted_regions:
                region_checks.append({
                    "check": "data_residency",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "detail": f"Region {region_name} is restricted for certain data types",
                })
                region_compliant = False
                residency_violations.append({
                    "region": region_name,
                    "detail": f"Region is restricted per data residency rules",
                })
            else:
                region_checks.append({
                    "check": "data_residency",
                    "status": "PASS",
                    "severity": "INFO",
                    "detail": f"Region {region_name} complies with data residency rules",
                })

            # Check cross-region transfer controls
            if region.get("cross_region_transfer", False):
                if not region.get("transfer_encryption", False):
                    region_checks.append({
                        "check": "cross_region_transfer",
                        "status": "FAIL",
                        "severity": "HIGH",
                        "detail": f"Cross-region transfers enabled without encryption in {region_name}",
                    })
                    region_compliant = False
                    all_recommendations.append(f"Enable transfer encryption for cross-region traffic in {region_name}")
                else:
                    region_checks.append({
                        "check": "cross_region_transfer",
                        "status": "PASS",
                        "severity": "INFO",
                        "detail": f"Cross-region transfers encrypted in {region_name}",
                    })
            else:
                region_checks.append({
                    "check": "cross_region_transfer",
                    "status": "PASS",
                    "severity": "INFO",
                    "detail": f"Cross-region transfers disabled in {region_name}",
                })

            region_score = sum(1 for c in region_checks if c["status"] == "PASS") / max(len(region_checks), 1)

            regions_status.append({
                "region": region_name,
                "compliant": region_compliant,
                "score": round(region_score, 2),
                "checks": region_checks,
                "frameworks": frameworks,
            })

        # Check data residency compliance globally
        residency_compliance: dict[str, Any] = {
            "compliant": len(residency_violations) == 0,
            "violations": residency_violations,
            "rules_evaluated": len(data_residency_rules),
            "regions_evaluated": len(regions),
        }

        overall_compliant = all(r["compliant"] for r in regions_status)
        overall_score = sum(r["score"] for r in regions_status) / max(len(regions_status), 1)

        elapsed = time.monotonic() - start
        metrics.inc_counter("compliance.multi_region_assessment")
        metrics.observe_histogram("compliance.multi_region.duration", elapsed)

        span.set_attribute("multi_region.regions", len(regions))
        span.set_attribute("multi_region.compliant", overall_compliant)

        result = {
            "assessment_id": assessment_id,
            "overall_compliant": overall_compliant,
            "overall_score": round(overall_score, 2),
            "regions_status": regions_status,
            "residency_compliance": residency_compliance,
            "recommendations": list(set(all_recommendations)),
            "assessed_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "multi_region_security_assessment_completed",
            assessment_id=assessment_id,
            regions=len(regions),
            compliant=overall_compliant,
        )

        return result
