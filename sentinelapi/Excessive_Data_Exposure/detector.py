"""Excessive Data Exposure & Sensitive Data Leakage Detection Engine (OWASP API3:2023)."""
import re
from typing import Dict, Any, List, Set, Tuple, Optional

# Sensitive Field Rules Dictionary: maps keyword regex to (Category, Severity, Reason)
SENSITIVE_FIELD_RULES = [
    # Critical: Authentication Credentials & Secrets
    (r"(^|_)password($|_|hash|salt)", "Authentication Credential", "CRITICAL", "Password or credential hash exposed in response"),
    (r"(^|_)pass($|_|wd)", "Authentication Credential", "CRITICAL", "Possible password field"),
    (r"(^|_)secret($|_|key|val)", "Secret Key", "CRITICAL", "Application or cryptographic secret exposed"),
    (r"(^|_)private_key($|_)", "Cryptographic Key", "CRITICAL", "Private key exposed directly in JSON response"),
    (r"(^|_)reset_token($|_)", "Auth Token", "CRITICAL", "Password reset token exposed (allows account takeover)"),
    (r"(^|_)mfa_secret($|_|key|seed)", "MFA Credential", "CRITICAL", "Multi-factor authentication seed or secret exposed"),
    (r"(^|_)cvv($|_|cvc)", "Payment Card", "CRITICAL", "Payment card verification code exposed"),
    (r"(^|_)ssn($|_|number)", "National Identifier", "CRITICAL", "Social Security Number exposed"),

    # High: Financial & PII Identifiers
    (r"(^|_)credit_card($|_|num|number)", "Financial Record", "HIGH", "Full credit card identifier exposed"),
    (r"(^|_)card_last4($|_)", "Payment Card", "MEDIUM", "Card last 4 digits exposed"),
    (r"(^|_)stripe_customer_id($|_)", "Payment Gateway", "HIGH", "Payment gateway customer account identifier exposed"),
    (r"(^|_)salary($|_|amount|val)", "Financial PII", "HIGH", "Confidential compensation data exposed"),
    (r"(^|_)bank_account($|_|num|no)", "Financial Record", "HIGH", "Bank account number exposed"),
    (r"(^|_)tax_id($|_|pan)", "Tax Identifier", "HIGH", "Tax or PAN identification exposed"),

    # High: Internal Privileges & Business Secrets
    (r"(^|_)internal_role($|_)", "Privilege Level", "HIGH", "Internal authorization role exposed"),
    (r"(^|_)is_admin($|_)", "Privilege Flag", "HIGH", "Administrative flag exposed in client response"),
    (r"(^|_)super_user($|_|admin)", "Privilege Flag", "HIGH", "Superuser status exposed"),
    (r"(^|_)permissions($|_)", "Authorization Model", "HIGH", "Internal permission matrix exposed"),
    (r"(^|_)wholesale_vendor_token($|_)", "Proprietary API Token", "HIGH", "Wholesale supplier vendor token leaked"),
    (r"(^|_)supplier_cost($|_|price)", "Proprietary Pricing", "HIGH", "Confidential supplier wholesale pricing leaked"),
    (r"(^|_)markup_margin($|_|percentage)", "Proprietary Algorithm", "HIGH", "Internal profit margin algorithm exposed"),

    # Medium: Session & Internal Metadata
    (r"(^|_)api_key($|_)", "API Credential", "HIGH", "API Key or bearer token exposed"),
    (r"(^|_)access_token($|_)", "Session Token", "HIGH", "User session access token exposed"),
    (r"(^|_)refresh_token($|_)", "Session Token", "HIGH", "Session refresh token exposed"),
    (r"(^|_)failed_login_attempts($|_)", "Internal Audit", "MEDIUM", "Brute-force security counter exposed"),
    (r"(^|_)debug_trace_code($|_|trace)", "System Diagnostic", "MEDIUM", "Internal system debug/trace identifier exposed"),
    (r"(^|_)shadow_ban($|_)", "Internal Flag", "MEDIUM", "Platform moderation status exposed"),
    (r"(^|_)deleted_at($|_)", "Soft Delete Metadata", "LOW", "Internal database soft-deletion timestamp exposed"),
]

# Sensitive Value Regex Patterns
SENSITIVE_VALUE_PATTERNS = [
    (re.compile(r"^\$2[abxy]?\$\d{2}\$[A-Za-z0-9./]{53}$"), "BCrypt Password Hash", "CRITICAL"),
    (re.compile(r"^eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$"), "JWT Bearer Token", "HIGH"),
    (re.compile(r"^\d{3}-\d{2}-\d{4}$"), "Social Security Number Format", "CRITICAL"),
    (re.compile(r"^-----BEGIN [A-Z ]*PRIVATE KEY-----"), "Raw PEM Private Key", "CRITICAL"),
    (re.compile(r"^(sk_live|wh_live|whsec_)[0-9a-zA-Z_]{16,}$"), "Production Secret Token", "CRITICAL"),
]

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}


def detect_sensitive_properties(
    data: Any,
    parent_path: str = "",
    declared_schema_keys: Optional[Set[str]] = None,
) -> List[Dict[str, Any]]:
    """Recursively walks JSON data to detect sensitive keys, values, and schema deviations."""
    findings = []

    if isinstance(data, dict):
        for key, value in data.items():
            current_path = f"{parent_path}.{key}" if parent_path else key
            lower_key = key.lower()

            # 1. Match against known sensitive field keyword rules
            matched_rule = False
            for pattern, category, severity, reason in SENSITIVE_FIELD_RULES:
                if re.search(pattern, lower_key):
                    findings.append({
                        "field_path": current_path,
                        "field_name": key,
                        "category": category,
                        "severity": severity,
                        "reason": reason,
                        "preview": _format_preview_val(value),
                    })
                    matched_rule = True
                    break

            # 2. Match against sensitive value formats (if value is a string and not already matched)
            if not matched_rule and isinstance(value, str):
                for val_regex, category, severity in SENSITIVE_VALUE_PATTERNS:
                    if val_regex.search(value):
                        findings.append({
                            "field_path": current_path,
                            "field_name": key,
                            "category": category,
                            "severity": severity,
                            "reason": f"Value matches format of {category}",
                            "preview": _format_preview_val(value),
                        })
                        matched_rule = True
                        break

            # 3. Check for Schema Drift / Undocumented Properties (if schema was provided)
            if not matched_rule and declared_schema_keys is not None:
                if key not in declared_schema_keys and parent_path == "":
                    # Undocumented root field
                    findings.append({
                        "field_path": current_path,
                        "field_name": key,
                        "category": "Undocumented Property",
                        "severity": "LOW",
                        "reason": "Property returned by API but not declared in OpenAPI schema",
                        "preview": _format_preview_val(value),
                    })

            # Recurse into nested structures
            if isinstance(value, (dict, list)):
                findings.extend(detect_sensitive_properties(value, current_path, None))

    elif isinstance(data, list):
        for idx, item in enumerate(data[:10]):  # check up to first 10 items
            findings.extend(detect_sensitive_properties(item, f"{parent_path}[{idx}]", declared_schema_keys))

    return findings


def analyze_endpoint_exposure(
    response_data: Any,
    declared_schema: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Evaluates an endpoint's response payload for Excessive Data Exposure."""
    declared_keys: Optional[Set[str]] = None
    if declared_schema and isinstance(declared_schema, dict):
        props = declared_schema.get("properties", {})
        if isinstance(props, dict):
            declared_keys = set(props.keys())

    findings = detect_sensitive_properties(response_data, declared_schema_keys=declared_keys)

    # Determine highest severity
    highest_severity = "NONE"
    highest_score = 0
    for f in findings:
        score = SEVERITY_ORDER.get(f["severity"], 0)
        if score > highest_score:
            highest_score = score
            highest_severity = f["severity"]

    # Filter critical & high issues for quick assessment
    critical_findings = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
    is_vulnerable = len(critical_findings) > 0 or len(findings) > 0 and highest_score >= 2

    return {
        "is_vulnerable": is_vulnerable,
        "severity": highest_severity,
        "findings_count": len(findings),
        "critical_count": len([f for f in findings if f["severity"] == "CRITICAL"]),
        "high_count": len([f for f in findings if f["severity"] == "HIGH"]),
        "medium_count": len([f for f in findings if f["severity"] == "MEDIUM"]),
        "low_count": len([f for f in findings if f["severity"] == "LOW"]),
        "findings": findings,
        "declared_keys": list(declared_keys) if declared_keys else [],
    }


def _format_preview_val(val: Any) -> str:
    """Formats value safely for display in UI table."""
    if val is None:
        return "null"
    if isinstance(val, (int, float, bool)):
        return str(val)
    if isinstance(val, str):
        if len(val) > 40:
            return f"{val[:37]}..."
        return val
    if isinstance(val, list):
        return f"[list of {len(val)} items]"
    if isinstance(val, dict):
        return f"{{object with {len(val)} keys}}"
    return str(val)[:40]
