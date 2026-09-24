"""Broken Function Level Authorization (BFLA) Detection Engine (OWASP API5:2023)."""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass


@dataclass
class BFLAProbeVector:
    id: str
    name: str
    description: str
    method: str
    payload: Optional[Dict[str, Any]]
    expected_status: List[int]
    cwe: str
    severity: str


@dataclass
class BFLAFinding:
    endpoint: str
    method: str
    test_id: str
    test_name: str
    status_code: int
    is_vulnerable: bool
    severity: str
    reason: str
    cwe: str
    reproduction_curl: str
    response_snippet: str
    remediation: str


ADMIN_ROUTE_PATTERNS = [
    "admin",
    "manage",
    "system",
    "config",
    "roles",
    "audit",
    "metrics",
    "logs",
    "backup",
    "root",
    "internal",
]


def is_admin_route(path: str) -> bool:
    """Checks if a path signifies administrative, superuser, or diagnostic functionality."""
    path_lower = path.lower()
    return any(keyword in path_lower for keyword in ADMIN_ROUTE_PATTERNS)


def generate_bfla_test_vectors(endpoint_path: str, declared_method: str) -> List[BFLAProbeVector]:
    """Generates targeted BFLA probe vectors for a given endpoint."""
    vectors: List[BFLAProbeVector] = []
    is_admin = is_admin_route(endpoint_path)

    # 1. Standard Function Access Probe with Low-Privilege Token
    vectors.append(
        BFLAProbeVector(
            id="BFLA-01-ROLE-EVAL",
            name="Standard User Access to Privileged Route",
            description="Executes endpoint using low-privilege (Role: user) authentication credentials.",
            method=declared_method.upper(),
            payload=None,
            expected_status=[403],
            cwe="CWE-285: Improper Authorization",
            severity="CRITICAL" if is_admin else "HIGH",
        )
    )

    # 2. HTTP Verb Tampering Probe (e.g. attempting DELETE or PUT on resources)
    if declared_method.upper() == "GET" and not ("public" in endpoint_path.lower() or "status" in endpoint_path.lower()):
        vectors.append(
            BFLAProbeVector(
                id="BFLA-02-VERB-TAMPERING-DELETE",
                name="HTTP Verb Tampering (DELETE Method Probe)",
                description="Attempts DELETE request using low-privilege credentials on read-only endpoints.",
                method="DELETE",
                payload=None,
                expected_status=[403, 405],
                cwe="CWE-654: Reliance on Client-Side Access Control (Verb Tampering)",
                severity="CRITICAL",
            )
        )

    # 3. Privilege Escalation Body Mutation Probe (on PUT/POST/PATCH)
    if declared_method.upper() in ("PUT", "POST", "PATCH") or "role" in endpoint_path.lower():
        vectors.append(
            BFLAProbeVector(
                id="BFLA-03-ROLE-ESCALATION",
                name="Privilege Escalation via Role Injection",
                description="Injects elevated privilege parameters ({'role': 'admin', 'is_admin': true}) in request body.",
                method="PUT" if declared_method.upper() == "GET" else declared_method.upper(),
                payload={"role": "admin", "is_admin": True, "permissions": ["*"]},
                expected_status=[403],
                cwe="CWE-269: Improper Privilege Management",
                severity="CRITICAL",
            )
        )

    return vectors


def evaluate_bfla_response(
    endpoint: str,
    method: str,
    vector: BFLAProbeVector,
    status_code: int,
    response_body: str,
    base_url: str,
    auth_header_value: str = "",
    is_public: bool = False,
) -> BFLAFinding:
    """Evaluates whether standard credentials executed unauthorized functions."""
    is_admin = is_admin_route(endpoint)
    is_vulnerable = False
    severity = "NONE"
    reason = "Endpoint properly enforced role authorization (403 Forbidden)."
    cwe = vector.cwe

    # Format cURL PoC
    target_url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"
    hdr_str = f"-H \"Authorization: {auth_header_value}\"" if auth_header_value else ""
    body_str = f"-H \"Content-Type: application/json\" -d '{{\"role\":\"admin\"}}'" if vector.payload else ""
    poc_curl = f"curl -s -X {method} \"{target_url}\" {hdr_str} {body_str}".strip()

    snippet = response_body.strip()
    if len(snippet) > 200:
        snippet = snippet[:197] + "..."

    # Check 1: Public endpoint baseline
    if is_public:
        return BFLAFinding(
            endpoint=endpoint,
            method=method,
            test_id=vector.id,
            test_name=vector.name,
            status_code=status_code,
            is_vulnerable=False,
            severity="NONE",
            reason="Public endpoint: Functionality accessible without privilege checks.",
            cwe=cwe,
            reproduction_curl=poc_curl,
            response_snippet=snippet,
            remediation="None required for public endpoints.",
        )

    # Check 2: Success response (200, 201, 204) on sensitive admin/destructive functions
    if status_code in (200, 201, 204):
        if is_admin or method.upper() == "DELETE" or vector.id in ("BFLA-02-VERB-TAMPERING-DELETE", "BFLA-03-ROLE-ESCALATION") or "role" in endpoint.lower():
            is_vulnerable = True
            severity = vector.severity if vector.severity != "NONE" else "CRITICAL"

            if vector.id == "BFLA-01-ROLE-EVAL":
                if method.upper() == "DELETE":
                    reason = f"CRITICAL: Destructive action allowed! Low-privilege user executed DELETE on '{endpoint}'."
                else:
                    reason = f"CRITICAL: Non-admin user successfully invoked administrative endpoint '{endpoint}'."
            elif vector.id == "BFLA-02-VERB-TAMPERING-DELETE":
                reason = f"CRITICAL: HTTP Verb Tampering succeeded. Non-admin user executed DELETE on '{endpoint}'."
            elif vector.id == "BFLA-03-ROLE-ESCALATION":
                reason = f"CRITICAL: Self-privilege escalation succeeded. Account updated with admin permissions."
            else:
                reason = f"CRITICAL: Function level authorization failed on {method} {endpoint}."

    # Check 3: Properly rejected with 403 Forbidden (RBAC Enforced)
    elif status_code == 403:
        is_vulnerable = False
        severity = "NONE"
        reason = "PROTECTED: Server correctly denied unauthorized function invocation with HTTP 403 Forbidden (RBAC Enforced)."

    # Check 4: Unauthenticated (HTTP 401 Unauthorized)
    elif status_code == 401:
        is_vulnerable = False
        severity = "INFO"
        reason = "AUTH REQUIRED (HTTP 401): The request was rejected as unauthenticated. Ensure a valid active low-privilege user token is configured."

    # Check 5: Method Not Allowed or Not Found
    elif status_code in (404, 405):
        is_vulnerable = False
        severity = "NONE"
        reason = f"PROTECTED / INACTIVE: Server returned HTTP {status_code}."

    remediation = (
        "Enforce strict Role-Based Access Control (RBAC) middleware. "
        "Explicitly verify that req.user.role === 'admin' before executing sensitive controller actions. "
        "Never rely solely on client-side button visibility to protect administrative endpoints."
    )

    return BFLAFinding(
        endpoint=endpoint,
        method=method,
        test_id=vector.id,
        test_name=vector.name,
        status_code=status_code,
        is_vulnerable=is_vulnerable,
        severity=severity,
        reason=reason,
        cwe=cwe,
        reproduction_curl=poc_curl,
        response_snippet=snippet,
        remediation=remediation,
    )
