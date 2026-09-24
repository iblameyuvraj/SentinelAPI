"""Authentication Misconfiguration Detection & Probing Engine (OWASP API2:2023)."""

import json
import base64
import time
import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class AuthMutationVector:
    id: str
    name: str
    description: str
    headers: Dict[str, str]
    expected_status: List[int]
    cwe: str
    severity: str


@dataclass
class AuthAuditFinding:
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


def _base64url_encode(data: bytes) -> str:
    """Encodes bytes to base64url string without padding."""
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _base64url_decode(s: str) -> bytes:
    """Decodes base64url string with padding restoration."""
    padding = 4 - (len(s) % 4)
    if padding and padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s.encode("utf-8"))


def parse_jwt(token: str) -> Optional[Tuple[Dict[str, Any], Dict[str, Any], str]]:
    """Safely parses JWT string into (header_dict, payload_dict, signature_str)."""
    clean_token = token.strip()
    if clean_token.lower().startswith("bearer "):
        clean_token = clean_token[7:].strip()

    parts = clean_token.split(".")
    if len(parts) < 2:
        return None

    try:
        header_raw = _base64url_decode(parts[0])
        payload_raw = _base64url_decode(parts[1])
        header = json.loads(header_raw.decode("utf-8"))
        payload = json.loads(payload_raw.decode("utf-8"))
        sig = parts[2] if len(parts) >= 3 else ""
        return header, payload, sig
    except Exception:
        return None


def generate_auth_test_vectors(
    base_token: str = "",
    base_headers: Optional[Dict[str, str]] = None,
) -> List[AuthMutationVector]:
    """Generates standardized security probe vectors to audit OWASP API2:2023 compliance."""
    vectors: List[AuthMutationVector] = []
    base_hdrs = dict(base_headers or {})

    # 1. Missing Authentication (No Authorization header)
    no_auth_headers = {k: v for k, v in base_hdrs.items() if k.lower() not in ("authorization", "cookie")}
    vectors.append(
        AuthMutationVector(
            id="AUTH-01-NO-AUTH",
            name="Missing Authentication Header",
            description="Executes request completely omitting Authorization credentials.",
            headers=no_auth_headers,
            expected_status=[401, 403],
            cwe="CWE-306: Missing Authentication for Critical Function",
            severity="CRITICAL",
        )
    )

    # 2. Empty Bearer Header
    empty_bearer_headers = dict(base_hdrs)
    empty_bearer_headers["Authorization"] = "Bearer"
    vectors.append(
        AuthMutationVector(
            id="AUTH-02-EMPTY-BEARER",
            name="Empty Bearer Token Header",
            description="Sends 'Authorization: Bearer' with empty token value.",
            headers=empty_bearer_headers,
            expected_status=[401, 403],
            cwe="CWE-287: Improper Authentication",
            severity="CRITICAL",
        )
    )

    # 3. Arbitrary / Fabricated Token
    fake_token_headers = dict(base_hdrs)
    fake_token_headers["Authorization"] = "Bearer sentinel_unauthorized_fake_token_9999"
    vectors.append(
        AuthMutationVector(
            id="AUTH-03-INVALID-TOKEN",
            name="Arbitrary / Fabricated Bearer Token",
            description="Sends an invalid, unauthenticated fake token to test credential validation.",
            headers=fake_token_headers,
            expected_status=[401, 403],
            cwe="CWE-287: Improper Authentication",
            severity="CRITICAL",
        )
    )

    # Inspect if base_token is a JWT
    jwt_data = parse_jwt(base_token) if base_token else None

    # 4. JWT alg:none Signature Bypass Vector
    if jwt_data:
        _, payload, _ = jwt_data
    else:
        payload = {"sub": "sentinel-auditor", "role": "admin", "iat": int(time.time())}

    none_header_b64 = _base64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode("utf-8"))
    payload_b64 = _base64url_encode(json.dumps(payload).encode("utf-8"))
    none_jwt = f"{none_header_b64}.{payload_b64}."

    none_alg_headers = dict(base_hdrs)
    none_alg_headers["Authorization"] = f"Bearer {none_jwt}"
    vectors.append(
        AuthMutationVector(
            id="AUTH-04-ALG-NONE",
            name="JWT alg:none Signature Bypass",
            description="Crafts an unsigned JWT with header {'alg': 'none'} and stripped signature.",
            headers=none_alg_headers,
            expected_status=[401, 403],
            cwe="CWE-347: Improper Verification of Cryptographic Signature",
            severity="CRITICAL",
        )
    )

    # 5. Tampered Signature Vector
    if jwt_data:
        orig_hdr, orig_pay, orig_sig = jwt_data
        hdr_b64 = _base64url_encode(json.dumps(orig_hdr).encode("utf-8"))
        pay_b64 = _base64url_encode(json.dumps(orig_pay).encode("utf-8"))
        # Tamper signature characters
        tampered_sig = (orig_sig[:-6] + "INVALID") if len(orig_sig) >= 6 else "tampered_sig_123"
        tampered_jwt = f"{hdr_b64}.{pay_b64}.{tampered_sig}"
    else:
        hdr_b64 = _base64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode("utf-8"))
        pay_b64 = _base64url_encode(json.dumps({"sub": "admin", "role": "admin"}).encode("utf-8"))
        tampered_jwt = f"{hdr_b64}.{pay_b64}.FORGED_SIGNATURE_SENTINEL_PROBE"

    tampered_headers = dict(base_hdrs)
    tampered_headers["Authorization"] = f"Bearer {tampered_jwt}"
    vectors.append(
        AuthMutationVector(
            id="AUTH-05-TAMPERED-SIG",
            name="Tampered Cryptographic Signature",
            description="Sends valid token structure with corrupted HMAC/RSA signature bytes.",
            headers=tampered_headers,
            expected_status=[401, 403],
            cwe="CWE-347: Improper Verification of Cryptographic Signature",
            severity="CRITICAL",
        )
    )

    # 6. Expired Token Vector
    now = int(time.time())
    expired_payload = dict(payload)
    expired_payload["exp"] = now - 3600  # 1 hour ago
    expired_payload["iat"] = now - 7200
    expired_pay_b64 = _base64url_encode(json.dumps(expired_payload).encode("utf-8"))
    dummy_hdr_b64 = _base64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode("utf-8"))
    expired_jwt = f"{dummy_hdr_b64}.{expired_pay_b64}.EXPIRED_SIGNATURE_PROBE"

    expired_headers = dict(base_hdrs)
    expired_headers["Authorization"] = f"Bearer {expired_jwt}"
    vectors.append(
        AuthMutationVector(
            id="AUTH-06-EXPIRED-TOKEN",
            name="Expired Token Validation",
            description="Sends token with 'exp' timestamp in the past to test expiration enforcement.",
            headers=expired_headers,
            expected_status=[401, 403],
            cwe="CWE-613: Insufficient Session Expiration",
            severity="HIGH",
        )
    )

    # 7. Malformed Token Vector (Stack Trace & Exception Leakage Check)
    malformed_headers = dict(base_hdrs)
    malformed_headers["Authorization"] = "Bearer not.a.valid.jwt.payload.with.invalid.characters!@#$%"
    vectors.append(
        AuthMutationVector(
            id="AUTH-07-MALFORMED-TOKEN",
            name="Malformed Token & Verbose Error Leakage",
            description="Sends malformed token string to test exception handling and stack trace suppression.",
            headers=malformed_headers,
            expected_status=[400, 401, 403],
            cwe="CWE-209: Generation of Error Message Containing Sensitive Information",
            severity="MEDIUM",
        )
    )

    return vectors


def evaluate_auth_response(
    endpoint: str,
    method: str,
    vector: AuthMutationVector,
    status_code: int,
    response_body: str,
    base_url: str,
    is_public: bool = False,
) -> AuthAuditFinding:
    """Evaluates HTTP response against security standards for OWASP API2:2023."""
    is_vulnerable = False
    severity = "NONE"
    reason = "Endpoint properly enforced authentication check."
    cwe = vector.cwe

    # Format curl PoC
    header_args = " ".join([f"-H \"{k}: {v}\"" for k, v in vector.headers.items()])
    target_url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"
    poc_curl = f"curl -s -X {method} \"{target_url}\" {header_args}".strip()

    # Snippet for preview
    snippet = response_body.strip()
    if len(snippet) > 200:
        snippet = snippet[:197] + "..."

    # Check 1: Public endpoint baseline
    if is_public:
        if status_code in (200, 201, 204):
            return AuthAuditFinding(
                endpoint=endpoint,
                method=method,
                test_id=vector.id,
                test_name=vector.name,
                status_code=status_code,
                is_vulnerable=False,
                severity="NONE",
                reason="Public endpoint: Open access permitted as intended.",
                cwe=cwe,
                reproduction_curl=poc_curl,
                response_snippet=snippet,
                remediation="None required for designated public endpoints.",
            )

    # Check 2: Endpoint returns success (200, 201, 204) when missing/invalid credentials provided
    if status_code in (200, 201, 204):
        is_vulnerable = True
        severity = vector.severity

        if vector.id == "AUTH-01-NO-AUTH":
            reason = "CRITICAL: Private endpoint accessible without any Authorization header."
        elif vector.id == "AUTH-02-EMPTY-BEARER":
            reason = "CRITICAL: Server accepted empty Bearer token header without verification."
        elif vector.id == "AUTH-03-INVALID-TOKEN":
            reason = "CRITICAL: Server accepted arbitrary/fabricated Bearer token."
        elif vector.id == "AUTH-04-ALG-NONE":
            reason = "CRITICAL: JWT alg:none Signature Bypass. Server accepted unsigned JWT."
        elif vector.id == "AUTH-05-TAMPERED-SIG":
            reason = "CRITICAL: Missing Signature Verification. Server accepted forged signature."
        elif vector.id == "AUTH-06-EXPIRED-TOKEN":
            reason = "HIGH: Server accepted expired token without verifying 'exp' claim."
        else:
            reason = f"{severity}: Server accepted invalid authorization payload."

    # Check 3: Server crash / 500 error leaking stack traces or internal framework paths
    elif status_code >= 500:
        # Check for stack trace leakage
        has_stack = any(
            pattern in response_body.lower()
            for pattern in ("stack_trace", "at json.parse", "at decodejwt", "syntaxerror", "traceback (most recent", "node_modules", "exception in thread")
        )
        if has_stack:
            is_vulnerable = True
            severity = "MEDIUM"
            reason = "MEDIUM: Server returned HTTP 500 and leaked internal exception stack traces."
            cwe = "CWE-209: Information Exposure Through an Error Message"
        else:
            is_vulnerable = False
            reason = f"Server returned {status_code} server error (unhandled error, but no verbose trace detected)."

    # Check 4: Proper 401 Unauthorized or 403 Forbidden
    elif status_code in (401, 403):
        is_vulnerable = False
        severity = "NONE"
        reason = f"PROTECTED: Server correctly rejected invalid credentials with HTTP {status_code}."

    remediation = _generate_remediation(vector.id)

    return AuthAuditFinding(
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


def _generate_remediation(test_id: str) -> str:
    """Provides technical remediation guidance for the specific auth flaw."""
    if test_id in ("AUTH-01-NO-AUTH", "AUTH-02-EMPTY-BEARER", "AUTH-03-INVALID-TOKEN"):
        return (
            "Enforce mandatory authentication middleware on all protected API routes. "
            "Ensure requests without valid Authorization Bearer tokens immediately terminate with 401 Unauthorized "
            "before executing controller or business logic."
        )
    elif test_id == "AUTH-04-ALG-NONE":
        return (
            "Explicitly whitelist cryptographic algorithms in your JWT verification library (e.g. algorithms=['HS256']). "
            "Never allow algorithm header negotiation or 'none' algorithm tokens in production."
        )
    elif test_id == "AUTH-05-TAMPERED-SIG":
        return (
            "Always cryptographically verify the token signature using a strong secret key or public key. "
            "Never rely on simply decoding the JWT payload (e.g. jwt.decode(verify=False))."
        )
    elif test_id == "AUTH-06-EXPIRED-TOKEN":
        return (
            "Ensure the JWT verification engine checks the 'exp' (expiration) claim and rejects tokens whose expiration "
            "timestamp is in the past. Set short-lived access token lifespans (15-60 minutes)."
        )
    elif test_id == "AUTH-07-MALFORMED-TOKEN":
        return (
            "Wrap token parsing in robust try/catch blocks and return uniform 401 Unauthorized JSON responses. "
            "Disable debug error pages and stack traces in production environments."
        )
    return "Enforce zero-trust token validation, algorithm whitelisting, and strict authorization middleware."
