"""Rate Limiting & Resource Exhaustion Detection Engine (OWASP API4:2023)."""

from typing import Dict, Any, List
from dataclasses import dataclass


@dataclass
class RateLimitFinding:
    endpoint: str
    method: str
    total_requests: int
    success_count: int
    throttled_count: int
    error_count: int
    has_429: bool
    rate_limit_headers: Dict[str, str]
    is_vulnerable: bool
    severity: str
    reason: str
    cwe: str
    reproduction_curl: str
    remediation: str


SENSITIVE_ROUTE_PATTERNS = [
    "login",
    "signin",
    "auth",
    "token",
    "password",
    "reset",
    "otp",
    "register",
    "signup",
    "payment",
    "checkout",
    "transfer",
    "export",
    "download",
    "search",
]


def is_sensitive_endpoint(endpoint: str) -> bool:
    """Checks if an endpoint path handles authentication, OTPs, heavy search, or financial actions."""
    path_lower = endpoint.lower()
    return any(keyword in path_lower for keyword in SENSITIVE_ROUTE_PATTERNS)


def extract_rate_limit_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Finds RFC and proprietary rate limiting headers in HTTP response."""
    found = {}
    tracked_keys = (
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "retry-after",
        "x-rate-limit-limit",
        "x-rate-limit-remaining",
        "x-rate-limit-reset",
        "ratelimit-limit",
        "ratelimit-remaining",
        "ratelimit-reset",
    )

    for k, v in headers.items():
        if k.lower() in tracked_keys:
            found[k] = v

    return found


def evaluate_rate_limit_results(
    endpoint: str,
    method: str,
    burst_count: int,
    status_codes: List[int],
    headers: Dict[str, str],
    base_url: str,
    is_public: bool = False,
) -> RateLimitFinding:
    """Evaluates burst request telemetry to detect unrestricted resource consumption."""
    throttled_count = status_codes.count(429)
    success_count = sum(1 for s in status_codes if 200 <= s < 300)
    error_count = sum(1 for s in status_codes if s >= 500)
    has_429 = throttled_count > 0

    rate_headers = extract_rate_limit_headers(headers)
    has_headers = len(rate_headers) > 0

    is_sensitive = is_sensitive_endpoint(endpoint)
    is_vulnerable = False
    severity = "NONE"
    cwe = "CWE-770: Allocation of Resources Without Limits or Throttling"

    target_url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"
    reproduction_curl = (
        f"# Burst test reproducing unrestricted requests without HTTP 429:\n"
        f"for i in $(seq 1 {burst_count}); do\n"
        f"  curl -s -o /dev/null -w \"HTTP %{{http_code}}\\n\" -X {method} \"{target_url}\"\n"
        f"done"
    )

    # Evaluation Rules:
    # 1. Endpoint returned 429 Too Many Requests: PROTECTED
    if has_429:
        is_vulnerable = False
        severity = "NONE"
        reason = f"PROTECTED: Server correctly enforced rate limiting and returned HTTP 429 ({throttled_count}/{burst_count} throttled)."
        remediation = "Rate limiting is active. Ensure Retry-After and X-RateLimit-* headers are consistently provided."

    # 2. Public health baseline with no sensitive processing
    elif is_public and not is_sensitive:
        is_vulnerable = False
        severity = "NONE"
        reason = f"PASS (Baseline): Public service endpoint permitted {burst_count} requests without throttling."
        remediation = "Maintain general DDoS and CDN edge rate limits."

    # 3. Sensitive Endpoint (auth/login/otp/search/export) with ZERO 429s
    elif is_sensitive:
        is_vulnerable = True
        severity = "HIGH"
        reason = (
            f"HIGH VULNERABILITY: Sensitive route '{endpoint}' processed all {success_count}/{burst_count} requests "
            f"without throttling or returning HTTP 429 (Brute-force / Abuse Risk)."
        )
        remediation = (
            "Implement strict IP & user-level rate limiting on sensitive routes. "
            "For authentication and OTP endpoints, allow max 5 requests per minute, returning HTTP 429 with 'Retry-After: 60'."
        )

    # 4. Standard route with zero throttling and no headers
    else:
        is_vulnerable = True
        severity = "MEDIUM"
        reason = (
            f"MEDIUM VULNERABILITY: Endpoint permitted {burst_count} rapid requests with zero rate-limit headers "
            f"or throttling."
        )
        remediation = (
            "Enforce API gateway or reverse-proxy rate limiting (e.g. 60-120 req/min) "
            "to prevent server thread exhaustion and scraping."
        )

    return RateLimitFinding(
        endpoint=endpoint,
        method=method,
        total_requests=burst_count,
        success_count=success_count,
        throttled_count=throttled_count,
        error_count=error_count,
        has_429=has_429,
        rate_limit_headers=rate_headers,
        is_vulnerable=is_vulnerable,
        severity=severity,
        reason=reason,
        cwe=cwe,
        reproduction_curl=reproduction_curl,
        remediation=remediation,
    )
