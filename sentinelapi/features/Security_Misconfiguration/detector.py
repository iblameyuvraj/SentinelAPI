"""Security Misconfiguration (OWASP API8:2023) Detection & Auditing Engine.

Evaluates API endpoints for:
- Missing HTTP Security Headers (HSTS, CSP, nosniff, X-Frame-Options, Referrer-Policy)
- Server & Framework Fingerprinting (X-Powered-By, Server, X-AspNet-Version)
- Insecure Cookie Directives (missing HttpOnly, Secure, SameSite)
- Overly Permissive CORS (wildcards on authenticated endpoints, origin reflection with credentials)
- Verbose Internal Error Disclosures (stack traces, file paths, database errors)
"""

import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass


@dataclass
class SecurityMisconfigFinding:
    endpoint: str
    method: str
    test_id: str
    test_name: str
    is_vulnerable: bool
    severity: str
    category: str
    reason: str
    cwe: str
    reproduction_curl: str
    header_found: Optional[str]
    remediation: str


def normalize_headers(headers: Dict[str, Any]) -> Dict[str, str]:
    """Converts headers to lowercase keys for case-insensitive lookup."""
    return {k.lower(): str(v) for k, v in headers.items()}


def parse_cookie_directives(cookie_str: str) -> Dict[str, Any]:
    """Parses a Set-Cookie string into its name, value, and security flags."""
    parts = [p.strip() for p in cookie_str.split(";")]
    if not parts or not parts[0]:
        return {}

    first = parts[0]
    name = first.split("=")[0].strip() if "=" in first else first

    flags = {p.lower(): True for p in parts[1:]}

    has_httponly = any("httponly" in f for f in flags)
    has_secure = any("secure" in f for f in flags)
    samesite_val = None
    for p in parts[1:]:
        if p.lower().startswith("samesite"):
            samesite_val = p.split("=")[1].strip() if "=" in p else "true"
            break

    return {
        "name": name,
        "raw": cookie_str,
        "httponly": has_httponly,
        "secure": has_secure,
        "samesite": samesite_val,
    }


def audit_endpoint_security_misconfig(
    endpoint: str,
    method: str,
    base_url: str,
    response_headers: Dict[str, Any],
    status_code: int,
    response_body: str,
    raw_set_cookie_headers: Optional[List[str]] = None,
    auth_header: str = "",
) -> List[SecurityMisconfigFinding]:
    """Evaluates an endpoint's response headers, cookies, and body for OWASP API8 misconfigurations."""
    findings: List[SecurityMisconfigFinding] = []
    norm_headers = normalize_headers(response_headers)

    target_url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"
    hdr_poc = f"-H \"Authorization: {auth_header}\"" if auth_header else ""
    poc_curl = f"curl -s -i -X {method} \"{target_url}\" {hdr_poc}".strip()

    # 1. HSTS: Strict-Transport-Security
    hsts = norm_headers.get("strict-transport-security")
    if not hsts:
        findings.append(
            SecurityMisconfigFinding(
                endpoint=endpoint,
                method=method,
                test_id="SEC-01-HSTS",
                test_name="Missing Strict-Transport-Security (HSTS)",
                is_vulnerable=True,
                severity="HIGH",
                category="Security Headers",
                reason="Strict-Transport-Security header is completely missing. Browsers may connect over plaintext HTTP, enabling SSL-stripping and MitM attacks.",
                cwe="CWE-319: Cleartext Transmission of Sensitive Information",
                reproduction_curl=poc_curl,
                header_found=None,
                remediation="Configure 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' in gateway or reverse proxy.",
            )
        )
    else:
        # Check max-age length
        match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
        max_age = int(match.group(1)) if match else 0
        if max_age < 15724800:  # Less than 6 months
            findings.append(
                SecurityMisconfigFinding(
                    endpoint=endpoint,
                    method=method,
                    test_id="SEC-01-HSTS",
                    test_name="Weak Strict-Transport-Security max-age",
                    is_vulnerable=True,
                    severity="MEDIUM",
                    category="Security Headers",
                    reason=f"HSTS max-age is only {max_age} seconds. Recommended minimum duration is 1 year (31536000 seconds).",
                    cwe="CWE-319: Cleartext Transmission of Sensitive Information",
                    reproduction_curl=poc_curl,
                    header_found=f"Strict-Transport-Security: {hsts}",
                    remediation="Increase HSTS max-age to 31536000 (1 year) and append 'includeSubDomains; preload'.",
                )
            )
        else:
            findings.append(
                SecurityMisconfigFinding(
                    endpoint=endpoint,
                    method=method,
                    test_id="SEC-01-HSTS",
                    test_name="Strict-Transport-Security (HSTS) Enforced",
                    is_vulnerable=False,
                    severity="NONE",
                    category="Security Headers",
                    reason=f"HSTS is properly configured with max-age={max_age}.",
                    cwe="CWE-319",
                    reproduction_curl=poc_curl,
                    header_found=f"Strict-Transport-Security: {hsts}",
                    remediation="Maintain existing HSTS configuration.",
                )
            )

    # 2. CSP: Content-Security-Policy
    csp = norm_headers.get("content-security-policy")
    if not csp:
        findings.append(
            SecurityMisconfigFinding(
                endpoint=endpoint,
                method=method,
                test_id="SEC-02-CSP",
                test_name="Missing Content-Security-Policy (CSP)",
                is_vulnerable=True,
                severity="HIGH",
                category="Security Headers",
                reason="Content-Security-Policy header is missing. Browsers lack restrictions against XSS, unauthorized data exfiltration, and malicious resource injection.",
                cwe="CWE-1021: Improper Restriction of Rendered UI Layers or Resources",
                reproduction_curl=poc_curl,
                header_found=None,
                remediation="Implement 'Content-Security-Policy: default-src \\'self\\'; frame-ancestors \\'none\\'; object-src \\'none\\''.",
            )
        )
    else:
        findings.append(
            SecurityMisconfigFinding(
                endpoint=endpoint,
                method=method,
                test_id="SEC-02-CSP",
                test_name="Content-Security-Policy Enforced",
                is_vulnerable=False,
                severity="NONE",
                category="Security Headers",
                reason="Content-Security-Policy is present and restricting resource origins.",
                cwe="CWE-1021",
                reproduction_curl=poc_curl,
                header_found=f"Content-Security-Policy: {csp[:80]}...",
                remediation="Maintain existing CSP policy.",
            )
        )

    # 3. MIME Sniffing: X-Content-Type-Options
    x_content_type = norm_headers.get("x-content-type-options")
    if not x_content_type or "nosniff" not in x_content_type.lower():
        findings.append(
            SecurityMisconfigFinding(
                endpoint=endpoint,
                method=method,
                test_id="SEC-03-NOSNIFF",
                test_name="Missing X-Content-Type-Options (nosniff)",
                is_vulnerable=True,
                severity="MEDIUM",
                category="Security Headers",
                reason="Missing 'X-Content-Type-Options: nosniff'. Browsers may attempt MIME-sniffing on API payloads, potentially treating JSON/text as executable scripts.",
                cwe="CWE-79: Cross-site Scripting via MIME Confusion",
                reproduction_curl=poc_curl,
                header_found=f"X-Content-Type-Options: {x_content_type}" if x_content_type else None,
                remediation="Set 'X-Content-Type-Options: nosniff' header on all HTTP responses.",
            )
        )
    else:
        findings.append(
            SecurityMisconfigFinding(
                endpoint=endpoint,
                method=method,
                test_id="SEC-03-NOSNIFF",
                test_name="MIME Sniffing Protection Enforced",
                is_vulnerable=False,
                severity="NONE",
                category="Security Headers",
                reason="'X-Content-Type-Options: nosniff' is actively enforced.",
                cwe="CWE-79",
                reproduction_curl=poc_curl,
                header_found=f"X-Content-Type-Options: {x_content_type}",
                remediation="None required.",
            )
        )

    # 4. Clickjacking: X-Frame-Options or frame-ancestors
    x_frame = norm_headers.get("x-frame-options")
    has_frame_ancestors = csp and "frame-ancestors" in csp.lower()
    if not x_frame and not has_frame_ancestors:
        findings.append(
            SecurityMisconfigFinding(
                endpoint=endpoint,
                method=method,
                test_id="SEC-04-CLICKJACK",
                test_name="Missing Clickjacking Protection (X-Frame-Options)",
                is_vulnerable=True,
                severity="MEDIUM",
                category="Security Headers",
                reason="Neither X-Frame-Options nor CSP frame-ancestors is present. Endpoint responses can be framed in an invisible iframe for Clickjacking attacks.",
                cwe="CWE-1021: Improper Restriction of Rendered UI Layers or Frames",
                reproduction_curl=poc_curl,
                header_found=None,
                remediation="Add 'X-Frame-Options: DENY' or 'Content-Security-Policy: frame-ancestors \\'none\\''.",
            )
        )
    else:
        findings.append(
            SecurityMisconfigFinding(
                endpoint=endpoint,
                method=method,
                test_id="SEC-04-CLICKJACK",
                test_name="Clickjacking Protection Active",
                is_vulnerable=False,
                severity="NONE",
                category="Security Headers",
                reason=f"Frame embedding restricted via {f'X-Frame-Options: {x_frame}' if x_frame else 'CSP frame-ancestors'}.",
                cwe="CWE-1021",
                reproduction_curl=poc_curl,
                header_found=f"X-Frame-Options: {x_frame}" if x_frame else "CSP frame-ancestors present",
                remediation="None required.",
            )
        )

    # 5. Technology Fingerprinting: X-Powered-By & Server
    x_powered_by = norm_headers.get("x-powered-by")
    server_hdr = norm_headers.get("server")

    if x_powered_by:
        findings.append(
            SecurityMisconfigFinding(
                endpoint=endpoint,
                method=method,
                test_id="SEC-05-BANNER",
                test_name="Technology Stack Fingerprint Leak (X-Powered-By)",
                is_vulnerable=True,
                severity="LOW",
                category="Information Disclosure",
                reason=f"Header discloses exact backend technology: 'X-Powered-By: {x_powered_by}'. Attackers can look up known CVEs targeting this specific framework.",
                cwe="CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
                reproduction_curl=poc_curl,
                header_found=f"X-Powered-By: {x_powered_by}",
                remediation="Disable 'X-Powered-By' via 'app.disable(\"x-powered-by\")' in Express or helmet().",
            )
        )

    if server_hdr and any(x in server_hdr.lower() for x in ("apache", "nginx", "php", "ubuntu", "debian", "microsoft")):
        findings.append(
            SecurityMisconfigFinding(
                endpoint=endpoint,
                method=method,
                test_id="SEC-05-BANNER",
                test_name="Detailed Server Banner Disclosure",
                is_vulnerable=True,
                severity="LOW",
                category="Information Disclosure",
                reason=f"Server header exposes underlying OS and server version: 'Server: {server_hdr}'.",
                cwe="CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
                reproduction_curl=poc_curl,
                header_found=f"Server: {server_hdr}",
                remediation="Configure reverse proxy or web server to suppress or mask the 'Server' response header.",
            )
        )

    # 6. CORS Configuration: Origin reflection and wildcards
    allow_origin = norm_headers.get("access-control-allow-origin")
    allow_credentials = norm_headers.get("access-control-allow-credentials", "").lower() == "true"

    if allow_origin == "*" and allow_credentials:
        findings.append(
            SecurityMisconfigFinding(
                endpoint=endpoint,
                method=method,
                test_id="SEC-06-CORS",
                test_name="Critical CORS Misconfiguration (Wildcard with Credentials)",
                is_vulnerable=True,
                severity="CRITICAL",
                category="CORS Misconfiguration",
                reason="Server allows 'Access-Control-Allow-Origin: *' alongside 'Access-Control-Allow-Credentials: true'. This allows any external website to make credentialed requests.",
                cwe="CWE-942: Permissive Cross-Domain Policy with Untrusted Domains",
                reproduction_curl=f"curl -s -i -H \"Origin: https://evil.com\" -X {method} \"{target_url}\"",
                header_found="Access-Control-Allow-Origin: * | Access-Control-Allow-Credentials: true",
                remediation="Do not combine wildcard origins with credentials. Whitelist specific trusted origins explicitly.",
            )
        )
    elif allow_origin and allow_origin != "null" and allow_credentials:
        findings.append(
            SecurityMisconfigFinding(
                endpoint=endpoint,
                method=method,
                test_id="SEC-06-CORS",
                test_name="Permissive CORS Origin Reflection with Credentials",
                is_vulnerable=True,
                severity="HIGH",
                category="CORS Misconfiguration",
                reason=f"Server reflected origin '{allow_origin}' with 'Access-Control-Allow-Credentials: true'. Attackers can read sensitive responses cross-origin.",
                cwe="CWE-942: Permissive Cross-Domain Policy with Untrusted Domains",
                reproduction_curl=f"curl -s -i -H \"Origin: https://attacker.org\" -X {method} \"{target_url}\"",
                header_found=f"Access-Control-Allow-Origin: {allow_origin} | Credentials: true",
                remediation="Implement strict domain whitelisting. Reject arbitrary Origin headers with Access-Control-Allow-Origin: null.",
            )
        )

    # 7. Insecure Cookies: Set-Cookie flags
    cookies_to_audit = raw_set_cookie_headers or []
    # Also check normalized headers if raw not passed
    if not cookies_to_audit and "set-cookie" in norm_headers:
        cookies_to_audit = [norm_headers["set-cookie"]]

    for cookie_str in cookies_to_audit:
        cookie_meta = parse_cookie_directives(cookie_str)
        if not cookie_meta:
            continue

        c_name = cookie_meta.get("name", "cookie")

        # 7a. Missing HttpOnly
        if not cookie_meta.get("httponly"):
            findings.append(
                SecurityMisconfigFinding(
                    endpoint=endpoint,
                    method=method,
                    test_id="SEC-07-COOKIE-HTTPONLY",
                    test_name=f"Insecure Cookie: Missing HttpOnly ({c_name})",
                    is_vulnerable=True,
                    severity="HIGH",
                    category="Cookie Security",
                    reason=f"Cookie '{c_name}' is set without the 'HttpOnly' flag. Malicious scripts (XSS) can access this cookie via document.cookie and steal session tokens.",
                    cwe="CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag",
                    reproduction_curl=poc_curl,
                    header_found=f"Set-Cookie: {cookie_str[:80]}...",
                    remediation=f"Append '; HttpOnly' to the Set-Cookie directive for '{c_name}'.",
                )
            )

        # 7b. Missing Secure flag
        if not cookie_meta.get("secure"):
            findings.append(
                SecurityMisconfigFinding(
                    endpoint=endpoint,
                    method=method,
                    test_id="SEC-08-COOKIE-SECURE",
                    test_name=f"Insecure Cookie: Missing Secure Flag ({c_name})",
                    is_vulnerable=True,
                    severity="HIGH",
                    category="Cookie Security",
                    reason=f"Cookie '{c_name}' is set without the 'Secure' flag. It will be transmitted over plaintext HTTP connections, exposing it to eavesdropping / MitM interception.",
                    cwe="CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
                    reproduction_curl=poc_curl,
                    header_found=f"Set-Cookie: {cookie_str[:80]}...",
                    remediation=f"Append '; Secure' to the Set-Cookie directive for '{c_name}'.",
                )
            )

        # 7c. Missing SameSite
        if not cookie_meta.get("samesite"):
            findings.append(
                SecurityMisconfigFinding(
                    endpoint=endpoint,
                    method=method,
                    test_id="SEC-09-COOKIE-SAMESITE",
                    test_name=f"Insecure Cookie: Missing SameSite Attribute ({c_name})",
                    is_vulnerable=True,
                    severity="MEDIUM",
                    category="Cookie Security",
                    reason=f"Cookie '{c_name}' lacks a SameSite attribute. The browser will attach it to cross-site requests, increasing risk of Cross-Site Request Forgery (CSRF).",
                    cwe="CWE-1275: Sensitive Cookie with Improper SameSite Attribute",
                    reproduction_curl=poc_curl,
                    header_found=f"Set-Cookie: {cookie_str[:80]}...",
                    remediation=f"Append '; SameSite=Strict' or '; SameSite=Lax' to the Set-Cookie directive for '{c_name}'.",
                )
            )

    # 8. Verbose Error Stack Trace Disclosure (Status 500+)
    if status_code >= 500:
        body_lower = response_body.lower()
        has_stack = any(kw in body_lower for kw in ("stack", "traceback", "exception", "econnrefused", "enotfound", "pg-pool", "syntaxerror", "uncaught"))
        if has_stack:
            findings.append(
                SecurityMisconfigFinding(
                    endpoint=endpoint,
                    method=method,
                    test_id="SEC-10-VERBOSE-ERROR",
                    test_name="Verbose Error Stack Trace & Internal Disclosure",
                    is_vulnerable=True,
                    severity="HIGH",
                    category="Information Disclosure",
                    reason="Server returned internal stack traces, system file paths, or database error traces. Attackers can map internal architecture and infrastructure.",
                    cwe="CWE-209: Generation of Error Message Containing Sensitive Information",
                    reproduction_curl=poc_curl,
                    header_found=f"HTTP {status_code} with stack trace in payload",
                    remediation="Sanitize all error responses in production. Log stack traces privately and return a generic error message with an Incident ID.",
                )
            )

    return findings
