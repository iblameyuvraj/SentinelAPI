# OWASP API8:2023 — Security Misconfiguration Test Matrix

## Overview
This test matrix defines test cases for identifying Security Misconfigurations in REST and GraphQL APIs, targeting missing HTTP security headers, insecure cookie attributes, CORS misconfigurations, and technology fingerprinting.

---

## Test Vectors

| Test ID | Test Name | Attack / Evaluation Vector | Target Headers / Attributes | Severity | Expected Behavior (Hardened) | Vulnerable Flaw (Vulnerable Backend) |
| :--- | :--- | :--- | :--- | :---: | :--- | :--- |
| **SEC-01-HSTS** | Missing Strict-Transport-Security | Inspects presence and `max-age` of HSTS header | `Strict-Transport-Security` | **HIGH** | Present with `max-age >= 15724800` | Header completely missing (HTTP downgrade vulnerability) |
| **SEC-02-CSP** | Missing Content-Security-Policy | Evaluates CSP presence and policy restrictions | `Content-Security-Policy` | **HIGH** | Present with restricted directives (`default-src 'self'`) | Missing CSP header (enables cross-site scripting & injection) |
| **SEC-03-NOSNIFF** | Missing MIME Sniffing Protection | Evaluates `X-Content-Type-Options` | `X-Content-Type-Options: nosniff` | **MEDIUM** | `nosniff` explicitly set | Missing header (allows MIME confusion attacks) |
| **SEC-04-CLICKJACK** | Missing Clickjacking Protection | Evaluates `X-Frame-Options` or CSP `frame-ancestors` | `X-Frame-Options: DENY \| SAMEORIGIN` | **MEDIUM** | `DENY` or `SAMEORIGIN` enforced | Missing header (allows UI redressing / clickjacking) |
| **SEC-05-REFERRER** | Insecure Referrer Policy | Checks `Referrer-Policy` header | `Referrer-Policy` | **LOW** | `strict-origin-when-cross-origin` or `no-referrer` | Missing or set to `unsafe-url` |
| **SEC-06-BANNER** | Server Technology Fingerprinting | Detects software version disclosure | `X-Powered-By`, `Server` | **LOW** | Banners stripped or generic (`Server: Protected`) | Leaks `X-Powered-By: Express/4.18.2` or specific OS |
| **SEC-07-COOKIE-HTTPONLY** | Missing HttpOnly on Session Cookies | Checks `Set-Cookie` directives | `HttpOnly` flag | **HIGH** | `HttpOnly` enforced on session cookies | Session token cookie readable via JavaScript `document.cookie` |
| **SEC-08-COOKIE-SECURE** | Missing Secure Flag on Cookies | Checks `Set-Cookie` directives | `Secure` flag | **HIGH** | `Secure` enforced on all sensitive cookies | Cookies transmitted in cleartext over unencrypted HTTP |
| **SEC-09-COOKIE-SAMESITE** | Missing SameSite Flag on Cookies | Checks `Set-Cookie` directives | `SameSite=Strict \| Lax` | **MEDIUM** | `SameSite=Strict` or `Lax` present | Missing SameSite flag (CSRF exposure) |
| **SEC-10-CORS-PERMISSIVE** | Wildcard / Arbitrary Origin CORS | Sends arbitrary `Origin: evil.com` with credentials | `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials` | **CRITICAL** | Rejects untrusted origins (`Access-Control-Allow-Origin: null`) | Reflects arbitrary origin with credentials allowed (`true`) |
| **SEC-11-VERBOSE-ERROR** | Verbose Stack Trace & Path Leakage | Evaluates 500 error response bodies | Response JSON payload | **HIGH** | Generic error with incident ticket ID | Leaks raw stack trace, SQL error, or file system paths |

---

## Production Remediation Summary

### Node.js / Express
```javascript
const helmet = require("helmet");

// Enforce full security header suite
app.use(helmet({
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  contentSecurityPolicy: { directives: { defaultSrc: ["'self'"] } },
  hidePoweredBy: true,
}));

// Secure Cookie Settings
res.cookie("session_id", token, {
  httpOnly: true,
  secure: true,
  sameSite: "strict",
  maxAge: 3600000,
});
```

### Python / FastAPI
```python
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Response

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response: Response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        if "x-powered-by" in response.headers:
            del response.headers["x-powered-by"]
        return response

app.add_middleware(SecurityHeadersMiddleware)
```
