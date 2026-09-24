# OWASP API2:2023 — Authentication Misconfiguration Security Test Cases

## 1. Executive Summary
**Authentication Misconfiguration (Broken Authentication)** occurs when an API fails to correctly implement authentication mechanisms, allowing attackers to compromise authentication tokens, spoof legitimate user identities, access unauthenticated endpoints, or exploit flawed JWT implementations.

Common attack vectors in APIs include:
- Unprotected sensitive or administrative routes (missing authentication middleware).
- Insecure JWT implementations (e.g. accepting `alg: none` unsigned tokens, failing to verify cryptographic HMAC/RSA signatures).
- Lack of token expiration validation (`exp` claim neglected).
- Permissive validation (accepting empty or arbitrary bearer tokens).
- Verbose error disclosures (returning HTTP 500 status codes with internal stack traces upon receiving malformed tokens).

---

## 2. Test Targets & Environment
- **Vulnerable Target:** `http://localhost:8004` (Port 8004)
- **Secured Reference Target:** `http://localhost:8005` (Port 8005)
- **OpenAPI Schema:** `backend/Authentication_Misconfiguration/openapi.json`
- **Secret Key:** `sentinel-super-secret-key-2026`

---

## 3. Test Cases Matrix

### Test Case AUTH-01: Missing Authentication on Sensitive Route
- **Endpoint:** `GET /api/admin/users`
- **Test Condition:** Sent with **NO** `Authorization` header.
- **Expected Secure Behavior:** Returns `401 Unauthorized` or `403 Forbidden`.
- **Vulnerable Server Response (`:8004`):**
  - **Status:** `200 OK`
  - **Body:** Leaks full user database records without authentication!
  - **Severity:** `CRITICAL`
- **Proof of Concept (PoC):**
  ```bash
  curl -s -X GET "http://localhost:8004/api/admin/users"
  ```
- **Secured Server Response (`:8005`):**
  - **Status:** `401 Unauthorized`
  - **Body:** `{"error": "Missing authorization credentials"}`

---

### Test Case AUTH-02: JWT `alg: none` Signature Bypass
- **Endpoint:** `GET /api/user/profile`
- **Test Condition:** Token header set to `{"alg": "none", "typ": "JWT"}` and signature stripped.
- **Token:** `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpZCI6MTAxLCJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0.`
- **Expected Secure Behavior:** Returns `401 Unauthorized` rejecting `none` algorithm.
- **Vulnerable Server Response (`:8004`):**
  - **Status:** `200 OK`
  - **Message:** `"Accepted JWT with alg: 'none' (unsigned token accepted!)"`
  - **Severity:** `CRITICAL`
- **Proof of Concept (PoC):**
  ```bash
  curl -s -X GET "http://localhost:8004/api/user/profile" \
    -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpZCI6MTAxLCJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0."
  ```
- **Secured Server Response (`:8005`):**
  - **Status:** `401 Unauthorized`
  - **Body:** `{"error": "Unsupported or unverified algorithm"}`

---

### Test Case AUTH-03: Missing Cryptographic Signature Verification
- **Endpoint:** `GET /api/user/profile`
- **Test Condition:** Valid token payload with a forged / corrupted signature.
- **Expected Secure Behavior:** Returns `401 Unauthorized` due to HMAC-SHA256 signature mismatch.
- **Vulnerable Server Response (`:8004`):**
  - **Status:** `200 OK` (Server blindly decodes base64 payload without computing cryptographic digest).
  - **Severity:** `CRITICAL`
- **Proof of Concept (PoC):**
  ```bash
  curl -s -X GET "http://localhost:8004/api/user/profile" \
    -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6OTk5LCJ1c2VybmFtZSI6ImhhY2tlciIsInJvbGUiOiJhZG1pbiJ9.FORGED_INVALID_SIGNATURE_XYZ"
  ```
- **Secured Server Response (`:8005`):**
  - **Status:** `401 Unauthorized`
  - **Body:** `{"error": "Invalid cryptographic signature"}`

---

### Test Case AUTH-04: Expired Token Acceptance
- **Endpoint:** `GET /api/user/settings`
- **Test Condition:** Token with `exp` timestamp in the past.
- **Expected Secure Behavior:** Returns `401 Unauthorized` rejecting expired tokens.
- **Vulnerable Server Response (`:8004`):**
  - **Status:** `200 OK`
  - **Severity:** `HIGH`
  - **Body:** Settings returned despite token being expired.
- **Secured Server Response (`:8005`):**
  - **Status:** `401 Unauthorized`
  - **Body:** `{"error": "Token has expired"}`

---

### Test Case AUTH-05: Verbose 500 Server Error Leakage
- **Endpoint:** `GET /api/user/data`
- **Test Condition:** Malformed, non-base64 token sent.
- **Expected Secure Behavior:** Uniform `401 Unauthorized` without server details.
- **Vulnerable Server Response (`:8004`):**
  - **Status:** `500 Internal Server Error`
  - **Severity:** `MEDIUM`
  - **Body:** Leaks internal Node.js stack traces and file paths (`at decodeJwtPayload /app/services/auth.js:42:18`).
- **Secured Server Response (`:8005`):**
  - **Status:** `401 Unauthorized`
  - **Body:** `{"error": "Malformed JWT structure"}`

---

### Test Case AUTH-06: Safe Public Endpoint Baseline
- **Endpoint:** `GET /api/public/status`
- **Test Condition:** Sent with NO `Authorization` header.
- **Expected Behavior:** Returns `200 OK` (Public service baseline).
- **Status on both `:8004` and `:8005`:** `200 OK` (`PASS / CLEAR`).
