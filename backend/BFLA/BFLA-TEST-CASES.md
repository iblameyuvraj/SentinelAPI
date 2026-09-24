# OWASP API5:2023 — Broken Function Level Authorization (BFLA) Security Test Cases

## 1. Executive Summary
**Broken Function Level Authorization (BFLA)** occurs when an API fails to enforce role-based access control (RBAC) boundaries, allowing standard or low-privileged users to invoke administrative functions, sensitive operations, or destructive endpoints.

Attack scenarios include:
1. **User-to-Admin Access:** Normal authenticated user querying administrative management routes (`/api/admin/*`, `/api/system/*`).
2. **HTTP Verb Tampering:** Standard users invoking dangerous HTTP methods (such as `DELETE`, `PUT`, `PATCH`) on endpoints where only `GET` was intended for clients.
3. **Privilege Escalation:** Modifying role parameters (`{"role": "admin"}`) in account update payloads.

---

## 2. Test Targets & Environment
- **Vulnerable Target:** `http://localhost:8008` (Port 8008)
- **Secured Reference Target:** `http://localhost:8009` (Port 8009)
- **OpenAPI Schema:** `backend/BFLA/openapi.json`
- **Standard User Token:** `Bearer user_token_101` (Role: `user`)
- **Admin User Token:** `Bearer admin_token_102` (Role: `admin`)

---

## 3. Test Cases Matrix

### Test Case BFLA-01: Unauthorized Administrative Metrics Query
- **Endpoint:** `GET /api/admin/system/metrics`
- **Caller Credential:** Standard User (`user_token_101`)
- **Expected Secure Behavior:** Returns `403 Forbidden` rejecting non-admin access.
- **Vulnerable Server Response (`:8008`):**
  - **Status:** `200 OK`
  - **Severity:** `CRITICAL`
  - **Impact:** Normal user views internal system metrics, vault status, and DB connections.
- **Proof of Concept (PoC):**
  ```bash
  curl -s -X GET "http://localhost:8008/api/admin/system/metrics" \
    -H "Authorization: Bearer user_token_101"
  ```
- **Secured Server Response (`:8009`):**
  - **Status:** `403 Forbidden`
  - **Body:** `{"error": "Forbidden: Administrative privileges required"}`

---

### Test Case BFLA-02: Unauthorized Audit Trail Exfiltration
- **Endpoint:** `GET /api/admin/audit-logs`
- **Caller Credential:** Standard User (`user_token_101`)
- **Expected Secure Behavior:** Returns `403 Forbidden`.
- **Vulnerable Server Response (`:8008`):**
  - **Status:** `200 OK`
  - **Severity:** `HIGH`
  - **Impact:** Confidential organization security audit logs leaked to unauthorized users.
- **Secured Server Response (`:8009`):**
  - **Status:** `403 Forbidden`

---

### Test Case BFLA-03: HTTP Verb Tampering (Unauthorized DELETE Account)
- **Endpoint:** `DELETE /api/users/103`
- **Caller Credential:** Standard User (`user_token_101`)
- **Expected Secure Behavior:** Returns `403 Forbidden`.
- **Vulnerable Server Response (`:8008`):**
  - **Status:** `200 OK`
  - **Severity:** `CRITICAL`
  - **Impact:** Standard user executes account deletion without admin privileges.
- **Proof of Concept (PoC):**
  ```bash
  curl -s -X DELETE "http://localhost:8008/api/users/103" \
    -H "Authorization: Bearer user_token_101"
  ```
- **Secured Server Response (`:8009`):**
  - **Status:** `403 Forbidden`

---

### Test Case BFLA-04: Self-Privilege Escalation to Admin
- **Endpoint:** `PUT /api/users/101/role`
- **Caller Credential:** Standard User (`user_token_101`)
- **Payload:** `{"role": "admin"}`
- **Expected Secure Behavior:** Returns `403 Forbidden`.
- **Vulnerable Server Response (`:8008`):**
  - **Status:** `200 OK`
  - **Severity:** `CRITICAL`
  - **Impact:** Attacker promotes their own account to `admin`.
- **Secured Server Response (`:8009`):**
  - **Status:** `403 Forbidden`
