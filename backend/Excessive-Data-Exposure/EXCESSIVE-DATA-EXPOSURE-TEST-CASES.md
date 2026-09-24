# OWASP API3:2023 — Excessive Data Exposure Security Test Cases

## 1. Executive Summary
**Excessive Data Exposure** occurs when an API endpoint returns full data objects from internal models or database entities, relying on client-side applications to filter out unnecessary or sensitive properties.

Attackers intercept or inspect raw HTTP responses to harvest credentials, PII, internal privileges, financial keys, and proprietary supplier algorithms.

---

## 2. Test Targets & Environment
- **Vulnerable Target:** `http://localhost:8002` (Port 8002)
- **Secured Reference Target:** `http://localhost:8003` (Port 8003)
- **OpenAPI Schema:** `backend/Excessive-Data-Exposure/openapi.json`
- **Authentication Scheme:** `Bearer <token>` (`Authorization: Bearer test_user_token_101`)

---

## 3. Test Cases Matrix

### Test Case EDE-01: Full User Record Exposure (Authentication Required)
- **Endpoint:** `GET /api/users/{userId}`
- **Test ID:** `101`
- **Auth Header:** `Authorization: Bearer test_token_101`
- **OpenAPI Declared Schema:** `{ id, name, username }`
- **Vulnerable Server Response (`:8002`):**
  ```json
  {
    "id": 101,
    "name": "Yuvraj",
    "username": "yuvraj_dev",
    "email": "yuvraj@example.com",
    "phone": "+91-9876543210",
    "password_hash": "$2b$12$e8Y5M6v8r4oP9xLz.K8e9uQeWJ1eC6sV1l.d6r7t8y9u0",
    "password_salt": "d41d8cd98f00b204e9800998ecf8427e",
    "reset_token": "9f83a45c-20c1-4b72-b5e1-8974a682cd12",
    "internal_role": "super_admin",
    "is_admin": true,
    "permissions": ["user.read", "user.write", "admin.override", "billing.bypass"],
    "ssn": "987-65-4321",
    "salary": 185000,
    "credit_card_last4": "4242",
    "stripe_customer_id": "cus_Nb89sL29xK0pQq",
    "mfa_secret": "JBSWY3DPEHPK3PXP"
  }
  ```
- **Severity:** `CRITICAL`
- **Leaked Categories:** Password Secrets, PII/National Identifiers, Financial Records, Internal Privileges.
- **Proof of Concept (PoC):**
  ```bash
  curl -s -X GET "http://localhost:8002/api/users/101" \
    -H "Authorization: Bearer test_token_101" \
    -H "Content-Type: application/json"
  ```
- **Expected Secure Response (`:8003`):**
  ```json
  {
    "id": 101,
    "name": "Yuvraj",
    "username": "yuvraj_dev"
  }
  ```

---

### Test Case EDE-02: User Profile Sensitive Exposure
- **Endpoint:** `GET /api/users/{userId}/profile`
- **Test ID:** `101`
- **Auth Header:** `Authorization: Bearer test_token_101`
- **OpenAPI Declared Schema:** `{ id, name, username, email }`
- **Vulnerable Server Response (`:8002`):**
  - Exposes unmasked phone, `mfa_secret: "JBSWY3DPEHPK3PXP"`, `failed_login_attempts: 0`, and `internal_role: "super_admin"`.
- **Severity:** `HIGH`
- **Proof of Concept (PoC):**
  ```bash
  curl -s -X GET "http://localhost:8002/api/users/101/profile" \
    -H "Authorization: Bearer test_token_101"
  ```

---

### Test Case EDE-03: Public Catalog Wholesale Secret Leakage
- **Endpoint:** `GET /api/products/{productId}`
- **Test ID:** `501`
- **Auth Header:** None (Public Endpoint)
- **OpenAPI Declared Schema:** `{ id, title, description, retail_price }`
- **Vulnerable Server Response (`:8002`):**
  - Exposes `wholesale_vendor_token`, `supplier_cost: 45`, `markup_margin_percentage: 564.4`, and `internal_inventory_warehouse_id`.
- **Severity:** `HIGH` (API Key & Business Logic Leakage)
- **Proof of Concept (PoC):**
  ```bash
  curl -s -X GET "http://localhost:8002/api/products/501"
  ```

---

### Test Case EDE-04: System Health Baseline Probe (Secure Control)
- **Endpoint:** `GET /api/system/health`
- **Auth Header:** None
- **Response (`:8002` & `:8003`):**
  ```json
  {
    "status": "online",
    "target": "Excessive Data Exposure Backend",
    "timestamp": "2026-09-24T12:00:00Z"
  }
  ```
- **Verdict:** `PASSED (SECURE)` — Zero sensitive attributes detected.

---

## 4. Remediation Standard (Zero-Trust Data Projection)
Backend services must implement **Response Data Transfer Objects (DTOs)** or database projection clauses (`SELECT id, name FROM users`) before sending JSON to clients:

```javascript
// Correct Implementation
function toPublicUserDTO(user) {
  return {
    id: user.id,
    name: user.name,
    username: user.username,
  };
}

app.get("/api/users/:userId", requireAuth, (req, res) => {
  const user = db.users.findById(req.params.userId);
  return res.json(toPublicUserDTO(user));
});
```
