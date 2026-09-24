# OWASP API4:2023 — Unrestricted Resource Consumption & Rate Limiting Security Test Cases

## 1. Executive Summary
**Unrestricted Resource Consumption (Rate Limiting Flaws)** occurs when API endpoints do not restrict the number, frequency, or size of requests from clients.

Attackers exploit unthrottled endpoints for:
1. **Credential Stuffing & Brute-Force:** Automating hundreds of password attempts on `/api/auth/login`.
2. **Denial-of-Wallet (Email / SMS Bombing):** Flooding endpoints like `/api/auth/forgot-password` to rack up third-party provider costs (Twilio, SendGrid) and spam legitimate users.
3. **Database & CPU Exhaustion (DoS):** Flooding complex search, filtering, or export endpoints to exhaust thread pools and database connections.
4. **Data Exfiltration:** Scraping entire datasets without encountering concurrency or volume limits.

---

## 2. Test Targets & Environment
- **Vulnerable Target:** `http://localhost:8006` (Port 8006)
- **Secured Reference Target:** `http://localhost:8007` (Port 8007)
- **OpenAPI Schema:** `backend/Rate-Limiting/openapi.json`
- **Standard Audit Burst:** 20 to 25 rapid requests per endpoint

---

## 3. Test Cases Matrix

### Test Case RATE-01: Authentication Brute-Force Exposure
- **Endpoint:** `POST /api/auth/login`
- **Burst Volume:** 25 requests within 2 seconds.
- **Expected Secure Behavior:** Returns `429 Too Many Requests` after 5 requests, accompanied by `Retry-After` header.
- **Vulnerable Server Response (`:8006`):**
  - **Status:** All 25 requests return `200 OK`.
  - **Headers:** No `X-RateLimit-*` or `Retry-After` headers.
  - **Severity:** `HIGH`
  - **Impact:** Attackers can brute-force passwords indefinitely without being blocked.
- **Secured Server Response (`:8007`):**
  - **Status:** First 5 return `200 OK`, subsequent 20 return `429 Too Many Requests`.
  - **Headers:** `Retry-After: 60`, `X-RateLimit-Limit: 5`, `X-RateLimit-Remaining: 0`.

---

### Test Case RATE-02: Denial-of-Wallet / OTP Flood (Forgot Password)
- **Endpoint:** `POST /api/auth/forgot-password`
- **Burst Volume:** 25 requests within 2 seconds.
- **Expected Secure Behavior:** Returns `429 Too Many Requests` after 3 requests.
- **Vulnerable Server Response (`:8006`):**
  - **Status:** All 25 requests return `200 OK`.
  - **Severity:** `HIGH`
  - **Impact:** SMS/Email flooding causing financial exhaustion and inbox spam.
- **Secured Server Response (`:8007`):**
  - **Status:** Throttled to 3 requests per minute, returning `429 Too Many Requests`.

---

### Test Case RATE-03: Heavy Query Search Compute Exhaustion
- **Endpoint:** `GET /api/search?q=test`
- **Burst Volume:** 25 requests within 2 seconds.
- **Expected Secure Behavior:** Returns `429 Too Many Requests` after threshold (8 requests).
- **Vulnerable Server Response (`:8006`):**
  - **Status:** All 25 requests return `200 OK`.
  - **Severity:** `MEDIUM`
  - **Impact:** Heavy CPU & database connection exhaustion leading to API latency spikes.
- **Secured Server Response (`:8007`):**
  - **Status:** Properly throttled with HTTP `429`.

---

### Test Case RATE-04: Large Data Export Bandwidth Flooding
- **Endpoint:** `GET /api/user/export`
- **Burst Volume:** 25 requests within 2 seconds.
- **Expected Secure Behavior:** Throttled after 3 requests.
- **Vulnerable Server Response (`:8006`):**
  - **Status:** All 25 requests return `200 OK` (5MB * 25 = 125MB data egress).
  - **Severity:** `MEDIUM`
- **Secured Server Response (`:8007`):**
  - **Status:** Returns `429 Too Many Requests`.

---

### Test Case RATE-05: Public Baseline Status
- **Endpoint:** `GET /api/public/status`
- **Burst Volume:** 25 requests within 2 seconds.
- **Expected Behavior:** High threshold permitted (100 req/min). Returns `200 OK`.
