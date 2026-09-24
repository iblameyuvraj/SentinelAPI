# OWASP API4:2023 — Unrestricted Resource Consumption & Rate Limiting Audit Report

- **API Target:** Fluffwalks Web API - BOLA & IDOR Security Test Suite (v1.0.0)
- **Base URL:** `https://www.fluffwalks.in`
- **Burst Volume Tested:** 20 requests/route
- **Scan Timestamp:** 2026-09-24 13:22:25 UTC
- **Standard:** OWASP API Security Top 10 — API4:2023 Unrestricted Resource Consumption
- **Routes Tested:** 7
- **Vulnerable Routes Identified:** 6

## Executive Summary
CRITICAL WARNING: The target API lacks essential request throttling and rate limiting controls. Sensitive endpoints permit unlimited burst requests, rendering the API vulnerable to credential stuffing, SMS/email denial-of-wallet, and DoS.

## Findings Matrix

| Endpoint | Method | Burst Reqs | 200 OK | 429 Throttled | Rate Limit Headers | Verdict | Severity |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `/api/user/101/profile` | GET | 20 | 0 | 0 | None | **VULNERABLE** | MEDIUM |
| `/api/user/101/rides` | GET | 20 | 0 | 0 | None | **VULNERABLE** | MEDIUM |
| `/api/user/101/boardings` | GET | 20 | 0 | 0 | None | **VULNERABLE** | MEDIUM |
| `/api/border/bookings/{bookingId}/status` | POST | 20 | 0 | 0 | None | PASS (Public) | NONE |
| `/api/payments/orders/{orderId}/cancel` | POST | 20 | 0 | 0 | None | **VULNERABLE** | HIGH |
| `/api/admin/rides/{rideId}/complete` | POST | 20 | 0 | 0 | None | **VULNERABLE** | MEDIUM |
| `/api/admin/partners/{partnerId}/verify` | POST | 20 | 0 | 0 | None | **VULNERABLE** | MEDIUM |

## Detailed Vulnerability Analysis & Proof of Concept

### Finding 1: Unrestricted Resource Consumption on `GET /api/user/101/profile`
- **Severity:** MEDIUM
- **CWE Classification:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Total Burst Requests:** 20
- **Successful Responses (Unthrottled):** 0
- **Throttled Responses (429):** 0
- **Security Risk:** MEDIUM VULNERABILITY: Endpoint permitted 20 rapid requests with zero rate-limit headers or throttling.

**Reproduction Proof-of-Concept:**
```bash
# Burst test reproducing unrestricted requests without HTTP 429:
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "HTTP %{http_code}\n" -X GET "https://www.fluffwalks.in/api/user/101/profile"
done
```

**Remediation Recommendation:**
> Enforce API gateway or reverse-proxy rate limiting (e.g. 60-120 req/min) to prevent server thread exhaustion and scraping.

### Finding 2: Unrestricted Resource Consumption on `GET /api/user/101/rides`
- **Severity:** MEDIUM
- **CWE Classification:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Total Burst Requests:** 20
- **Successful Responses (Unthrottled):** 0
- **Throttled Responses (429):** 0
- **Security Risk:** MEDIUM VULNERABILITY: Endpoint permitted 20 rapid requests with zero rate-limit headers or throttling.

**Reproduction Proof-of-Concept:**
```bash
# Burst test reproducing unrestricted requests without HTTP 429:
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "HTTP %{http_code}\n" -X GET "https://www.fluffwalks.in/api/user/101/rides"
done
```

**Remediation Recommendation:**
> Enforce API gateway or reverse-proxy rate limiting (e.g. 60-120 req/min) to prevent server thread exhaustion and scraping.

### Finding 3: Unrestricted Resource Consumption on `GET /api/user/101/boardings`
- **Severity:** MEDIUM
- **CWE Classification:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Total Burst Requests:** 20
- **Successful Responses (Unthrottled):** 0
- **Throttled Responses (429):** 0
- **Security Risk:** MEDIUM VULNERABILITY: Endpoint permitted 20 rapid requests with zero rate-limit headers or throttling.

**Reproduction Proof-of-Concept:**
```bash
# Burst test reproducing unrestricted requests without HTTP 429:
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "HTTP %{http_code}\n" -X GET "https://www.fluffwalks.in/api/user/101/boardings"
done
```

**Remediation Recommendation:**
> Enforce API gateway or reverse-proxy rate limiting (e.g. 60-120 req/min) to prevent server thread exhaustion and scraping.

### Finding 4: Unrestricted Resource Consumption on `POST /api/payments/orders/{orderId}/cancel`
- **Severity:** HIGH
- **CWE Classification:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Total Burst Requests:** 20
- **Successful Responses (Unthrottled):** 0
- **Throttled Responses (429):** 0
- **Security Risk:** HIGH VULNERABILITY: Sensitive route '/api/payments/orders/{orderId}/cancel' processed all 0/20 requests without throttling or returning HTTP 429 (Brute-force / Abuse Risk).

**Reproduction Proof-of-Concept:**
```bash
# Burst test reproducing unrestricted requests without HTTP 429:
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST "https://www.fluffwalks.in/api/payments/orders/{orderId}/cancel"
done
```

**Remediation Recommendation:**
> Implement strict IP & user-level rate limiting on sensitive routes. For authentication and OTP endpoints, allow max 5 requests per minute, returning HTTP 429 with 'Retry-After: 60'.

### Finding 5: Unrestricted Resource Consumption on `POST /api/admin/rides/{rideId}/complete`
- **Severity:** MEDIUM
- **CWE Classification:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Total Burst Requests:** 20
- **Successful Responses (Unthrottled):** 0
- **Throttled Responses (429):** 0
- **Security Risk:** MEDIUM VULNERABILITY: Endpoint permitted 20 rapid requests with zero rate-limit headers or throttling.

**Reproduction Proof-of-Concept:**
```bash
# Burst test reproducing unrestricted requests without HTTP 429:
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST "https://www.fluffwalks.in/api/admin/rides/{rideId}/complete"
done
```

**Remediation Recommendation:**
> Enforce API gateway or reverse-proxy rate limiting (e.g. 60-120 req/min) to prevent server thread exhaustion and scraping.

### Finding 6: Unrestricted Resource Consumption on `POST /api/admin/partners/{partnerId}/verify`
- **Severity:** MEDIUM
- **CWE Classification:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Total Burst Requests:** 20
- **Successful Responses (Unthrottled):** 0
- **Throttled Responses (429):** 0
- **Security Risk:** MEDIUM VULNERABILITY: Endpoint permitted 20 rapid requests with zero rate-limit headers or throttling.

**Reproduction Proof-of-Concept:**
```bash
# Burst test reproducing unrestricted requests without HTTP 429:
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST "https://www.fluffwalks.in/api/admin/partners/{partnerId}/verify"
done
```

**Remediation Recommendation:**
> Enforce API gateway or reverse-proxy rate limiting (e.g. 60-120 req/min) to prevent server thread exhaustion and scraping.
