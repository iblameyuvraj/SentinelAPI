# OWASP API4:2023 — Unrestricted Resource Consumption & Rate Limiting Audit Report

- **API Target:** Rate Limiting & Resource Exhaustion Test API (v1.0.0)
- **Base URL:** `http://localhost:8006`
- **Burst Volume Tested:** 30 requests/route
- **Scan Timestamp:** 2026-09-24 13:19:31 UTC
- **Standard:** OWASP API Security Top 10 — API4:2023 Unrestricted Resource Consumption
- **Routes Tested:** 5
- **Vulnerable Routes Identified:** 4

## Executive Summary
CRITICAL WARNING: The target API lacks essential request throttling and rate limiting controls. Sensitive endpoints permit unlimited burst requests, rendering the API vulnerable to credential stuffing, SMS/email denial-of-wallet, and DoS.

## Findings Matrix

| Endpoint | Method | Burst Reqs | 200 OK | 429 Throttled | Rate Limit Headers | Verdict | Severity |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `/api/public/status` | GET | 30 | 30 | 0 | None | PASS (Public) | NONE |
| `/api/auth/login` | POST | 30 | 30 | 0 | None | **VULNERABLE** | HIGH |
| `/api/auth/forgot-password` | POST | 30 | 30 | 0 | None | **VULNERABLE** | HIGH |
| `/api/search` | GET | 30 | 30 | 0 | None | **VULNERABLE** | HIGH |
| `/api/user/export` | GET | 30 | 30 | 0 | None | **VULNERABLE** | HIGH |

## Detailed Vulnerability Analysis & Proof of Concept

### Finding 1: Unrestricted Resource Consumption on `POST /api/auth/login`
- **Severity:** HIGH
- **CWE Classification:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Total Burst Requests:** 30
- **Successful Responses (Unthrottled):** 30
- **Throttled Responses (429):** 0
- **Security Risk:** HIGH VULNERABILITY: Sensitive route '/api/auth/login' processed all 30/30 requests without throttling or returning HTTP 429 (Brute-force / Abuse Risk).

**Reproduction Proof-of-Concept:**
```bash
# Burst test reproducing unrestricted requests without HTTP 429:
for i in $(seq 1 30); do
  curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST "http://localhost:8006/api/auth/login"
done
```

**Remediation Recommendation:**
> Implement strict IP & user-level rate limiting on sensitive routes. For authentication and OTP endpoints, allow max 5 requests per minute, returning HTTP 429 with 'Retry-After: 60'.

### Finding 2: Unrestricted Resource Consumption on `POST /api/auth/forgot-password`
- **Severity:** HIGH
- **CWE Classification:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Total Burst Requests:** 30
- **Successful Responses (Unthrottled):** 30
- **Throttled Responses (429):** 0
- **Security Risk:** HIGH VULNERABILITY: Sensitive route '/api/auth/forgot-password' processed all 30/30 requests without throttling or returning HTTP 429 (Brute-force / Abuse Risk).

**Reproduction Proof-of-Concept:**
```bash
# Burst test reproducing unrestricted requests without HTTP 429:
for i in $(seq 1 30); do
  curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST "http://localhost:8006/api/auth/forgot-password"
done
```

**Remediation Recommendation:**
> Implement strict IP & user-level rate limiting on sensitive routes. For authentication and OTP endpoints, allow max 5 requests per minute, returning HTTP 429 with 'Retry-After: 60'.

### Finding 3: Unrestricted Resource Consumption on `GET /api/search`
- **Severity:** HIGH
- **CWE Classification:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Total Burst Requests:** 30
- **Successful Responses (Unthrottled):** 30
- **Throttled Responses (429):** 0
- **Security Risk:** HIGH VULNERABILITY: Sensitive route '/api/search' processed all 30/30 requests without throttling or returning HTTP 429 (Brute-force / Abuse Risk).

**Reproduction Proof-of-Concept:**
```bash
# Burst test reproducing unrestricted requests without HTTP 429:
for i in $(seq 1 30); do
  curl -s -o /dev/null -w "HTTP %{http_code}\n" -X GET "http://localhost:8006/api/search"
done
```

**Remediation Recommendation:**
> Implement strict IP & user-level rate limiting on sensitive routes. For authentication and OTP endpoints, allow max 5 requests per minute, returning HTTP 429 with 'Retry-After: 60'.

### Finding 4: Unrestricted Resource Consumption on `GET /api/user/export`
- **Severity:** HIGH
- **CWE Classification:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Total Burst Requests:** 30
- **Successful Responses (Unthrottled):** 30
- **Throttled Responses (429):** 0
- **Security Risk:** HIGH VULNERABILITY: Sensitive route '/api/user/export' processed all 30/30 requests without throttling or returning HTTP 429 (Brute-force / Abuse Risk).

**Reproduction Proof-of-Concept:**
```bash
# Burst test reproducing unrestricted requests without HTTP 429:
for i in $(seq 1 30); do
  curl -s -o /dev/null -w "HTTP %{http_code}\n" -X GET "http://localhost:8006/api/user/export"
done
```

**Remediation Recommendation:**
> Implement strict IP & user-level rate limiting on sensitive routes. For authentication and OTP endpoints, allow max 5 requests per minute, returning HTTP 429 with 'Retry-After: 60'.
