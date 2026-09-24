# OWASP API4:2023 — Unrestricted Resource Consumption & Rate Limiting Audit Report

- **API Target:** Rate Limiting Sandbox Test API (v1.0.0)
- **Base URL:** `http://localhost:8006`
- **Burst Volume Tested:** 20 requests/route
- **Scan Timestamp:** 2026-09-24 13:19:47 UTC
- **Standard:** OWASP API Security Top 10 — API4:2023 Unrestricted Resource Consumption
- **Routes Tested:** 1
- **Vulnerable Routes Identified:** 1

## Executive Summary
CRITICAL WARNING: The target API lacks essential request throttling and rate limiting controls. Sensitive endpoints permit unlimited burst requests, rendering the API vulnerable to credential stuffing, SMS/email denial-of-wallet, and DoS.

## Findings Matrix

| Endpoint | Method | Burst Reqs | 200 OK | 429 Throttled | Rate Limit Headers | Verdict | Severity |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `/api/auth/login` | POST | 20 | 20 | 0 | None | **VULNERABLE** | HIGH |

## Detailed Vulnerability Analysis & Proof of Concept

### Finding 1: Unrestricted Resource Consumption on `POST /api/auth/login`
- **Severity:** HIGH
- **CWE Classification:** CWE-770
- **Total Burst Requests:** 20
- **Successful Responses (Unthrottled):** 20
- **Throttled Responses (429):** 0
- **Security Risk:** Sensitive route processed 20 requests without throttling.

**Reproduction Proof-of-Concept:**
```bash
for i in 1..20; do curl http://localhost:8006/api/auth/login; done
```

**Remediation Recommendation:**
> Implement rate limiting.
