# OWASP API4:2023 — Unrestricted Resource Consumption & Rate Limiting Audit Report

- **API Target:** Rate Limiting & Resource Exhaustion Test API (v1.0.0)
- **Base URL:** `http://localhost:8007`
- **Burst Volume Tested:** 20 requests/route
- **Scan Timestamp:** 2026-09-24 13:20:04 UTC
- **Standard:** OWASP API Security Top 10 — API4:2023 Unrestricted Resource Consumption
- **Routes Tested:** 5
- **Vulnerable Routes Identified:** 0

## Executive Summary
CLEARANCE: The target API correctly enforces rate limiting across critical and standard endpoints, returning HTTP 429 Too Many Requests upon exceeding thresholds.

## Findings Matrix

| Endpoint | Method | Burst Reqs | 200 OK | 429 Throttled | Rate Limit Headers | Verdict | Severity |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `/api/public/status` | GET | 20 | 20 | 0 | Yes | PASS (Public) | NONE |
| `/api/auth/login` | POST | 20 | 0 | 20 | Yes | PROTECTED | NONE |
| `/api/auth/forgot-password` | POST | 20 | 0 | 20 | Yes | PROTECTED | NONE |
| `/api/search` | GET | 20 | 0 | 20 | Yes | PROTECTED | NONE |
| `/api/user/export` | GET | 20 | 0 | 20 | Yes | PROTECTED | NONE |