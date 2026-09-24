# OWASP API2:2023 — Authentication Misconfiguration Security Audit Report

- **API Target:** Authentication Misconfiguration Sandbox API (v1.0.0)
- **Base URL:** `http://localhost:8005`
- **Scan Timestamp:** 2026-09-24 13:08:27 UTC
- **Standard:** OWASP API Security Top 10 — API2:2023 Broken Authentication
- **Total Probes Executed:** 35
- **Vulnerabilities Identified:** 0

## Executive Summary
CLEARANCE: Authentication boundaries are strictly enforced. Unauthenticated, unsigned, expired, and forged requests were all properly rejected with 401/403 status codes.

## Findings Matrix

| Endpoint | Method | Test Vector | Status | Verdict | Severity |
| :--- | :---: | :--- | :---: | :---: | :---: |
| `/api/public/status` | GET | Missing Authentication Header | `200` | PROTECTED | NONE |
| `/api/public/status` | GET | Empty Bearer Token Header | `200` | PROTECTED | NONE |
| `/api/public/status` | GET | Arbitrary / Fabricated Bearer Token | `200` | PROTECTED | NONE |
| `/api/public/status` | GET | JWT alg:none Signature Bypass | `200` | PROTECTED | NONE |
| `/api/public/status` | GET | Tampered Cryptographic Signature | `200` | PROTECTED | NONE |
| `/api/public/status` | GET | Expired Token Validation | `200` | PROTECTED | NONE |
| `/api/public/status` | GET | Malformed Token & Verbose Error Leakage | `200` | PROTECTED | NONE |
| `/api/admin/users` | GET | Missing Authentication Header | `401` | PROTECTED | NONE |
| `/api/admin/users` | GET | Empty Bearer Token Header | `401` | PROTECTED | NONE |
| `/api/admin/users` | GET | Arbitrary / Fabricated Bearer Token | `401` | PROTECTED | NONE |
| `/api/admin/users` | GET | JWT alg:none Signature Bypass | `401` | PROTECTED | NONE |
| `/api/admin/users` | GET | Tampered Cryptographic Signature | `401` | PROTECTED | NONE |
| `/api/admin/users` | GET | Expired Token Validation | `401` | PROTECTED | NONE |
| `/api/admin/users` | GET | Malformed Token & Verbose Error Leakage | `401` | PROTECTED | NONE |
| `/api/user/profile` | GET | Missing Authentication Header | `401` | PROTECTED | NONE |
| `/api/user/profile` | GET | Empty Bearer Token Header | `401` | PROTECTED | NONE |
| `/api/user/profile` | GET | Arbitrary / Fabricated Bearer Token | `401` | PROTECTED | NONE |
| `/api/user/profile` | GET | JWT alg:none Signature Bypass | `401` | PROTECTED | NONE |
| `/api/user/profile` | GET | Tampered Cryptographic Signature | `401` | PROTECTED | NONE |
| `/api/user/profile` | GET | Expired Token Validation | `401` | PROTECTED | NONE |
| `/api/user/profile` | GET | Malformed Token & Verbose Error Leakage | `401` | PROTECTED | NONE |
| `/api/user/settings` | GET | Missing Authentication Header | `401` | PROTECTED | NONE |
| `/api/user/settings` | GET | Empty Bearer Token Header | `401` | PROTECTED | NONE |
| `/api/user/settings` | GET | Arbitrary / Fabricated Bearer Token | `401` | PROTECTED | NONE |
| `/api/user/settings` | GET | JWT alg:none Signature Bypass | `401` | PROTECTED | NONE |
| `/api/user/settings` | GET | Tampered Cryptographic Signature | `401` | PROTECTED | NONE |
| `/api/user/settings` | GET | Expired Token Validation | `401` | PROTECTED | NONE |
| `/api/user/settings` | GET | Malformed Token & Verbose Error Leakage | `401` | PROTECTED | NONE |
| `/api/user/data` | GET | Missing Authentication Header | `401` | PROTECTED | NONE |
| `/api/user/data` | GET | Empty Bearer Token Header | `401` | PROTECTED | NONE |
| `/api/user/data` | GET | Arbitrary / Fabricated Bearer Token | `401` | PROTECTED | NONE |
| `/api/user/data` | GET | JWT alg:none Signature Bypass | `401` | PROTECTED | NONE |
| `/api/user/data` | GET | Tampered Cryptographic Signature | `401` | PROTECTED | NONE |
| `/api/user/data` | GET | Expired Token Validation | `401` | PROTECTED | NONE |
| `/api/user/data` | GET | Malformed Token & Verbose Error Leakage | `401` | PROTECTED | NONE |