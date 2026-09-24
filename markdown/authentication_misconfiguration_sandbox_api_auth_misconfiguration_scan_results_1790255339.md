# OWASP API2:2023 — Authentication Misconfiguration Security Audit Report

- **API Target:** Authentication Misconfiguration Sandbox API (v1.0.0)
- **Base URL:** `http://localhost:8005`
- **Scan Timestamp:** 2026-09-24 13:08:59 UTC
- **Standard:** OWASP API Security Top 10 — API2:2023 Broken Authentication
- **Total Probes Executed:** 5
- **Vulnerabilities Identified:** 0

## Executive Summary
CLEARANCE: Authentication boundaries are strictly enforced. Unauthenticated, unsigned, expired, and forged requests were all properly rejected with 401/403 status codes.

## Findings Matrix

| Endpoint | Method | Test Vector | Status | Verdict | Severity |
| :--- | :---: | :--- | :---: | :---: | :---: |
| `/api/public/status` | GET | Missing Authentication Header | `200` | PROTECTED | NONE |
| `/api/admin/users` | GET | Missing Authentication Header | `401` | PROTECTED | NONE |
| `/api/user/profile` | GET | Missing Authentication Header | `401` | PROTECTED | NONE |
| `/api/user/settings` | GET | Missing Authentication Header | `401` | PROTECTED | NONE |
| `/api/user/data` | GET | Missing Authentication Header | `401` | PROTECTED | NONE |