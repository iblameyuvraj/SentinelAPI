# OWASP API9:2023 — Shadow & Zombie APIs Audit Report

- **API Target:** Production Inventory API (v2.0) (v2.0.0)
- **Base URL:** `http://localhost:8012`
- **Scan Timestamp:** 2026-09-24 14:08:06 UTC
- **Standard:** OWASP API Security Top 10 — API9:2023 Improper Inventory Management
- **Probes Evaluated:** 15
- **Undocumented Assets Found:** 6

## Executive Summary
CRITICAL WARNING: Undocumented Shadow APIs, deprecated Zombie endpoints, or diagnostic interfaces were discovered actively running on the production host. These endpoints bypass standard security controls, lack monitoring, and expose confidential data.

## Findings Matrix

| Endpoint | Category | Audit Check | Status | Verdict | Severity |
| :--- | :--- | :--- | :---: | :---: | :---: |
| `GET /api/v1/users` | Zombie API | Zombie API: Deprecated v1 Version Active | `200` | **ZOMBIE API** | HIGH |
| `GET /api/v2/beta/export-users` | Shadow API | Shadow API: Undocumented Beta Export (users) | `200` | **SHADOW API** | CRITICAL |
| `GET /api/v1/products` | Zombie API | Zombie API: Deprecated v1 Version Active | `404` | OFFLINE (404) | NONE |
| `GET /api/v2/beta/export-products` | Shadow API | Shadow API: Undocumented Beta Export (products) | `404` | OFFLINE (404) | NONE |
| `POST /api/v1/auth/legacy-login` | Zombie API | Zombie API: Deprecated Authentication Bypass | `200` | **ZOMBIE API** | HIGH |
| `GET /debug/server-vars` | Exposed Diagnostic | Exposed Diagnostic Server Variables | `200` | **EXPOSED DIAGNOSTIC** | CRITICAL |
| `GET /debug/vars` | Exposed Diagnostic | Exposed Go/Internal Debug Vars | `404` | OFFLINE (404) | NONE |
| `GET /actuator/health` | Exposed Diagnostic | Exposed Spring Boot Actuator Health | `200` | **EXPOSED DIAGNOSTIC** | MEDIUM |
| `GET /actuator/env` | Exposed Diagnostic | Exposed Spring Boot Actuator Environment | `404` | OFFLINE (404) | NONE |
| `GET /actuator/metrics` | Exposed Diagnostic | Exposed Spring Boot Actuator Metrics | `404` | OFFLINE (404) | NONE |
| `GET /metrics` | Exposed Diagnostic | Prometheus / System Metrics Endpoint | `404` | OFFLINE (404) | NONE |
| `GET /api/config.old` | Backup / Config Leak | Exposed Configuration Backup File | `200` | **BACKUP / CONFIG LEAK** | CRITICAL |
| `GET /config.json` | Backup / Config Leak | Exposed Public Configuration File | `404` | OFFLINE (404) | NONE |
| `GET /.env` | Backup / Config Leak | Exposed Root Environment File | `404` | OFFLINE (404) | NONE |
| `GET /.git/HEAD` | Backup / Config Leak | Exposed Git Repository Metadata | `404` | OFFLINE (404) | NONE |

## Detailed Vulnerability Analysis & Proof of Concept

### Finding 1: Zombie API: Deprecated v1 Version Active on `GET /api/v1/users`
- **Severity:** HIGH
- **Asset Category:** Zombie API
- **CWE Classification:** CWE-1050: Designation of Ineffective or Inappropriate Security Control
- **HTTP Status Returned:** `200`
- **Security Risk:** CRITICAL ZOMBIE API: Deprecated endpoint '/api/v1/users' is actively running on production and returned HTTP 200. Deprecated APIs often lack modern authorization and security patches.

**Reproduction Proof-of-Concept:**
```bash
curl -s -i -X GET "http://localhost:8012/api/v1/users"
```

**Server Response Preview:**
```json
{"warning":"ZOMBIE API: Deprecated v1 endpoint still active without modern authentication!","version":"1.0-deprecated","users":[{"id":101,"username":"alice_crypto","email":"alice@example.com","ssn"...
```

**Remediation Recommendation:**
> Permanently decommission legacy v1 endpoints. Return HTTP 410 Gone with a 'Sunset' header directing consumers to the active v2 API version.

### Finding 2: Shadow API: Undocumented Beta Export (users) on `GET /api/v2/beta/export-users`
- **Severity:** CRITICAL
- **Asset Category:** Shadow API
- **CWE Classification:** CWE-1059: Incomplete Documentation
- **HTTP Status Returned:** `200`
- **Security Risk:** CRITICAL SHADOW API: Undocumented live route '/api/v2/beta/export-users' was discovered running in production. Shadow endpoints operate outside security monitoring and governance.

**Reproduction Proof-of-Concept:**
```bash
curl -s -i -X GET "http://localhost:8012/api/v2/beta/export-users"
```

**Server Response Preview:**
```json
{"warning":"SHADOW API DETECTED: Undocumented beta endpoint live in production!","exported_records":2,"data":[{"id":101,"username":"alice_crypto","password_hash":"$2b$12$e829312...hashed"},{"id":10...
```

**Remediation Recommendation:**
> Audit live codebase. Either document this endpoint formally in the OpenAPI specification or decommission it if it is an unapproved beta/internal hook.

### Finding 3: Zombie API: Deprecated Authentication Bypass on `POST /api/v1/auth/legacy-login`
- **Severity:** HIGH
- **Asset Category:** Zombie API
- **CWE Classification:** CWE-287: Improper Authentication
- **HTTP Status Returned:** `200`
- **Security Risk:** CRITICAL ZOMBIE API: Deprecated endpoint '/api/v1/auth/legacy-login' is actively running on production and returned HTTP 200. Deprecated APIs often lack modern authorization and security patches.

**Reproduction Proof-of-Concept:**
```bash
curl -s -i -X POST "http://localhost:8012/api/v1/auth/legacy-login"
```

**Server Response Preview:**
```json
{"warning":"ZOMBIE API: Legacy v1 login endpoint bypasses modern 2FA enforcement!","status":"authenticated","bypass_2fa":true,"token":"legacy_insecure_token_1928"}
```

**Remediation Recommendation:**
> Permanently decommission legacy v1 endpoints. Return HTTP 410 Gone with a 'Sunset' header directing consumers to the active v2 API version.

### Finding 4: Exposed Diagnostic Server Variables on `GET /debug/server-vars`
- **Severity:** CRITICAL
- **Asset Category:** Exposed Diagnostic
- **CWE Classification:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **HTTP Status Returned:** `200`
- **Security Risk:** CRITICAL EXPOSURE: System diagnostic endpoint '/debug/server-vars' is publicly exposed (HTTP 200), leaking internal system state, memory variables, or infrastructure metrics.

**Reproduction Proof-of-Concept:**
```bash
curl -s -i -X GET "http://localhost:8012/debug/server-vars"
```

**Server Response Preview:**
```json
{"warning":"SHADOW DIAGNOSTIC DETECTED: Server environment variables exposed!","environment":"production","internal_db_host":"postgres-cluster.internal.sentinel.io","jwt_secret_key":"super_secret_j...
```

**Remediation Recommendation:**
> Restrict access to internal networks/VPN or disable debug/actuator endpoints in production.

### Finding 5: Exposed Spring Boot Actuator Health on `GET /actuator/health`
- **Severity:** MEDIUM
- **Asset Category:** Exposed Diagnostic
- **CWE Classification:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **HTTP Status Returned:** `200`
- **Security Risk:** CRITICAL EXPOSURE: System diagnostic endpoint '/actuator/health' is publicly exposed (HTTP 200), leaking internal system state, memory variables, or infrastructure metrics.

**Reproduction Proof-of-Concept:**
```bash
curl -s -i -X GET "http://localhost:8012/actuator/health"
```

**Server Response Preview:**
```json
{"status":"UP","components":{"db":{"status":"UP"},"diskSpace":{"status":"UP"}}}
```

**Remediation Recommendation:**
> Restrict access to internal networks/VPN or disable debug/actuator endpoints in production.

### Finding 6: Exposed Configuration Backup File on `GET /api/config.old`
- **Severity:** CRITICAL
- **Asset Category:** Backup / Config Leak
- **CWE Classification:** CWE-552: Files or Directories Accessible to External Parties
- **HTTP Status Returned:** `200`
- **Security Risk:** CRITICAL ARTIFACT LEAK: Configuration or backup artifact '/api/config.old' is accessible over HTTP (HTTP 200).

**Reproduction Proof-of-Concept:**
```bash
curl -s -i -X GET "http://localhost:8012/api/config.old"
```

**Server Response Preview:**
```json
{"warning":"SHADOW BACKUP DETECTED: Deprecated configuration file left accessible!","database_url":"postgres://admin:Password123@localhost:5432/main_db"}
```

**Remediation Recommendation:**
> Remove backup files (*.old, *.bak, .env, .git) from the web root and configure web server to deny access.
