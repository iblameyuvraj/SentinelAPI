# OWASP API9:2023 — Shadow & Zombie APIs Audit Report

- **API Target:** Production Inventory API (v2.0) (v2.0.0)
- **Base URL:** `http://localhost:8013`
- **Scan Timestamp:** 2026-09-24 14:08:46 UTC
- **Standard:** OWASP API Security Top 10 — API9:2023 Improper Inventory Management
- **Probes Evaluated:** 15
- **Undocumented Assets Found:** 0

## Executive Summary
CLEARANCE: Clean API inventory verified. Deprecated routes are either properly decommissioned (HTTP 410) or disabled (HTTP 404). Zero undocumented shadow assets detected.

## Findings Matrix

| Endpoint | Category | Audit Check | Status | Verdict | Severity |
| :--- | :--- | :--- | :---: | :---: | :---: |
| `GET /api/v1/users` | Zombie API | Zombie API: Deprecated v1 Version Active | `410` | RETIRED (410) | NONE |
| `GET /api/v2/beta/export-users` | Shadow API | Shadow API: Undocumented Beta Export (users) | `404` | OFFLINE (404) | NONE |
| `GET /api/v1/products` | Zombie API | Zombie API: Deprecated v1 Version Active | `410` | RETIRED (410) | NONE |
| `GET /api/v2/beta/export-products` | Shadow API | Shadow API: Undocumented Beta Export (products) | `404` | OFFLINE (404) | NONE |
| `POST /api/v1/auth/legacy-login` | Zombie API | Zombie API: Deprecated Authentication Bypass | `410` | RETIRED (410) | NONE |
| `GET /debug/server-vars` | Exposed Diagnostic | Exposed Diagnostic Server Variables | `404` | OFFLINE (404) | NONE |
| `GET /debug/vars` | Exposed Diagnostic | Exposed Go/Internal Debug Vars | `404` | OFFLINE (404) | NONE |
| `GET /actuator/health` | Exposed Diagnostic | Exposed Spring Boot Actuator Health | `404` | OFFLINE (404) | NONE |
| `GET /actuator/env` | Exposed Diagnostic | Exposed Spring Boot Actuator Environment | `404` | OFFLINE (404) | NONE |
| `GET /actuator/metrics` | Exposed Diagnostic | Exposed Spring Boot Actuator Metrics | `404` | OFFLINE (404) | NONE |
| `GET /metrics` | Exposed Diagnostic | Prometheus / System Metrics Endpoint | `404` | OFFLINE (404) | NONE |
| `GET /api/config.old` | Backup / Config Leak | Exposed Configuration Backup File | `404` | OFFLINE (404) | NONE |
| `GET /config.json` | Backup / Config Leak | Exposed Public Configuration File | `404` | OFFLINE (404) | NONE |
| `GET /.env` | Backup / Config Leak | Exposed Root Environment File | `404` | OFFLINE (404) | NONE |
| `GET /.git/HEAD` | Backup / Config Leak | Exposed Git Repository Metadata | `404` | OFFLINE (404) | NONE |