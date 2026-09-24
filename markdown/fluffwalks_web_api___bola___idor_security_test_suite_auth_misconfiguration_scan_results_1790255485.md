# OWASP API2:2023 — Authentication Misconfiguration Security Audit Report

- **API Target:** Fluffwalks Web API - BOLA & IDOR Security Test Suite (v1.0.0)
- **Base URL:** `https://www.fluffwalks.in`
- **Scan Timestamp:** 2026-09-24 13:11:25 UTC
- **Standard:** OWASP API Security Top 10 — API2:2023 Broken Authentication
- **Total Probes Executed:** 49
- **Vulnerabilities Identified:** 0

## Executive Summary
CLEARANCE: Authentication boundaries are strictly enforced. Unauthenticated, unsigned, expired, and forged requests were all properly rejected with 401/403 status codes.

## Findings Matrix

| Endpoint | Method | Test Vector | Status | Verdict | Severity |
| :--- | :---: | :--- | :---: | :---: | :---: |
| `/api/user/101/profile` | GET | Missing Authentication Header | `404` | PROTECTED | NONE |
| `/api/user/101/profile` | GET | Empty Bearer Token Header | `404` | PROTECTED | NONE |
| `/api/user/101/profile` | GET | Arbitrary / Fabricated Bearer Token | `404` | PROTECTED | NONE |
| `/api/user/101/profile` | GET | JWT alg:none Signature Bypass | `403` | PROTECTED | NONE |
| `/api/user/101/profile` | GET | Tampered Cryptographic Signature | `404` | PROTECTED | NONE |
| `/api/user/101/profile` | GET | Expired Token Validation | `404` | PROTECTED | NONE |
| `/api/user/101/profile` | GET | Malformed Token & Verbose Error Leakage | `404` | PROTECTED | NONE |
| `/api/user/101/rides` | GET | Missing Authentication Header | `404` | PROTECTED | NONE |
| `/api/user/101/rides` | GET | Empty Bearer Token Header | `404` | PROTECTED | NONE |
| `/api/user/101/rides` | GET | Arbitrary / Fabricated Bearer Token | `404` | PROTECTED | NONE |
| `/api/user/101/rides` | GET | JWT alg:none Signature Bypass | `403` | PROTECTED | NONE |
| `/api/user/101/rides` | GET | Tampered Cryptographic Signature | `404` | PROTECTED | NONE |
| `/api/user/101/rides` | GET | Expired Token Validation | `404` | PROTECTED | NONE |
| `/api/user/101/rides` | GET | Malformed Token & Verbose Error Leakage | `404` | PROTECTED | NONE |
| `/api/user/101/boardings` | GET | Missing Authentication Header | `404` | PROTECTED | NONE |
| `/api/user/101/boardings` | GET | Empty Bearer Token Header | `404` | PROTECTED | NONE |
| `/api/user/101/boardings` | GET | Arbitrary / Fabricated Bearer Token | `404` | PROTECTED | NONE |
| `/api/user/101/boardings` | GET | JWT alg:none Signature Bypass | `403` | PROTECTED | NONE |
| `/api/user/101/boardings` | GET | Tampered Cryptographic Signature | `404` | PROTECTED | NONE |
| `/api/user/101/boardings` | GET | Expired Token Validation | `404` | PROTECTED | NONE |
| `/api/user/101/boardings` | GET | Malformed Token & Verbose Error Leakage | `404` | PROTECTED | NONE |
| `/api/border/bookings/{bookingId}/status` | POST | Missing Authentication Header | `404` | PROTECTED | NONE |
| `/api/border/bookings/{bookingId}/status` | POST | Empty Bearer Token Header | `404` | PROTECTED | NONE |
| `/api/border/bookings/{bookingId}/status` | POST | Arbitrary / Fabricated Bearer Token | `404` | PROTECTED | NONE |
| `/api/border/bookings/{bookingId}/status` | POST | JWT alg:none Signature Bypass | `403` | PROTECTED | NONE |
| `/api/border/bookings/{bookingId}/status` | POST | Tampered Cryptographic Signature | `404` | PROTECTED | NONE |
| `/api/border/bookings/{bookingId}/status` | POST | Expired Token Validation | `404` | PROTECTED | NONE |
| `/api/border/bookings/{bookingId}/status` | POST | Malformed Token & Verbose Error Leakage | `404` | PROTECTED | NONE |
| `/api/payments/orders/{orderId}/cancel` | POST | Missing Authentication Header | `404` | PROTECTED | NONE |
| `/api/payments/orders/{orderId}/cancel` | POST | Empty Bearer Token Header | `404` | PROTECTED | NONE |
| `/api/payments/orders/{orderId}/cancel` | POST | Arbitrary / Fabricated Bearer Token | `404` | PROTECTED | NONE |
| `/api/payments/orders/{orderId}/cancel` | POST | JWT alg:none Signature Bypass | `403` | PROTECTED | NONE |
| `/api/payments/orders/{orderId}/cancel` | POST | Tampered Cryptographic Signature | `404` | PROTECTED | NONE |
| `/api/payments/orders/{orderId}/cancel` | POST | Expired Token Validation | `404` | PROTECTED | NONE |
| `/api/payments/orders/{orderId}/cancel` | POST | Malformed Token & Verbose Error Leakage | `404` | PROTECTED | NONE |
| `/api/admin/rides/{rideId}/complete` | POST | Missing Authentication Header | `404` | PROTECTED | NONE |
| `/api/admin/rides/{rideId}/complete` | POST | Empty Bearer Token Header | `404` | PROTECTED | NONE |
| `/api/admin/rides/{rideId}/complete` | POST | Arbitrary / Fabricated Bearer Token | `404` | PROTECTED | NONE |
| `/api/admin/rides/{rideId}/complete` | POST | JWT alg:none Signature Bypass | `403` | PROTECTED | NONE |
| `/api/admin/rides/{rideId}/complete` | POST | Tampered Cryptographic Signature | `404` | PROTECTED | NONE |
| `/api/admin/rides/{rideId}/complete` | POST | Expired Token Validation | `404` | PROTECTED | NONE |
| `/api/admin/rides/{rideId}/complete` | POST | Malformed Token & Verbose Error Leakage | `404` | PROTECTED | NONE |
| `/api/admin/partners/{partnerId}/verify` | POST | Missing Authentication Header | `404` | PROTECTED | NONE |
| `/api/admin/partners/{partnerId}/verify` | POST | Empty Bearer Token Header | `404` | PROTECTED | NONE |
| `/api/admin/partners/{partnerId}/verify` | POST | Arbitrary / Fabricated Bearer Token | `404` | PROTECTED | NONE |
| `/api/admin/partners/{partnerId}/verify` | POST | JWT alg:none Signature Bypass | `403` | PROTECTED | NONE |
| `/api/admin/partners/{partnerId}/verify` | POST | Tampered Cryptographic Signature | `404` | PROTECTED | NONE |
| `/api/admin/partners/{partnerId}/verify` | POST | Expired Token Validation | `404` | PROTECTED | NONE |
| `/api/admin/partners/{partnerId}/verify` | POST | Malformed Token & Verbose Error Leakage | `404` | PROTECTED | NONE |