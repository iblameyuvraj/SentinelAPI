# Fluffwalks Web API (`fluffwalks.in`) — BOLA & IDOR Security Test Cases

**Target Domain:** `https://www.fluffwalks.in` / `http://localhost:3000`  
**Framework:** Next.js App Router (TypeScript) + Supabase Auth / PostgreSQL  
**Audit Standard:** OWASP API Security Top 10 (2023) — **API1:2023 Broken Object Level Authorization (BOLA / IDOR)**

---

## 1. Threat Modeling & Architecture Overview

Fluffwalks operates a multi-tenant pet care platform handling sensitive customer data (dog walking bookings, pet boarding home stays, live GPS ride statuses, payment transactions, and partner payouts).

### Privilege Domains & User Roles:
1. **Customer (Pet Owner)**: Owns pet profiles, booked walks (`booked_rides`), and home boarding stays (`booked_boardings`).
2. **Boarder (Partner)**: Pet care providers assigned to host specific boarding stays.
3. **Admin**: Manages partner verifications, manual ride completions, and system analytics.

---

## 2. Test Cases Matrix

| Test Case | Target Endpoint | Source Route File | Risk Vector | Expected Status | Vulnerable Status |
|---|---|---|---|---|---|
| **TC-01** | `GET /api/user/{userId}/profile` | `app/api/user/profile/route.ts` | Customer Profile Data Exposure | `403 Forbidden` | `200 OK (PII Leaked)` |
| **TC-02** | `GET /api/user/{userId}/rides` | `app/api/user/rides/route.ts` | Cross-Tenant Walk History Snooping | `403 Forbidden` | `200 OK (Rides Leaked)` |
| **TC-03** | `GET /api/user/{userId}/boardings` | `app/api/user/boardings/route.ts` | Cross-Tenant Boarding Stays Exposure | `403 Forbidden` | `200 OK (Stays Leaked)` |
| **TC-04** | `POST /api/border/bookings/{bookingId}/status` | `app/api/border/update-booking-status/route.ts` | Unauthorized Stay Status Manipulation | `403 Forbidden` | `200 OK (Unauthorized Update)` |
| **TC-05** | `POST /api/payments/orders/{orderId}/cancel` | `app/api/payments/cancel/route.ts` | Malicious Order Cancellation / Deletion | `403 Forbidden` | `200 OK (Order Cancelled)` |
| **TC-06** | `POST /api/admin/rides/{rideId}/complete` | `app/api/admin/complete-ride/route.ts` | Privilege Escalation to Ride Completion | `403 Forbidden` | `200 OK (Unauthorized Commission)` |
| **TC-07** | `POST /api/admin/partners/{partnerId}/verify` | `app/api/admin/verify-partner/route.ts` | Unauthorized Partner Status Approval | `403 Forbidden` | `200 OK (Partner Modified)` |

---

## 3. Deep-Dive Test Scenarios

### Test Case TC-01: Cross-Tenant Profile Data Exposure
* **Endpoint:** `GET /api/user/{userId}/profile`
* **Source:** `app/api/user/profile/route.ts`
* **Threat:** User B supplies User A's Supabase UUID to read their private phone number, address, and pet details.
* **Current Implementation Note:** `app/api/user/profile/route.ts` relies on `supabase.auth.getUser()`, querying `eq('id', user.id)`. When accessed with path parameters, the server must reject attempts to access records where `token.user.id !== requested_userId`.

---

### Test Case TC-04: Boarder Stay Status Manipulation
* **Endpoint:** `POST /api/border/bookings/{bookingId}/status`
* **Source:** `app/api/border/update-booking-status/route.ts`
* **Threat:** A rogue partner or user submits a request to transition an unassigned boarding stay to `completed`.
* **Security Validation Check:**
  ```typescript
  // Fluffwalks Enforcement Check:
  if (booking.boarder_id !== user.id) {
    return NextResponse.json({ error: 'Forbidden — you are not assigned to this stay.' }, { status: 403 })
  }
  ```
* **Expected Result:** **HTTP 403 Forbidden** (Validated BOLA protection).

---

### Test Case TC-05: Razorpay Payment Cancellation Hijack
* **Endpoint:** `POST /api/payments/orders/{orderId}/cancel`
* **Source:** `app/api/payments/cancel/route.ts`
* **Threat:** An attacker discovers or enumerates a `razorpay_order_id` belonging to a rival customer and issues a cancellation request, triggering DB record cleanup.
* **Security Validation Check:**
  ```typescript
  // Fluffwalks Enforcement Check:
  if (payment.user_id !== user.id) {
    return NextResponse.json({ error: 'Forbidden.' }, { status: 403 })
  }
  ```
* **Expected Result:** **HTTP 403 Forbidden** (Validated BOLA protection).

---

### Test Case TC-06: Ride Completion & UGC Referral Exploitation
* **Endpoint:** `POST /api/admin/rides/{rideId}/complete`
* **Source:** `app/api/admin/complete-ride/route.ts`
* **Threat:** A normal customer calls the completion route on their own pending walk to trigger referral credit or mark rides as done without admin authorization.
* **Expected Result:** **HTTP 403 Forbidden** (Must require admin session token).

---

## 4. How to Run the Security Audit in SentinelAPI

1. Launch the SentinelAPI CLI:
   ```bash
   sentinel
   ```
2. Select **`1. OpenAPI / Swagger`** from the API Source menu.
3. Drag & drop or enter the specification path:
   ```text
   fluffwalks-test-case/openapi.json
   ```
4. Confirm specification verification (**`Y`**).
5. Select **`2. BOLA / IDOR (Broken Object Level Authorization)`**.
6. SentinelAPI will dynamically detect the 7 candidate endpoints and UUID schemas, allowing you to configure live Supabase tokens and run the automated assessment!
