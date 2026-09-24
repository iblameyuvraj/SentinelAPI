# OWASP API9:2023 — Shadow & Zombie APIs Test Matrix

## Overview
This test matrix defines test cases for identifying Improper Inventory Management, Shadow APIs, Zombie APIs, and Environment/Diagnostic Leakage according to **OWASP API9:2023**.

---

## Definitions
* **Zombie API:** An older, deprecated, or retired version of an API (e.g. `v1`, `v0`, `/legacy/`) that remains active on production servers. Often lacks modern authentication, rate limiting, and security patches.
* **Shadow API:** An active API route operating on the server that is completely absent from the official OpenAPI / Swagger specification or developer documentation (e.g., hidden bulk export endpoints, beta routes, unmapped admin hooks).
* **Exposed Diagnostics / Actuators:** Debug, profiling, or framework internal management endpoints (e.g. `/debug/vars`, `/actuator/env`, `/metrics`) inadvertently left public.
* **Configuration & Backup Artifacts:** Legacy backups and source control files left exposed on the web root (e.g., `/config.old`, `/.env`, `/.git/HEAD`).

---

## Test Vectors

| Test ID | Category | Target Probe Pattern | Vector Description | Severity | Expected Behavior (Hardened) | Vulnerable Flaw (Vulnerable Backend) |
| :--- | :--- | :--- | :--- | :---: | :--- | :--- |
| **INV-01-ZOMBIE-V1** | Zombie API | `/api/v1/*`, `/v1/*` | Version downgrade probe on declared `/api/v2/*` endpoints | **HIGH** | Returns `410 Gone` with Sunset header or `404 Not Found` | Returns `200 OK` with legacy unauthenticated data |
| **INV-02-SHADOW-BETA** | Shadow API | `/api/v2/beta/*`, `/api/beta/*` | Crawls candidate undocumented beta and staging routes | **CRITICAL** | Returns `404 Not Found` in production | Returns `200 OK` exposing unauthenticated bulk exports |
| **INV-03-DIAG-DEBUG** | Exposed Diagnostics | `/debug/server-vars`, `/debug/*` | Probes for diagnostic endpoints exposing runtime environment | **CRITICAL** | Returns `404 Not Found` (stripped in prod) | Returns `200 OK` with database hosts and secrets |
| **INV-04-ACTUATOR** | Framework Actuator | `/actuator/health`, `/actuator/*` | Probes Spring Boot and microservice actuator routes | **MEDIUM** | Returns `404 Not Found` or `401 Unauthorized` | Returns `200 OK` exposing internal service topology |
| **INV-05-BACKUP-LEAK** | Sensitive Backup | `*.old`, `*.bak`, `/.env` | Probes for left-behind backup and configuration files | **CRITICAL** | Returns `404 Not Found` | Returns `200 OK` with plaintext credentials |

---

## Production Remediation Summary

### Node.js / Express: Decommissioning & Gateway Routing
```javascript
// 1. Explicitly decommission old versions with HTTP 410 Gone & Sunset headers
app.use("/api/v1", (req, res) => {
  res.setHeader("Sunset", "Wed, 01 Jan 2025 00:00:00 GMT");
  res.setHeader("Link", '</api/v2>; rel="successor-version"');
  return res.status(410).json({
    error: "Gone",
    message: "API v1 was decommissioned. Please migrate to /api/v2/."
  });
});

// 2. Prohibit unmapped routes in production
if (process.env.NODE_ENV === "production") {
  // Never mount /debug, /actuator, or /beta routes
}
```

### Python / FastAPI: Route Whitelisting
```python
from fastapi import FastAPI, Response, status

app = FastAPI(docs_url=None if PROD else "/docs")

# Prohibit deprecated prefixes
@app.api_route("/api/v1/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE"])
def deprecated_v1_handler(full_path: str):
    return Response(
        status_code=status.HTTP_410_GONE,
        headers={"Sunset": "Wed, 01 Jan 2025 00:00:00 GMT"},
        content='{"error": "API v1 permanently retired."}',
        media_type="application/json"
    )
```
